use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use vasp_core::{protocol::*, scheduler::Schedule};

pub struct Store {
    pub conn: Connection,
    pub directory: PathBuf,
}
impl Store {
    pub fn open(directory: &Path) -> Result<Self> {
        if !directory.exists() {
            std::fs::create_dir_all(directory)?;
        }
        if std::fs::symlink_metadata(directory)?
            .file_type()
            .is_symlink()
        {
            bail!("Data directory cannot be a symlink");
        }
        vasp_platform::isolation::protect_directory(directory)?;
        let path = directory.join("vasp.db");
        if path.exists() && std::fs::metadata(&path)?.len() > 1024 * 1024 * 1024 {
            bail!("Database exceeds 1 GiB; archive it before continuing");
        }
        let conn = Connection::open(&path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // Enforce the storage ceiling during writes too, including long-running observers.
        let page_size: u64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        conn.pragma_update(None, "max_page_count", (1024 * 1024 * 1024_u64) / page_size)?;
        conn.pragma_update(None, "journal_size_limit", 16 * 1024 * 1024)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,device TEXT NOT NULL,at INTEGER NOT NULL,json TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS observations_device ON observations(device,at DESC);
            CREATE TABLE IF NOT EXISTS advisories(key TEXT PRIMARY KEY,source TEXT NOT NULL,at INTEGER NOT NULL,json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,device TEXT NOT NULL,at INTEGER NOT NULL,json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,at INTEGER NOT NULL,event TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS schedules(name TEXT PRIMARY KEY,json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS peers(device TEXT PRIMARY KEY,fingerprint TEXT NOT NULL UNIQUE,certificate BLOB NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS replay(peer TEXT NOT NULL,request TEXT NOT NULL,at INTEGER NOT NULL,PRIMARY KEY(peer,request));
            CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,at INTEGER NOT NULL,json TEXT NOT NULL);")?;
        let version: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key='schema'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if version.as_deref().is_some_and(|v| v != "1") {
            bail!("Unsupported database schema; migration required");
        }
        conn.execute("INSERT OR IGNORE INTO meta VALUES('schema','1')", [])?;
        if conn.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? != "ok" {
            bail!("Database integrity check failed");
        }
        let store = Self {
            conn,
            directory: directory.to_owned(),
        };
        store.verify_audit()?;
        Ok(store)
    }
    pub fn device_id(&self) -> Result<Uuid> {
        if let Some(id) = self.get::<Uuid>("device_id")? {
            return Ok(id);
        }
        let id = Uuid::new_v4();
        self.conn.execute(
            "INSERT OR IGNORE INTO meta(key,value) VALUES('device_id',?1)",
            [serde_json::to_string(&id)?],
        )?;
        self.get("device_id")?
            .context("Device initialization failed")
    }
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let v: Option<String> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
            .optional()?;
        v.map(|s| Ok(serde_json::from_str(&s)?)).transpose()
    }
    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, serde_json::to_string(value)?],
        )?;
        Ok(())
    }
    pub fn latest(&self, device: Uuid) -> Result<Option<Observation>> {
        let v: Option<String> = self
            .conn
            .query_row(
                "SELECT json FROM observations WHERE device=?1 ORDER BY at DESC,rowid DESC LIMIT 1",
                [device.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        v.map(|s| Ok(serde_json::from_str(&s)?)).transpose()
    }
    pub fn devices(&self) -> Result<Vec<Observation>> {
        let mut q=self.conn.prepare("SELECT json FROM observations o WHERE rowid=(SELECT rowid FROM observations WHERE device=o.device ORDER BY at DESC,rowid DESC LIMIT 1)")?;
        let rows = q.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
    }
    pub fn save_observation(&mut self, o: &Observation, findings: &[Finding]) -> Result<()> {
        o.validate(vasp_core::now()).map_err(anyhow::Error::msg)?;
        let json = serde_json::to_string(o)?;
        if json.len() > MAX_MESSAGE {
            bail!("Observation is too large");
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO observations VALUES(?1,?2,?3,?4)",
            params![
                o.id.to_string(),
                o.device_id.to_string(),
                o.observed_at,
                json
            ],
        )?;
        tx.execute(
            "DELETE FROM findings WHERE device=?1",
            [o.device_id.to_string()],
        )?;
        for f in findings {
            tx.execute(
                "INSERT OR REPLACE INTO findings VALUES(?1,?2,?3,?4)",
                params![
                    f.id,
                    f.device_id.to_string(),
                    f.created_at,
                    serde_json::to_string(f)?
                ],
            )?;
        }
        append(
            &tx,
            &format!(
                "observation:{}:{}:findings={}",
                o.device_id,
                o.id,
                findings.len()
            ),
            vasp_core::now(),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn save_advisories(&mut self, source: &str, items: &[Advisory]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for a in items {
            let key = vasp_core::digest(
                format!("{:?}:{}:{}:{:?}", a.source, a.id, a.product, a.ecosystem).as_bytes(),
            );
            tx.execute(
                "INSERT OR REPLACE INTO advisories VALUES(?1,?2,?3,?4)",
                params![key, source, a.fetched_at, serde_json::to_string(a)?],
            )?;
        }
        tx.execute("INSERT INTO meta VALUES('advisory_revision','1') ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)", [])?;
        append(
            &tx,
            &format!("feed:{source}:records={}", items.len()),
            vasp_core::now(),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn advisories(&self) -> Result<Vec<Advisory>> {
        self.json_rows("SELECT json FROM advisories ORDER BY at DESC LIMIT 50000")
    }
    pub fn findings(&self) -> Result<Vec<Finding>> {
        let mut fs: Vec<Finding> =
            self.json_rows("SELECT json FROM findings ORDER BY at DESC LIMIT 5000")?;
        fs.sort_by(|a, b| a.priority.cmp(&b.priority));
        Ok(fs)
    }
    fn json_rows<T: DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>> {
        let mut q = self.conn.prepare(sql)?;
        q.query_map([], |r| r.get::<_, String>(0))?
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect()
    }
    pub fn schedule(&self, name: &str, interval: u64) -> Result<Schedule> {
        let row: Option<String> = self
            .conn
            .query_row("SELECT json FROM schedules WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(row
            .map(|s| serde_json::from_str(&s))
            .transpose()?
            .unwrap_or_else(|| Schedule::new(interval)))
    }
    pub fn schedules(&self) -> Result<Vec<(String, Schedule)>> {
        let mut q = self.conn.prepare("SELECT name,json FROM schedules")?;
        q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .map(|r| {
                let (n, s) = r?;
                Ok((n, serde_json::from_str(&s)?))
            })
            .collect()
    }
    pub fn save_schedule(&self, name: &str, s: &Schedule) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO schedules VALUES(?1,?2)",
            params![name, serde_json::to_string(s)?],
        )?;
        Ok(())
    }
    pub fn audit(&mut self, event: &str) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        append(&tx, event, vasp_core::now())?;
        tx.commit()?;
        Ok(())
    }
    pub fn verify_audit(&self) -> Result<()> {
        let mut previous = self.get::<String>("audit_anchor")?.unwrap_or_default();
        let mut q = self
            .conn
            .prepare("SELECT at,event,previous,hash FROM audit ORDER BY seq")?;
        for row in q.query_map([], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })? {
            let (at, event, p, h) = row?;
            if p != previous || hash_entry(at, &event, &p) != h {
                bail!("Audit integrity failure; actions and collection stopped");
            }
            previous = h;
        }
        let head = self.get::<String>("audit_head")?.unwrap_or_default();
        if previous != head {
            bail!("Audit head mismatch");
        }
        Ok(())
    }
    pub fn audit_tail(&self) -> Result<Vec<(u64, String)>> {
        let mut q = self
            .conn
            .prepare("SELECT at,event FROM audit ORDER BY seq DESC LIMIT 100")?;
        Ok(q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    pub fn retain(&mut self, now: u64) -> Result<()> {
        let cutoff = now.saturating_sub(30 * 86400);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM observations WHERE at<?1 AND id NOT IN (SELECT id FROM observations o WHERE rowid=(SELECT rowid FROM observations WHERE device=o.device ORDER BY at DESC,rowid DESC LIMIT 1))",[cutoff])?;
        tx.execute("DELETE FROM advisories WHERE at<?1", [cutoff])?;
        tx.execute("DELETE FROM reports WHERE at<?1", [cutoff])?;
        tx.execute("DELETE FROM replay WHERE at<?1", [cutoff])?;
        // Remove only a contiguous prefix; wall-clock jumps may put an older timestamp
        // after a newer audit record. Deleting by time alone would break the chain.
        let anchor: Option<(u64, String)> = tx
            .query_row(
                "SELECT seq,hash FROM audit WHERE seq < COALESCE((SELECT MIN(seq) FROM audit WHERE at>=?1),9223372036854775807) ORDER BY seq DESC LIMIT 1",
                [cutoff],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((seq, anchor)) = anchor {
            tx.execute(
                "INSERT OR REPLACE INTO meta VALUES('audit_anchor',?1)",
                [serde_json::to_string(&anchor)?],
            )?;
            tx.execute("DELETE FROM audit WHERE seq<=?1", [seq])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn admit_peer(&mut self, device: Uuid, cert: &[u8]) -> Result<String> {
        if cert.len() > 16384 {
            bail!("Certificate too large");
        }
        let count: u32 =
            self.conn
                .query_row("SELECT COUNT(*) FROM peers WHERE revoked=0", [], |r| {
                    r.get(0)
                })?;
        if count >= 10 {
            bail!("Ten-device enrollment limit reached");
        }
        let fingerprint = vasp_core::digest(cert);
        self.conn.execute(
            "INSERT INTO peers VALUES(?1,?2,?3,0)",
            params![device.to_string(), fingerprint, cert],
        )?;
        self.audit(&format!("peer-enrolled:{device}:{fingerprint}"))?;
        Ok(fingerprint)
    }
    pub fn peers(&self) -> Result<Vec<(Uuid, String, Vec<u8>)>> {
        let mut q = self
            .conn
            .prepare("SELECT device,fingerprint,certificate FROM peers WHERE revoked=0")?;
        q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .map(|r| {
            let (id, f, c) = r?;
            Ok((Uuid::parse_str(&id)?, f, c))
        })
        .collect()
    }
    pub fn revoke(&mut self, id: Uuid) -> Result<()> {
        self.conn.execute(
            "UPDATE peers SET revoked=1 WHERE device=?1",
            [id.to_string()],
        )?;
        self.audit(&format!("peer-revoked:{id}"))
    }
    pub fn accept_request(&mut self, peer: Uuid, id: Uuid, sent: u64, now: u64) -> Result<()> {
        if sent > now.saturating_add(30) || now.saturating_sub(sent) > 120 {
            bail!("Stale network request");
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revoked: Option<bool> = tx
            .query_row(
                "SELECT revoked FROM peers WHERE device=?1",
                [peer.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if revoked != Some(false) {
            bail!("Peer not enrolled or revoked");
        }
        tx.execute(
            "INSERT INTO replay VALUES(?1,?2,?3)",
            params![peer.to_string(), id.to_string(), now],
        )
        .context("Replay rejected")?;
        tx.commit()?;
        Ok(())
    }
}
fn hash_entry(at: u64, event: &str, previous: &str) -> String {
    vasp_core::digest(format!("{at}:{}:{event}:{previous}", event.len()).as_bytes())
}
fn append(tx: &rusqlite::Transaction<'_>, event: &str, now: u64) -> Result<()> {
    let previous: Option<String> = tx
        .query_row("SELECT value FROM meta WHERE key='audit_head'", [], |r| {
            r.get(0)
        })
        .optional()?;
    let previous = previous
        .map(|s| serde_json::from_str::<String>(&s))
        .transpose()?
        .unwrap_or_default();
    let hash = hash_entry(now, event, &previous);
    tx.execute(
        "INSERT INTO audit(at,event,previous,hash) VALUES(?1,?2,?3,?4)",
        params![now, event, previous, hash],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO meta VALUES('audit_head',?1)",
        [serde_json::to_string(&hash)?],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_preserves_chain_across_clock_changes() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(d.path()).unwrap();
        let tx = s.conn.transaction().unwrap();
        append(&tx, "old", 1).unwrap();
        append(&tx, "recent", 40 * 86400).unwrap();
        append(&tx, "clock-rollback", 2).unwrap();
        tx.commit().unwrap();
        s.retain(50 * 86400).unwrap();
        s.verify_audit().unwrap();
        assert_eq!(s.audit_tail().unwrap().len(), 2);
    }
    #[test]
    fn corruption_and_truncation_are_detected() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(d.path()).unwrap();
        s.audit("a").unwrap();
        s.audit("b").unwrap();
        s.verify_audit().unwrap();
        s.conn.execute("DELETE FROM audit WHERE seq=2", []).unwrap();
        assert!(s.verify_audit().is_err());
    }
    #[test]
    fn replay_revocation_and_identity() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(d.path()).unwrap();
        let peer = Uuid::new_v4();
        s.admit_peer(peer, b"fixture").unwrap();
        let r = Uuid::new_v4();
        s.accept_request(peer, r, 100, 100).unwrap();
        assert!(s.accept_request(peer, r, 100, 100).is_err());
        s.revoke(peer).unwrap();
        assert!(s.accept_request(peer, Uuid::new_v4(), 100, 100).is_err());
    }
}
