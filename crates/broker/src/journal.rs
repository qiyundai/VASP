use anyhow::{Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
use uuid::Uuid;
use vasp_core::broker::*;

/// Administrator-owned storage, completely separate from the coordinator's user database.
/// A request, its receipt, and its chain link commit atomically before any response is sent.
pub struct Journal {
    db: Connection,
    device: Uuid,
}
impl Journal {
    pub fn open(path: &Path, device: Uuid) -> Result<Self> {
        if path.try_exists()? && std::fs::metadata(path)?.len() > 64 * 1024 * 1024 {
            bail!("Broker journal exceeds storage ceiling");
        }
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(1))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,sid TEXT NOT NULL,at INTEGER NOT NULL,receipt TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS requests_time ON requests(at);")?;
        let page: u64 = db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        db.pragma_update(None, "max_page_count", (64 * 1024 * 1024_u64) / page)?;
        if db.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? != "ok" {
            bail!("Broker journal corruption");
        }
        db.execute(
            "INSERT OR IGNORE INTO meta VALUES('device',?1)",
            [device.to_string()],
        )?;
        let existing: String =
            db.query_row("SELECT value FROM meta WHERE key='device'", [], |r| {
                r.get(0)
            })?;
        if existing != device.to_string() {
            bail!("Broker journal belongs to another endpoint");
        }
        let mut this = Self { db, device };
        this.verify()?;
        // There is never a recovered block: this broker never opens a WFP session.
        this.db.execute(
            "INSERT OR REPLACE INTO meta VALUES('automatic_actions_disabled','true')",
            [],
        )?;
        this.db.execute(
            "INSERT OR REPLACE INTO meta VALUES('boot_id',?1)",
            [Uuid::new_v4().to_string()],
        )?;
        Ok(this)
    }
    fn verify(&mut self) -> Result<()> {
        let mut previous = self
            .db
            .query_row("SELECT value FROM meta WHERE key='anchor'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .unwrap_or_default();
        let mut q = self
            .db
            .prepare("SELECT id,sid,at,receipt,previous,hash FROM requests ORDER BY rowid")?;
        for row in q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })? {
            let (id, sid, at, receipt, prev, hash) = row?;
            if prev != previous || link(&id, &sid, at, &receipt, &prev) != hash {
                bail!("Broker journal chain invalid");
            }
            previous = hash;
        }
        let head = self
            .db
            .query_row("SELECT value FROM meta WHERE key='head'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .unwrap_or_default();
        if head != previous {
            bail!("Broker journal truncated");
        }
        Ok(())
    }
    pub fn handle(
        &mut self,
        config: &Configuration,
        sid: &str,
        session: Uuid,
        r: &Request,
        now: u64,
        inventory: impl FnOnce() -> Result<Inventory>,
    ) -> Result<Response> {
        let mut response = Response {
            schema: VERSION,
            request_id: r.id,
            device_id: self.device,
            accepted: false,
            automatic_blocking: false,
            active_blocks: 0,
            policy_version: config.policy.version,
            reason: String::new(),
            inventory: None,
        };
        if let Err(reason) = authorize(config, sid, session, r, now) {
            response.reason = reason;
            return Ok(response);
        }
        if config.policy.device_id != self.device {
            bail!("Endpoint configuration mismatch");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let high: u64 = tx
            .query_row("SELECT value FROM meta WHERE key='high_water'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .unwrap_or_else(|| "0".into())
            .parse()?;
        if now < high {
            response.reason = "Clock rollback: broker remains disabled".into();
            return Ok(response);
        }
        let duplicate = tx
            .query_row(
                "SELECT 1 FROM requests WHERE id=?1",
                [r.id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if duplicate {
            response.reason = "Replayed request rejected".into();
            return Ok(response);
        }
        let recent: u32 = tx.query_row(
            "SELECT COUNT(*) FROM requests WHERE sid=?1 AND at>=?2",
            params![sid, now.saturating_sub(60)],
            |row| row.get(0),
        )?;
        if recent >= 60 {
            response.reason = "Broker request limit exceeded".into();
            return Ok(response);
        }
        match &r.command {
            Command::Status {} => {
                response.accepted = true;
                response.reason =
                    "Authenticated local broker; automatic blocking is release-disabled".into();
            }
            Command::Inventory {} => match inventory() {
                Ok(value) => {
                    response.accepted = true;
                    response.inventory = Some(value);
                    response.reason = "Read-only Windows build inventory".into();
                }
                Err(_) => {
                    response.reason = "Windows inventory is unavailable".into();
                }
            },
            Command::StopAutomaticActions {} => {
                tx.execute(
                    "INSERT OR REPLACE INTO meta VALUES('automatic_actions_disabled','true')",
                    [],
                )?;
                response.accepted = true;
                response.reason = "Automatic actions disabled locally and durably".into();
            }
            Command::RemoveTemporaryBlocks {} => {
                response.accepted = true;
                response.reason =
                    "This broker cannot create filters; no owned temporary blocks exist".into();
            }
            Command::ProposeBlock { .. } => {
                // Do not evaluate caller/model-supplied evidence or invoke WFP in this release.
                response.reason = "Automatic blocking unavailable: authorization and recovery release gates are closed".into();
            }
        }
        let receipt = serde_json::to_string(&response)?;
        let previous = tx
            .query_row("SELECT value FROM meta WHERE key='head'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .unwrap_or_default();
        let hash = link(&r.id.to_string(), sid, now, &receipt, &previous);
        tx.execute(
            "INSERT INTO requests VALUES(?1,?2,?3,?4,?5,?6)",
            params![r.id.to_string(), sid, now, receipt, previous, hash],
        )?;
        tx.execute("INSERT OR REPLACE INTO meta VALUES('head',?1)", [hash])?;
        tx.execute(
            "INSERT OR REPLACE INTO meta VALUES('high_water',?1)",
            [now.to_string()],
        )?;
        // Monotonic accepted timestamps make this a contiguous prefix, including restarts.
        let anchor: Option<(i64, String)> = tx
            .query_row(
                "SELECT rowid,hash FROM requests WHERE at<?1 ORDER BY rowid DESC LIMIT 1",
                [now.saturating_sub(30 * 86400)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((row, hash)) = anchor {
            tx.execute("INSERT OR REPLACE INTO meta VALUES('anchor',?1)", [hash])?;
            tx.execute("DELETE FROM requests WHERE rowid<=?1", [row])?;
        }
        tx.commit()?;
        Ok(response)
    }
    pub fn finish(&mut self) -> Result<()> {
        self.verify()?;
        self.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }
}
fn link(id: &str, sid: &str, at: u64, receipt: &str, previous: &str) -> String {
    vasp_core::digest(format!("{id}|{sid}|{at}|{}|{receipt}|{previous}", receipt.len()).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vasp_core::{policy::LocalPolicy, protocol::*};
    fn config() -> Configuration {
        Configuration {
            schema: 1,
            policy: LocalPolicy::observe_only(Uuid::new_v4()),
            callers: vec![Caller {
                sid: "S-1-5-21-1-2-3-1001".into(),
                role: Role::Operator,
            }],
        }
    }
    fn request(c: &Configuration) -> Request {
        Request {
            schema: 1,
            session: Uuid::new_v4(),
            id: Uuid::new_v4(),
            device_id: c.policy.device_id,
            policy_version: c.policy.version,
            issued_at: 100,
            command: Command::Status {},
        }
    }
    #[test]
    fn durable_replay_crash_reopen_and_clock_rollback() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("broker.db");
        let c = config();
        let mut r = request(&c);
        let mut journal = Journal::open(&path, c.policy.device_id).unwrap();
        assert!(
            journal
                .handle(&c, &c.callers[0].sid, r.session, &r, 100, || unreachable!())
                .unwrap()
                .accepted
        );
        drop(journal); // Simulates loss without finish/checkpoint.
        let mut journal = Journal::open(&path, c.policy.device_id).unwrap();
        assert!(
            !journal
                .handle(&c, &c.callers[0].sid, r.session, &r, 100, || unreachable!())
                .unwrap()
                .accepted
        );
        r.id = Uuid::new_v4();
        r.issued_at = 99;
        assert!(
            !journal
                .handle(&c, &c.callers[0].sid, r.session, &r, 99, || unreachable!())
                .unwrap()
                .accepted
        );
        journal.finish().unwrap();
        assert!(Journal::open(&path, Uuid::new_v4()).is_err());
    }
    #[test]
    fn activation_fabricated_evidence_and_policy_escalation_cannot_block() {
        let temp = tempfile::tempdir().unwrap();
        let mut c = config();
        let mut r = request(&c);
        r.command = Command::ProposeBlock {
            proposal: ActionProposal {
                schema: 1,
                id: Uuid::new_v4(),
                device_id: c.policy.device_id,
                rule: RuleId::DefenderDestination,
                policy_version: 1,
                target: BlockTarget::Destination {
                    application: r"C:\Apps\app.exe".into(),
                    address: "203.0.113.1".parse().unwrap(),
                    port: 443,
                },
                evidence_ids: vec![Uuid::new_v4()],
                created_at: 100,
                expires_at: 200,
            },
        };
        let mut journal =
            Journal::open(&temp.path().join("broker.db"), c.policy.device_id).unwrap();
        let denied = journal
            .handle(&c, &c.callers[0].sid, r.session, &r, 100, || unreachable!())
            .unwrap();
        assert!(!denied.accepted && !denied.automatic_blocking && denied.active_blocks == 0);
        c.policy.enabled = true;
        r.id = Uuid::new_v4();
        assert!(
            !journal
                .handle(&c, &c.callers[0].sid, r.session, &r, 100, || unreachable!())
                .unwrap()
                .accepted
        );
    }
    #[test]
    fn journal_tampering_and_storage_errors_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("broker.db");
        let c = config();
        let r = request(&c);
        let mut journal = Journal::open(&path, c.policy.device_id).unwrap();
        journal
            .handle(&c, &c.callers[0].sid, r.session, &r, 100, || unreachable!())
            .unwrap();
        journal
            .db
            .execute("UPDATE requests SET receipt='tampered'", [])
            .unwrap();
        drop(journal);
        assert!(Journal::open(&path, c.policy.device_id).is_err());
        assert!(Journal::open(temp.path(), c.policy.device_id).is_err());
    }

    #[test]
    fn quotas_denials_and_disk_failure_never_return_success() {
        let temp = tempfile::tempdir().unwrap();
        let c = config();
        let mut r = request(&c);
        let mut journal =
            Journal::open(&temp.path().join("broker.db"), c.policy.device_id).unwrap();
        for _ in 0..60 {
            r.id = Uuid::new_v4();
            assert!(
                journal
                    .handle(&c, &c.callers[0].sid, r.session, &r, 100, || unreachable!())
                    .unwrap()
                    .accepted
            );
        }
        r.id = Uuid::new_v4();
        assert!(
            !journal
                .handle(&c, &c.callers[0].sid, r.session, &r, 100, || unreachable!())
                .unwrap()
                .accepted
        );
        r.issued_at = 200;
        journal.db.pragma_update(None, "query_only", true).unwrap();
        // A storage write failure cannot produce an accepted durable receipt.
        assert!(
            journal
                .handle(&c, &c.callers[0].sid, r.session, &r, 200, || unreachable!())
                .is_err()
        );
    }
}
