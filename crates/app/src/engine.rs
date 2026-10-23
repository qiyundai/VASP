use crate::{
    network::Feed,
    store::Store,
    workers::{self, Request},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use vasp_core::protocol::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u16,
    pub feeds_enabled: bool,
    pub model: crate::models::ModelConfig,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            schema: 1,
            feeds_enabled: true,
            model: Default::default(),
        }
    }
}
pub fn config(store: &Store) -> Result<Config> {
    let c: Config = store.get("config")?.unwrap_or_default();
    if c.schema != 1 {
        anyhow::bail!("Unsupported configuration schema");
    }
    Ok(c)
}

pub fn scan(store: &mut Store) -> Result<usize> {
    let id = store.device_id()?;
    let o: Observation =
        serde_json::from_value(workers::run(&Request::Collect { device_id: id })?)?;
    let old = store.latest(id)?;
    let advisories = store.advisories()?;
    let findings = vasp_core::matching::assess(&o, &advisories, old.as_ref(), vasp_core::now());
    store.save_observation(&o, &findings)?;
    Ok(findings.len())
}
pub fn refresh(store: &mut Store, force: bool) -> Result<()> {
    let date = time::OffsetDateTime::now_utc();
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = format!("{}-{}", date.year(), months[date.month() as usize - 1]);
    for (name, interval, feed) in [
        ("CISA KEV", 1800, Feed::Kev),
        ("Microsoft advisories", 1800, Feed::Microsoft { month }),
        ("Chromium release research", 1800, Feed::ChromiumResearch),
    ] {
        let now = vasp_core::now();
        let mut schedule = store.schedule(name, interval)?;
        if !force && !schedule.due(now) {
            continue;
        }
        let result = (|| -> Result<()> {
            let items: Vec<Advisory> = serde_json::from_value(workers::feed(feed)?)?;
            store.save_advisories(name, &items)?;
            Ok(())
        })();
        match result {
            Ok(()) => schedule.success(now),
            Err(e) => schedule.failure(now, e.to_string()),
        };
        store.save_schedule(name, &schedule)?;
    }
    refresh_nvd(store, force)?;
    let now = vasp_core::now();
    let mut schedule = store.schedule("EPSS relevant findings", 86400)?;
    if force || schedule.due(now) {
        let findings = store.findings()?;
        let mut ids: Vec<_> = findings
            .into_iter()
            .filter_map(|f| f.advisory_id)
            .filter(|id| vasp_core::feeds::valid_cve(id))
            .collect();
        ids.sort();
        ids.dedup();
        ids.truncate(100);
        if !ids.is_empty() {
            let result = (|| -> Result<()> {
                let scores: Vec<(String, f64)> =
                    serde_json::from_value(workers::feed(Feed::Epss { cves: ids })?)?;
                let mut advisories = store.advisories()?;
                for a in &mut advisories {
                    if let Some((_, s)) = scores.iter().find(|(id, _)| id == &a.id) {
                        a.epss = Some(*s);
                    }
                }
                store.save_advisories("enriched", &advisories)?;
                Ok(())
            })();
            match result {
                Ok(()) => schedule.success(now),
                Err(e) => schedule.failure(now, e.to_string()),
            }
        } else {
            schedule.success(now);
        }
        store.save_schedule("EPSS relevant findings", &schedule)?;
    }
    // Re-evaluate on feed changes or hourly aging, not on every idle polling tick.
    let revision = store.get::<u64>("advisory_revision")?.unwrap_or(0);
    let assessed = store.get::<(u64, u64)>("assessment_revision")?;
    if assessed.is_some_and(|(r, at)| r == revision && now >= at && now - at < 3600) {
        return Ok(());
    }
    // Re-evaluate against fresh intel without fabricating a new device observation.
    let advisories = store.advisories()?;
    for o in store.devices()? {
        let fs = vasp_core::matching::assess(&o, &advisories, None, now);
        let tx = store.conn.transaction()?;
        tx.execute("DELETE FROM findings WHERE device=?1 AND json_extract(json,'$.advisory_id') IS NOT NULL",[o.device_id.to_string()])?;
        for f in fs {
            tx.execute(
                "INSERT OR REPLACE INTO findings VALUES(?1,?2,?3,?4)",
                rusqlite::params![
                    f.id,
                    f.device_id.to_string(),
                    f.created_at,
                    serde_json::to_string(&f)?
                ],
            )?;
        }
        tx.commit()?;
    }
    store.set("assessment_revision", &(revision, now))?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct NvdCursor {
    since: u64,
    until: u64,
    index: u32,
}
fn refresh_nvd(store: &mut Store, force: bool) -> Result<()> {
    let now = vasp_core::now();
    let mut s = store.schedule("NVD incremental (7-day initial window)", 7200)?;
    if !force && !s.due(now) {
        return Ok(());
    }
    let mut cursor = store
        .get::<Option<NvdCursor>>("nvd_cursor")?
        .flatten()
        .unwrap_or(NvdCursor {
            since: s
                .last_success
                .unwrap_or(now.saturating_sub(7 * 86400))
                .saturating_sub(120),
            until: now,
            index: 0,
        });
    let result = (|| -> Result<bool> {
        let value = workers::feed(Feed::Nvd {
            start_index: cursor.index,
            since: cursor.since,
            until: cursor.until,
        })?;
        let items: Vec<Advisory> = serde_json::from_value(value["items"].clone())?;
        let total = value["total"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing NVD pagination metadata"))?;
        let count = value["count"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing NVD page count"))?;
        if count == 0 && total > u64::from(cursor.index) {
            anyhow::bail!("NVD pagination made no progress");
        }
        store.save_advisories("NVD", &items)?;
        cursor.index = cursor.index.saturating_add(count as u32);
        Ok(u64::from(cursor.index) >= total)
    })();
    match result {
        Ok(true) => {
            store.set::<Option<NvdCursor>>("nvd_cursor", &None)?;
            s.success(cursor.until);
        }
        Ok(false) => {
            store.set("nvd_cursor", &Some(cursor))?;
            s.next_at = now + 30;
            s.last_error = Some("Initial synchronization is incomplete; more pages queued.".into());
        }
        Err(e) => s.failure(now, e.to_string()),
    }
    store.save_schedule("NVD incremental (7-day initial window)", &s)?;
    Ok(())
}

pub fn tick(store: &mut Store) -> Result<()> {
    let c = config(store)?;
    let now = vasp_core::now();
    let mut schedule = store.schedule("Local inventory", 3600)?;
    if schedule.due(now) {
        match scan(store) {
            Ok(_) => schedule.success(now),
            Err(e) => schedule.failure(now, e.to_string()),
        };
        store.save_schedule("Local inventory", &schedule)?;
    }
    let mut event_schedule = store.schedule("Security event polling", 30)?;
    if event_schedule.due(now) {
        let result = (|| -> Result<()> {
            let id = store.device_id()?;
            let batch: EventBatch =
                serde_json::from_value(workers::run(&Request::Events { device_id: id })?)?;
            if batch.device_id != id
                || batch.collected_at > now + 30
                || batch.events.len() > 1024
                || batch.coverage.len() > 64
            {
                anyhow::bail!("Invalid event collector response");
            }
            store.set("latest_events", &batch)?;
            let mut event_observation = Observation::empty(id, batch.collected_at);
            event_observation.events = batch.events;
            let findings = vasp_core::matching::assess(&event_observation, &[], None, now);
            for f in findings {
                store.conn.execute(
                    "INSERT OR REPLACE INTO findings VALUES(?1,?2,?3,?4)",
                    rusqlite::params![f.id, id.to_string(), now, serde_json::to_string(&f)?],
                )?;
            }
            let unavailable: Vec<_> = batch
                .coverage
                .iter()
                .filter(|c| c.state != CoverageState::Available)
                .map(|c| c.area.as_str())
                .collect();
            if !unavailable.is_empty() {
                store.set(
                    "event_coverage_warning",
                    &Some(format!(
                        "Partial event coverage: {}",
                        unavailable.join(", ")
                    )),
                )?;
            } else {
                store.set::<Option<String>>("event_coverage_warning", &None)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                event_schedule.success(now);
                event_schedule.last_error = store
                    .get::<Option<String>>("event_coverage_warning")?
                    .flatten();
            }
            Err(e) => event_schedule.failure(now, e.to_string()),
        };
        store.save_schedule("Security event polling", &event_schedule)?;
    }
    if c.feeds_enabled {
        refresh(store, false)?;
    }
    let mut model = store.schedule("AI investigation", 3600)?;
    if !matches!(c.model.provider, crate::models::Provider::Disabled) && model.due(now) {
        match crate::models::analyze(store, &c.model) {
            Ok(_) => model.success(now),
            Err(e) => model.failure(now, e.to_string()),
        };
        store.save_schedule("AI investigation", &model)?;
    }
    store.retain(now)?;
    crate::transport::report_pending(store)?;
    Ok(())
}

pub fn status(store: &Store) -> Result<serde_json::Value> {
    Ok(
        serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"mode":"observe_only","device_id":store.device_id()?,"devices":store.devices()?,"findings":store.findings()?,"schedules":store.schedules()?,"router":UnsupportedRouter.capabilities(),"automatic_actions_available":false,"active_blocks":[],"limits":{"devices":10,"retention_days":30},"release_gates":["Privileged broker and IPC integration","AppContainer conformance","WFP recovery VM tests","72-hour soak","Independent security review","Release signing"]}),
    )
}
