//! The broker wire protocol and authorization contract. No execution capability exists here.
use crate::{policy::LocalPolicy, protocol::ActionProposal};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SERVICE: &str = "VaspBroker";
pub const PIPE: &str = r"\\.\pipe\VASP.Broker.v1";
pub const VERSION: u16 = 1;
pub const MAX_FRAME: usize = 16 * 1024;
/// Compile-time gate. There is deliberately no config, CLI, IPC or model override.
pub const ENFORCEMENT_ENABLED: bool = false;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Observer,
    Operator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub sid: String,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub schema: u16,
    pub policy: LocalPolicy,
    pub callers: Vec<Caller>,
}
impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != VERSION
            || self.policy.device_id.is_nil()
            || self.policy.version == 0
            || self.callers.is_empty()
            || self.callers.len() > 10
        {
            return Err("Invalid broker configuration".into());
        }
        let mut sids = std::collections::BTreeSet::new();
        for c in &self.callers {
            if !valid_sid(&c.sid) || !sids.insert(&c.sid) {
                return Err("Invalid or duplicate caller SID".into());
            }
        }
        // A future approved release must introduce an explicit migration, not reinterpret an enabled flag.
        if self.policy.enabled {
            return Err("Automatic blocking cannot be activated in this release".into());
        }
        Ok(())
    }
}
pub fn valid_sid(sid: &str) -> bool {
    let parts: Vec<_> = sid.split('-').collect();
    (4..=18).contains(&parts.len())
        && parts[0] == "S"
        && parts[1] == "1"
        && parts[2..].iter().all(|p| {
            !p.is_empty()
                && p.len() <= 10
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u32>().is_ok()
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub schema: u16,
    pub session: Uuid,
    pub device_id: Uuid,
    pub policy_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Status {},
    Inventory {},
    StopAutomaticActions {},
    RemoveTemporaryBlocks {},
    ProposeBlock { proposal: ActionProposal },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u16,
    pub session: Uuid,
    pub id: Uuid,
    pub device_id: Uuid,
    pub policy_version: u64,
    pub issued_at: u64,
    pub command: Command,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub windows_build: String,
    pub revision: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub schema: u16,
    pub request_id: Uuid,
    pub device_id: Uuid,
    pub accepted: bool,
    pub automatic_blocking: bool,
    pub active_blocks: u32,
    pub policy_version: u64,
    pub reason: String,
    pub inventory: Option<Inventory>,
}

/// `sid` and token attributes MUST come from the pipe's Windows impersonation token.
pub fn authorize(
    config: &Configuration,
    sid: &str,
    session: Uuid,
    r: &Request,
    now: u64,
) -> Result<Role, String> {
    config.validate()?;
    let caller = config
        .callers
        .iter()
        .find(|c| c.sid == sid)
        .ok_or("Caller not locally enrolled")?;
    if r.schema != VERSION
        || r.id.is_nil()
        || r.session != session
        || r.session.is_nil()
        || r.device_id != config.policy.device_id
        || r.policy_version != config.policy.version
    {
        return Err("Request session, device, schema or policy mismatch".into());
    }
    if r.issued_at > now || now.saturating_sub(r.issued_at) > 30 {
        return Err("Stale or future request".into());
    }
    if !matches!(r.command, Command::Status {} | Command::Inventory {})
        && caller.role != Role::Operator
    {
        return Err("Operation not granted to this caller".into());
    }
    Ok(caller.role)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_authority_and_closed_wire_catalog() {
        let device = Uuid::new_v4();
        let session = Uuid::new_v4();
        let config = Configuration {
            schema: 1,
            policy: LocalPolicy::observe_only(device),
            callers: vec![Caller {
                sid: "S-1-5-21-1-2-3-1001".into(),
                role: Role::Observer,
            }],
        };
        let mut r = Request {
            schema: 1,
            session,
            id: Uuid::new_v4(),
            device_id: device,
            policy_version: 1,
            issued_at: 100,
            command: Command::Status {},
        };
        assert!(authorize(&config, &config.callers[0].sid, session, &r, 100).is_ok());
        assert!(authorize(&config, "S-1-5-21-1-2-3-9999", session, &r, 100).is_err());
        assert!(authorize(&config, &config.callers[0].sid, Uuid::new_v4(), &r, 100).is_err());
        assert!(authorize(&config, &config.callers[0].sid, session, &r, 99).is_err());
        assert!(authorize(&config, &config.callers[0].sid, session, &r, 131).is_err());
        r.device_id = Uuid::new_v4();
        assert!(authorize(&config, &config.callers[0].sid, session, &r, 100).is_err());
        r.device_id = device;
        r.policy_version += 1;
        assert!(authorize(&config, &config.callers[0].sid, session, &r, 100).is_err());
        r.policy_version = config.policy.version;
        r.command = Command::StopAutomaticActions {};
        assert!(authorize(&config, &config.callers[0].sid, session, &r, 100).is_err());
        for raw in [
            r#"{"operation":"execute","command":"whoami"}"#,
            r#"{"operation":"status","sid":"S-1-5-18"}"#,
            r#"{"operation":"enable_automatic_actions"}"#,
            r#"{"operation":"set_policy"}"#,
        ] {
            assert!(serde_json::from_str::<Command>(raw).is_err());
        }
        assert!(!ENFORCEMENT_ENABLED);
    }
}
