//! Pure authorization logic. Evidence is loaded by the endpoint, never accepted from a model or coordinator.
use crate::protocol::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPolicy {
    pub version: u64,
    pub device_id: Uuid,
    pub enabled: bool,
    pub defender_destination: bool,
    pub unapproved_listener: bool,
    pub protected_addresses: Vec<IpAddr>,
    pub protected_applications: Vec<String>,
    pub approved_listeners: Vec<u16>,
}
impl LocalPolicy {
    pub fn observe_only(device_id: Uuid) -> Self {
        Self {
            version: 1,
            device_id,
            enabled: false,
            defender_destination: false,
            unapproved_listener: false,
            protected_addresses: vec![],
            protected_applications: vec![],
            approved_listeners: vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedEvidence {
    pub id: Uuid,
    pub device_id: Uuid,
    pub rule: RuleId,
    pub target: BlockTarget,
    pub collected_at: u64,
    pub independently_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLease {
    pub id: Uuid,
    pub target_key: String,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PolicyLedger {
    pub high_water_time: u64,
    pub seen: BTreeSet<Uuid>,
    pub leases: Vec<ActionLease>,
}

fn protected(p: &LocalPolicy, t: &BlockTarget) -> bool {
    // Broad protected service ports are intentionally conservative for v1.
    const PORTS: &[u16] = &[
        22, 53, 67, 68, 123, 135, 139, 445, 546, 547, 3389, 5353, 5985, 5986, 7443,
    ];
    let ip = t.address();
    let special = ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || match ip {
            IpAddr::V4(a) => a.is_link_local() || a.is_broadcast(),
            IpAddr::V6(a) => a.is_unicast_link_local(),
        };
    special
        || PORTS.contains(&t.port())
        || p.protected_addresses.contains(&ip)
        || p.protected_applications
            .iter()
            .any(|a| a.eq_ignore_ascii_case(t.application()))
        || t.application().to_lowercase().contains("vasp")
        || t.application().to_lowercase().contains("\\windows\\")
}

pub fn evaluate(
    p: &LocalPolicy,
    a: &ActionProposal,
    e: &[VerifiedEvidence],
    l: &PolicyLedger,
    now: u64,
) -> PolicyDecision {
    let deny = |s: &str| PolicyDecision::Deny { reason: s.into() };
    if !p.enabled {
        return deny("Automatic actions are disabled locally");
    }
    if a.schema != VERSION || a.device_id != p.device_id || a.policy_version != p.version {
        return deny("Device or policy mismatch");
    }
    if now < l.high_water_time {
        return deny("Clock moved backward; local reconciliation required");
    }
    if l.seen.contains(&a.id) {
        return deny("Replayed request");
    }
    if a.created_at > now
        || now.saturating_sub(a.created_at) > 30
        || a.expires_at <= now
        || a.expires_at > now.saturating_add(600)
    {
        return deny("Invalid action lifetime");
    }
    let path = a.target.application().as_bytes();
    if a.target.application().len() > 1024
        || path.len() < 4
        || !path[0].is_ascii_alphabetic()
        || path[1] != b':'
        || path[2] != b'\\'
        || path[2..].contains(&b':')
        || a.target.application().contains(['\0', '\n', '\r'])
        || a.target.application().contains("..")
        || a.target.port() == 0
        || protected(p, &a.target)
    {
        return deny("Target is protected or invalid");
    }
    let rule_allowed = match (&a.rule, &a.target) {
        (RuleId::DefenderDestination, BlockTarget::Destination { .. }) => p.defender_destination,
        (RuleId::UnapprovedListener, BlockTarget::Listener { port, .. }) => {
            p.unapproved_listener && !p.approved_listeners.contains(port)
        }
        _ => false,
    };
    if !rule_allowed {
        return deny("Rule not preauthorized for this target");
    }
    if a.evidence_ids.is_empty()
        || a.evidence_ids.len() > 8
        || !a.evidence_ids.iter().all(|id| {
            e.iter().any(|v| {
                v.id == *id
                    && v.independently_verified
                    && v.device_id == p.device_id
                    && v.rule == a.rule
                    && v.target == a.target
                    && v.collected_at <= now
                    && now - v.collected_at <= 60
            })
        })
    {
        return deny("Fresh endpoint evidence required");
    }
    if l.leases.iter().filter(|x| x.end > now).count() >= 3 {
        return deny("Three concurrent blocks already active");
    }
    let key = a.target.key();
    if l.leases.iter().any(|x| x.target_key == key && x.end > now) {
        return deny("Target already blocked");
    }
    let used: u64 = l
        .leases
        .iter()
        .filter(|x| x.target_key == key)
        .map(|x| {
            x.end
                .min(now)
                .saturating_sub(x.start.max(now.saturating_sub(3600)))
        })
        .fold(0, u64::saturating_add);
    if used.saturating_add(a.expires_at - now) > 1800 {
        return deny("Target reached hourly containment limit");
    }
    PolicyDecision::Permit {
        expires_at: a.expires_at,
    }
}

impl PolicyLedger {
    /// Call inside the same durable transaction that reserves the action, before touching WFP.
    pub fn reserve(
        &mut self,
        p: &LocalPolicy,
        a: &ActionProposal,
        e: &[VerifiedEvidence],
        now: u64,
    ) -> PolicyDecision {
        let result = evaluate(p, a, e, self, now);
        self.high_water_time = self.high_water_time.max(now);
        if let PolicyDecision::Permit { expires_at } = result {
            self.seen.insert(a.id);
            self.leases.push(ActionLease {
                id: a.id,
                target_key: a.target.key(),
                start: now,
                end: expires_at,
            });
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (LocalPolicy, ActionProposal, Vec<VerifiedEvidence>) {
        let id = Uuid::new_v4();
        let eid = Uuid::new_v4();
        let mut p = LocalPolicy::observe_only(id);
        p.enabled = true;
        p.defender_destination = true;
        let t = BlockTarget::Destination {
            application: "C:\\Apps\\app.exe".into(),
            address: "203.0.113.9".parse().unwrap(),
            port: 443,
        };
        let a = ActionProposal {
            schema: VERSION,
            id: Uuid::new_v4(),
            device_id: id,
            rule: RuleId::DefenderDestination,
            policy_version: 1,
            target: t.clone(),
            evidence_ids: vec![eid],
            created_at: 10000,
            expires_at: 10600,
        };
        let e = vec![VerifiedEvidence {
            id: eid,
            device_id: id,
            rule: RuleId::DefenderDestination,
            target: t,
            collected_at: 10000,
            independently_verified: true,
        }];
        (p, a, e)
    }
    #[test]
    fn disabled_and_fabricated_evidence_fail_closed() {
        let (mut p, a, mut e) = fixture();
        p.enabled = false;
        assert!(matches!(
            evaluate(&p, &a, &e, &PolicyLedger::default(), 10000),
            PolicyDecision::Deny { .. }
        ));
        p.enabled = true;
        e[0].independently_verified = false;
        assert!(matches!(
            evaluate(&p, &a, &e, &PolicyLedger::default(), 10000),
            PolicyDecision::Deny { .. }
        ));
    }
    #[test]
    fn replay_cross_device_and_clock_rollback_rejected() {
        let (p, a, e) = fixture();
        let mut l = PolicyLedger::default();
        assert!(matches!(
            l.reserve(&p, &a, &e, 10000),
            PolicyDecision::Permit { .. }
        ));
        assert!(matches!(
            evaluate(&p, &a, &e, &l, 10000),
            PolicyDecision::Deny { .. }
        ));
        let mut b = a.clone();
        b.id = Uuid::new_v4();
        b.device_id = Uuid::new_v4();
        assert!(matches!(
            evaluate(&p, &b, &e, &l, 10000),
            PolicyDecision::Deny { .. }
        ));
        assert!(matches!(
            evaluate(&p, &a, &e, &l, 9999),
            PolicyDecision::Deny { .. }
        ));
    }
    #[test]
    fn protected_ipv4_ipv6_and_management_ports() {
        let (p, mut a, e) = fixture();
        for ip in ["127.0.0.1", "::1", "fe80::1", "0.0.0.0", "ff02::1"] {
            a.target = BlockTarget::Destination {
                application: "C:\\Apps\\app.exe".into(),
                address: ip.parse().unwrap(),
                port: 443,
            };
            assert!(matches!(
                evaluate(&p, &a, &e, &PolicyLedger::default(), 10000),
                PolicyDecision::Deny { .. }
            ));
        }
    }
    #[test]
    fn duration_and_hourly_budget_are_hard_limits() {
        let (p, mut a, e) = fixture();
        a.expires_at = 10601;
        assert!(matches!(
            evaluate(&p, &a, &e, &PolicyLedger::default(), 10000),
            PolicyDecision::Deny { .. }
        ));
        a.expires_at = 10600;
        let mut l = PolicyLedger::default();
        l.leases.push(ActionLease {
            id: Uuid::new_v4(),
            target_key: a.target.key(),
            start: 8200,
            end: 10000,
        });
        assert!(matches!(
            evaluate(&p, &a, &e, &l, 10000),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn fourth_concurrent_block_and_stale_evidence_are_denied() {
        let (p, mut a, mut e) = fixture();
        let mut ledger = PolicyLedger::default();
        for port in [8443, 8444, 8445] {
            a.id = Uuid::new_v4();
            a.target = BlockTarget::Destination {
                application: "C:\\Apps\\app.exe".into(),
                address: "203.0.113.9".parse().unwrap(),
                port,
            };
            e[0].target = a.target.clone();
            assert!(matches!(
                ledger.reserve(&p, &a, &e, 10000),
                PolicyDecision::Permit { .. }
            ));
        }
        a.id = Uuid::new_v4();
        a.target = BlockTarget::Destination {
            application: "C:\\Apps\\app.exe".into(),
            address: "203.0.113.9".parse().unwrap(),
            port: 8446,
        };
        e[0].target = a.target.clone();
        assert!(matches!(
            ledger.reserve(&p, &a, &e, 10000),
            PolicyDecision::Deny { .. }
        ));
        e[0].collected_at = 9900;
        assert!(matches!(
            evaluate(&p, &a, &e, &PolicyLedger::default(), 10000),
            PolicyDecision::Deny { .. }
        ));
    }
}
