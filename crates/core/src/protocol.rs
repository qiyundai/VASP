use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

pub const VERSION: u16 = 1;
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Available,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub area: String,
    pub state: CoverageState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Software {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub ecosystem: Option<String>,
    pub package: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub address: IpAddr,
    pub port: u16,
    pub pid: u32,
    pub application: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Neighbor {
    pub address: IpAddr,
    pub interface: u32,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: String,
    pub state: String,
    pub start_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persistence {
    pub location: String,
    pub name: String,
    pub value_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub channel: String,
    pub event_id: u32,
    pub record_id: u64,
    pub xml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatch {
    pub device_id: Uuid,
    pub collected_at: u64,
    pub events: Vec<SecurityEvent>,
    pub coverage: Vec<Coverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: u16,
    pub id: Uuid,
    pub device_id: Uuid,
    pub observed_at: u64,
    pub os_name: String,
    pub os_version: String,
    pub updates: Vec<String>,
    pub software: Vec<Software>,
    pub services: Vec<Service>,
    pub listeners: Vec<Listener>,
    pub neighbors: Vec<Neighbor>,
    pub persistence: Vec<Persistence>,
    pub events: Vec<SecurityEvent>,
    pub defender_enabled: Option<bool>,
    pub firewall_enabled: Option<bool>,
    pub coverage: Vec<Coverage>,
}

impl Observation {
    pub fn empty(device_id: Uuid, now: u64) -> Self {
        Self {
            schema: VERSION,
            id: Uuid::new_v4(),
            device_id,
            observed_at: now,
            os_name: String::new(),
            os_version: String::new(),
            updates: vec![],
            software: vec![],
            services: vec![],
            listeners: vec![],
            neighbors: vec![],
            persistence: vec![],
            events: vec![],
            defender_enabled: None,
            firewall_enabled: None,
            coverage: vec![],
        }
    }
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self.schema != VERSION
            || self.observed_at > now.saturating_add(30)
            || now.saturating_sub(self.observed_at) > 86400
        {
            return Err("Unsupported or stale observation".into());
        }
        if self.software.len() > 10000
            || self.listeners.len() > 10000
            || self.events.len() > 256
            || self.coverage.len() > 64
            || self.neighbors.len() > 4096
            || self.services.len() > 5000
            || self.persistence.len() > 5000
        {
            return Err("Observation exceeds limits".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    CisaKev,
    Nvd,
    Osv,
    Vendor,
    Cve,
    Research,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    pub schema: u16,
    pub id: String,
    pub source: Source,
    pub source_url: String,
    pub fetched_at: u64,
    pub title: String,
    pub description: String,
    pub vendor: String,
    pub product: String,
    pub ecosystem: Option<String>,
    pub ranges: Vec<VersionRange>,
    pub exact_versions: Vec<String>,
    pub exploited: bool,
    pub epss: Option<f64>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Applicability {
    Confirmed,
    Possible,
    Unknown,
    Unaffected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Critical,
    High,
    Medium,
    Informational,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: u16,
    pub id: String,
    pub device_id: Uuid,
    pub observation_id: Uuid,
    pub advisory_id: Option<String>,
    pub title: String,
    pub explanation: String,
    pub applicability: Applicability,
    pub priority: Priority,
    pub evidence: Vec<String>,
    pub source_urls: Vec<String>,
    pub remediation: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvestigationRequest {
    ExplainFinding { finding_id: String },
    RefreshInventory,
    LookupAdvisory { advisory_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    DefenderDestination,
    UnapprovedListener,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BlockTarget {
    Destination {
        application: String,
        address: IpAddr,
        port: u16,
    },
    Listener {
        application: String,
        address: IpAddr,
        port: u16,
    },
}
impl BlockTarget {
    pub fn application(&self) -> &str {
        match self {
            Self::Destination { application, .. } | Self::Listener { application, .. } => {
                application
            }
        }
    }
    pub fn address(&self) -> IpAddr {
        match self {
            Self::Destination { address, .. } | Self::Listener { address, .. } => *address,
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            Self::Destination { port, .. } | Self::Listener { port, .. } => *port,
        }
    }
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            match self {
                Self::Destination { .. } => "out",
                Self::Listener { .. } => "in",
            },
            self.application().to_lowercase(),
            self.address(),
            self.port()
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionProposal {
    pub schema: u16,
    pub id: Uuid,
    pub device_id: Uuid,
    pub rule: RuleId,
    pub policy_version: u64,
    pub target: BlockTarget,
    pub evidence_ids: Vec<Uuid>,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    Permit { expires_at: u64 },
    Deny { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionReceipt {
    pub schema: u16,
    pub request_id: Uuid,
    pub device_id: Uuid,
    pub decision: PolicyDecision,
    pub applied_at: Option<u64>,
    pub removed_at: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterCapabilities {
    pub inventory: bool,
    pub temporary_blocks: bool,
    pub autonomous_expiry: bool,
    pub reason: String,
}
pub trait RouterAdapter {
    fn capabilities(&self) -> RouterCapabilities;
}
pub struct UnsupportedRouter;
impl RouterAdapter for UnsupportedRouter {
    fn capabilities(&self) -> RouterCapabilities {
        RouterCapabilities { inventory: false, temporary_blocks: false, autonomous_expiry: false, reason: "TELUS gateway integration has not been verified. LAN discovery is not router protection.".into() }
    }
}
