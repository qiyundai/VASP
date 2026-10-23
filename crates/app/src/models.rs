use crate::store::Store;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{io::Read, net::IpAddr, time::Duration};
use vasp_core::ai::{AnalystFact, AnalystReport, ModelBudget};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum Provider {
    #[default]
    Disabled,
    OpenAi,
    Lan {
        endpoint: String,
        ca_pem: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfig {
    pub provider: Provider,
    pub model: String,
    pub cloud_opt_in: bool,
    pub daily_tokens: u64,
    pub daily_microusd: u64,
    pub ceiling_microusd_per_million_tokens: u64,
}
impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            provider: Provider::Disabled,
            model: String::new(),
            cloud_opt_in: false,
            daily_tokens: 50000,
            daily_microusd: 0,
            ceiling_microusd_per_million_tokens: 0,
        }
    }
}

pub fn analyze(store: &mut Store, config: &ModelConfig) -> Result<AnalystReport> {
    if matches!(config.provider, Provider::Disabled) {
        bail!("Model analysis is disabled");
    }
    if config.model.is_empty() || config.model.len() > 128 {
        bail!("Configure an explicit model identifier");
    }
    if matches!(config.provider, Provider::OpenAi)
        && (!config.cloud_opt_in
            || config.daily_microusd == 0
            || config.ceiling_microusd_per_million_tokens == 0)
    {
        bail!("Cloud analysis requires opt-in and an explicit spending ceiling");
    }
    let facts = vasp_core::ai::project(&store.findings()?);
    if facts.is_empty() {
        bail!("No findings to analyze");
    }
    let input = serde_json::to_string(&facts)?;
    if input.len() > 16384 {
        bail!("Minimized facts exceed model input limit");
    }
    let tokens = (input.len() + vasp_core::ai::INSTRUCTIONS.len() + 1024 + 1024) as u64;
    let cost = if matches!(config.provider, Provider::OpenAi) {
        tokens
            .saturating_mul(config.ceiling_microusd_per_million_tokens)
            .div_ceil(1_000_000)
    } else {
        0
    };
    // Serialize reservations across processes, retain the worst-case charge on failure.
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    use rusqlite::OptionalExtension;
    let in_flight: Option<String> = tx
        .query_row(
            "SELECT value FROM meta WHERE key='model_inflight_until'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let now = vasp_core::now();
    if in_flight
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|t| t > now)
    {
        bail!("Another model request is already in progress");
    }
    let value: Option<String> = tx
        .query_row("SELECT value FROM meta WHERE key='model_budget'", [], |r| {
            r.get(0)
        })
        .optional()?;
    let mut budget: ModelBudget = value
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or_default();
    budget
        .reserve(
            vasp_core::now(),
            tokens,
            cost,
            config.daily_tokens,
            config.daily_microusd,
        )
        .map_err(anyhow::Error::msg)?;
    tx.execute(
        "INSERT OR REPLACE INTO meta VALUES('model_budget',?1)",
        [serde_json::to_string(&budget)?],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO meta VALUES('model_inflight_until',?1)",
        [(now + 120).to_string()],
    )?;
    tx.commit()?;
    let slot = if matches!(config.provider, Provider::OpenAi) {
        "VASP/OpenAI"
    } else {
        "VASP/LAN"
    };
    let credential = vasp_platform::secrets::read(slot)
        .context("Configure the provider credential with vasp credential")?;
    let result = crate::workers::run(&crate::workers::Request::Model {
        config: config.clone(),
        facts: facts.clone(),
        credential,
    })?;
    let report = vasp_core::ai::validate_report(&serde_json::to_vec(&result)?, &facts)
        .map_err(anyhow::Error::msg)?;
    store.conn.execute(
        "INSERT INTO reports VALUES(?1,?2,?3)",
        rusqlite::params![
            uuid::Uuid::new_v4().to_string(),
            vasp_core::now(),
            serde_json::to_string(&report)?
        ],
    )?;
    store.audit("analyst-report:advisory-only")?;
    Ok(report)
}

pub fn request(
    config: &ModelConfig,
    facts: &[AnalystFact],
    credential: &str,
) -> Result<AnalystReport> {
    let input = serde_json::to_string(facts)?;
    if input.len() > 16384 || credential.is_empty() || credential.len() > 2048 {
        bail!("Invalid model request");
    }
    let (client, url, body) = match &config.provider {
        Provider::Disabled => bail!("Model disabled"),
        Provider::OpenAi => {
            if !config.cloud_opt_in {
                bail!("Cloud not authorized");
            }
            let url = url::Url::parse("https://api.openai.com/v1/responses")?;
            let client = crate::network::public_client(&url)?;
            let body = serde_json::json!({"model":config.model,"instructions":vasp_core::ai::INSTRUCTIONS,"input":input,"max_output_tokens":1024,"store":false,"text":{"format":{"type":"json_object"}}});
            (client, url, body)
        }
        Provider::Lan { endpoint, ca_pem } => {
            let url = url::Url::parse(endpoint)?;
            let ip: IpAddr = url
                .host_str()
                .context("LAN address required")?
                .trim_matches(['[', ']'])
                .parse()
                .context("LAN provider must use a literal private IP address")?;
            let private = match ip {
                IpAddr::V4(v) => v.is_private(),
                IpAddr::V6(v) => v.is_unique_local(),
            };
            if !private
                || url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                bail!("LAN provider requires authenticated HTTPS at a literal private address");
            }
            let cert = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .tls_built_in_root_certs(false)
                .add_root_certificate(cert)
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(60))
                .build()?;
            let body = serde_json::json!({"model":config.model,"messages":[{"role":"system","content":vasp_core::ai::INSTRUCTIONS},{"role":"user","content":input}],"max_tokens":1024,"stream":false,"response_format":{"type":"json_object"}});
            (client, url, body)
        }
    };
    // Do not surface provider error bodies: they may contain secrets or hostile content.
    let response = client
        .post(url)
        .bearer_auth(credential)
        .json(&body)
        .send()
        .map_err(|_| anyhow::anyhow!("Model transport failed"))?;
    if !response.status().is_success() {
        bail!(
            "Model provider returned HTTP {}",
            response.status().as_u16()
        );
    }
    let mut bytes = vec![];
    response.take(131073).read_to_end(&mut bytes)?;
    if bytes.len() > 131072 {
        bail!("Model envelope too large");
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let text = match &config.provider {
        Provider::OpenAi => {
            let mut text = String::new();
            if let Some(output) = value["output"].as_array() {
                for message in output {
                    if message["type"] == "message"
                        && let Some(parts) = message["content"].as_array()
                    {
                        for part in parts {
                            if part["type"] == "output_text" {
                                text.push_str(part["text"].as_str().unwrap_or(""));
                            }
                        }
                    }
                }
            }
            text
        }
        _ => value["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    };
    vasp_core::ai::validate_report(text.as_bytes(), facts).map_err(anyhow::Error::msg)
}
