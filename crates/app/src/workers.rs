use crate::network::Feed;
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Events {
        device_id: Uuid,
    },
    Collect {
        device_id: Uuid,
    },
    Fetch {
        feed: Feed,
    },
    Parse {
        feed: Feed,
        body: String,
        at: u64,
    },
    Model {
        config: crate::models::ModelConfig,
        facts: Vec<vasp_core::ai::AnalystFact>,
        credential: String,
    },
    SandboxProbe {
        private_path: String,
    },
}

pub fn execute(request: Request) -> Result<serde_json::Value> {
    match request {
        Request::Events { device_id } => Ok(serde_json::to_value(
            vasp_platform::inventory::events(device_id)?,
        )?),
        Request::SandboxProbe { private_path } => {
            let private_read_denied = std::fs::read(private_path).is_err();
            let network_denied = std::net::TcpStream::connect_timeout(
                &"1.1.1.1:443".parse()?,
                Duration::from_secs(2),
            )
            .is_err();
            let child_process_denied = Command::new("C:\\Windows\\System32\\whoami.exe")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .is_err();
            Ok(
                serde_json::json!({"private_read_denied":private_read_denied,"network_denied":network_denied,"child_process_denied":child_process_denied}),
            )
        }
        Request::Model {
            config,
            facts,
            credential,
        } => Ok(serde_json::to_value(crate::models::request(
            &config,
            &facts,
            &credential,
        )?)?),
        Request::Collect { device_id } => Ok(serde_json::to_value(
            vasp_platform::inventory::collect(device_id)?,
        )?),
        Request::Fetch { feed } => {
            Ok(serde_json::json!({"body":STANDARD.encode(crate::network::fetch(&feed)?)}))
        }
        Request::Parse { feed, body, at } => {
            if body.len() > 48 * 1024 * 1024 {
                bail!("Encoded feed too large");
            }
            let bytes = STANDARD.decode(body)?;
            let items=match feed {Feed::Kev=>vasp_core::feeds::parse_kev(&bytes,at),Feed::Nvd{..}=>{
            let root=vasp_core::feeds::json(&bytes).map_err(anyhow::Error::msg)?;
            let items=vasp_core::feeds::parse_nvd(&bytes,at).map_err(anyhow::Error::msg)?;
            return Ok(serde_json::json!({"items":items,"total":root["totalResults"],"start":root["startIndex"],"count":root["resultsPerPage"]}));
        },Feed::Osv{..}=>vasp_core::feeds::parse_osv(&bytes,at),
            Feed::Epss{..}=>return Ok(serde_json::to_value(vasp_core::feeds::parse_epss(&bytes).map_err(anyhow::Error::msg)?)?),
            Feed::Cve{..}=>vasp_core::feeds::parse_cve(&bytes,at),
            Feed::Microsoft{..}=>vasp_core::feeds::parse_msrc(&bytes,at),
            Feed::ChromiumResearch=>vasp_core::feeds::parse_chromium_rss(&bytes,at),
        }.map_err(anyhow::Error::msg)?;
            Ok(serde_json::to_value(items)?)
        }
    }
}
pub fn worker_main() -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(50 * 1024 * 1024 + 1)
        .read_to_end(&mut input)?;
    if input.len() > 50 * 1024 * 1024 {
        bail!("Worker request too large");
    }
    let request: Request = serde_json::from_slice(&input)?;
    let value = execute(request)?;
    serde_json::to_writer(std::io::stdout().lock(), &value)?;
    Ok(())
}

pub fn executable() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    let cli = exe.with_file_name("vasp.exe");
    if !cli.is_file() {
        bail!("vasp.exe must be installed beside vasp-desktop.exe");
    }
    Ok(cli)
}

pub fn run(request: &Request) -> Result<serde_json::Value> {
    if !matches!(request, Request::Collect { .. } | Request::Events { .. }) {
        use vasp_platform::sandbox::NetworkAccess;
        let access = match request {
            Request::Parse { .. } | Request::SandboxProbe { .. } => NetworkAccess::None,
            Request::Model { config, .. }
                if matches!(config.provider, crate::models::Provider::Lan { .. }) =>
            {
                NetworkAccess::Lan
            }
            Request::Model { .. } => NetworkAccess::CloudModel,
            _ => NetworkAccess::Internet,
        };
        let output =
            vasp_platform::sandbox::run(&executable()?, serde_json::to_vec(request)?, access)?;
        return Ok(serde_json::from_slice(&output)?);
    }
    let mut command = Command::new(executable()?);
    command
        .arg("worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn()?;
    let job = match vasp_platform::isolation::Job::attach(&child, 384 * 1024 * 1024) {
        Ok(job) => job,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e.context("Worker job isolation failed"));
        }
    };
    let stdout = child.stdout.take().context("Missing worker output")?;
    let stderr = child.stderr.take().context("Missing worker diagnostics")?;
    let out = std::thread::spawn(move || {
        let mut b = vec![];
        stdout
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut b)
            .map(|_| b)
    });
    let err = std::thread::spawn(move || {
        let mut b = vec![];
        stderr.take(8192).read_to_end(&mut b).map(|_| b)
    });
    let payload = serde_json::to_vec(request)?;
    let mut input = child.stdin.take().context("Missing worker input")?;
    let writer = std::thread::spawn(move || input.write_all(&payload));
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Worker timed out; no results accepted");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = out
        .join()
        .map_err(|_| anyhow::anyhow!("Worker reader failed"))??;
    let error = err
        .join()
        .map_err(|_| anyhow::anyhow!("Worker reader failed"))??;
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("Worker writer failed"))??;
    drop(job);
    if !status.success() {
        bail!("Worker failed: {}", String::from_utf8_lossy(&error));
    }
    if output.len() > 64 * 1024 * 1024 {
        bail!("Worker output exceeds limit");
    }
    Ok(serde_json::from_slice(&output)?)
}

pub fn feed(feed: Feed) -> Result<serde_json::Value> {
    let raw = run(&Request::Fetch { feed: feed.clone() })?;
    let body = raw["body"]
        .as_str()
        .context("Worker returned no feed body")?
        .to_owned();
    run(&Request::Parse {
        feed,
        body,
        at: vasp_core::now(),
    })
}
