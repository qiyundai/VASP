use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::{io::Read, path::PathBuf};
use uuid::Uuid;
use vasp::{engine, network::Feed, store::Store, transport, workers};

#[derive(Parser)]
#[command(
    version,
    about = "VASP local security observer. Automatic containment is release-gated."
)]
struct Cli {
    #[arg(long, global = true, default_value = "data")]
    data: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init,
    Scan,
    Status,
    Broker {
        #[arg(value_parser=["status", "inventory", "stop", "remove-blocks"], default_value="status")]
        operation: String,
    },
    Feeds,
    Watch {
        #[arg(long, default_value_t = 0)]
        iterations: u32,
    },
    Analyze,
    Configure {
        file: PathBuf,
    },
    Credential {
        #[arg(value_parser=["openai","lan"])]
        provider: String,
    },
    Identity,
    Enroll {
        #[arg(long)]
        device: Uuid,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        fingerprint: String,
    },
    Revoke {
        device: Uuid,
    },
    Serve {
        #[arg(long)]
        bind: std::net::SocketAddr,
    },
    Send {
        #[arg(long)]
        coordinator: std::net::SocketAddr,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        fingerprint: String,
    },
    Connect {
        #[arg(long)]
        coordinator: std::net::SocketAddr,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        fingerprint: String,
    },
    Disconnect,
    Lookup {
        cve: String,
    },
    Package {
        ecosystem: String,
        name: String,
        version: String,
    },
    VerifyAudit,
    StopActions,
    RemoveBlocks,
    #[command(hide = true)]
    Worker,
    SandboxCheck,
}
fn main() {
    if let Err(e) = run() {
        eprintln!("VASP: {e:#}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let cli = Cli::parse();
    if matches!(cli.command, Command::Worker) {
        return workers::worker_main();
    }
    let mut store = Store::open(&cli.data)?;
    match cli.command {
        Command::Broker { operation } => {
            use vasp_core::broker::Command as Operation;
            let operation = match operation.as_str() {
                "inventory" => Operation::Inventory {},
                "stop" => Operation::StopAutomaticActions {},
                "remove-blocks" => Operation::RemoveTemporaryBlocks {},
                _ => Operation::Status {},
            };
            let result = vasp::broker::request(operation, store.device_id()?)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if !result.accepted {
                bail!("Broker denied the request");
            }
        }
        Command::Init => {
            let id = store.device_id()?;
            if store.get::<engine::Config>("config")?.is_none() {
                store.set("config", &engine::Config::default())?;
            }
            if store
                .get::<vasp_core::policy::LocalPolicy>("local_policy")?
                .is_none()
            {
                store.set(
                    "local_policy",
                    &vasp_core::policy::LocalPolicy::observe_only(id),
                )?;
            }
            store.audit("initialized:observe-only")?;
            println!(
                "VASP initialized. Device: {id}\nMode: observe-only. Existing configuration preserved; new installations default to cloud disabled."
            );
        }
        Command::Scan => {
            let count = engine::scan(&mut store)?;
            println!(
                "Observation saved. {count} findings; use status or vasp-desktop to inspect coverage."
            );
        }
        Command::Status => println!(
            "{}",
            serde_json::to_string_pretty(&engine::status(&store)?)?
        ),
        Command::Feeds => {
            engine::refresh(&mut store, true)?;
            for (name, s) in store.schedules()? {
                println!("{name}: {}", s.last_error.as_deref().unwrap_or("updated"));
            }
        }
        Command::Watch { iterations } => {
            let mut n = 0;
            loop {
                engine::tick(&mut store)?;
                n += 1;
                if iterations > 0 && n >= iterations {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        }
        Command::Analyze => {
            let config = engine::config(&store)?;
            let r = vasp::models::analyze(&mut store, &config.model)?;
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
        Command::Configure { file } => {
            let bytes = std::fs::read(file)?;
            if bytes.len() > 65536 {
                bail!("Config exceeds limit");
            }
            let c: engine::Config = serde_json::from_slice(&bytes)?;
            if c.schema != 1 {
                bail!("Unsupported config schema");
            }
            store.set("config", &c)?;
            store.audit("configuration-updated-locally")?;
            println!("Configuration saved. No privileged action permissions changed.");
        }
        Command::Credential { provider } => {
            eprintln!(
                "Read credential from standard input (do not pass secrets as command arguments)."
            );
            let mut secret = String::new();
            std::io::stdin().take(2049).read_to_string(&mut secret)?;
            vasp_platform::secrets::write(
                if provider == "openai" {
                    "VASP/OpenAI"
                } else {
                    "VASP/LAN"
                },
                secret.trim(),
            )?;
            println!("Credential saved to Windows Credential Manager.");
        }
        Command::Identity => {
            let fp = transport::create_identity(&mut store)?;
            println!(
                "Device: {}\nSHA-256: {fp}\nPublic certificate: {}",
                store.device_id()?,
                store.directory.join("identity.der").display()
            );
        }
        Command::Enroll {
            device,
            certificate,
            fingerprint,
        } => {
            let cert = std::fs::read(certificate)?;
            if vasp_core::digest(&cert) != fingerprint.to_lowercase() {
                bail!("Fingerprint mismatch; enrollment refused");
            }
            let mut roots = rustls::RootCertStore::empty();
            roots.add(rustls::pki_types::CertificateDer::from(cert.clone()))?;
            store.admit_peer(device, &cert)?;
            println!("Explicitly enrolled {device} for observation reporting only.");
        }
        Command::Revoke { device } => {
            store.revoke(device)?;
            println!("Revoked {device}.");
        }
        Command::Serve { bind } => {
            transport::create_identity(&mut store)?;
            drop(store);
            transport::serve(&cli.data, bind)?;
        }
        Command::Send {
            coordinator,
            certificate,
            fingerprint,
        } => {
            let cert = std::fs::read(certificate)?;
            if vasp_core::digest(&cert) != fingerprint.to_lowercase() {
                bail!("Coordinator fingerprint mismatch");
            }
            let ack = transport::send(&store, coordinator, &cert)?;
            println!("Report accepted: {}", ack.request_id);
        }
        Command::Connect {
            coordinator,
            certificate,
            fingerprint,
        } => {
            if !transport::is_lan(coordinator.ip()) {
                bail!("Select an explicit LAN coordinator address");
            }
            let cert = std::fs::read(certificate)?;
            if cert.len() > 16384 || vasp_core::digest(&cert) != fingerprint.to_lowercase() {
                bail!("Coordinator fingerprint mismatch or oversized certificate");
            }
            let mut roots = rustls::RootCertStore::empty();
            roots.add(rustls::pki_types::CertificateDer::from(cert.clone()))?;
            transport::create_identity(&mut store)?;
            store.set(
                "coordinator",
                &transport::Coordinator {
                    address: coordinator,
                    certificate: cert,
                },
            )?;
            store
                .conn
                .execute("DELETE FROM meta WHERE key='last_sent_observation'", [])?;
            store.audit("coordinator-pinned-locally")?;
            println!(
                "Coordinator pinned. The observer will report new inventory; enroll this device on the coordinator separately."
            );
        }
        Command::Disconnect => {
            store.conn.execute(
                "DELETE FROM meta WHERE key IN ('coordinator','last_sent_observation')",
                [],
            )?;
            store.audit("coordinator-disconnected-locally")?;
            println!("Coordinator reporting disabled; local observation continues.");
        }
        Command::Lookup { cve } => {
            let items: Vec<vasp_core::protocol::Advisory> =
                serde_json::from_value(workers::feed(Feed::Cve { id: cve })?)?;
            let count = items.len();
            store.save_advisories("CVE record", &items)?;
            println!("Stored {count} CVE product records.");
        }
        Command::Package {
            ecosystem,
            name,
            version,
        } => {
            let items: Vec<vasp_core::protocol::Advisory> =
                serde_json::from_value(workers::feed(Feed::Osv {
                    ecosystem,
                    package: name,
                    version,
                })?)?;
            println!("{}", serde_json::to_string_pretty(&items)?);
            store.save_advisories("OSV", &items)?;
        }
        Command::VerifyAudit => {
            store.verify_audit()?;
            println!("Audit chain verified. This does not attest host integrity.");
        }
        Command::StopActions => {
            let id = store.device_id()?;
            let mut p = store
                .get::<vasp_core::policy::LocalPolicy>("local_policy")?
                .unwrap_or_else(|| vasp_core::policy::LocalPolicy::observe_only(id));
            p.enabled = false;
            p.version = p.version.saturating_add(1);
            store.set("local_policy", &p)?;
            store.audit("automatic-actions-disabled-locally")?;
            println!("Automatic actions disabled. This build never enables enforcement.");
        }
        Command::RemoveBlocks => {
            if vasp_platform::wfp::RELEASE_ENFORCEMENT_APPROVED {
                bail!("Broker integration required");
            }
            println!(
                "This observe-only build cannot create filters; there are no VASP blocks to remove."
            );
        }
        Command::SandboxCheck => {
            let result = workers::run(&workers::Request::SandboxProbe {
                private_path: store
                    .directory
                    .join("vasp.db")
                    .canonicalize()?
                    .to_string_lossy()
                    .into_owned(),
            })?;
            if result["private_read_denied"] != true
                || result["network_denied"] != true
                || result["child_process_denied"] != true
            {
                bail!("Sandbox conformance failed: {result}");
            }
            store.set("sandbox_verified", &true)?;
            store.audit("sandbox-conformance-passed")?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Worker => unreachable!(),
    }
    Ok(())
}
