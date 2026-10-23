#![forbid(unsafe_code)]

pub mod journal;

pub fn run() -> anyhow::Result<()> {
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--service"] {
        anyhow::bail!(
            "Run through the Windows Service Control Manager with --service. Automatic blocking is disabled."
        );
    }
    #[cfg(windows)]
    {
        vasp_platform::broker_service::run(service)
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("The broker requires Windows");
    }
}

#[cfg(windows)]
fn service(stop: &std::sync::atomic::AtomicBool) -> anyhow::Result<()> {
    use std::{sync::atomic::Ordering, time::Duration};
    use vasp_core::broker::*;
    use vasp_platform::broker_ipc;
    let identity = broker_ipc::current_identity()?;
    if identity.sid != "S-1-5-18"
        || identity.session != 0
        || identity.app_container
        || identity.integrity < 0x4000
    {
        anyhow::bail!("Broker must run as the local SYSTEM service");
    }
    let directory = broker_ipc::state_directory()?;
    let config: Configuration = serde_json::from_slice(&broker_ipc::read_protected_config(
        &directory.path.join("policy.json"),
    )?)?;
    config.validate().map_err(anyhow::Error::msg)?;
    let mut journal =
        journal::Journal::open(&directory.path.join("broker.db"), config.policy.device_id)?;
    let mut server =
        broker_ipc::Server::new(PIPE, config.callers.iter().map(|c| c.sid.clone()).collect())?;
    vasp_platform::broker_service::ready();
    while !stop.load(Ordering::SeqCst) {
        let handled = (|| -> anyhow::Result<()> {
            let Some(caller) = server.accept(Duration::from_millis(250))? else {
                return Ok(());
            };
            let hello = Hello {
                schema: VERSION,
                session: uuid::Uuid::new_v4(),
                device_id: config.policy.device_id,
                policy_version: config.policy.version,
            };
            server.channel().write(&serde_json::to_vec(&hello)?)?;
            let request: Request = serde_json::from_slice(&server.channel().read()?)?;
            let response = journal.handle(
                &config,
                &caller.sid,
                hello.session,
                &request,
                vasp_core::now(),
                broker_ipc::inventory,
            )?;
            server.channel().write(&serde_json::to_vec(&response)?)?;
            Ok(())
        })();
        // Malformed/unauthorized connections cannot shut down the service or create actions.
        // Per-request errors go to the authenticated response; pre-auth input isn't logged.
        server.disconnect();
        if handled.is_err() {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    journal.finish()?;
    Ok(())
}
