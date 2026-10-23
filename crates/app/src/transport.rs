use crate::store::Store;
use anyhow::{Context, Result, bail};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;
use vasp_core::protocol::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema: u16,
    pub request_id: Uuid,
    pub device_id: Uuid,
    pub sent_at: u64,
    pub observation: Observation,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub schema: u16,
    pub request_id: Uuid,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coordinator {
    pub address: SocketAddr,
    pub certificate: Vec<u8>,
}

/// Retry only new observations. A failed/absent coordinator never disables local collection.
pub fn report_pending(store: &mut Store) -> Result<()> {
    let Some(coordinator) = store.get::<Coordinator>("coordinator")? else {
        return Ok(());
    };
    let Some(observation) = store.latest(store.device_id()?)? else {
        return Ok(());
    };
    if store.get::<Uuid>("last_sent_observation")? == Some(observation.id) {
        return Ok(());
    }
    let now = vasp_core::now();
    let mut schedule = store.schedule("Coordinator reporting", 30)?;
    if !schedule.due(now) {
        return Ok(());
    }
    match send(store, coordinator.address, &coordinator.certificate) {
        Ok(_) => {
            store.set("last_sent_observation", &observation.id)?;
            schedule.success(now);
        }
        Err(e) => schedule.failure(now, e.to_string()),
    }
    store.save_schedule("Coordinator reporting", &schedule)
}

fn crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
pub fn create_identity(store: &mut Store) -> Result<String> {
    let cert_path = store.directory.join("identity.der");
    let key_path = store.directory.join("identity.key");
    if cert_path.exists() && key_path.exists() {
        return Ok(vasp_core::digest(&std::fs::read(cert_path)?));
    }
    if cert_path.exists() || key_path.exists() {
        bail!("Incomplete identity; recover it explicitly before continuing");
    }
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec!["vasp.local".into()])?;
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, store.device_id()?.to_string());
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let cert = params.self_signed(&key)?;
    let mut key_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(key_path)?;
    key_file.write_all(&key.serialize_der())?;
    key_file.sync_all()?;
    let mut cert_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(cert_path)?;
    cert_file.write_all(cert.der().as_ref())?;
    cert_file.sync_all()?;
    let fingerprint = vasp_core::digest(cert.der().as_ref());
    store.audit(&format!("identity-created:{fingerprint}"))?;
    Ok(fingerprint)
}
fn identity(directory: &Path) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    Ok((
        CertificateDer::from(std::fs::read(directory.join("identity.der"))?),
        PrivatePkcs8KeyDer::from(std::fs::read(directory.join("identity.key"))?).into(),
    ))
}
fn roots(certs: impl IntoIterator<Item = Vec<u8>>) -> Result<RootCertStore> {
    let mut r = RootCertStore::empty();
    for cert in certs {
        r.add(CertificateDer::from(cert))?;
    }
    Ok(r)
}
pub fn is_lan(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(a) => a.is_private() || a.is_loopback(),
        std::net::IpAddr::V6(a) => a.is_unique_local() || a.is_loopback(),
    }
}

pub fn send(store: &Store, address: SocketAddr, server_cert: &[u8]) -> Result<Ack> {
    if !is_lan(address.ip()) {
        bail!("Coordinator must have a specific LAN address");
    }
    crypto();
    let (cert, key) = identity(&store.directory)?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots([server_cert.to_vec()])?)
        .with_client_auth_cert(vec![cert], key)?;
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("vasp.local")?)?;
    let mut socket = socket;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket)?;
    }
    let remote = connection
        .peer_certificates()
        .and_then(|c| c.first())
        .context("Missing coordinator certificate")?;
    if vasp_core::digest(remote.as_ref()) != vasp_core::digest(server_cert) {
        bail!("Coordinator certificate pin mismatch");
    }
    let mut stream = rustls::StreamOwned::new(connection, socket);
    let id = store.device_id()?;
    let observation = store
        .latest(id)?
        .context("Run a local scan before sending")?;
    let envelope = Envelope {
        schema: VERSION,
        request_id: Uuid::new_v4(),
        device_id: id,
        sent_at: vasp_core::now(),
        observation,
    };
    write_frame(&mut stream, &serde_json::to_vec(&envelope)?)?;
    let ack: Ack = serde_json::from_slice(&read_frame(&mut stream)?)?;
    if ack.schema != VERSION || ack.request_id != envelope.request_id || !ack.accepted {
        bail!("Invalid coordinator acknowledgement");
    }
    Ok(ack)
}

pub fn serve(directory: &Path, bind: SocketAddr) -> Result<()> {
    if !is_lan(bind.ip()) || bind.ip().is_unspecified() {
        bail!("Bind to one explicit private/loopback interface");
    }
    crypto();
    let listener = TcpListener::bind(bind)?;
    eprintln!(
        "VASP observation receiver listening on {bind}; no remote administration or action endpoint"
    );
    // Bounded concurrent connections; each has a strict frame deadline and socket timeouts.
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for socket in listener.incoming() {
        let socket = socket?;
        if !is_lan(socket.peer_addr()?.ip()) {
            continue;
        }
        if active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 4 {
            active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            continue;
        }
        let directory = directory.to_owned();
        let active = Arc::clone(&active);
        std::thread::spawn(move || {
            struct Slot(Arc<std::sync::atomic::AtomicUsize>);
            impl Drop for Slot {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let _slot = Slot(active);
            if let Err(e) = receive(&directory, socket) {
                eprintln!("Rejected LAN report: {e}");
            }
        });
    }
    Ok(())
}
fn receive(directory: &Path, mut socket: TcpStream) -> Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut store = Store::open(directory)?;
    let peers = store.peers()?;
    if peers.is_empty() {
        bail!("No devices enrolled");
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(
        peers.iter().map(|(_, _, cert)| cert.clone()),
    )?))
    .build()?;
    let (cert, key) = identity(directory)?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)?;
    let mut connection = rustls::ServerConnection::new(Arc::new(config))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while connection.is_handshaking() {
        if Instant::now() > deadline {
            bail!("TLS handshake deadline exceeded");
        }
        connection.complete_io(&mut socket)?;
    }
    let cert = connection
        .peer_certificates()
        .and_then(|p| p.first())
        .context("Missing client certificate")?;
    let fingerprint = vasp_core::digest(cert.as_ref());
    let device = peers
        .iter()
        .find(|(_, f, _)| *f == fingerprint)
        .map(|(id, _, _)| *id)
        .context("Unpinned client certificate")?;
    let mut stream = rustls::StreamOwned::new(connection, socket);
    let envelope: Envelope = serde_json::from_slice(&read_frame(&mut stream)?)?;
    if envelope.schema != VERSION
        || envelope.device_id != device
        || envelope.observation.device_id != device
    {
        bail!("Cross-device observation rejected");
    }
    let now = vasp_core::now();
    envelope
        .observation
        .validate(now)
        .map_err(anyhow::Error::msg)?;
    store.accept_request(device, envelope.request_id, envelope.sent_at, now)?;
    let old = store.latest(device)?;
    let duplicate = old.as_ref().is_some_and(|o| {
        o.id == envelope.observation.id
            && serde_json::to_vec(o).ok() == serde_json::to_vec(&envelope.observation).ok()
    });
    if !duplicate
        && old
            .as_ref()
            .is_some_and(|o| o.observed_at >= envelope.observation.observed_at)
    {
        bail!("Replayed or out-of-order observation");
    }
    if !duplicate {
        let findings = vasp_core::matching::assess(
            &envelope.observation,
            &store.advisories()?,
            old.as_ref(),
            now,
        );
        store.save_observation(&envelope.observation, &findings)?;
    }
    write_frame(
        &mut stream,
        &serde_json::to_vec(&Ack {
            schema: VERSION,
            request_id: envelope.request_id,
            accepted: true,
        })?,
    )?;
    Ok(())
}
pub fn write_frame(w: &mut impl Write, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_MESSAGE {
        bail!("Frame too large");
    }
    w.write_all(&(bytes.len() as u32).to_be_bytes())?;
    w.write_all(bytes)?;
    w.flush()?;
    Ok(())
}
pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>> {
    let start = Instant::now();
    let mut header = [0u8; 4];
    r.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    if size > MAX_MESSAGE {
        bail!("Frame too large");
    }
    let mut bytes = vec![0u8; size];
    let mut offset = 0;
    while offset < size {
        if start.elapsed() > Duration::from_secs(15) {
            bail!("Frame deadline exceeded");
        }
        let end = (offset + 8192).min(size);
        let n = r.read(&mut bytes[offset..end])?;
        if n == 0 {
            bail!("Truncated frame");
        }
        offset += n;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_and_truncated_frames() {
        let mut b = ((MAX_MESSAGE + 1) as u32).to_be_bytes().as_slice().to_vec();
        assert!(read_frame(&mut b.as_slice()).is_err());
        b = vec![0, 0, 0, 2, 1];
        assert!(read_frame(&mut b.as_slice()).is_err());
    }
    #[test]
    fn mutual_tls_pinned_identity_roundtrip() {
        crypto();
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let mut sa = Store::open(a.path()).unwrap();
        let mut sb = Store::open(b.path()).unwrap();
        create_identity(&mut sa).unwrap();
        create_identity(&mut sb).unwrap();
        let id = sb.device_id().unwrap();
        sa.admit_peer(id, &std::fs::read(b.path().join("identity.der")).unwrap())
            .unwrap();
        let o = Observation::empty(id, vasp_core::now());
        sb.save_observation(&o, &[]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let path = a.path().to_owned();
        let thread = std::thread::spawn(move || {
            receive(&path, listener.accept().unwrap().0)?;
            receive(&path, listener.accept().unwrap().0)
        });
        let ack = send(
            &sb,
            addr,
            &std::fs::read(a.path().join("identity.der")).unwrap(),
        )
        .unwrap();
        assert!(ack.accepted);
        assert!(
            send(
                &sb,
                addr,
                &std::fs::read(a.path().join("identity.der")).unwrap()
            )
            .unwrap()
            .accepted
        );
        thread.join().unwrap().unwrap();
        assert!(sa.latest(id).unwrap().is_some());
    }

    #[test]
    fn unpaired_and_cross_device_tls_reports_are_rejected() {
        for enroll in [false, true] {
            let a = tempfile::tempdir().unwrap();
            let b = tempfile::tempdir().unwrap();
            let mut sa = Store::open(a.path()).unwrap();
            let mut sb = Store::open(b.path()).unwrap();
            create_identity(&mut sa).unwrap();
            create_identity(&mut sb).unwrap();
            if enroll {
                // A valid enrolled certificate may still not report for another device UUID.
                sa.admit_peer(
                    Uuid::new_v4(),
                    &std::fs::read(b.path().join("identity.der")).unwrap(),
                )
                .unwrap();
            }
            let o = Observation::empty(sb.device_id().unwrap(), vasp_core::now());
            sb.save_observation(&o, &[]).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let path = a.path().to_owned();
            let thread = std::thread::spawn(move || receive(&path, listener.accept().unwrap().0));
            assert!(
                send(
                    &sb,
                    addr,
                    &std::fs::read(a.path().join("identity.der")).unwrap()
                )
                .is_err()
            );
            assert!(thread.join().unwrap().is_err());
            assert!(sa.devices().unwrap().is_empty());
        }
    }
}
