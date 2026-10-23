//! Explicit disposable-VM executable. Not a broker, installer, or release artifact.
//! Every filter targets this executable, loopback TCP, and a test-selected high port.
#![forbid(unsafe_code)]
#[cfg(windows)]
mod harness {
    use anyhow::{Context, Result, ensure};
    use std::{
        io::{Read, Write},
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
        os::windows::process::CommandExt,
        process::{Child, Command, Stdio},
        sync::mpsc::{self, Receiver},
        thread,
        time::{Duration, Instant},
    };
    use vasp_core::{protocol::BlockTarget, recovery::RecoveryGuard};
    use vasp_platform::{
        isolation::Job,
        wfp::{self, DynamicSession, LeaseSession},
    };

    const POLL: Duration = Duration::from_millis(50);
    const HEARTBEAT_MS: u64 = 2000;
    fn target(address: SocketAddr, inbound: bool) -> Result<BlockTarget> {
        ensure!(
            address.ip().is_loopback() && address.port() >= 1024,
            "Only loopback high-port fixtures are allowed"
        );
        let application = std::env::current_exe()?
            .to_str()
            .context("Unicode fixture path")?
            .to_owned();
        Ok(if inbound {
            BlockTarget::Listener {
                application,
                address: address.ip(),
                port: address.port(),
            }
        } else {
            BlockTarget::Destination {
                application,
                address: address.ip(),
                port: address.port(),
            }
        })
    }
    fn command() -> Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW; no console flashes during faults.
        Ok(command)
    }
    fn connect(address: SocketAddr) -> bool {
        TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok()
    }
    fn eventually(mut assertion: impl FnMut() -> Result<bool>) -> Result<()> {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if assertion()? {
                return Ok(());
            }
            ensure!(
                Instant::now() < end,
                "Recovery did not complete within five seconds"
            );
            thread::sleep(POLL);
        }
    }
    fn fixture(ip: IpAddr) -> Result<(TcpListener, SocketAddr)> {
        fixture_at(SocketAddr::new(ip, 0))
    }
    fn fixture_at(address: SocketAddr) -> Result<(TcpListener, SocketAddr)> {
        let socket = TcpListener::bind(address)?;
        let address = socket.local_addr()?;
        socket.set_nonblocking(true)?;
        // Drain accepted connections so failures cannot be caused by a full listen backlog.
        let drain = socket.try_clone()?;
        thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(90);
            while Instant::now() < until {
                let _ = drain.accept();
                thread::sleep(Duration::from_millis(5));
            }
        });
        Ok((socket, address))
    }
    enum Event {
        Ready(u64, uuid::Uuid),
        Beat(u64),
        Closed,
    }
    struct Worker {
        child: Child,
        job: Option<Job>,
        events: Receiver<Event>,
        key: uuid::Uuid,
        guard: RecoveryGuard,
    }
    impl Worker {
        fn start(address: SocketAddr, mode: &str, seconds: u64) -> Result<Self> {
            Self::start_with_owner_deadline(
                address,
                mode,
                seconds,
                seconds.saturating_add(2).min(600),
            )
        }
        fn start_with_owner_deadline(
            address: SocketAddr,
            mode: &str,
            seconds: u64,
            owner_seconds: u64,
        ) -> Result<Self> {
            ensure!((1..=600).contains(&owner_seconds), "Invalid owner deadline");
            let guard = RecoveryGuard::new(wfp::recovery_sample(), seconds, HEARTBEAT_MS)
                .map_err(anyhow::Error::msg)?;
            let mut child = command()?
                .args([
                    "worker",
                    &address.to_string(),
                    mode,
                    &owner_seconds.to_string(),
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            let job = match Job::attach(&child, 128 * 1024 * 1024) {
                Ok(job) => job,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
            let mut stdout = child.stdout.take().context("Worker stdout")?;
            let (sender, events) = mpsc::sync_channel(2);
            thread::spawn(move || {
                let read = (|| -> std::io::Result<()> {
                    let mut ready = [0u8; 24];
                    stdout.read_exact(&mut ready)?;
                    let mut id = [0u8; 8];
                    id.copy_from_slice(&ready[..8]);
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&ready[8..]);
                    if sender
                        .send(Event::Ready(
                            u64::from_le_bytes(id),
                            uuid::Uuid::from_bytes(key),
                        ))
                        .is_err()
                    {
                        return Ok(());
                    }
                    loop {
                        let mut beat = [0u8; 8];
                        stdout.read_exact(&mut beat)?;
                        if sender.send(Event::Beat(u64::from_le_bytes(beat))).is_err() {
                            return Ok(());
                        }
                    }
                })();
                let _ = read;
                let _ = sender.send(Event::Closed);
            });
            // Construct the cleanup owner before the first fallible write.
            let mut instance = Self {
                child,
                job: Some(job),
                events,
                key: uuid::Uuid::nil(),
                guard,
            };
            // Worker cannot open WFP before successful job assignment. EOF also refuses startup.
            instance
                .child
                .stdin
                .take()
                .context("Worker stdin")?
                .write_all(b"G")?;
            let Event::Ready(id, key) = instance.events.recv_timeout(Duration::from_secs(5))?
            else {
                anyhow::bail!("Worker failed before ready");
            };
            ensure!(id != 0 && !key.is_nil(), "Invalid worker receipt");
            instance.key = key;
            instance.guard.check(wfp::recovery_sample())?;
            Ok(instance)
        }
        fn supervise(&mut self) -> Result<String> {
            loop {
                // Check before consuming queued beats: pre-sleep beats cannot reset the deadline.
                if let Err(reason) = self.guard.check(wfp::recovery_sample()) {
                    self.stop()?;
                    return Ok(reason.to_string());
                }
                match self.events.recv_timeout(POLL) {
                    Ok(Event::Beat(sequence)) => {
                        if let Err(reason) = self.guard.heartbeat(sequence, wfp::recovery_sample())
                        {
                            self.stop()?;
                            return Ok(reason.to_string());
                        }
                    }
                    Ok(Event::Closed) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        self.stop()?;
                        return Ok("worker exited".into());
                    }
                    Ok(Event::Ready(..)) => {
                        self.stop()?;
                        anyhow::bail!("Duplicate ready receipt");
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        }
        fn stop(&mut self) -> Result<()> {
            self.job.take(); // Windows kills the exact process attached to this owned job.
            eventually(|| Ok(self.child.try_wait()?.is_some()))
        }
    }
    impl Drop for Worker {
        fn drop(&mut self) {
            self.job.take();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    fn worker(address: SocketAddr, mode: &str, seconds: u64) -> Result<()> {
        ensure!(
            mode == "hang" || mode == "heartbeat",
            "Unknown fixture mode"
        );
        let mut go = [0u8; 1];
        std::io::stdin().read_exact(&mut go)?;
        ensure!(go == *b"G", "Supervisor did not authorize fixture startup");
        ensure!((1..=600).contains(&seconds), "Invalid owner deadline");
        let mut session = LeaseSession::open()?;
        let inspector = DynamicSession::open()?;
        let id = session.add(&target(address, false)?, vasp_core::now() + seconds)?;
        let key = inspector.key(id)?;
        let mut out = std::io::stdout().lock();
        out.write_all(&id.to_le_bytes())?;
        out.write_all(key.as_bytes())?;
        out.flush()?;
        drop(out);
        if mode == "hang" {
            // Fault injection deliberately stops the owner's expiry loop as well as its heartbeat.
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        // A blocked heartbeat pipe must never stall the owner's independent expiry loop.
        thread::spawn(|| {
            let mut sequence = 0u64;
            let mut out = std::io::stdout().lock();
            loop {
                thread::sleep(Duration::from_millis(100));
                sequence += 1;
                if out
                    .write_all(&sequence.to_le_bytes())
                    .and_then(|_| out.flush())
                    .is_err()
                {
                    return;
                }
            }
        });
        while inspector.contains_key(key)? {
            session.expire()?;
            thread::sleep(POLL);
        }
        Ok(())
    }
    fn targeting(ip: IpAddr) -> Result<()> {
        let (_listener, address) = fixture(ip)?;
        let (_other, other) = fixture(ip)?;
        ensure!(
            connect(address) && connect(other),
            "Fixture unavailable before filtering"
        );
        let inspector = DynamicSession::open()?;
        let udp_receiver = UdpSocket::bind(address)?;
        udp_receiver.set_read_timeout(Some(Duration::from_millis(500)))?;
        let udp_sender = UdpSocket::bind(SocketAddr::new(ip, 0))?;
        let other_address = if ip.is_ipv4() {
            Some(fixture_at(SocketAddr::new(
                Ipv4Addr::new(127, 0, 0, 2).into(),
                address.port(),
            ))?)
        } else {
            None
        };
        if let Some((_, alternative)) = &other_address {
            ensure!(connect(*alternative), "Alternate address baseline failed");
        }
        for inbound in [false, true] {
            let session = DynamicSession::open()?;
            let id = session.add(&target(address, inbound)?)?;
            let key = session.key(id)?;
            ensure!(inspector.contains_key(key)?, "Filter not visible");
            ensure!(
                !connect(address),
                "Matching TCP flow was not blocked: {address}, inbound={inbound}"
            );
            ensure!(connect(other), "Unrelated port was blocked");
            if let Some((_, alternative)) = &other_address {
                ensure!(connect(*alternative), "Unrelated IPv4 address was blocked");
            }
            udp_sender.send_to(b"fixture", address)?;
            let mut datagram = [0u8; 16];
            ensure!(
                udp_receiver.recv_from(&mut datagram)?.0 == 7 && &datagram[..7] == b"fixture",
                "TCP filter blocked UDP"
            );
            session.remove(id)?;
            ensure!(
                !inspector.contains_key(key)? && connect(address),
                "Explicit removal did not recover"
            );
            let id = session.add(&target(address, inbound)?)?;
            let key = session.key(id)?;
            drop(session);
            eventually(|| Ok(!inspector.contains_key(key)? && connect(address)))?;
        }
        // A second executable path must still reach the blocked destination.
        let session = DynamicSession::open()?;
        session.add(&target(address, false)?)?;
        let copy_dir = std::env::current_dir()?.join("data/wfp-recovery");
        std::fs::create_dir_all(&copy_dir)?;
        let copy = copy_dir.join(format!("probe-{}.exe", uuid::Uuid::new_v4()));
        std::fs::copy(std::env::current_exe()?, &copy)?;
        let status = Command::new(&copy)
            .creation_flags(0x08000000)
            .args(["probe", &address.to_string()])
            .status();
        let _ = std::fs::remove_file(copy);
        ensure!(status?.success(), "Unrelated application was blocked");
        println!(
            "PASS: {ip} exact application, direction, address/port, explicit removal and session drop"
        );
        Ok(())
    }
    fn suite() -> Result<()> {
        ensure!(
            !vasp_core::broker::ENFORCEMENT_ENABLED && !wfp::RELEASE_ENFORCEMENT_APPROVED,
            "Production gate must remain disabled"
        );
        targeting(Ipv4Addr::LOCALHOST.into())?;
        targeting(Ipv6Addr::LOCALHOST.into())?;
        let (_listener, address) = fixture(Ipv4Addr::LOCALHOST.into())?;
        let inspector = DynamicSession::open()?;
        let mut leases = LeaseSession::open()?;
        ensure!(
            leases
                .add(&target(address, false)?, vasp_core::now() + 601)
                .is_err(),
            "Overlong lease accepted"
        );
        let id = leases.add(&target(address, false)?, vasp_core::now() + 2)?;
        let key = inspector.key(id)?;
        ensure!(!connect(address), "Lease did not block");
        eventually(|| {
            leases.expire()?;
            Ok(!inspector.contains_key(key)? && connect(address))
        })?;
        println!("PASS: native lease expiry and duration bound");
        let mut child = Worker::start_with_owner_deadline(address, "heartbeat", 30, 2)?;
        ensure!(
            !connect(address),
            "Independent expiry fixture did not block"
        );
        // Do not service the supervisor: emulate a stalled watchdog while owner keeps running.
        eventually(|| Ok(!inspector.contains_key(child.key)? && connect(address)))?;
        child.stop()?;
        println!("PASS: owner expires its filter while supervisor stops processing heartbeats");
        for (mode, seconds, expected) in [
            ("hang", 30, "heartbeat deadline missed"),
            ("heartbeat", 3, "lease expired"),
        ] {
            let mut child = Worker::start(address, mode, seconds)?;
            ensure!(
                inspector.contains_key(child.key)? && !connect(address),
                "Worker did not install fixture"
            );
            ensure!(child.supervise()? == expected, "Wrong recovery reason");
            eventually(|| Ok(!inspector.contains_key(child.key)? && connect(address)))?;
            println!("PASS: watchdog {mode} terminates owner and removes filter");
        }
        let mut child = Worker::start(address, "hang", 30)?;
        child.child.kill()?;
        ensure!(child.supervise()? == "worker exited", "Crash not observed");
        eventually(|| Ok(!inspector.contains_key(child.key)? && connect(address)))?;
        println!("PASS: forced filter-owner crash cleanup");
        // Crash the supervisor, not its worker. The non-inherited job handle must kill the worker.
        let mut supervisor = command()?
            .args(["supervisor", &address.to_string()])
            .stdout(Stdio::piped())
            .spawn()?;
        let result = (|| -> Result<()> {
            let mut out = supervisor.stdout.take().context("Supervisor stdout")?;
            let (tx, rx) = mpsc::sync_channel(1);
            thread::spawn(move || {
                let mut key = [0u8; 16];
                let result = out
                    .read_exact(&mut key)
                    .map(|_| uuid::Uuid::from_bytes(key));
                let _ = tx.send(result);
            });
            let key = rx.recv_timeout(Duration::from_secs(8))??;
            ensure!(
                inspector.contains_key(key)? && !connect(address),
                "Supervisor fixture missing"
            );
            supervisor.kill()?;
            supervisor.wait()?;
            eventually(|| Ok(!inspector.contains_key(key)? && connect(address)))?;
            println!("PASS: supervisor crash closes job and kills filter owner");
            Ok(())
        })();
        let _ = supervisor.kill();
        let _ = supervisor.wait();
        result?;
        println!("PASS: automatic blocking remains disabled; physical power tests are separate");
        Ok(())
    }
    pub fn run() -> Result<()> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        match args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["suite", "--disposable-vm"] => suite(),
            ["worker", address, mode, seconds] => worker(address.parse()?, mode, seconds.parse()?),
            ["probe", address] => {
                let address = address.parse()?;
                target(address, false)?;
                ensure!(connect(address), "Probe failed");
                Ok(())
            }
            ["supervisor", address] => {
                let mut child = Worker::start(address.parse()?, "hang", 30)?;
                std::io::stdout().write_all(child.key.as_bytes())?;
                std::io::stdout().flush()?;
                // Intentionally omit supervision: suite kills this process to test job-handle closure.
                thread::sleep(Duration::from_secs(10));
                child.stop()
            }
            ["power-arm", "--disposable-vm", path] => {
                let (_listener, address) = fixture(Ipv4Addr::LOCALHOST.into())?;
                let mut child = Worker::start(address, "heartbeat", 600)?;
                ensure!(!connect(address), "Power fixture not blocking");
                let sample = wfp::recovery_sample();
                let receipt = serde_json::json!({"key": child.key, "armed_at": sample.wall_seconds,
                    "interrupt_ms": sample.awake_and_sleep_ms, "address": address.to_string(), "owner_pid": child.child.id()});
                // Create-new prevents overwriting an earlier power test's evidence.
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?;
                file.write_all(&serde_json::to_vec(&receipt)?)?;
                file.sync_all()?;
                let reason = child.supervise()?;
                let inspector = DynamicSession::open()?;
                eventually(|| Ok(!inspector.contains_key(child.key)?))?;
                std::fs::write(
                    format!("{path}.result"),
                    serde_json::to_vec(
                        &serde_json::json!({"reason":reason,"removed":true,"checked_at":vasp_core::now()}),
                    )?,
                )?;
                Ok(())
            }
            ["absent", key] => {
                ensure!(
                    !DynamicSession::open()?.contains_key(key.parse()?)?,
                    "Filter survived recovery"
                );
                Ok(())
            }
            _ => anyhow::bail!(
                "Use suite --disposable-vm; this example is never a production enforcement interface"
            ),
        }
    }
}
fn main() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        harness::run()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("Windows disposable VM required")
    }
}
