use anyhow::Result;
use uuid::Uuid;
use vasp_core::protocol::*;

pub fn collect(device_id: Uuid) -> Result<Observation> {
    let mut o = Observation::empty(device_id, vasp_core::now());
    #[cfg(windows)]
    native::collect(&mut o);
    #[cfg(not(windows))]
    o.coverage.push(Coverage {
        area: "Operating system".into(),
        state: CoverageState::Unavailable,
        detail: "Windows collection only".into(),
    });
    Ok(o)
}

pub fn events(device_id: Uuid) -> Result<EventBatch> {
    let mut o = Observation::empty(device_id, vasp_core::now());
    #[cfg(windows)]
    native::collect_events(&mut o);
    Ok(EventBatch {
        device_id,
        collected_at: o.observed_at,
        events: o.events,
        coverage: o.coverage,
    })
}

#[cfg(windows)]
mod native {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;
    use winreg::{RegKey, enums::*};
    use wmi::WMIConnection;

    fn rows(ns: &str, query: &str) -> Result<Vec<HashMap<String, Value>>> {
        Ok(WMIConnection::with_namespace_path(ns)?.raw_query(query)?)
    }
    fn s(r: &HashMap<String, Value>, key: &str) -> String {
        r.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(2048)
            .collect()
    }
    fn n(r: &HashMap<String, Value>, key: &str) -> u32 {
        r.get(key).and_then(Value::as_u64).unwrap_or(0) as u32
    }
    fn coverage(o: &mut Observation, area: &str, result: Result<()>) {
        match result {
            Ok(()) => o.coverage.push(Coverage {
                area: area.into(),
                state: CoverageState::Available,
                detail: "Collected locally".into(),
            }),
            Err(e) => o.coverage.push(Coverage {
                area: area.into(),
                state: CoverageState::Unavailable,
                detail: e.to_string().chars().take(256).collect(),
            }),
        }
    }
    pub fn collect(o: &mut Observation) {
        let r = (|| {
            let os = rows(
                "ROOT\\CIMV2",
                "SELECT Caption,Version FROM Win32_OperatingSystem",
            )?;
            if let Some(r) = os.first() {
                o.os_name = s(r, "Caption");
                o.os_version = s(r, "Version");
            } else {
                anyhow::bail!("No operating system record");
            }
            let key = RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")?;
            let ubr: u32 = key.get_value("UBR").unwrap_or(0);
            o.os_version = format!("{}.{}", o.os_version, ubr);
            Ok(())
        })();
        coverage(o, "Windows build", r);
        let r = (|| {
            for row in rows(
                "ROOT\\CIMV2",
                "SELECT HotFixID FROM Win32_QuickFixEngineering",
            )? {
                o.updates.push(s(&row, "HotFixID"));
            }
            Ok(())
        })();
        coverage(o, "Installed hotfixes", r);
        o.coverage.push(Coverage{area:"Update supersedence".into(),state:CoverageState::Unavailable,detail:"Hotfix inventory is not a complete servicing/supersedence graph. Windows CVE applicability remains unconfirmed.".into()});
        let mut readable = 0;
        for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
            for flag in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
                if let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                    KEY_READ | flag,
                ) {
                    readable += 1;
                    for name in root.enum_keys().filter_map(Result::ok).take(10000) {
                        if let Ok(k) = root.open_subkey(name) {
                            let name: String = k.get_value("DisplayName").unwrap_or_default();
                            if name.is_empty() {
                                continue;
                            }
                            o.software.push(Software {
                                name,
                                publisher: k.get_value("Publisher").unwrap_or_default(),
                                version: k.get_value("DisplayVersion").unwrap_or_default(),
                                ecosystem: None,
                                package: None,
                            });
                        }
                    }
                }
            }
        }
        for software in &mut o.software {
            vasp_core::matching::identify_desktop_package(software);
        }
        o.software
            .sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        o.software
            .dedup_by(|a, b| a.name == b.name && a.version == b.version);
        o.coverage.push(Coverage{area:"Installed applications".into(),state:if readable>0{CoverageState::Partial}else{CoverageState::Unavailable},detail:"Registry-installed applications only. Portable apps, other users, Store packages and embedded dependencies may be absent.".into()});
        let r = (|| {
            for row in rows(
                "ROOT\\CIMV2",
                "SELECT Name,State,StartMode FROM Win32_Service",
            )?
            .into_iter()
            .take(5000)
            {
                o.services.push(Service {
                    name: s(&row, "Name"),
                    state: s(&row, "State"),
                    start_mode: s(&row, "StartMode"),
                });
            }
            Ok(())
        })();
        coverage(o, "Services", r);
        let r = (|| {
            let processes: HashMap<_, _> = rows(
                "ROOT\\CIMV2",
                "SELECT ProcessId,ExecutablePath FROM Win32_Process",
            )?
            .into_iter()
            .map(|r| (n(&r, "ProcessId"), s(&r, "ExecutablePath")))
            .collect();
            for row in rows("ROOT\\StandardCimv2","SELECT LocalAddress,LocalPort,OwningProcess FROM MSFT_NetTCPConnection WHERE State=2")?.into_iter().take(10000){
                if let Ok(address)=s(&row,"LocalAddress").split('%').next().unwrap_or("").parse(){let pid=n(&row,"OwningProcess");o.listeners.push(Listener{address,port:n(&row,"LocalPort") as u16,pid,application:processes.get(&pid).filter(|s|!s.is_empty()).cloned()});}
            }
            Ok(())
        })();
        coverage(o, "TCP listeners", r);
        let r = (|| {
            for row in rows(
                "ROOT\\StandardCimv2",
                "SELECT IPAddress,InterfaceIndex,State FROM MSFT_NetNeighbor",
            )?
            .into_iter()
            .take(4096)
            {
                if let Ok(address) = s(&row, "IPAddress")
                    .split('%')
                    .next()
                    .unwrap_or("")
                    .parse::<std::net::IpAddr>()
                    && !address.is_multicast()
                    && !address.is_unspecified()
                {
                    o.neighbors.push(Neighbor {
                        address,
                        interface: n(&row, "InterfaceIndex"),
                        state: n(&row, "State").to_string(),
                    });
                }
            }
            Ok(())
        })();
        coverage(o, "Passive LAN neighbors", r);
        let r = (|| {
            let rs = rows(
                "ROOT\\Microsoft\\Windows\\Defender",
                "SELECT RealTimeProtectionEnabled FROM MSFT_MpComputerStatus",
            )?;
            o.defender_enabled = rs
                .first()
                .and_then(|r| r.get("RealTimeProtectionEnabled"))
                .and_then(Value::as_bool);
            if o.defender_enabled.is_none() {
                anyhow::bail!("Defender state unavailable");
            }
            Ok(())
        })();
        coverage(o, "Defender", r);
        let r = (|| {
            let rs = rows(
                "ROOT\\StandardCimv2",
                "SELECT Enabled FROM MSFT_NetFirewallProfile",
            )?;
            if rs.is_empty() {
                anyhow::bail!("No firewall profiles");
            }
            let states: Vec<_> = rs
                .iter()
                .filter_map(|r| r.get("Enabled"))
                .filter_map(|v| v.as_u64().map(|n| n == 1).or_else(|| v.as_bool()))
                .collect();
            if states.len() != rs.len() {
                anyhow::bail!("Incomplete firewall profile data");
            }
            o.firewall_enabled = Some(states.iter().all(|v| *v));
            Ok(())
        })();
        coverage(o, "Firewall profiles", r);
        for (hive, label) in [(HKEY_LOCAL_MACHINE, "Machine"), (HKEY_CURRENT_USER, "User")] {
            for path in [
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ] {
                if let Ok(key) = RegKey::predef(hive).open_subkey(path) {
                    for (name, value) in key.enum_values().filter_map(Result::ok).take(1000) {
                        o.persistence.push(Persistence {
                            location: format!("{label}\\{path}"),
                            name,
                            value_hash: vasp_core::digest(&value.bytes),
                        });
                    }
                }
            }
        }
        o.coverage.push(Coverage{area:"Startup entries".into(),state:CoverageState::Partial,detail:"Run and RunOnce registry entries. Scheduled tasks, WMI persistence and other users are not yet collected.".into()});
        collect_events(o);
        o.coverage.push(Coverage {
            area: "Automatic containment".into(),
            state: CoverageState::Unavailable,
            detail: "Release safety gate closed; observation and recommendations only.".into(),
        });
    }

    pub fn collect_events(o: &mut Observation) {
        for channel in ["Microsoft-Windows-Windows Defender/Operational", "Security"] {
            let r = read_events(channel).map(|events| o.events.extend(events));
            coverage(o, channel, r);
        }
    }

    fn read_events(channel: &str) -> Result<Vec<SecurityEvent>> {
        use windows::{Win32::System::EventLog::*, core::PCWSTR};
        struct Event(EVT_HANDLE);
        impl Drop for Event {
            fn drop(&mut self) {
                unsafe {
                    let _ = EvtClose(self.0);
                }
            }
        }
        let path: Vec<u16> = channel.encode_utf16().chain(Some(0)).collect();
        let filter = if channel == "Security" {
            "*[System[(EventID=1102 or EventID=4719) and TimeCreated[timediff(@SystemTime) <= 3600000]]]"
        } else {
            "*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5010) and TimeCreated[timediff(@SystemTime) <= 3600000]]]"
        };
        let filter: Vec<u16> = filter.encode_utf16().chain(Some(0)).collect();
        // SAFETY: UTF-16 strings are terminated and handles are owned until EvtClose.
        let query = Event(unsafe {
            EvtQuery(
                None,
                PCWSTR(path.as_ptr()),
                PCWSTR(filter.as_ptr()),
                EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
            )?
        });
        let mut result = vec![];
        for _ in 0..64 {
            let mut handles = [0isize; 1];
            let mut returned = 0;
            if let Err(e) = unsafe { EvtNext(query.0, &mut handles, 1000, 0, &mut returned) } {
                if e.code().0 as u32 == 0x80070103 {
                    break;
                }
                return Err(e.into());
            }
            if returned == 0 {
                break;
            }
            let event = Event(EVT_HANDLE(handles[0]));
            let mut used = 0;
            let mut count = 0;
            let mut xml = vec![0u16; 32768];
            unsafe {
                EvtRender(
                    None,
                    event.0,
                    EvtRenderEventXml.0,
                    (xml.len() * 2) as u32,
                    Some(xml.as_mut_ptr().cast()),
                    &mut used,
                    &mut count,
                )?;
            }
            let text = String::from_utf16_lossy(&xml[..(used as usize / 2).min(xml.len())])
                .trim_end_matches('\0')
                .to_owned();
            fn tag(xml: &str, name: &str) -> u64 {
                xml.split(&format!("<{name}>"))
                    .nth(1)
                    .and_then(|s| s.split('<').next())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0)
            }
            result.push(SecurityEvent {
                channel: channel.into(),
                event_id: tag(&text, "EventID") as u32,
                record_id: tag(&text, "EventRecordID"),
                xml: text,
            });
        }
        Ok(result)
    }
}
