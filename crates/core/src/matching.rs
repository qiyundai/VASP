use crate::protocol::*;
use std::cmp::Ordering;

fn compare(a: &str, b: &str, ecosystem: &str) -> Option<Ordering> {
    if ecosystem == "vendor-dotted" {
        fn components(s: &str) -> Option<Vec<u64>> {
            if s.len() > 64 {
                return None;
            }
            let mut n = s
                .split('.')
                .map(|p| {
                    if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
                        p.parse().ok()
                    } else {
                        None
                    }
                })
                .collect::<Option<Vec<u64>>>()?;
            if n.len() > 8 {
                return None;
            }
            while n.last() == Some(&0) {
                n.pop();
            }
            Some(n)
        }
        return Some(components(a)?.cmp(&components(b)?));
    }
    if matches!(ecosystem, "npm" | "crates.io" | "Go") {
        let parse = |s: &str| semver::Version::parse(s.trim_start_matches('v')).ok();
        return Some(parse(a)?.cmp(&parse(b)?));
    }
    // Do not pretend lexical order models Debian, RPM, PEP 440, or vendor versions.
    None
}

/// Explicit identity mappings only. Never infer package identity from arbitrary substrings.
pub fn identify_desktop_package(s: &mut Software) {
    let name = s.name.to_lowercase();
    let publisher = s.publisher.to_lowercase();
    let package = if name == "google chrome" && publisher.starts_with("google") {
        Some("chrome")
    } else if name.starts_with("mozilla firefox") && publisher.starts_with("mozilla") {
        Some("firefox")
    } else if name.starts_with("7-zip ") && publisher.contains("igor pavlov") {
        Some("7-zip")
    } else if name == "vlc media player" && publisher.contains("videolan") {
        Some("vlc_media_player")
    } else {
        None
    };
    if let Some(p) = package {
        s.package = Some(p.into());
        s.ecosystem = Some("vendor-dotted".into());
    }
}

pub fn applicable(s: &Software, a: &Advisory) -> Applicability {
    let package_match = s.package.as_ref().is_some_and(|p| p == &a.product)
        && s.ecosystem.is_some()
        && s.ecosystem == a.ecosystem;
    if !package_match {
        let normalize = |v: &str| {
            v.to_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        };
        let name = normalize(&s.name);
        let product = normalize(&a.product);
        // An OS advisory must never attach to Windows SDKs or platform-targeting packages.
        if product == "windows" || product.starts_with("windows ") {
            if s.ecosystem.as_deref() != Some("windows") {
                return Applicability::Unaffected;
            }
            if product.contains("server") && !name.contains("server") {
                return Applicability::Unaffected;
            }
            for generation in ["windows 7", "windows 8", "windows 10", "windows 11"] {
                if product.starts_with(generation) && !name.contains(generation) {
                    return Applicability::Unaffected;
                }
            }
            return Applicability::Possible;
        }
        if !a.vendor.is_empty()
            && !s.publisher.is_empty()
            && !normalize(&s.publisher).contains(&normalize(&a.vendor))
        {
            return Applicability::Unaffected;
        }
        if product.len() < 3 || !format!(" {name} ").contains(&format!(" {product} ")) {
            return Applicability::Unaffected;
        }
        return Applicability::Possible;
    }
    if a.exact_versions.contains(&s.version) {
        return Applicability::Confirmed;
    }
    let Some(ecosystem) = s.ecosystem.as_deref() else {
        return Applicability::Unknown;
    };
    let mut unknown = a.ranges.is_empty();
    for r in &a.ranges {
        let low = match r.introduced.as_deref() {
            None | Some("0") => Some(true),
            Some(v) => compare(&s.version, v, ecosystem).map(|c| c != Ordering::Less),
        };
        let high = match (&r.fixed, &r.last_affected) {
            (Some(v), _) => compare(&s.version, v, ecosystem).map(|c| c == Ordering::Less),
            (_, Some(v)) => compare(&s.version, v, ecosystem).map(|c| c != Ordering::Greater),
            _ => Some(true),
        };
        match (low, high) {
            (Some(true), Some(true)) => return Applicability::Confirmed,
            (None, _) | (_, None) => unknown = true,
            _ => {}
        }
    }
    if unknown {
        Applicability::Unknown
    } else {
        Applicability::Unaffected
    }
}

pub fn assess(
    o: &Observation,
    advisories: &[Advisory],
    previous: Option<&Observation>,
    now: u64,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut add = |key: String,
                   title: String,
                   explanation: String,
                   applicability: Applicability,
                   priority: Priority,
                   advisory: Option<&Advisory>,
                   evidence: Vec<String>,
                   remediation: String| {
        findings.push(Finding {
            schema: VERSION,
            id: crate::digest(format!("{}:{key}", o.device_id).as_bytes()),
            device_id: o.device_id,
            observation_id: o.id,
            advisory_id: advisory.map(|a| a.id.clone()),
            title,
            explanation,
            applicability,
            priority,
            evidence,
            source_urls: advisory
                .map(|a| vec![a.source_url.clone()])
                .unwrap_or_default(),
            remediation,
            created_at: now,
        });
    };
    let os = Software {
        name: o.os_name.clone(),
        publisher: "Microsoft".into(),
        version: o.os_version.clone(),
        ecosystem: Some("windows".into()),
        package: Some("windows".into()),
    };
    let mut candidates: std::collections::BTreeMap<
        (String, String),
        std::collections::BTreeMap<String, &Advisory>,
    > = std::collections::BTreeMap::new();
    let mut by_id: std::collections::BTreeMap<&str, Vec<&Advisory>> =
        std::collections::BTreeMap::new();
    for a in advisories {
        by_id.entry(&a.id).or_default().push(a);
    }
    for a in advisories {
        if a.source == Source::Research {
            continue;
        }
        for s in o.software.iter().chain(std::iter::once(&os)) {
            let mut status = applicable(s, a);
            if status == Applicability::Confirmed
                && by_id.get(a.id.as_str()).is_some_and(|records| {
                    records.iter().any(|other| {
                        other.product == a.product
                            && other.ecosystem == a.ecosystem
                            && applicable(s, other) == Applicability::Unaffected
                    })
                })
            {
                status = Applicability::Possible;
            }
            if status == Applicability::Unaffected {
                continue;
            }
            let stale = a.fetched_at > now
                || now.saturating_sub(a.fetched_at) > 86400
                || o.observed_at > now
                || now.saturating_sub(o.observed_at) > 7200;
            if stale && status == Applicability::Confirmed {
                status = Applicability::Possible;
            }
            if status != Applicability::Confirmed {
                candidates
                    .entry((s.name.clone(), s.version.clone()))
                    .or_default()
                    .insert(a.id.clone(), a);
                continue;
            }
            add(
                format!("{}:{}:{}", a.id, s.name, s.version),
                format!("{}: {}", a.id, s.name),
                if status == Applicability::Confirmed {
                    "Package identity and affected version match the advisory.".into()
                } else {
                    "Candidate match; affected version or current advisory status is unverified. No automatic action is authorized.".into()
                },
                status,
                if a.exploited
                    || by_id
                        .get(a.id.as_str())
                        .is_some_and(|records| records.iter().any(|other| other.exploited))
                {
                    Priority::High
                } else {
                    Priority::Medium
                },
                Some(a),
                vec![
                    format!("Installed: {} {}", s.name, s.version),
                    format!("Source: {:?}; fetched {}", a.source, a.fetched_at),
                ],
                a.remediation.clone(),
            );
        }
    }
    for ((name, version), records) in candidates {
        let mut evidence = vec![
            format!("Installed: {name} {version}"),
            format!(
                "{} unique advisories require version verification",
                records.len()
            ),
        ];
        evidence.extend(records.keys().take(100).cloned());
        add(format!("candidate:{name}:{version}"),format!("Verify advisory applicability: {name}"),
            "Product identity suggests research candidates. These are not confirmed vulnerabilities; affected versions, platform conditions and installed fixes require verification.".into(),
            Applicability::Possible,Priority::Informational,records.values().next().copied(),evidence,
            "Review the linked vendor guidance against the exact installed build. For Windows, check servicing and cumulative-update supersedence before concluding exposure.".into());
    }
    for (name, enabled) in [
        ("Defender real-time protection", o.defender_enabled),
        ("Windows firewall", o.firewall_enabled),
    ] {
        if enabled == Some(false) {
            add(
                name.into(),
                format!("{name} is disabled"),
                "Windows reported a disabled security control.".into(),
                Applicability::Confirmed,
                Priority::High,
                None,
                vec![format!("Observed at {}", o.observed_at)],
                "Review Windows Security and restore protection if appropriate.".into(),
            );
        }
    }
    if let Some(old) = previous {
        let startup_baseline = old
            .coverage
            .iter()
            .any(|c| c.area == "Startup entries" && c.state != CoverageState::Unavailable)
            && !old.persistence.is_empty();
        for item in o.persistence.iter().filter(|_| startup_baseline) {
            if !old.persistence.iter().any(|p| {
                p.location == item.location
                    && p.name == item.name
                    && p.value_hash == item.value_hash
            }) {
                add(format!("persistence:{}:{}",item.location,item.name),"Startup configuration changed".into(),
                    "A startup entry was added or changed. This can be legitimate; inspect the application before acting.".into(),
                    Applicability::Unknown,Priority::Medium,None,vec![item.location.clone(),item.name.clone()],"Review the corresponding startup application in Windows settings.".into());
            }
        }
        let listener_baseline = old
            .coverage
            .iter()
            .any(|c| c.area == "TCP listeners" && c.state == CoverageState::Available);
        for l in o.listeners.iter().filter(|_| listener_baseline) {
            if l.address.is_loopback() {
                continue;
            }
            if !old.listeners.iter().any(|p| {
                p.address == l.address && p.port == l.port && p.application == l.application
            }) {
                add(format!("listener:{}:{}",l.address,l.port),format!("New listening service on port {}",l.port),
                    "A new local TCP listener appeared. Reachability from outside the PC has not been established.".into(),
                    Applicability::Unknown,Priority::Medium,None,vec![format!("{}:{}; PID {}",l.address,l.port,l.pid)],"Review the owning application and its Windows firewall rules.".into());
            }
        }
    }
    for e in &o.events {
        if e.channel.contains("Defender") && matches!(e.event_id, 1116 | 1117 | 5001 | 5010) {
            add(format!("event:{}:{}",e.channel,e.record_id),format!("Defender security event {}",e.event_id),
                "Windows Defender recorded a detection, response, or protection-state event. A detection alone does not prove a safe network-block target.".into(),
                Applicability::Confirmed,Priority::High,None,vec![format!("{} record {}",e.channel,e.record_id)],"Review Windows Security Protection history.".into());
        }
    }
    findings.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.id.cmp(&b.id)));
    findings.dedup_by(|a, b| a.id == b.id);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Software, Advisory) {
        (
            Software {
                name: "Example".into(),
                publisher: "".into(),
                version: "1.2.0".into(),
                ecosystem: Some("npm".into()),
                package: Some("example".into()),
            },
            Advisory {
                schema: 1,
                id: "CVE-2026-1234".into(),
                source: Source::Osv,
                source_url: "https://osv.dev/".into(),
                fetched_at: 1,
                title: "".into(),
                description: "".into(),
                vendor: "".into(),
                product: "example".into(),
                ecosystem: Some("npm".into()),
                ranges: vec![VersionRange {
                    introduced: Some("1.0.0".into()),
                    fixed: Some("1.3.0".into()),
                    last_affected: None,
                }],
                exact_versions: vec![],
                exploited: false,
                epss: None,
                remediation: "".into(),
            },
        )
    }
    #[test]
    fn version_boundaries() {
        let (mut s, a) = fixture();
        assert_eq!(applicable(&s, &a), Applicability::Confirmed);
        s.version = "1.3.0".into();
        assert_eq!(applicable(&s, &a), Applicability::Unaffected);
        s.version = "0.9.0".into();
        assert_eq!(applicable(&s, &a), Applicability::Unaffected);
        s.version = "vendor edition".into();
        assert_eq!(applicable(&s, &a), Applicability::Unknown);
    }
    #[test]
    fn name_only_never_confirms_and_vendor_versions_unknown() {
        let (mut s, mut a) = fixture();
        s.package = None;
        assert_eq!(applicable(&s, &a), Applicability::Possible);
        s.package = Some("example".into());
        s.ecosystem = Some("Debian".into());
        a.ecosystem = s.ecosystem.clone();
        assert_eq!(applicable(&s, &a), Applicability::Unknown);
    }
}
