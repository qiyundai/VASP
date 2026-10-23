use uuid::Uuid;
use vasp_core::{ai, feeds, matching, protocol::*};

fn software(name: &str) -> Software {
    Software {
        name: name.into(),
        publisher: "Microsoft Corporation".into(),
        version: "10.0.26100.5000".into(),
        ecosystem: None,
        package: None,
    }
}
fn windows_advisory(id: &str) -> Advisory {
    Advisory {
        schema: VERSION,
        id: id.into(),
        source: Source::CisaKev,
        source_url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".into(),
        fetched_at: 100,
        title: "Windows issue".into(),
        description: "public advisory".into(),
        vendor: "Microsoft".into(),
        product: "Windows".into(),
        ecosystem: None,
        ranges: vec![],
        exact_versions: vec![],
        exploited: true,
        epss: None,
        remediation: "Check vendor guidance".into(),
    }
}

#[test]
fn os_advisories_never_match_sdk_or_installation_assistant() {
    let a = windows_advisory("CVE-2026-1234");
    for name in [
        "Windows SDK Desktop Headers",
        "Microsoft.WindowsDesktop.App.Runtime",
        "Windows 11 Installation Assistant",
    ] {
        assert_eq!(
            matching::applicable(&software(name), &a),
            Applicability::Unaffected
        );
    }
}

#[test]
fn thousands_of_unverified_os_records_are_one_research_candidate() {
    let mut o = Observation::empty(Uuid::new_v4(), 100);
    o.os_name = "Microsoft Windows 11 Pro".into();
    o.os_version = "10.0.26100.5000".into();
    o.software = vec![software("Windows SDK")];
    let records: Vec<_> = (1000..4000)
        .map(|n| windows_advisory(&format!("CVE-2026-{n}")))
        .collect();
    let findings = matching::assess(&o, &records, None, 100);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].applicability, Applicability::Possible);
    assert_eq!(findings[0].priority, Priority::Informational);
    assert!(findings[0].evidence.len() <= 102);
}

#[test]
fn product_tokens_and_publishers_prevent_accidental_identity_matches() {
    let mut a = windows_advisory("CVE-2026-1234");
    a.product = "git".into();
    a.vendor = String::new();
    assert_eq!(
        matching::applicable(&software("Digital scanner"), &a),
        Applicability::Unaffected
    );
    a.product = "ios".into();
    a.vendor = "Apple".into();
    assert_eq!(
        matching::applicable(&software("Microsoft iOS SDK"), &a),
        Applicability::Unaffected
    );
}

#[test]
fn incomplete_previous_collection_does_not_invent_changes() {
    let id = Uuid::new_v4();
    let before = Observation::empty(id, 100);
    let mut after = Observation::empty(id, 110);
    after.listeners.push(Listener {
        address: "0.0.0.0".parse().unwrap(),
        port: 9000,
        pid: 12,
        application: Some("C:\\Apps\\app.exe".into()),
    });
    after.persistence.push(Persistence {
        location: "Run".into(),
        name: "App".into(),
        value_hash: "abc".into(),
    });
    assert!(matching::assess(&after, &[], Some(&before), 110).is_empty());
}

#[test]
fn analyst_projection_excludes_sensitive_observation_material() {
    let f = Finding {
        schema: 1,
        id: "abc".into(),
        device_id: Uuid::new_v4(),
        observation_id: Uuid::new_v4(),
        advisory_id: Some("CVE-2026-1234".into()),
        title: "user Alice at 192.168.1.2".into(),
        explanation: "credential sk-secret".into(),
        applicability: Applicability::Unknown,
        priority: Priority::Medium,
        evidence: vec!["C:\\Users\\Alice\\private.txt".into()],
        source_urls: vec![],
        remediation: "raw diagnostic".into(),
        created_at: 1,
    };
    let json = serde_json::to_string(&ai::project(&[f])).unwrap();
    for secret in [
        "Alice",
        "192.168",
        "sk-secret",
        "private.txt",
        "raw diagnostic",
    ] {
        assert!(!json.contains(secret));
    }
}

#[test]
fn xml_entities_and_pagination_are_not_silently_accepted() {
    assert!(
        feeds::parse_chromium_rss(
            br#"<!DOCTYPE rss [<!ENTITY e SYSTEM "file:///C:/secret">]><rss/>"#,
            0
        )
        .is_err()
    );
    assert!(feeds::parse_osv(br#"{"vulns":[],"next_page_token":"more"}"#, 0).is_err());
}

#[test]
fn bounded_malformed_input_corpus_does_not_panic() {
    let mut seed = 7u64;
    for len in 0..2048usize {
        let mut bytes = vec![0u8; len];
        for b in &mut bytes {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (seed >> 24) as u8;
        }
        let _ = feeds::parse_kev(&bytes, 0);
        let _ = feeds::parse_osv(&bytes, 0);
        let _ = feeds::parse_nvd(&bytes, 0);
        let _ = feeds::parse_cve(&bytes, 0);
        let _ = feeds::parse_msrc(&bytes, 0);
        let _ = feeds::parse_chromium_rss(&bytes, 0);
        let _ = ai::validate_report(&bytes, &[]);
    }
}

#[test]
fn benign_baseline_has_no_actions_or_findings() {
    let mut o = Observation::empty(Uuid::new_v4(), 100);
    o.os_name = "Windows 11".into();
    o.defender_enabled = Some(true);
    o.firewall_enabled = Some(true);
    assert!(matching::assess(&o, &[], Some(&o), 100).is_empty());
}

#[test]
fn nvd_confirmed_desktop_version_and_complex_conditions() {
    let mut body = serde_json::json!({"vulnerabilities":[{"cve":{"id":"CVE-2026-1234","descriptions":[],"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:windows:*:*","versionStartIncluding":"120.0.0.0","versionEndExcluding":"122.0.1.0"}]}]}]}}]});
    let a = feeds::parse_nvd(&serde_json::to_vec(&body).unwrap(), 100).unwrap();
    let mut s = Software {
        name: "Google Chrome".into(),
        publisher: "Google LLC".into(),
        version: "121.0.0.0".into(),
        ecosystem: None,
        package: None,
    };
    matching::identify_desktop_package(&mut s);
    assert_eq!(matching::applicable(&s, &a[0]), Applicability::Confirmed);
    s.version = "122.0.1.0".into();
    assert_eq!(matching::applicable(&s, &a[0]), Applicability::Unaffected);
    body["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"][0]["operator"] = "AND".into();
    let a = feeds::parse_nvd(&serde_json::to_vec(&body).unwrap(), 100).unwrap();
    assert_ne!(matching::applicable(&s, &a[0]), Applicability::Confirmed);
}

#[test]
fn conflicting_sources_and_stale_observations_never_confirm() {
    let mut a = windows_advisory("CVE-2026-1234");
    a.product = "demo".into();
    a.ecosystem = Some("npm".into());
    a.ranges = vec![VersionRange {
        introduced: Some("1.0.0".into()),
        fixed: Some("3.0.0".into()),
        last_affected: None,
    }];
    let mut b = a.clone();
    b.source = Source::Osv;
    b.ranges[0].fixed = Some("2.0.0".into());
    let mut o = Observation::empty(Uuid::new_v4(), 100);
    o.software.push(Software {
        name: "Demo".into(),
        publisher: String::new(),
        version: "2.0.0".into(),
        ecosystem: Some("npm".into()),
        package: Some("demo".into()),
    });
    assert!(
        matching::assess(&o, &[a.clone(), b], None, 100)
            .iter()
            .all(|f| f.applicability != Applicability::Confirmed)
    );
    assert!(
        matching::assess(&o, &[a], None, 9000)
            .iter()
            .all(|f| f.applicability != Applicability::Confirmed)
    );
}

#[test]
fn withdrawn_osv_and_unknown_range_limits_do_not_confirm() {
    let withdrawn = br#"{"vulns":[{"id":"GHSA-xxxx-yyyy-zzzz","withdrawn":"2026-01-01","affected":[{"package":{"name":"demo","ecosystem":"npm"},"versions":["1.0.0"]}]}]}"#;
    assert!(feeds::parse_osv(withdrawn, 0).unwrap().is_empty());
    let limited = br#"{"vulns":[{"id":"GHSA-xxxx-yyyy-zzzz","affected":[{"package":{"name":"demo","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"limit":"2.0.0"}]}]}]}]}"#;
    assert!(feeds::parse_osv(limited, 0).unwrap()[0].ranges.is_empty());
}
