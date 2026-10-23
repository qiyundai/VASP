use crate::protocol::*;
use serde_json::Value;

pub const MAX_FEED: usize = 32 * 1024 * 1024;
fn text(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .chars()
        .take(16384)
        .collect()
}
pub fn json(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > MAX_FEED {
        return Err("Feed exceeds 32 MiB".into());
    }
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
}
pub fn parse_kev(bytes: &[u8], now: u64) -> Result<Vec<Advisory>, String> {
    let root = json(bytes)?;
    let rows = root["vulnerabilities"]
        .as_array()
        .ok_or("Missing vulnerabilities array")?;
    if rows.len() > 30000 {
        return Err("Too many advisories".into());
    }
    rows.iter()
        .map(|v| {
            let id = text(v, "cveID");
            if !valid_cve(&id) {
                return Err("Invalid CVE identifier".into());
            }
            Ok(Advisory {
                schema: VERSION,
                id,
                source: Source::CisaKev,
                source_url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".into(),
                fetched_at: now,
                title: text(v, "vulnerabilityName"),
                description: text(v, "shortDescription"),
                vendor: text(v, "vendorProject"),
                product: text(v, "product"),
                ecosystem: None,
                ranges: vec![],
                exact_versions: vec![],
                exploited: true,
                epss: None,
                remediation: text(v, "requiredAction"),
            })
        })
        .collect()
}
pub fn valid_cve(id: &str) -> bool {
    let parts: Vec<_> = id.split('-').collect();
    parts.len() == 3
        && parts[0] == "CVE"
        && parts[1].len() == 4
        && (4..=10).contains(&parts[2].len())
        && parts[1..]
            .iter()
            .all(|s| s.bytes().all(|b| b.is_ascii_digit()))
}
pub fn parse_osv(bytes: &[u8], now: u64) -> Result<Vec<Advisory>, String> {
    let root = json(bytes)?;
    let empty = vec![];
    let records = root
        .get("vulns")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    if root.get("next_page_token").is_some() {
        return Err("OSV response is paginated; incomplete results are not accepted".into());
    }
    let mut out = vec![];
    for v in records.iter().take(2000) {
        if v.get("withdrawn").is_some_and(|x| !x.is_null()) {
            continue;
        }
        let Some(affected) = v["affected"].as_array() else {
            continue;
        };
        for a in affected.iter().take(100) {
            let mut ranges = vec![];
            if let Some(rs) = a["ranges"].as_array() {
                for r in rs {
                    if r["type"].as_str() != Some("SEMVER") {
                        continue;
                    }
                    let mut introduced = None;
                    if let Some(events) = r["events"].as_array() {
                        for event in events {
                            if let Some(s) = event["introduced"].as_str() {
                                introduced = Some(s.to_owned());
                            }
                            if event.get("limit").is_some() {
                                // A limit ends knowledge, not necessarily the vulnerable interval.
                                // Omit this range rather than turning it into an unbounded claim.
                                introduced = None;
                            }
                            if event.get("fixed").is_some() || event.get("last_affected").is_some()
                            {
                                ranges.push(VersionRange {
                                    introduced: introduced.take(),
                                    fixed: event["fixed"].as_str().map(str::to_owned),
                                    last_affected: event["last_affected"]
                                        .as_str()
                                        .map(str::to_owned),
                                });
                            }
                        }
                    }
                    if introduced.is_some() {
                        ranges.push(VersionRange {
                            introduced,
                            fixed: None,
                            last_affected: None,
                        });
                    }
                }
            }
            let id = text(v, "id");
            out.push(Advisory {
                schema: VERSION,
                source: Source::Osv,
                source_url: format!("https://osv.dev/vulnerability/{id}"),
                id,
                fetched_at: now,
                title: text(v, "summary"),
                description: text(v, "details"),
                vendor: String::new(),
                product: text(&a["package"], "name"),
                ecosystem: a["package"]["ecosystem"].as_str().map(str::to_owned),
                ranges,
                exact_versions: a["versions"]
                    .as_array()
                    .map(|x| {
                        x.iter()
                            .filter_map(Value::as_str)
                            .take(10000)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                exploited: false,
                epss: None,
                remediation: "Consult the upstream advisory and install a verified fixed release."
                    .into(),
            });
        }
    }
    Ok(out)
}

pub fn parse_nvd(bytes: &[u8], now: u64) -> Result<Vec<Advisory>, String> {
    let root = json(bytes)?;
    let rows = root["vulnerabilities"]
        .as_array()
        .ok_or("Missing NVD vulnerabilities")?;
    let mut out = vec![];
    for row in rows.iter().take(2000) {
        let v = &row["cve"];
        let id = text(v, "id");
        if !valid_cve(&id) {
            continue;
        }
        let description = v["descriptions"]
            .as_array()
            .and_then(|a| a.iter().find(|d| d["lang"] == "en"))
            .map(|d| text(d, "value"))
            .unwrap_or_default();
        // Confirm only a simple OR of desktop application versions with no environment
        // constraints. Complex CPE logic remains a research candidate.
        let configs = v["configurations"].as_array();
        let simple = configs.is_some_and(|c| {
            c.len() == 1
                && c[0]["operator"].as_str().is_none_or(|op| op == "OR")
                && c[0]["negate"] != true
                && c[0]["nodes"].as_array().is_some_and(|nodes| {
                    nodes.len() == 1
                        && nodes[0]["operator"] == "OR"
                        && nodes[0]["negate"] != true
                        && nodes[0].get("children").is_none()
                })
        });
        fn products(v: &Value, out: &mut Vec<Value>) {
            match v {
                Value::Object(m) => {
                    if m.get("vulnerable").and_then(Value::as_bool) == Some(true)
                        && m.contains_key("criteria")
                    {
                        out.push(v.clone());
                    }
                    for x in m.values() {
                        products(x, out);
                    }
                }
                Value::Array(a) => {
                    for x in a {
                        products(x, out);
                    }
                }
                _ => {}
            }
        }
        let mut matches = vec![];
        products(&v["configurations"], &mut matches);
        let mut grouped = std::collections::BTreeMap::<(String, String), Advisory>::new();
        let mut unsupported = std::collections::BTreeSet::new();
        for m in matches {
            let criteria = text(&m, "criteria");
            let c: Vec<_> = criteria.split(':').collect();
            if c.len() != 13 {
                continue;
            }
            let vendor = c[3].to_owned();
            let product = c[4].to_owned();
            let key = (vendor.clone(), product.clone());
            let a=grouped.entry(key.clone()).or_insert_with(||Advisory{schema:VERSION,id:id.clone(),source:Source::Nvd,source_url:format!("https://nvd.nist.gov/vuln/detail/{id}"),fetched_at:now,title:id.clone(),description:description.clone(),vendor,product,ecosystem:None,ranges:vec![],exact_versions:vec![],exploited:false,epss:None,remediation:"Check the vendor advisory and install a verified fixed release. Windows update supersedence is not inferred from hotfix names.".into()});
            let known = matches!(
                (c[3], c[4]),
                ("google", "chrome")
                    | ("mozilla", "firefox")
                    | ("7-zip", "7-zip")
                    | ("videolan", "vlc_media_player")
            );
            let plain = simple
                && known
                && c[2] == "a"
                && c[6..10].iter().all(|x| *x == "*")
                && matches!(c[10], "*" | "windows")
                && c[11..].iter().all(|x| *x == "*")
                && m.get("versionStartExcluding").is_none();
            if !plain {
                unsupported.insert(key);
                continue;
            }
            a.ecosystem = Some("vendor-dotted".into());
            if c[5] != "*" && c[5] != "-" {
                a.exact_versions.push(c[5].into());
            } else if m.get("versionEndExcluding").is_some()
                || m.get("versionEndIncluding").is_some()
            {
                a.ranges.push(VersionRange {
                    introduced: m["versionStartIncluding"].as_str().map(str::to_owned),
                    fixed: m["versionEndExcluding"].as_str().map(str::to_owned),
                    last_affected: m["versionEndIncluding"].as_str().map(str::to_owned),
                });
            } else {
                unsupported.insert(key);
            }
        }
        for (key, mut a) in grouped {
            if unsupported.contains(&key) {
                a.ecosystem = None;
                a.ranges.clear();
                a.exact_versions.clear();
            }
            out.push(a);
        }
    }
    Ok(out)
}

pub fn parse_epss(bytes: &[u8]) -> Result<Vec<(String, f64)>, String> {
    let root = json(bytes)?;
    let rows = root["data"].as_array().ok_or("Missing EPSS data")?;
    rows.iter()
        .map(|v| {
            let id = text(v, "cve");
            let score = text(v, "epss").parse::<f64>().map_err(|_| "Invalid EPSS")?;
            if !valid_cve(&id) || !score.is_finite() || !(0.0..=1.0).contains(&score) {
                return Err("Invalid EPSS record".into());
            }
            Ok((id, score))
        })
        .collect()
}

pub fn parse_cve(bytes: &[u8], now: u64) -> Result<Vec<Advisory>, String> {
    let root = json(bytes)?;
    let id = text(&root["cveMetadata"], "cveId");
    if !valid_cve(&id) {
        return Err("Invalid CVE record".into());
    }
    if root["cveMetadata"]["state"].as_str() == Some("REJECTED") {
        return Ok(vec![]);
    }
    let cna = &root["containers"]["cna"];
    let description = cna["descriptions"]
        .as_array()
        .and_then(|a| a.iter().find(|d| d["lang"] == "en"))
        .map(|v| text(v, "value"))
        .unwrap_or_default();
    let Some(affected) = cna["affected"].as_array() else {
        return Ok(vec![]);
    };
    Ok(affected
        .iter()
        .take(1000)
        .map(|a| Advisory {
            schema: VERSION,
            id: id.clone(),
            source: Source::Cve,
            source_url: format!("https://www.cve.org/CVERecord?id={id}"),
            fetched_at: now,
            title: text(cna, "title"),
            description: description.clone(),
            vendor: text(a, "vendor"),
            product: text(a, "product"),
            ecosystem: None,
            ranges: vec![],
            exact_versions: vec![],
            exploited: false,
            epss: None,
            remediation:
                "Review vendor affected-version conditions and mitigation advice in the CVE record."
                    .into(),
        })
        .collect())
}

pub fn parse_msrc(bytes: &[u8], now: u64) -> Result<Vec<Advisory>, String> {
    let root = json(bytes)?;
    let records = root["Vulnerability"]
        .as_array()
        .ok_or("Missing MSRC Vulnerability list")?;
    let mut names = std::collections::BTreeMap::new();
    fn walk(v: &Value, names: &mut std::collections::BTreeMap<String, String>) {
        match v {
            Value::Object(m) => {
                if let (Some(id), Some(name)) = (
                    m.get("ProductID").and_then(Value::as_str),
                    m.get("Value").and_then(Value::as_str),
                ) {
                    names.insert(id.to_owned(), name.to_owned());
                }
                for v in m.values() {
                    walk(v, names);
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, names);
                }
            }
            _ => {}
        }
    }
    walk(&root["ProductTree"], &mut names);
    let mut out = vec![];
    for v in records.iter().take(5000) {
        let id = text(v, "CVE");
        if !valid_cve(&id) {
            continue;
        }
        let mut products = std::collections::BTreeSet::new();
        if let Some(statuses) = v["ProductStatuses"].as_array() {
            for status in statuses {
                if status["Type"].as_i64() != Some(0) {
                    continue;
                }
                if let Some(ids) = status["ProductID"].as_array() {
                    for product in ids {
                        if let Some(name) = product.as_str().and_then(|id| names.get(id)) {
                            let name = if name.starts_with("Windows 11") {
                                "Windows 11"
                            } else if name.starts_with("Windows 10") {
                                "Windows 10"
                            } else {
                                name.as_str()
                            };
                            products.insert(name.to_owned());
                        }
                    }
                }
            }
        }
        for product in products {
            out.push(Advisory{schema:VERSION,id:id.clone(),source:Source::Vendor,source_url:format!("https://msrc.microsoft.com/update-guide/vulnerability/{id}"),fetched_at:now,title:text(&v["Title"],"Value"),description:String::new(),vendor:"Microsoft".into(),product,ecosystem:None,ranges:vec![],exact_versions:vec![],exploited:false,epss:None,remediation:"Check the Microsoft Security Update Guide for the exact Windows build and superseding cumulative update.".into()});
        }
    }
    Ok(out)
}

pub fn parse_chromium_rss(bytes: &[u8], now: u64) -> Result<Vec<Advisory>, String> {
    use quick_xml::{Reader, events::Event};
    if bytes.len() > MAX_FEED {
        return Err("RSS exceeds size limit".into());
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut inside = false;
    let mut tag = String::new();
    let mut title = String::new();
    let mut link = String::new();
    let mut description = String::new();
    let mut out = vec![];
    let mut depth = 0u32;
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) => {
                depth += 1;
                if depth > 64 {
                    return Err("RSS nesting limit".into());
                }
                tag = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if tag == "item" {
                    inside = true;
                    title.clear();
                    link.clear();
                    description.clear();
                }
            }
            Event::End(e) => {
                depth = depth.saturating_sub(1);
                if e.name().as_ref() == b"item" {
                    inside = false;
                    let u = url::Url::parse(&link).map_err(|_| "Invalid RSS source link")?;
                    if u.scheme() == "https"
                        && u.host_str() == Some("chromereleases.googleblog.com")
                    {
                        out.push(Advisory{schema:VERSION,id:format!("research:{}",crate::digest(link.as_bytes())),source:Source::Research,source_url:link.clone(),fetched_at:now,title:title.clone(),description:description.chars().take(16384).collect(),vendor:"Google".into(),product:"Google Chrome".into(),ecosystem:None,ranges:vec![],exact_versions:vec![],exploited:false,epss:None,remediation:"Read the release note to verify platform, channel and affected versions. Research reporting alone does not confirm applicability.".into()});
                    }
                    if out.len() >= 50 {
                        break;
                    }
                }
                tag.clear();
            }
            Event::Text(e) if inside => {
                let value = e.decode().map_err(|e| e.to_string())?;
                match tag.as_str() {
                    "title" => title.push_str(&value),
                    "link" => link.push_str(&value),
                    "description" => description.push_str(&value),
                    _ => {}
                }
            }
            Event::CData(e) if inside && tag == "description" => {
                description.push_str(&e.decode().map_err(|e| e.to_string())?)
            }
            Event::DocType(_) => return Err("DTD/entity declarations are prohibited".into()),
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_and_oversized_rejected() {
        assert!(parse_kev(b"{}", 0).is_err());
        assert!(json(&vec![b' '; MAX_FEED + 1]).is_err());
        assert!(json(b"{\"a\":NaN}").is_err());
    }
    #[test]
    fn kev_does_not_invent_version_ranges() {
        let a = parse_kev(
            br#"{"vulnerabilities":[{"cveID":"CVE-2026-1234","product":"Widget"}]}"#,
            1,
        )
        .unwrap();
        assert!(a[0].ranges.is_empty());
        assert!(a[0].exploited);
    }
    #[test]
    fn osv_ranges() {
        let a=parse_osv(br#"{"vulns":[{"id":"GHSA-test","affected":[{"package":{"name":"x","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}]}"#,1).unwrap();
        assert_eq!(a[0].ranges[0].fixed.as_deref(), Some("1.2.0"));
    }
}
