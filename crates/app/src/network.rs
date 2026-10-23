use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    net::{IpAddr, ToSocketAddrs},
    time::Duration,
};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "feed", rename_all = "snake_case", deny_unknown_fields)]
pub enum Feed {
    Kev,
    Nvd {
        start_index: u32,
        since: u64,
        until: u64,
    },
    Epss {
        cves: Vec<String>,
    },
    Osv {
        ecosystem: String,
        package: String,
        version: String,
    },
    Cve {
        id: String,
    },
    Microsoft {
        month: String,
    },
    ChromiumResearch,
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_multicast()
                || a.is_unspecified()
                || a.is_documentation()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 192 && o[1] == 0))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            s[0] & 0xe000 == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && s[1] < 0x200)
                && !(s[0] == 0x2001 && s[1] == 0xdb8)
                && a.to_ipv4_mapped().is_none()
        }
    }
}

pub fn public_client(url: &Url) -> Result<reqwest::blocking::Client> {
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("Only HTTPS public origins are accepted");
    }
    let host = url.host_str().context("Missing hostname")?;
    let addresses: Vec<_> = (host, 443).to_socket_addrs()?.collect();
    if addresses.is_empty() || addresses.iter().any(|a| !public_ip(a.ip())) {
        bail!("Public fetch resolved to a prohibited address");
    }
    Ok(reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(45))
        .user_agent("VASP/0.1 local defensive research")
        .resolve_to_addrs(host, &addresses)
        .build()?)
}
pub fn bounded_response(response: reqwest::blocking::Response, limit: usize) -> Result<Vec<u8>> {
    let response = response.error_for_status()?;
    if response.status().is_redirection() {
        bail!("Redirects are not permitted");
    }
    if response.content_length().is_some_and(|n| n > limit as u64) {
        bail!("Response exceeds size limit");
    }
    let mut bytes = vec![];
    response.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("Response exceeds size limit");
    }
    Ok(bytes)
}
pub fn fetch(feed: &Feed) -> Result<Vec<u8>> {
    let url = match feed {
        Feed::Kev => Url::parse(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        )?,
        Feed::Nvd {
            start_index,
            since,
            until,
        } => {
            if until < since || until - since > 120 * 86400 {
                bail!("Invalid NVD time window");
            }
            let format = time::format_description::parse_borrowed::<2>(
                "[year]-[month]-[day]T[hour]:[minute]:[second].000",
            )?;
            let since =
                time::OffsetDateTime::from_unix_timestamp(*since as i64)?.format(&format)?;
            let until =
                time::OffsetDateTime::from_unix_timestamp(*until as i64)?.format(&format)?;
            let mut u = Url::parse("https://services.nvd.nist.gov/rest/json/cves/2.0")?;
            u.query_pairs_mut()
                .append_pair("resultsPerPage", "2000")
                .append_pair("startIndex", &start_index.to_string())
                .append_pair("lastModStartDate", &since)
                .append_pair("lastModEndDate", &until);
            u
        }
        Feed::Epss { cves } => {
            if cves.len() > 100 || cves.iter().any(|id| !vasp_core::feeds::valid_cve(id)) {
                bail!("Invalid CVE batch");
            }
            let mut u = Url::parse("https://api.first.org/data/v1/epss")?;
            u.query_pairs_mut().append_pair("cve", &cves.join(","));
            u
        }
        Feed::Osv { .. } => Url::parse("https://api.osv.dev/v1/query")?,
        Feed::Cve { id } => {
            if !vasp_core::feeds::valid_cve(id) {
                bail!("Invalid CVE ID");
            }
            Url::parse(&format!("https://cveawg.mitre.org/api/cve/{id}"))?
        }
        Feed::Microsoft { month } => {
            if month.len() != 8
                || !month
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                bail!("Invalid MSRC month");
            }
            Url::parse(&format!(
                "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}"
            ))?
        }
        Feed::ChromiumResearch => Url::parse("https://feeds.feedburner.com/GoogleChromeReleases")?,
    };
    let client = public_client(&url)?;
    let response = match feed {
        Feed::Osv {
            ecosystem,
            package,
            version,
        } => {
            if ecosystem.len() > 32 || package.len() > 256 || version.len() > 128 {
                bail!("Package query too large");
            }
            client.post(url).json(&serde_json::json!({"package":{"ecosystem":ecosystem,"name":package},"version":version})).send()?
        }
        _ => client
            .get(url)
            .header(
                reqwest::header::ACCEPT,
                if matches!(feed, Feed::ChromiumResearch) {
                    "application/rss+xml"
                } else {
                    "application/json"
                },
            )
            .send()?,
    };
    bounded_response(
        response,
        if matches!(feed, Feed::Microsoft { .. }) {
            vasp_core::feeds::MAX_FEED
        } else {
            16 * 1024 * 1024
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ssrf_special_ranges_rejected() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "2002:7f00:1::",
            "2001:db8::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(public_ip("1.1.1.1".parse().unwrap()));
    }
}
