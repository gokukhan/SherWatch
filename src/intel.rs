//! Threat intelligence: downloads public blocklists on a schedule, keeps them on disk,
//! and answers "is this IP / domain known bad?". Feed definitions can grow at runtime:
//! extra feeds are read from data/feeds/feeds.json and from an optional remote manifest,
//! so new sources are picked up without a rebuild. Anything the parser cannot handle
//! (a new feed kind, a retired source, a newer required app version) is reported as
//! "needs app update" so the user can ask for a code change.

use crate::config::{FeedCfg, IntelCfg};
use ipnet::IpNet;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SUPPORTED_KINDS: &[&str] = &[
    "csv_ip", "ip_lines", "cidr_lines", "ipsum", "domain_lines", "url_lines", "hosts_lines", "json_ip", "kev",
];

#[derive(Debug, Clone, Serialize)]
pub struct FeedStatus {
    pub name: String,
    pub url: String,
    pub kind: String,
    pub source: String,
    pub entries: usize,
    pub updated: Option<i64>,
    pub error: Option<String>,
    pub supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Manifest {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub min_app_version: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub feeds: Vec<FeedCfg>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct UpdateStatus {
    pub app_version: String,
    pub manifest_version: String,
    pub manifest_checked: Option<i64>,
    pub update_required: bool,
    pub reasons: Vec<String>,
}

#[derive(Default)]
struct IntelData {
    ips: HashMap<IpAddr, String>,
    cidrs: Vec<(IpNet, String)>,
    domains: HashMap<String, String>,
    kev: Vec<crate::inventory::KevEntry>,
    feeds: Vec<FeedStatus>,
    last_refresh: Option<i64>,
    update: UpdateStatus,
}

pub struct Intel {
    cfg: IntelCfg,
    dir: PathBuf,
    data: RwLock<IntelData>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntelSummary {
    pub ips: usize,
    pub cidrs: usize,
    pub domains: usize,
    pub last_refresh: Option<i64>,
    pub next_refresh: Option<i64>,
    pub feeds: Vec<FeedStatus>,
    pub update: UpdateStatus,
}

impl Intel {
    pub fn new(cfg: IntelCfg, dir: PathBuf) -> Self {
        Self { cfg, dir, data: RwLock::new(IntelData::default()) }
    }

    pub fn summary(&self) -> IntelSummary {
        let d = self.data.read();
        IntelSummary {
            ips: d.ips.len(),
            cidrs: d.cidrs.len(),
            domains: d.domains.len(),
            last_refresh: d.last_refresh,
            next_refresh: d.last_refresh.map(|t| t + (self.cfg.refresh_hours * 3600 * 1000) as i64),
            feeds: d.feeds.clone(),
            update: d.update.clone(),
        }
    }

    pub fn refresh_hours(&self) -> u64 {
        self.cfg.refresh_hours.max(1)
    }

    pub fn kev_entries(&self) -> Vec<crate::inventory::KevEntry> {
        self.data.read().kev.clone()
    }

    /// Returns the feed name when the IP is listed.
    pub fn check_ip(&self, ip: &IpAddr) -> Option<String> {
        let d = self.data.read();
        if let Some(src) = d.ips.get(ip) {
            return Some(src.clone());
        }
        for (net, src) in &d.cidrs {
            if net.contains(ip) {
                return Some(src.clone());
            }
        }
        None
    }

    /// Returns the feed name when the domain (or any parent domain) is listed.
    pub fn check_domain(&self, host: &str) -> Option<String> {
        let d = self.data.read();
        if d.domains.is_empty() {
            return None;
        }
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = h.split('.').collect();
        for i in 0..labels.len().saturating_sub(1) {
            let candidate = labels[i..].join(".");
            if let Some(src) = d.domains.get(&candidate) {
                return Some(src.clone());
            }
        }
        None
    }

    fn extra_feeds_path(&self) -> PathBuf {
        self.dir.join("feeds.json")
    }

    /// All feed definitions: config.toml, then data/feeds/feeds.json, then the remote manifest.
    fn collect_feeds(&self, manifest: Option<&Manifest>) -> Vec<(FeedCfg, String)> {
        let mut out: Vec<(FeedCfg, String)> = self.cfg.feeds.iter().cloned().map(|f| (f, "config".to_string())).collect();
        if let Ok(s) = std::fs::read_to_string(self.extra_feeds_path()) {
            match serde_json::from_str::<Manifest>(&s) {
                Ok(m) => {
                    for f in m.feeds {
                        if !out.iter().any(|(e, _)| e.url == f.url) {
                            out.push((f, "feeds.json".into()));
                        }
                    }
                }
                Err(e) => tracing::warn!("feeds.json is not valid: {e}"),
            }
        }
        if let Some(m) = manifest {
            for f in &m.feeds {
                if !out.iter().any(|(e, _)| e.url == f.url) {
                    out.push((f.clone(), "manifest".into()));
                }
            }
        }
        out.into_iter().filter(|(f, _)| f.enabled).collect()
    }

    /// Load feeds from disk, downloading any that are missing or older than the refresh interval.
    pub async fn refresh(&self, force: bool) {
        self.refresh_opts(force, true).await
    }

    /// Parse whatever is on disk without touching the network (fast startup).
    pub async fn load_local(&self) {
        self.refresh_opts(false, false).await
    }

    async fn refresh_opts(&self, force: bool, download: bool) {
        std::fs::create_dir_all(&self.dir).ok();
        let client = reqwest::Client::builder()
            .user_agent("SherWatch/0.1 (local threat feed sync)")
            .timeout(std::time::Duration::from_secs(90))
            .build()
            .unwrap();
        let max_age = std::time::Duration::from_secs(self.cfg.refresh_hours * 3600);

        let mut update = UpdateStatus { app_version: APP_VERSION.into(), ..Default::default() };
        let mut manifest: Option<Manifest> = None;
        if download && !self.cfg.manifest_url.trim().is_empty() {
            update.manifest_checked = Some(crate::util::now_ms());
            match client.get(&self.cfg.manifest_url).send().await {
                Ok(r) if r.status().is_success() => match r.json::<Manifest>().await {
                    Ok(m) => {
                        update.manifest_version = m.version.clone();
                        if !m.min_app_version.is_empty() && crate::util::version_newer(&m.min_app_version, APP_VERSION) {
                            update.reasons.push(format!(
                                "Manifest requires app version {} (running {}). {}",
                                m.min_app_version,
                                APP_VERSION,
                                m.notes
                            ));
                        }
                        // Persist new feed definitions locally so they survive offline starts.
                        let _ = std::fs::write(self.extra_feeds_path(), serde_json::to_string_pretty(&m).unwrap_or_default());
                        manifest = Some(m);
                    }
                    Err(e) => update.reasons.push(format!("Manifest could not be parsed: {e}")),
                },
                Ok(r) => update.reasons.push(format!("Manifest fetch returned HTTP {}", r.status())),
                Err(e) => tracing::warn!("manifest fetch failed: {e}"),
            }
        }

        let mut new = IntelData::default();
        for (feed, source) in self.collect_feeds(manifest.as_ref()) {
            let supported = SUPPORTED_KINDS.contains(&feed.kind.as_str());
            if !supported {
                update.reasons.push(format!(
                    "Feed '{}' uses kind '{}' which this build cannot parse.",
                    feed.name, feed.kind
                ));
                new.feeds.push(FeedStatus {
                    name: feed.name.clone(),
                    url: feed.url.clone(),
                    kind: feed.kind.clone(),
                    source,
                    entries: 0,
                    updated: None,
                    error: Some("unsupported feed kind".into()),
                    supported: false,
                });
                continue;
            }
            let path = self.dir.join(&feed.file);
            let stale = match std::fs::metadata(&path).and_then(|m| m.modified()) {
                Ok(m) => m.elapsed().map(|e| e > max_age).unwrap_or(true),
                Err(_) => true,
            };
            let mut error = None;
            if download && (stale || force) {
                match client.get(&feed.url).send().await {
                    Ok(resp) if resp.status().is_success() => match resp.text().await {
                        Ok(body) => {
                            if body.trim_start().starts_with("<!DOCTYPE") || body.trim_start().starts_with("<html") {
                                error = Some("source returned an HTML page instead of data".into());
                            } else if let Err(e) = std::fs::write(&path, &body) {
                                error = Some(format!("write failed: {e}"));
                            }
                        }
                        Err(e) => error = Some(format!("read failed: {e}")),
                    },
                    Ok(resp) => {
                        let code = resp.status().as_u16();
                        error = Some(format!("HTTP {code}"));
                        if matches!(code, 404 | 410 | 401 | 403) {
                            update.reasons.push(format!(
                                "Feed '{}' returned HTTP {code}; the source moved, was retired or now needs a key.",
                                feed.name
                            ));
                        }
                    }
                    Err(e) => error = Some(format!("download failed: {e}")),
                }
            }
            let (entries, parse_err) = match std::fs::read_to_string(&path) {
                Ok(body) => (parse_feed(&feed, &body, self.cfg.ipsum_min_score, &mut new), None),
                Err(e) => (0, Some(format!("no local copy: {e}"))),
            };
            let updated = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).timestamp_millis());
            new.feeds.push(FeedStatus {
                name: feed.name.clone(),
                url: feed.url.clone(),
                kind: feed.kind.clone(),
                source,
                entries,
                updated,
                error: error.or(parse_err),
                supported: true,
            });
        }
        update.update_required = !update.reasons.is_empty();
        new.update = update;
        new.last_refresh = if download { Some(crate::util::now_ms()) } else { self.data.read().last_refresh };
        tracing::info!(
            "threat intel loaded: {} IPs, {} CIDRs, {} domains from {} feeds",
            new.ips.len(),
            new.cidrs.len(),
            new.domains.len(),
            new.feeds.len()
        );
        *self.data.write() = new;
    }
}

fn parse_feed(feed: &FeedCfg, body: &str, ipsum_min: u32, out: &mut IntelData) -> usize {
    let mut n = 0;
    let name = feed.name.clone();
    match feed.kind.as_str() {
        "csv_ip" => {
            let mut col: Option<usize> = None;
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let cells: Vec<String> = line.split(',').map(|c| c.trim().trim_matches('"').to_string()).collect();
                if col.is_none() {
                    col = cells.iter().position(|c| c.eq_ignore_ascii_case(&feed.column));
                    if col.is_some() {
                        continue;
                    }
                    col = Some(cells.iter().position(|c| c.parse::<IpAddr>().is_ok()).unwrap_or(0));
                }
                if let Some(v) = col.and_then(|c| cells.get(c)) {
                    if let Ok(ip) = v.parse::<IpAddr>() {
                        out.ips.insert(ip, name.clone());
                        n += 1;
                    }
                }
            }
        }
        "ip_lines" => {
            for line in body.lines() {
                if let Ok(ip) = line.trim().parse::<IpAddr>() {
                    out.ips.insert(ip, name.clone());
                    n += 1;
                }
            }
        }
        "cidr_lines" => {
            for line in body.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with(';') || l.starts_with('#') {
                    continue;
                }
                let tok = l.split([';', ' ', '\t', ',']).next().unwrap_or("");
                if let Ok(net) = tok.parse::<IpNet>() {
                    out.cidrs.push((net, name.clone()));
                    n += 1;
                } else if let Ok(ip) = tok.parse::<IpAddr>() {
                    out.ips.insert(ip, name.clone());
                    n += 1;
                }
            }
        }
        "ipsum" => {
            for line in body.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                let mut it = l.split_whitespace();
                let (Some(ip), Some(score)) = (it.next(), it.next()) else { continue };
                let score: u32 = score.parse().unwrap_or(0);
                if score >= ipsum_min {
                    if let Ok(ip) = ip.parse::<IpAddr>() {
                        out.ips.entry(ip).or_insert_with(|| format!("{name} (score {score})"));
                        n += 1;
                    }
                }
            }
        }
        "domain_lines" => {
            for line in body.lines() {
                let l = line.trim().to_ascii_lowercase();
                if l.is_empty() || l.starts_with('#') || !l.contains('.') {
                    continue;
                }
                let d = l.split_whitespace().next().unwrap_or("").to_string();
                out.domains.insert(d, name.clone());
                n += 1;
            }
        }
        "hosts_lines" => {
            // "0.0.0.0 bad.example" style lists
            for line in body.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                let mut it = l.split_whitespace();
                let (Some(_), Some(host)) = (it.next(), it.next()) else { continue };
                let host = host.to_ascii_lowercase();
                if host.contains('.') && host != "localhost.localdomain" {
                    out.domains.insert(host, name.clone());
                    n += 1;
                }
            }
        }
        "url_lines" => {
            for line in body.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                let rest = l.split("://").nth(1).unwrap_or(l);
                let host = rest.split(['/', ':', '?']).next().unwrap_or("").to_ascii_lowercase();
                if host.is_empty() {
                    continue;
                }
                if let Ok(ip) = host.parse::<IpAddr>() {
                    out.ips.insert(ip, name.clone());
                } else {
                    out.domains.insert(host, name.clone());
                }
                n += 1;
            }
        }
        "kev" => {
            let path = std::path::Path::new("");
            let _ = path;
            #[derive(serde::Deserialize)]
            struct Doc {
                vulnerabilities: Vec<crate::inventory::KevEntry>,
            }
            if let Ok(d) = serde_json::from_str::<Doc>(body) {
                n = d.vulnerabilities.len();
                out.kev = d.vulnerabilities;
            }
        }
        "json_ip" => {
            // Any JSON document: collect every string value that parses as an IP or CIDR.
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                let mut stack = vec![v];
                while let Some(v) = stack.pop() {
                    match v {
                        serde_json::Value::String(s) => {
                            if let Ok(ip) = s.parse::<IpAddr>() {
                                out.ips.insert(ip, name.clone());
                                n += 1;
                            } else if let Ok(net) = s.parse::<IpNet>() {
                                out.cidrs.push((net, name.clone()));
                                n += 1;
                            }
                        }
                        serde_json::Value::Array(a) => stack.extend(a),
                        serde_json::Value::Object(o) => stack.extend(o.into_values()),
                        _ => {}
                    }
                }
            }
        }
        other => {
            tracing::warn!("unknown feed kind {other} for {}", feed.name);
        }
    }
    n
}
