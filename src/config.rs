use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerCfg,
    #[serde(default)]
    pub analysis: AnalysisCfg,
    #[serde(default)]
    pub intel: IntelCfg,
    #[serde(default)]
    pub virustotal: VtCfg,
    #[serde(default)]
    pub geo: GeoCfg,
    #[serde(default)]
    pub vuln: VulnCfg,
    #[serde(default)]
    pub ai: AiCfg,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AiCfg {
    /// auto | ollama | openai | anthropic | off
    #[serde(default = "d_auto")]
    pub provider: String,
    /// Ollama: http://127.0.0.1:11434 (default). OpenAI-compatible: the API root, e.g. https://api.groq.com/openai
    #[serde(default)]
    pub base_url: String,
    /// Model name. Ollama: picked automatically from installed models when empty.
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub api_key: String,
}
impl Default for AiCfg {
    fn default() -> Self {
        Self { provider: d_auto(), base_url: String::new(), model: String::new(), api_key: String::new() }
    }
}
fn d_auto() -> String { "auto".into() }

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct VulnCfg {
    /// Look up CVEs for exact product versions through Shodan's free CVEDB after every
    /// inventory scan. Sends product names and version numbers (never file contents).
    /// Off by default; the dashboard has a button to run it on demand.
    #[serde(default)]
    pub online_lookup: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerCfg {
    #[serde(default = "d_bind")]
    pub bind: String,
    #[serde(default = "d_port")]
    pub port: u16,
    #[serde(default = "d_true")]
    pub open_browser: bool,
}
impl Default for ServerCfg {
    fn default() -> Self {
        Self { bind: d_bind(), port: d_port(), open_browser: true }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalysisCfg {
    #[serde(default = "d_cooldown")]
    pub alert_cooldown_minutes: u64,
    #[serde(default = "d_exfil_min")]
    pub exfil_bytes_per_minute: u64,
    #[serde(default = "d_exfil_5")]
    pub exfil_bytes_per_5min: u64,
    #[serde(default = "d_many")]
    pub many_destinations_threshold: usize,
    /// Programs allowed to upload freely (executable names, case-insensitive). Any other program that
    /// sends more than `file_upload_bytes_per_minute` to public addresses raises a critical
    /// "file leaving this PC" alert (R27).
    #[serde(default = "d_approved")]
    pub approved_uploaders: Vec<String>,
    #[serde(default = "d_file_upload")]
    pub file_upload_bytes_per_minute: u64,
    /// Upload to a file-sharing service (R28) is critical from this many bytes on one connection.
    #[serde(default = "d_sharing_min")]
    pub file_sharing_min_bytes: u64,
    /// File-sharing and paste services; a hostname matches when it equals or ends with one of these.
    #[serde(default = "d_sharing_domains")]
    pub file_sharing_domains: Vec<String>,
    #[serde(default = "d_beacon_n")]
    pub beacon_min_intervals: usize,
    #[serde(default = "d_beacon_cv")]
    pub beacon_max_cv: f64,
    #[serde(default)]
    pub watch_countries: Vec<String>,
    #[serde(default = "d_true")]
    pub reverse_dns: bool,
    /// Executables you vouch for: "path|sha256" entries written by the Trust button. Suppresses the
    /// unsigned / suspicious-path rules for that exact file; a changed file alerts again.
    #[serde(default)]
    pub trusted: Vec<String>,
}
impl Default for AnalysisCfg {
    fn default() -> Self {
        Self {
            alert_cooldown_minutes: d_cooldown(),
            exfil_bytes_per_minute: d_exfil_min(),
            exfil_bytes_per_5min: d_exfil_5(),
            many_destinations_threshold: d_many(),
            approved_uploaders: d_approved(),
            file_upload_bytes_per_minute: d_file_upload(),
            file_sharing_min_bytes: d_sharing_min(),
            file_sharing_domains: d_sharing_domains(),
            beacon_min_intervals: d_beacon_n(),
            beacon_max_cv: d_beacon_cv(),
            watch_countries: vec![],
            reverse_dns: true,
            trusted: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntelCfg {
    #[serde(default = "d_refresh")]
    pub refresh_hours: u64,
    #[serde(default = "d_ipsum")]
    pub ipsum_min_score: u32,
    /// Optional remote JSON manifest with additional feeds and the minimum app version
    /// needed for new detections. Empty disables the remote check.
    #[serde(default)]
    pub manifest_url: String,
    #[serde(default)]
    pub feeds: Vec<FeedCfg>,
}
impl Default for IntelCfg {
    fn default() -> Self {
        Self { refresh_hours: d_refresh(), ipsum_min_score: d_ipsum(), manifest_url: String::new(), feeds: vec![] }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct FeedCfg {
    pub name: String,
    pub url: String,
    /// csv_ip | ip_lines | cidr_lines | ipsum | domain_lines | url_lines | hosts_lines | json_ip
    pub kind: String,
    #[serde(default)]
    pub column: String,
    pub file: String,
    #[serde(default = "d_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct VtCfg {
    #[serde(default)]
    pub api_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeoCfg {
    #[serde(default = "d_mmdb")]
    pub mmdb: String,
    #[serde(default = "d_geo_url")]
    pub download_url: String,
    /// Your own location for the globe arcs. Leave unset to detect from your public IP.
    #[serde(default)]
    pub home_lat: Option<f64>,
    #[serde(default)]
    pub home_lon: Option<f64>,
    /// Ask api.ipify.org for the public IP once at start, then locate it with the local database.
    #[serde(default = "d_true")]
    pub detect_public_ip: bool,
}
impl Default for GeoCfg {
    fn default() -> Self {
        Self { mmdb: d_mmdb(), download_url: d_geo_url(), home_lat: None, home_lon: None, detect_public_ip: true }
    }
}

fn d_bind() -> String { "127.0.0.1".into() }
fn d_port() -> u16 { 8787 }
fn d_true() -> bool { true }
fn d_cooldown() -> u64 { 10 }
fn d_exfil_min() -> u64 { 25 * 1024 * 1024 }
fn d_exfil_5() -> u64 { 200 * 1024 * 1024 }
fn d_many() -> usize { 100 }
/// Platform default: OneDrive on Windows, the usual sync clients elsewhere. Names are compared
/// without the ".exe" suffix (see `util::name_matches`), so the shipped config.toml works everywhere.
fn d_approved() -> Vec<String> { crate::platform::DEFAULT_APPROVED_UPLOADERS.iter().map(|s| s.to_string()).collect() }
fn d_file_upload() -> u64 { 5 * 1024 * 1024 }
fn d_sharing_min() -> u64 { 256 * 1024 }
fn d_sharing_domains() -> Vec<String> {
    [
        "wetransfer.com", "we.tl", "mega.nz", "mega.io", "mega.co.nz", "dropbox.com", "dropboxusercontent.com", "box.com",
        "mediafire.com", "sendspace.com", "4shared.com", "zippyshare.com", "gofile.io", "file.io", "transfer.sh", "anonfiles.com",
        "pixeldrain.com", "catbox.moe", "filebin.net", "ufile.io", "uploadfiles.io", "fromsmash.com", "swisstransfer.com",
        "filetransfer.io", "wormhole.app", "send.vis.ee", "filemail.com", "sendgb.com", "tresorit.com", "pcloud.com", "icedrive.net",
        "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co", "privatebin.net", "api.telegram.org",
        "discord.com", "discordapp.com", "api.anonfiles.com", "bayfiles.com", "krakenfiles.com", "ddownload.com", "uptobox.com",
        "filen.io", "proton.me", "drive.proton.me", "backblaze.com", "backblazeb2.com", "s3.amazonaws.com",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn d_beacon_n() -> usize { 6 }
fn d_beacon_cv() -> f64 { 0.25 }
fn d_refresh() -> u64 { 6 }
fn d_ipsum() -> u32 { 3 }
fn d_mmdb() -> String { "data/geo/dbip-city-lite.mmdb".into() }
fn d_geo_url() -> String { "https://download.db-ip.com/free/dbip-city-lite-{YYYY}-{MM}.mmdb.gz".into() }

// ---------- editable settings (Settings page) ----------
// The page sends only the fields it changed; a missing field keeps its value. Secrets arrive as
// "(set)" when untouched. Values are validated here, applied to the live config and written back to
// config.toml with toml_edit so the comments in the file survive.

#[derive(Debug, Default, Deserialize)]
pub struct ConfigPatch {
    #[serde(default)]
    pub analysis: AnalysisPatch,
    #[serde(default)]
    pub intel: IntelPatch,
    #[serde(default)]
    pub vuln: VulnPatch,
    #[serde(default)]
    pub ai: AiPatch,
    #[serde(default)]
    pub virustotal: VtPatch,
    #[serde(default)]
    pub geo: GeoPatch,
    #[serde(default)]
    pub server: ServerPatch,
}
#[derive(Debug, Default, Deserialize)]
pub struct AnalysisPatch {
    pub alert_cooldown_minutes: Option<u64>,
    pub exfil_bytes_per_minute: Option<u64>,
    pub exfil_bytes_per_5min: Option<u64>,
    pub many_destinations_threshold: Option<usize>,
    pub approved_uploaders: Option<Vec<String>>,
    pub file_upload_bytes_per_minute: Option<u64>,
    pub file_sharing_min_bytes: Option<u64>,
    pub file_sharing_domains: Option<Vec<String>>,
    pub beacon_min_intervals: Option<usize>,
    pub beacon_max_cv: Option<f64>,
    pub watch_countries: Option<Vec<String>>,
    pub reverse_dns: Option<bool>,
}
#[derive(Debug, Default, Deserialize)]
pub struct IntelPatch {
    pub refresh_hours: Option<u64>,
    pub ipsum_min_score: Option<u32>,
}
#[derive(Debug, Default, Deserialize)]
pub struct VulnPatch {
    pub online_lookup: Option<bool>,
}
#[derive(Debug, Default, Deserialize)]
pub struct AiPatch {
    pub provider: Option<String>,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
pub struct VtPatch {
    pub api_key: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
pub struct GeoPatch {
    /// A number sets the coordinate; null or "" clears it (auto-detect again).
    pub home_lat: Option<serde_json::Value>,
    pub home_lon: Option<serde_json::Value>,
    pub detect_public_ip: Option<bool>,
}
#[derive(Debug, Default, Deserialize)]
pub struct ServerPatch {
    pub port: Option<u16>,
    pub open_browser: Option<bool>,
}

fn clean_list(v: &[String], lower: bool, upper: bool) -> Vec<String> {
    let mut out: Vec<String> = v
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| if lower { s.to_ascii_lowercase() } else if upper { s.to_ascii_uppercase() } else { s.to_string() })
        .collect();
    out.dedup();
    out
}

fn coord(v: &serde_json::Value, lo: f64, hi: f64, what: &str) -> Result<Option<f64>, String> {
    match v {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) if s.trim().is_empty() => Ok(None),
        serde_json::Value::String(s) => s.trim().parse::<f64>().map(Some).map_err(|_| format!("{what} is not a number")),
        serde_json::Value::Number(n) => Ok(n.as_f64()),
        _ => Err(format!("{what} is not a number")),
    }
    .and_then(|o| match o {
        Some(x) if x < lo || x > hi => Err(format!("{what} must be between {lo} and {hi}")),
        other => Ok(other),
    })
}

/// Apply a patch to `cfg`. Returns the "section.key" names that changed and the subset that only
/// takes effect after a restart.
pub fn apply_patch(cfg: &mut Config, p: &ConfigPatch) -> Result<(Vec<String>, Vec<String>), String> {
    let mut changed = vec![];
    let mut restart = vec![];
    macro_rules! set {
        ($key:expr, $field:expr, $val:expr) => {{
            let v = $val;
            if $field != v {
                $field = v;
                changed.push($key.to_string());
            }
        }};
    }
    fn range<T: PartialOrd + std::fmt::Display + Copy>(v: T, lo: T, hi: T, what: &str) -> Result<T, String> {
        if v < lo || v > hi {
            Err(format!("{what} must be between {lo} and {hi}"))
        } else {
            Ok(v)
        }
    }
    let a = &p.analysis;
    if let Some(v) = a.alert_cooldown_minutes { set!("analysis.alert_cooldown_minutes", cfg.analysis.alert_cooldown_minutes, range(v, 1, 1440, "alert cooldown")?); }
    if let Some(v) = a.exfil_bytes_per_minute { set!("analysis.exfil_bytes_per_minute", cfg.analysis.exfil_bytes_per_minute, range(v, 65_536, 1 << 40, "exfiltration per minute")?); }
    if let Some(v) = a.exfil_bytes_per_5min { set!("analysis.exfil_bytes_per_5min", cfg.analysis.exfil_bytes_per_5min, range(v, 65_536, 1 << 40, "exfiltration per 5 minutes")?); }
    if let Some(v) = a.many_destinations_threshold { set!("analysis.many_destinations_threshold", cfg.analysis.many_destinations_threshold, range(v, 5, 100_000, "fan-out threshold")?); }
    if let Some(v) = &a.approved_uploaders { set!("analysis.approved_uploaders", cfg.analysis.approved_uploaders, clean_list(v, true, false)); }
    if let Some(v) = a.file_upload_bytes_per_minute { set!("analysis.file_upload_bytes_per_minute", cfg.analysis.file_upload_bytes_per_minute, range(v, 65_536, 1 << 40, "file upload threshold")?); }
    if let Some(v) = a.file_sharing_min_bytes { set!("analysis.file_sharing_min_bytes", cfg.analysis.file_sharing_min_bytes, range(v, 1024, 1 << 40, "file-sharing threshold")?); }
    if let Some(v) = &a.file_sharing_domains { set!("analysis.file_sharing_domains", cfg.analysis.file_sharing_domains, clean_list(v, true, false)); }
    if let Some(v) = a.beacon_min_intervals { set!("analysis.beacon_min_intervals", cfg.analysis.beacon_min_intervals, range(v, 3, 1000, "beacon intervals")?); }
    if let Some(v) = a.beacon_max_cv { set!("analysis.beacon_max_cv", cfg.analysis.beacon_max_cv, range(v, 0.01, 5.0, "beacon jitter")?); }
    if let Some(v) = &a.watch_countries {
        let list = clean_list(v, false, true);
        if let Some(bad) = list.iter().find(|c| c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_alphabetic())) {
            return Err(format!("watch country \"{bad}\" is not a two-letter code"));
        }
        set!("analysis.watch_countries", cfg.analysis.watch_countries, list);
    }
    if let Some(v) = a.reverse_dns { set!("analysis.reverse_dns", cfg.analysis.reverse_dns, v); }

    if let Some(v) = p.intel.refresh_hours { set!("intel.refresh_hours", cfg.intel.refresh_hours, range(v, 1, 168, "feed refresh hours")?); }
    if let Some(v) = p.intel.ipsum_min_score { set!("intel.ipsum_min_score", cfg.intel.ipsum_min_score, range(v, 1, 10, "IPsum score")?); }
    if let Some(v) = p.vuln.online_lookup { set!("vuln.online_lookup", cfg.vuln.online_lookup, v); }

    if let Some(v) = &p.ai.provider {
        let v = v.trim().to_ascii_lowercase();
        if !["free", "ollama", "anthropic", "openai"].contains(&v.as_str()) {
            return Err("assistant provider must be free, ollama, anthropic or openai".into());
        }
        set!("ai.provider", cfg.ai.provider, v);
    }
    if let Some(v) = &p.ai.base_url { set!("ai.base_url", cfg.ai.base_url, v.trim().to_string()); }
    if let Some(v) = &p.ai.model { set!("ai.model", cfg.ai.model, v.trim().to_string()); }
    if let Some(v) = &p.ai.api_key {
        if v != "(set)" { set!("ai.api_key", cfg.ai.api_key, v.trim().to_string()); }
    }
    if let Some(v) = &p.virustotal.api_key {
        if v != "(set)" {
            set!("virustotal.api_key", cfg.virustotal.api_key, v.trim().to_string());
            if changed.last().map(|k| k == "virustotal.api_key").unwrap_or(false) {
                restart.push("virustotal.api_key".into());
            }
        }
    }
    if let Some(v) = &p.geo.home_lat { set!("geo.home_lat", cfg.geo.home_lat, coord(v, -90.0, 90.0, "home latitude")?); }
    if let Some(v) = &p.geo.home_lon { set!("geo.home_lon", cfg.geo.home_lon, coord(v, -180.0, 180.0, "home longitude")?); }
    if let Some(v) = p.geo.detect_public_ip { set!("geo.detect_public_ip", cfg.geo.detect_public_ip, v); }
    if let Some(v) = p.server.port {
        set!("server.port", cfg.server.port, range(v, 1024, 65535, "port")?);
        if changed.last().map(|k| k == "server.port").unwrap_or(false) {
            restart.push("server.port".into());
        }
    }
    if let Some(v) = p.server.open_browser { set!("server.open_browser", cfg.server.open_browser, v); }
    Ok((changed, restart))
}

/// Write the given "section.key" values of `cfg` into config.toml, keeping every comment and the
/// rest of the file as it is. Missing file: starts from the shipped default.
pub fn write_keys(path: &Path, cfg: &Config, keys: &[String]) -> Result<(), String> {
    use toml_edit::{value, Array, DocumentMut, Item};
    let text = std::fs::read_to_string(path).unwrap_or_else(|_| crate::DEFAULT_CONFIG.to_string());
    let mut doc: DocumentMut = text.parse().map_err(|e| format!("config.toml is not valid TOML: {e}"))?;
    let arr = |v: &[String]| {
        let mut a = Array::new();
        for s in v {
            a.push(s.as_str());
        }
        value(a)
    };
    for key in keys {
        let Some((sec, k)) = key.split_once('.') else { continue };
        let a = &cfg.analysis;
        let item: Option<Item> = match key.as_str() {
            "analysis.alert_cooldown_minutes" => Some(value(a.alert_cooldown_minutes as i64)),
            "analysis.exfil_bytes_per_minute" => Some(value(a.exfil_bytes_per_minute as i64)),
            "analysis.exfil_bytes_per_5min" => Some(value(a.exfil_bytes_per_5min as i64)),
            "analysis.many_destinations_threshold" => Some(value(a.many_destinations_threshold as i64)),
            "analysis.approved_uploaders" => Some(arr(&a.approved_uploaders)),
            "analysis.file_upload_bytes_per_minute" => Some(value(a.file_upload_bytes_per_minute as i64)),
            "analysis.file_sharing_min_bytes" => Some(value(a.file_sharing_min_bytes as i64)),
            "analysis.file_sharing_domains" => Some(arr(&a.file_sharing_domains)),
            "analysis.beacon_min_intervals" => Some(value(a.beacon_min_intervals as i64)),
            "analysis.beacon_max_cv" => Some(value(a.beacon_max_cv)),
            "analysis.watch_countries" => Some(arr(&a.watch_countries)),
            "analysis.reverse_dns" => Some(value(a.reverse_dns)),
            "intel.refresh_hours" => Some(value(cfg.intel.refresh_hours as i64)),
            "intel.ipsum_min_score" => Some(value(cfg.intel.ipsum_min_score as i64)),
            "vuln.online_lookup" => Some(value(cfg.vuln.online_lookup)),
            "ai.provider" => Some(value(cfg.ai.provider.as_str())),
            "ai.base_url" => Some(value(cfg.ai.base_url.as_str())),
            "ai.model" => Some(value(cfg.ai.model.as_str())),
            "ai.api_key" => Some(value(cfg.ai.api_key.as_str())),
            "virustotal.api_key" => Some(value(cfg.virustotal.api_key.as_str())),
            "geo.home_lat" => cfg.geo.home_lat.map(value),
            "geo.home_lon" => cfg.geo.home_lon.map(value),
            "geo.detect_public_ip" => Some(value(cfg.geo.detect_public_ip)),
            "server.port" => Some(value(cfg.server.port as i64)),
            "server.open_browser" => Some(value(cfg.server.open_browser)),
            _ => continue,
        };
        if !doc.contains_table(sec) {
            doc[sec] = Item::Table(toml_edit::Table::new());
        }
        match item {
            Some(mut v) => {
                // Keep the spacing and trailing comment of the old value ("5242880    # 5 MB").
                if let (Some(old), Some(new)) = (doc[sec][k].as_value(), v.as_value_mut()) {
                    *new.decor_mut() = old.decor().clone();
                }
                doc[sec][k] = v;
            }
            None => {
                if let Some(t) = doc[sec].as_table_mut() {
                    t.remove(k);
                }
            }
        }
    }
    std::fs::write(path, doc.to_string()).map_err(|e| e.to_string())
}

pub fn load(path: &Path) -> Config {
    match std::fs::read_to_string(path) {
        Ok(s) => match toml::from_str::<Config>(&s) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("config parse error in {}: {e}; using defaults", path.display());
                Config::default()
            }
        },
        Err(_) => {
            tracing::warn!("no config at {}; using defaults", path.display());
            Config::default()
        }
    }
}
