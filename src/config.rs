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
    #[serde(default = "d_beacon_n")]
    pub beacon_min_intervals: usize,
    #[serde(default = "d_beacon_cv")]
    pub beacon_max_cv: f64,
    #[serde(default)]
    pub watch_countries: Vec<String>,
    #[serde(default = "d_true")]
    pub reverse_dns: bool,
}
impl Default for AnalysisCfg {
    fn default() -> Self {
        Self {
            alert_cooldown_minutes: d_cooldown(),
            exfil_bytes_per_minute: d_exfil_min(),
            exfil_bytes_per_5min: d_exfil_5(),
            many_destinations_threshold: d_many(),
            beacon_min_intervals: d_beacon_n(),
            beacon_max_cv: d_beacon_cv(),
            watch_countries: vec![],
            reverse_dns: true,
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
fn d_beacon_n() -> usize { 6 }
fn d_beacon_cv() -> f64 { 0.25 }
fn d_refresh() -> u64 { 6 }
fn d_ipsum() -> u32 { 3 }
fn d_mmdb() -> String { "data/geo/dbip-city-lite.mmdb".into() }
fn d_geo_url() -> String { "https://download.db-ip.com/free/dbip-city-lite-{YYYY}-{MM}.mmdb.gz".into() }

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
