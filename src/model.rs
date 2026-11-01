use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 10,
            Severity::High => 25,
            Severity::Critical => 60,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    pub fn parse(s: &str) -> Severity {
        match s {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}
impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// Identity of a flow. The local address is left out on purpose: UDP sockets bind to 0.0.0.0
/// while ETW reports concrete addresses, so (pid, proto, local port, remote) is the stable key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub pid: u32,
    pub proto: Proto,
    pub local_port: u16,
    pub remote: SocketAddr,
}

#[derive(Debug, Clone, Serialize)]
pub struct Connection {
    pub key: FlowKey,
    pub pid: u32,
    pub proto: Proto,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub pkts_out: u64,
    pub pkts_in: u64,
    pub scope: &'static str,
    pub country: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub hostname: Option<String>,
    pub intel: Option<String>,
    pub flags: Vec<String>,
    pub risk: u32,
    #[serde(skip)]
    pub last_table_seen: i64,
    #[serde(skip)]
    pub from_etw: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SigStatus {
    #[default]
    Pending,
    Valid,
    NotSigned,
    Invalid,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ExeMeta {
    pub sig: SigStatus,
    pub signer: Option<String>,
    pub sha256: Option<String>,
    pub size: u64,
    pub vt_positives: Option<u32>,
    pub vt_total: Option<u32>,
    pub vt_checked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub cmdline: String,
    pub parent_pid: u32,
    pub parent_name: String,
    pub start_time: i64,
    pub user: String,
    pub first_net_seen: i64,
    pub last_seen: i64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub path_flags: Vec<String>,
    pub meta: ExeMeta,
    pub risk: u32,
    pub alert_count: u32,
    pub conn_count: usize,
    pub public_conn_count: usize,
    pub listen_count: usize,
    pub dns_count: u64,
    pub rate_out: f64,
    pub rate_in: f64,
    pub alive: bool,
    /// last 300 seconds of (bytes_out, bytes_in)
    pub series: VecDeque<(u64, u64)>,
    #[serde(skip)]
    pub sec_out: u64,
    #[serde(skip)]
    pub sec_in: u64,
    #[serde(skip)]
    pub info_loaded: bool,
}

impl ProcessInfo {
    pub fn new(pid: u32, now: i64) -> Self {
        Self {
            pid,
            name: String::new(),
            exe: String::new(),
            cmdline: String::new(),
            parent_pid: 0,
            parent_name: String::new(),
            start_time: 0,
            user: String::new(),
            first_net_seen: now,
            last_seen: now,
            bytes_out: 0,
            bytes_in: 0,
            path_flags: vec![],
            meta: ExeMeta::default(),
            risk: 0,
            alert_count: 0,
            conn_count: 0,
            public_conn_count: 0,
            listen_count: 0,
            dns_count: 0,
            rate_out: 0.0,
            rate_in: 0.0,
            alive: true,
            series: VecDeque::with_capacity(300),
            sec_out: 0,
            sec_in: 0,
            info_loaded: false,
        }
    }
    /// Outbound bytes over the last `secs` seconds.
    pub fn out_last(&self, secs: usize) -> u64 {
        self.series.iter().rev().take(secs).map(|(o, _)| *o).sum::<u64>() + self.sec_out
    }
    pub fn in_last(&self, secs: usize) -> u64 {
        self.series.iter().rev().take(secs).map(|(_, i)| *i).sum::<u64>() + self.sec_in
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: i64,
    pub ts: i64,
    pub severity: Severity,
    pub rule: String,
    pub title: String,
    pub detail: String,
    pub pid: u32,
    pub process: String,
    pub exe: String,
    pub remote: String,
    pub count: u32,
    pub acked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsEvent {
    pub ts: i64,
    pub pid: u32,
    pub process: String,
    pub query: String,
    pub qtype: u32,
    pub status: u32,
    pub results: Vec<IpAddr>,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub ts: i64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub conns: usize,
    pub procs: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Listener {
    pub pid: u32,
    pub process: String,
    pub proto: Proto,
    pub addr: IpAddr,
    pub port: u16,
    pub first_seen: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}
