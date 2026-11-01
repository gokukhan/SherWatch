use crate::config::Config;
use crate::db::{Db, DbMsg};
use crate::geo::Geo;
use crate::intel::Intel;
use crate::model::*;
use crate::util::{self, now_ms};
use dashmap::{DashMap, DashSet};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::mpsc;
use tokio::sync::broadcast;

fn load_trusted(cfg: &[String], root: &std::path::Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for entry in cfg {
        let (exe, sha) = entry.split_once('|').unwrap_or((entry.as_str(), ""));
        map.insert(exe.trim().to_ascii_lowercase(), sha.trim().to_string());
    }
    if let Ok(s) = std::fs::read_to_string(root.join("data").join("trusted.json")) {
        if let Ok(list) = serde_json::from_str::<Vec<serde_json::Value>>(&s) {
            for v in list {
                if let Some(exe) = v["exe"].as_str() {
                    map.insert(exe.to_ascii_lowercase(), v["sha256"].as_str().unwrap_or("").to_string());
                }
            }
        }
    }
    map
}

#[derive(Default, Clone)]
pub struct InventoryState {
    pub items: HashMap<String, crate::inventory::InventoryItem>,
    pub os: crate::inventory::OsInfo,
    pub last_scan: Option<i64>,
    pub scanning: bool,
    pub online_running: bool,
    pub online_progress: String,
    pub online_last: Option<i64>,
    pub kev_count: usize,
    pub pid_services: HashMap<u32, Vec<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Out,
    In,
}

/// Rolling window of DNS activity for one (pid, base domain) pair.
#[derive(Default)]
pub struct DnsWindow {
    pub events: VecDeque<(i64, String, u32, u32)>, // ts, full name, qtype, status
}

pub struct AppState {
    /// Live configuration: edited from the Settings page and written back to config.toml.
    pub cfg: RwLock<Config>,
    pub root: PathBuf,
    pub started: i64,
    pub is_admin: bool,
    pub geo: Geo,
    pub intel: Intel,
    pub db: Db,

    pub conns: DashMap<FlowKey, Connection>,
    pub procs: DashMap<u32, ProcessInfo>,
    pub exe_meta: DashMap<String, ExeMeta>,
    pub listeners: DashMap<(Proto, u16, u32), Listener>,

    pub alerts: RwLock<VecDeque<Alert>>,
    alert_seq: AtomicI64,
    cooldown: Mutex<HashMap<String, (i64, i64, i64)>>,

    pub dns: RwLock<VecDeque<DnsEvent>>,
    pub ip_to_host: DashMap<IpAddr, String>,
    pub dns_windows: DashMap<(u32, String), DnsWindow>,
    pub dns_seen_ips: DashSet<IpAddr>,

    pub series: RwLock<VecDeque<Sample>>,
    pub known_apps: DashSet<String>,
    pub local_ips: DashSet<IpAddr>,
    pub beacons: DashMap<(u32, IpAddr), VecDeque<i64>>,
    pub dst_window: DashMap<u32, VecDeque<(i64, IpAddr)>>,
    pub inbound_accepts: DashMap<u32, (u64, i64)>,
    /// Addresses of the configured file-sharing services, resolved forward in the background so R28 can
    /// match connections even when no hostname was captured (no admin, no reverse name).
    pub sharing_ips: DashMap<IpAddr, String>,

    pub ws_tx: broadcast::Sender<String>,
    pub etw_active: AtomicBool,
    pub etw_error: RwLock<Option<String>>,
    pub etw_events: AtomicU64,
    pub hosts_issues: RwLock<Vec<String>>,
    pub home: RwLock<Option<(f64, f64, String)>>,
    pub inventory: RwLock<InventoryState>,
    /// "exe|proto|port" combinations that already raised a listener alert this session.
    pub seen_listeners: DashSet<String>,
    /// True when the database knew almost no applications at startup (first run on this PC).
    pub first_run: bool,
    /// Trusted executables: lowercase path -> sha256 (from config.toml plus data/trusted.json).
    pub trusted: RwLock<HashMap<String, String>>,

    sec_out: AtomicU64,
    sec_in: AtomicU64,
    pub total_out: AtomicU64,
    pub total_in: AtomicU64,
    tick_count: AtomicU64,

    pub proc_tx: mpsc::Sender<u32>,
    pub sig_tx: mpsc::Sender<String>,
    pub rdns_tx: mpsc::Sender<IpAddr>,
    rdns_done: DashSet<IpAddr>,
}

#[derive(Serialize)]
pub struct Overview {
    pub now: i64,
    pub started: i64,
    pub is_admin: bool,
    pub etw_active: bool,
    pub etw_error: Option<String>,
    pub etw_events: u64,
    pub geo_available: bool,
    pub rate_out: u64,
    pub rate_in: u64,
    pub total_out: u64,
    pub total_in: u64,
    pub conns: usize,
    pub public_conns: usize,
    pub procs: usize,
    pub listeners: usize,
    pub alerts_by_sev: HashMap<String, usize>,
    pub unacked: usize,
    pub top: Vec<TopProc>,
    pub countries: Vec<(String, u64)>,
    pub intel_ips: usize,
    pub intel_domains: usize,
    pub update_required: bool,
    pub app_version: String,
}

#[derive(Serialize, Clone)]
pub struct TopProc {
    pub pid: u32,
    pub name: String,
    pub rate_out: f64,
    pub rate_in: f64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub risk: u32,
    pub conns: usize,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: Config,
        root: PathBuf,
        is_admin: bool,
        geo: Geo,
        intel: Intel,
        db: Db,
        proc_tx: mpsc::Sender<u32>,
        sig_tx: mpsc::Sender<String>,
        rdns_tx: mpsc::Sender<IpAddr>,
    ) -> Self {
        let (ws_tx, _) = broadcast::channel(512);
        let known = DashSet::new();
        for k in db.load_known_apps() {
            known.insert(k.exe.to_ascii_lowercase());
        }
        let first_run = known.len() < 10;
        let recent = db.load_recent_alerts(500);
        let seq = db.next_alert_id();
        let cfg_trusted = cfg.analysis.trusted.clone();
        let root_for_trusted = root.clone();
        let mut alerts = VecDeque::new();
        for a in recent.into_iter().rev() {
            alerts.push_back(a);
        }
        Self {
            cfg: RwLock::new(cfg),
            root,
            started: now_ms(),
            is_admin,
            geo,
            intel,
            db,
            conns: DashMap::new(),
            procs: DashMap::new(),
            exe_meta: DashMap::new(),
            listeners: DashMap::new(),
            alerts: RwLock::new(alerts),
            alert_seq: AtomicI64::new(seq),
            cooldown: Mutex::new(HashMap::new()),
            dns: RwLock::new(VecDeque::with_capacity(5000)),
            ip_to_host: DashMap::new(),
            dns_windows: DashMap::new(),
            dns_seen_ips: DashSet::new(),
            series: RwLock::new(VecDeque::with_capacity(600)),
            known_apps: known,
            local_ips: DashSet::new(),
            beacons: DashMap::new(),
            dst_window: DashMap::new(),
            inbound_accepts: DashMap::new(),
            sharing_ips: DashMap::new(),
            ws_tx,
            etw_active: AtomicBool::new(false),
            etw_error: RwLock::new(None),
            etw_events: AtomicU64::new(0),
            hosts_issues: RwLock::new(vec![]),
            home: RwLock::new(None),
            inventory: RwLock::new(InventoryState::default()),
            seen_listeners: DashSet::new(),
            first_run,
            trusted: RwLock::new(load_trusted(&cfg_trusted, &root_for_trusted)),
            sec_out: AtomicU64::new(0),
            sec_in: AtomicU64::new(0),
            total_out: AtomicU64::new(0),
            total_in: AtomicU64::new(0),
            tick_count: AtomicU64::new(0),
            proc_tx,
            sig_tx,
            rdns_tx,
            rdns_done: DashSet::new(),
        }
    }

    // ---------- processes ----------

    pub fn touch_process(&self, pid: u32) {
        let now = now_ms();
        let mut fresh = false;
        self.procs
            .entry(pid)
            .and_modify(|p| {
                if !p.alive && p.info_loaded && now - p.last_seen > 5_000 {
                    // Windows reused the PID for a new process: start a clean record.
                    *p = ProcessInfo::new(pid, now);
                    fresh = true;
                } else {
                    p.last_seen = now;
                    if !p.info_loaded && !p.alive {
                        // Seen again after a failed lookup: give the inspector another chance.
                        p.alive = true;
                        fresh = true;
                    }
                }
            })
            .or_insert_with(|| {
                fresh = true;
                ProcessInfo::new(pid, now)
            });
        if fresh {
            let _ = self.proc_tx.send(pid);
        }
    }

    pub fn process_name(&self, pid: u32) -> String {
        self.procs.get(&pid).map(|p| p.name.clone()).unwrap_or_default()
    }

    pub fn process_exe(&self, pid: u32) -> String {
        self.procs.get(&pid).map(|p| p.exe.clone()).unwrap_or_default()
    }

    /// Called by the process-info worker once it has resolved a PID.
    pub fn apply_process_info(
        &self,
        pid: u32,
        name: String,
        exe: String,
        cmdline: String,
        parent_pid: u32,
        parent_name: String,
        start_time: i64,
        user: String,
    ) {
        let flags = util::path_flags(&exe);
        let key = exe.to_ascii_lowercase();
        let meta = self.exe_meta.get(&key).map(|m| m.clone());
        let services = self.inventory.read().pid_services.get(&pid).cloned().unwrap_or_default();
        if let Some(mut p) = self.procs.get_mut(&pid) {
            p.name = name.clone();
            p.exe = exe.clone();
            if !services.is_empty() {
                p.services = services;
            }
            p.cmdline = cmdline;
            p.parent_pid = parent_pid;
            p.parent_name = parent_name;
            p.start_time = start_time;
            p.user = user;
            p.path_flags = flags;
            p.info_loaded = true;
            if let Some(m) = meta {
                p.meta = m;
            }
        }
        if !exe.is_empty() {
            if self.exe_meta.get(&key).is_none() {
                self.exe_meta.insert(key.clone(), ExeMeta::default());
                let _ = self.sig_tx.send(exe.clone());
            }
            if !self.known_apps.contains(&key) {
                self.known_apps.insert(key);
                let now = now_ms();
                self.db.send(DbMsg::KnownApp { exe: exe.clone(), name: name.clone(), first_seen: now });
                // Only alert when the database already had history; the first run learns quietly for an hour.
                let learning = self.first_run && now - self.started < 3_600_000;
                if !learning && now - self.started > 20_000 {
                    self.push_alert(
                        Severity::Info,
                        "R13-new-app",
                        format!("New application on the network: {name}"),
                        format!("{exe} made its first network connection on this machine."),
                        pid,
                        "",
                    );
                }
            }
        }
    }

    pub fn apply_exe_meta(&self, exe: &str, meta: ExeMeta) {
        let key = exe.to_ascii_lowercase();
        self.exe_meta.insert(key.clone(), meta.clone());
        for mut p in self.procs.iter_mut() {
            if p.exe.eq_ignore_ascii_case(exe) {
                p.meta = meta.clone();
            }
        }
    }

    pub fn mark_process_dead(&self, pid: u32) {
        if let Some(mut p) = self.procs.get_mut(&pid) {
            p.alive = false;
        }
    }

    // ---------- connections ----------

    fn enrich(&self, remote: IpAddr) -> (GeoInfo, Option<String>, Option<String>, &'static str) {
        let scope = util::ip_scope(&remote);
        if scope != "public" {
            return (GeoInfo::default(), None, None, scope);
        }
        let geo = self.geo.lookup(remote);
        let intel = self.intel.check_ip(&remote);
        let host = self.ip_to_host.get(&remote).map(|h| h.clone());
        let _ = &host;
        if host.is_none() && self.cfg.read().analysis.reverse_dns && self.rdns_done.insert(remote) {
            let _ = self.rdns_tx.send(remote);
        }
        (geo, intel, host, scope)
    }

    fn make_connection(&self, key: FlowKey, local: IpAddr, state: &str, from_etw: bool) -> Connection {
        let now = now_ms();
        let remote = key.remote.ip();
        let (geo, intel, host, scope) = self.enrich(remote);
        let mut flags = vec![];
        if intel.is_some() {
            flags.push("intel".into());
        }
        let owner = host.as_deref().and_then(util::owner_from_hostname).or_else(|| util::ip_owner(&remote));
        Connection {
            key,
            pid: key.pid,
            proto: key.proto,
            local_addr: local,
            local_port: key.local_port,
            remote_addr: remote,
            remote_port: key.remote.port(),
            state: state.to_string(),
            first_seen: now,
            last_seen: now,
            bytes_out: 0,
            bytes_in: 0,
            pkts_out: 0,
            pkts_in: 0,
            scope,
            country: geo.country,
            country_name: geo.country_name,
            city: geo.city,
            lat: geo.lat,
            lon: geo.lon,
            hostname: host,
            owner,
            intel,
            flags,
            risk: 0,
            last_table_seen: if from_etw { 0 } else { now },
            from_etw,
        }
    }

    fn on_new_connection(&self, key: &FlowKey) {
        let remote = key.remote.ip();
        self.touch_process(key.pid);
        // Connections discovered in the first seconds existed before we started: not "new" contacts.
        if now_ms() - self.started < 5_000 {
            return;
        }
        if util::is_public_ip(&remote) {
            let now = now_ms();
            let mut b = self.beacons.entry((key.pid, remote)).or_default();
            if b.back().map(|t| now - t > 500).unwrap_or(true) {
                b.push_back(now);
                while b.len() > 64 {
                    b.pop_front();
                }
            }
            let mut w = self.dst_window.entry(key.pid).or_default();
            w.push_back((now, remote));
            while w.front().map(|(t, _)| now - t > 60_000).unwrap_or(false) {
                w.pop_front();
            }
        }
    }

    /// Upsert from the OS connection table.
    pub fn upsert_table_conn(&self, pid: u32, proto: Proto, local: SocketAddr, remote: SocketAddr, state: &str) {
        if !local.ip().is_unspecified() {
            self.local_ips.insert(util::normalize_ip(local.ip()));
        }
        let key = FlowKey { pid, proto, local_port: local.port(), remote: SocketAddr::new(util::normalize_ip(remote.ip()), remote.port()) };
        let now = now_ms();
        let mut fresh = false;
        self.conns
            .entry(key)
            .and_modify(|c| {
                c.last_table_seen = now;
                c.last_seen = now;
                if c.state != state {
                    c.state = state.to_string();
                }
                if c.local_addr.is_unspecified() {
                    c.local_addr = util::normalize_ip(local.ip());
                }
            })
            .or_insert_with(|| {
                fresh = true;
                self.make_connection(key, util::normalize_ip(local.ip()), state, false)
            });
        if fresh {
            self.on_new_connection(&key);
        }
    }

    /// Upsert from an ETW send/receive event.
    pub fn record_flow(&self, pid: u32, proto: Proto, a: SocketAddr, b: SocketAddr, dir: Dir, size: u32) {
        // Decide which side is local: known local IP, else the non-public side, else `a`.
        let a_ip = util::normalize_ip(a.ip());
        let b_ip = util::normalize_ip(b.ip());
        let (local, remote) = if self.local_ips.contains(&a_ip) {
            (SocketAddr::new(a_ip, a.port()), SocketAddr::new(b_ip, b.port()))
        } else if self.local_ips.contains(&b_ip) {
            (SocketAddr::new(b_ip, b.port()), SocketAddr::new(a_ip, a.port()))
        } else if util::is_public_ip(&a_ip) && !util::is_public_ip(&b_ip) {
            (SocketAddr::new(b_ip, b.port()), SocketAddr::new(a_ip, a.port()))
        } else {
            (SocketAddr::new(a_ip, a.port()), SocketAddr::new(b_ip, b.port()))
        };
        let key = FlowKey { pid, proto, local_port: local.port(), remote };
        let now = now_ms();
        let size64 = size as u64;
        let mut fresh = false;
        {
            let mut c = self.conns.entry(key).or_insert_with(|| {
                fresh = true;
                self.make_connection(key, local.ip(), if proto == Proto::Udp { "udp" } else { "active" }, true)
            });
            c.last_seen = now;
            match dir {
                Dir::Out => {
                    c.bytes_out += size64;
                    c.pkts_out += 1;
                }
                Dir::In => {
                    c.bytes_in += size64;
                    c.pkts_in += 1;
                }
            }
        }
        if fresh {
            self.on_new_connection(&key);
        } else {
            self.touch_process(pid);
        }
        // Loopback traffic never leaves the PC (the dashboard itself, local dev servers, IPC over TCP):
        // it stays visible on the connection row but is not counted as the process's upload/download,
        // so the volume and file-exfiltration rules and the top-talker list only reflect real traffic.
        if remote.ip().is_loopback() {
            return;
        }
        if let Some(mut p) = self.procs.get_mut(&pid) {
            match dir {
                Dir::Out => {
                    p.bytes_out += size64;
                    p.sec_out += size64;
                }
                Dir::In => {
                    p.bytes_in += size64;
                    p.sec_in += size64;
                }
            }
        }
        match dir {
            Dir::Out => {
                self.sec_out.fetch_add(size64, Ordering::Relaxed);
                self.total_out.fetch_add(size64, Ordering::Relaxed);
            }
            Dir::In => {
                self.sec_in.fetch_add(size64, Ordering::Relaxed);
                self.total_in.fetch_add(size64, Ordering::Relaxed);
            }
        }
    }

    pub fn note_connect(&self, pid: u32, remote: IpAddr) {
        let remote = util::normalize_ip(remote);
        if !util::is_public_ip(&remote) {
            return;
        }
        let now = now_ms();
        let mut b = self.beacons.entry((pid, remote)).or_default();
        if b.back().map(|t| now - t > 500).unwrap_or(true) {
            b.push_back(now);
            while b.len() > 64 {
                b.pop_front();
            }
        }
    }

    pub fn note_accept(&self, pid: u32, peer: IpAddr) {
        let peer = util::normalize_ip(peer);
        if peer.is_loopback() {
            return;
        }
        let mut e = self.inbound_accepts.entry(pid).or_insert((0, 0));
        e.0 += 1;
        e.1 = now_ms();
    }

    pub fn upsert_listener(&self, pid: u32, proto: Proto, addr: IpAddr, port: u16) -> bool {
        let key = (proto, port, pid);
        if self.listeners.contains_key(&key) {
            return false;
        }
        self.touch_process(pid);
        self.listeners.insert(
            key,
            Listener { pid, process: self.process_name(pid), proto, addr: util::normalize_ip(addr), port, first_seen: now_ms() },
        );
        true
    }

    /// Remove closed connections and dead listeners. Called from the table poller.
    pub fn expire(&self, seen_listeners: &std::collections::HashSet<(Proto, u16, u32)>) {
        let now = now_ms();
        let mut closed = vec![];
        self.conns.retain(|k, c| {
            let idle = now - c.last_seen;
            let keep = if c.proto == Proto::Tcp {
                if c.last_table_seen > 0 {
                    now - c.last_table_seen < 4_000
                } else {
                    idle < 30_000
                }
            } else {
                idle < 60_000
            };
            if !keep {
                closed.push((*k, c.clone()));
            }
            keep
        });
        for (_, c) in closed {
            if c.bytes_in + c.bytes_out > 0 || c.scope == "public" {
                let name = self.process_name(c.pid);
                let exe = self.process_exe(c.pid);
                self.db.send(DbMsg::ConnClosed { conn: c, name, exe });
            }
        }
        self.listeners.retain(|k, _| seen_listeners.contains(k));
        // Processes with no connections for an hour (10 minutes once exited) are dropped from memory.
        let active: std::collections::HashSet<u32> = self.conns.iter().map(|c| c.pid).collect();
        // Live records stay an hour after their last activity; exited ones 10 minutes, or an hour when they
        // raised alerts so the drawer behind those alerts keeps its details.
        self.procs.retain(|pid, p| active.contains(pid) || now - p.last_seen < if p.alive || p.alert_count > 0 { 3_600_000 } else { 600_000 });
        self.beacons.retain(|(pid, _), v| self.procs.contains_key(pid) && v.back().map(|t| now - t < 4 * 3600_000).unwrap_or(false));
        self.dst_window.retain(|pid, w| {
            while w.front().map(|(t, _)| now - t > 60_000).unwrap_or(false) {
                w.pop_front();
            }
            self.procs.contains_key(pid) && !w.is_empty()
        });
        self.dns_windows.retain(|(pid, _), w| {
            while w.events.front().map(|(t, ..)| now - t > 300_000).unwrap_or(false) {
                w.events.pop_front();
            }
            self.procs.contains_key(pid) && !w.events.is_empty()
        });
        self.inbound_accepts.retain(|pid, (_, last)| self.procs.contains_key(pid) && now - *last < 600_000);
    }

    // ---------- DNS ----------

    pub fn record_dns(&self, mut ev: DnsEvent) {
        // The monitor's own lookups (reverse DNS for the globe and connection labels, resolving the
        // file-sharing hosts) are not the user's activity: they would dominate the DNS page and
        // the top-domains chart, so they are not recorded at all.
        if ev.pid == std::process::id() {
            return;
        }
        self.touch_process(ev.pid);
        ev.process = self.process_name(ev.pid);
        if let Some(mut p) = self.procs.get_mut(&ev.pid) {
            p.dns_count += 1;
        }
        for ip in &ev.results {
            let ip = util::normalize_ip(*ip);
            self.ip_to_host.entry(ip).or_insert_with(|| ev.query.clone());
            self.dns_seen_ips.insert(ip);
            // Back-fill hostnames on live connections.
            for mut c in self.conns.iter_mut() {
                if c.remote_addr == ip && c.hostname.is_none() {
                    c.hostname = Some(ev.query.clone());
                    if let Some(o) = util::owner_from_hostname(&ev.query) {
                        c.owner = Some(o);
                    }
                }
            }
        }
        if let Some(src) = self.intel.check_domain(&ev.query) {
            ev.flags.push("intel".into());
            self.push_alert(
                Severity::Critical,
                "R02-intel-domain",
                format!("{} resolved a known malicious domain", ev.process),
                format!("Query for {} is listed by {src}.", ev.query),
                ev.pid,
                &ev.query,
            );
        }
        let base = util::base_domain(&ev.query);
        {
            let mut w = self.dns_windows.entry((ev.pid, base)).or_default();
            w.events.push_back((ev.ts, ev.query.clone(), ev.qtype, ev.status));
            while w.events.front().map(|(t, ..)| ev.ts - t > 300_000).unwrap_or(false) {
                w.events.pop_front();
            }
        }
        self.db.send(DbMsg::Dns(ev.clone()));
        let msg = serde_json::json!({"type": "dns", "event": ev}).to_string();
        let _ = self.ws_tx.send(msg);
        let mut d = self.dns.write();
        d.push_back(ev);
        while d.len() > 5000 {
            d.pop_front();
        }
    }

    // ---------- alerts ----------

    pub fn push_alert(&self, severity: Severity, rule: &str, title: String, detail: String, pid: u32, remote: &str) -> bool {
        self.push_alert_cd(severity, rule, title, detail, pid, remote, None)
    }

    /// `cooldown` overrides the configured window (used by slow, periodic rules so they do not re-alert every scan).
    #[allow(clippy::too_many_arguments)]
    pub fn push_alert_cd(&self, severity: Severity, rule: &str, title: String, detail: String, pid: u32, remote: &str, cooldown: Option<i64>) -> bool {
        let now = now_ms();
        let process = self.process_name(pid);
        let exe = self.process_exe(pid);
        let key = format!("{rule}|{}|{remote}", if exe.is_empty() { pid.to_string() } else { exe.to_ascii_lowercase() });
        let cooldown_ms = cooldown.unwrap_or((self.cfg.read().analysis.alert_cooldown_minutes * 60_000) as i64);
        {
            let mut cd = self.cooldown.lock();
            if let Some((first, id, last_bump)) = cd.get(&key).copied() {
                if now - first < cooldown_ms {
                    // Same condition still true: count it at most once a minute, keep the original time.
                    if now - last_bump >= 60_000 {
                        let mut alerts = self.alerts.write();
                        if let Some(a) = alerts.iter_mut().find(|a| a.id == id) {
                            a.count += 1;
                            self.db.send(DbMsg::Alert(a.clone()));
                        }
                        cd.insert(key, (first, id, now));
                    }
                    return false;
                }
            }
            if cd.len() > 5000 {
                cd.retain(|_, (t, _, _)| now - *t < cooldown_ms);
            }
            let id = self.alert_seq.fetch_add(1, Ordering::SeqCst) + 1;
            cd.insert(key, (now, id, now));
            let alert = Alert {
                id,
                ts: now,
                severity,
                rule: rule.to_string(),
                title,
                detail,
                pid,
                process,
                exe,
                remote: remote.to_string(),
                count: 1,
                acked: false,
            };
            if let Some(mut p) = self.procs.get_mut(&pid) {
                p.alert_count += 1;
                p.risk = (p.risk + severity.weight()).min(100);
            }
            self.db.send(DbMsg::Alert(alert.clone()));
            let _ = self.ws_tx.send(serde_json::json!({"type": "alert", "alert": alert}).to_string());
            tracing::warn!("[{}] {} - {}", severity.as_str().to_uppercase(), alert.title, alert.detail);
            let mut alerts = self.alerts.write();
            alerts.push_back(alert);
            while alerts.len() > 2000 {
                alerts.pop_front();
            }
        }
        true
    }

    pub fn ack_alert(&self, id: i64) -> bool {
        let mut alerts = self.alerts.write();
        if let Some(a) = alerts.iter_mut().find(|a| a.id == id) {
            a.acked = true;
            self.db.send(DbMsg::Ack(id));
            return true;
        }
        false
    }

    pub fn ack_all(&self) {
        let mut alerts = self.alerts.write();
        for a in alerts.iter_mut() {
            if !a.acked {
                a.acked = true;
                self.db.send(DbMsg::Ack(a.id));
            }
        }
    }

    // ---------- per-second tick ----------

    pub fn tick(&self) {
        let now = now_ms();
        let n = self.tick_count.fetch_add(1, Ordering::Relaxed) + 1;
        let out = self.sec_out.swap(0, Ordering::Relaxed);
        let inn = self.sec_in.swap(0, Ordering::Relaxed);
        let conn_count = self.conns.len();
        let public = self.conns.iter().filter(|c| c.scope == "public").count();

        // Per-process counters: connection counts and series.
        let mut conn_by_pid: HashMap<u32, (usize, usize)> = HashMap::new();
        for c in self.conns.iter() {
            let e = conn_by_pid.entry(c.pid).or_default();
            e.0 += 1;
            if c.scope == "public" {
                e.1 += 1;
            }
        }
        let mut listen_by_pid: HashMap<u32, usize> = HashMap::new();
        for l in self.listeners.iter() {
            *listen_by_pid.entry(l.pid).or_default() += 1;
        }
        let mut top: Vec<TopProc> = vec![];
        let flush_traffic = n % 10 == 0;
        for mut p in self.procs.iter_mut() {
            let (so, si) = (p.sec_out, p.sec_in);
            p.sec_out = 0;
            p.sec_in = 0;
            p.series.push_back((so, si));
            while p.series.len() > 300 {
                p.series.pop_front();
            }
            p.rate_out = p.rate_out * 0.6 + so as f64 * 0.4;
            p.rate_in = p.rate_in * 0.6 + si as f64 * 0.4;
            let (cc, pc) = conn_by_pid.get(&p.pid).copied().unwrap_or((0, 0));
            p.conn_count = cc;
            p.public_conn_count = pc;
            p.listen_count = listen_by_pid.get(&p.pid).copied().unwrap_or(0);
            if p.risk > 0 && n % 60 == 0 {
                p.risk = p.risk.saturating_sub(1);
            }
            if flush_traffic {
                let bo: u64 = p.series.iter().rev().take(10).map(|(o, _)| *o).sum();
                let bi: u64 = p.series.iter().rev().take(10).map(|(_, i)| *i).sum();
                if bo + bi > 0 {
                    self.db.send(DbMsg::Traffic { ts: now, pid: p.pid, name: p.name.clone(), exe: p.exe.clone(), bytes_in: bi, bytes_out: bo });
                }
            }
            top.push(TopProc {
                pid: p.pid,
                name: if p.name.is_empty() { format!("pid {}", p.pid) } else { p.name.clone() },
                rate_out: p.rate_out,
                rate_in: p.rate_in,
                bytes_out: p.bytes_out,
                bytes_in: p.bytes_in,
                risk: p.risk,
                conns: cc,
            });
        }
        top.sort_by(|a, b| (b.bytes_out + b.bytes_in).cmp(&(a.bytes_out + a.bytes_in)));
        top.truncate(8);

        let alive = self.procs.iter().filter(|p| p.alive).count();
        let sample = Sample { ts: now, bytes_out: out, bytes_in: inn, conns: conn_count, procs: alive };
        {
            let mut s = self.series.write();
            s.push_back(sample.clone());
            while s.len() > 600 {
                s.pop_front();
            }
        }
        let msg = serde_json::json!({
            "type": "tick",
            "sample": sample,
            "public_conns": public,
            "top": top,
            "etw": self.etw_active.load(Ordering::Relaxed),
            "etw_events": self.etw_events.load(Ordering::Relaxed),
            "unacked": self.alerts.read().iter().filter(|a| !a.acked && a.severity > Severity::Info).count(),
        })
        .to_string();
        let _ = self.ws_tx.send(msg);
    }

    pub fn overview(&self) -> Overview {
        let series = self.series.read();
        let last: Vec<&Sample> = series.iter().rev().take(3).collect();
        let n = last.len().max(1) as u64;
        let rate_out = last.iter().map(|s| s.bytes_out).sum::<u64>() / n;
        let rate_in = last.iter().map(|s| s.bytes_in).sum::<u64>() / n;
        drop(series);
        let alerts = self.alerts.read();
        let mut by_sev: HashMap<String, usize> = HashMap::new();
        let mut unacked = 0;
        for a in alerts.iter() {
            *by_sev.entry(a.severity.as_str().to_string()).or_default() += 1;
            if !a.acked && a.severity > Severity::Info {
                unacked += 1;
            }
        }
        drop(alerts);
        let mut top: Vec<TopProc> = self
            .procs
            .iter()
            .map(|p| TopProc {
                pid: p.pid,
                name: if p.name.is_empty() { format!("pid {}", p.pid) } else { p.name.clone() },
                rate_out: p.rate_out,
                rate_in: p.rate_in,
                bytes_out: p.bytes_out,
                bytes_in: p.bytes_in,
                risk: p.risk,
                conns: p.conn_count,
            })
            .collect();
        top.sort_by(|a, b| (b.bytes_out + b.bytes_in).cmp(&(a.bytes_out + a.bytes_in)));
        top.truncate(10);
        let mut countries: HashMap<String, u64> = HashMap::new();
        let mut public = 0;
        for c in self.conns.iter() {
            if c.scope == "public" {
                public += 1;
                let k = c.country.clone().unwrap_or_else(|| "??".into());
                *countries.entry(k).or_default() += 1;
            }
        }
        let mut countries: Vec<(String, u64)> = countries.into_iter().collect();
        countries.sort_by(|a, b| b.1.cmp(&a.1));
        countries.truncate(12);
        let intel = self.intel.summary();
        Overview {
            now: now_ms(),
            started: self.started,
            is_admin: self.is_admin,
            etw_active: self.etw_active.load(Ordering::Relaxed),
            etw_error: self.etw_error.read().clone(),
            etw_events: self.etw_events.load(Ordering::Relaxed),
            geo_available: self.geo.available(),
            rate_out,
            rate_in,
            total_out: self.total_out.load(Ordering::Relaxed),
            total_in: self.total_in.load(Ordering::Relaxed),
            conns: self.conns.len(),
            public_conns: public,
            procs: self.procs.iter().filter(|p| p.alive).count(),
            listeners: self.listeners.len(),
            alerts_by_sev: by_sev,
            unacked,
            top,
            countries,
            intel_ips: intel.ips + intel.cidrs,
            intel_domains: intel.domains,
            update_required: intel.update.update_required,
            app_version: crate::intel::APP_VERSION.to_string(),
        }
    }

    /// True when the executable is on the trust list with its current hash.
    pub fn is_trusted(&self, exe: &str, sha256: Option<&str>) -> bool {
        let t = self.trusted.read();
        match t.get(&exe.to_ascii_lowercase()) {
            Some(h) if h.is_empty() => true,
            Some(h) => sha256.map(|s| s.eq_ignore_ascii_case(h)).unwrap_or(false),
            None => false,
        }
    }

    pub fn trust_exe(&self, exe: &str, sha256: &str) {
        self.trusted.write().insert(exe.to_ascii_lowercase(), sha256.to_string());
        self.save_trusted();
        // Clear the risk the trust-sensitive rules added so the process reads as clean.
        for mut p in self.procs.iter_mut() {
            if p.exe.eq_ignore_ascii_case(exe) {
                p.risk = 0;
            }
        }
    }

    pub fn untrust_exe(&self, exe: &str) {
        self.trusted.write().remove(&exe.to_ascii_lowercase());
        self.save_trusted();
    }

    fn save_trusted(&self) {
        let t = self.trusted.read();
        let list: Vec<serde_json::Value> = t.iter().map(|(k, v)| serde_json::json!({"exe": k, "sha256": v})).collect();
        let _ = std::fs::write(self.root.join("data").join("trusted.json"), serde_json::to_string_pretty(&list).unwrap_or_default());
    }

    pub fn set_hostname(&self, ip: IpAddr, host: String) {
        self.ip_to_host.entry(ip).or_insert_with(|| host.clone());
        let owner = util::owner_from_hostname(&host);
        for mut c in self.conns.iter_mut() {
            if c.remote_addr == ip && c.hostname.is_none() {
                c.hostname = Some(host.clone());
                if owner.is_some() {
                    c.owner = owner;
                }
            }
        }
    }
}
