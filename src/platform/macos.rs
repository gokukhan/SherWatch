//! macOS implementation: nettop for per-process and per-connection byte counts, pf for blocking,
//! codesign for signatures, launchctl / system_profiler / sw_vers for the inventory.

use super::unix::{self, Deltas};
use crate::model::{Proto, SigStatus};
use crate::state::{AppState, Dir};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub use super::unix::{
    hosts_file_path, is_admin, kill_process, path_flags, quiet, relaunch_elevated, BROWSERS, DNS_SERVICES, LOLBINS, MAIL_CLIENTS, OFFICE_APPS, RDP_CLIENTS,
    SCRIPT_HOSTS, SSH_CLIENTS, SYSTEM_NAMES,
};

pub fn pseudo_process(pid: u32) -> Option<(&'static str, &'static str, &'static str)> {
    // nettop reports the kernel's own traffic as kernel_task with pid 0.
    if pid == 0 { Some(("kernel_task", "", "root")) } else { None }
}

pub const OS_NAME: &str = "macOS";
pub const CAPTURE_BACKEND: &str = "nettop";
pub const DNS_CAPTURE: bool = false;
pub const NO_PRIVILEGE_MESSAGE: &str = "Not running as root: byte counts cover only your own processes, other users' processes show no owner, and firewall actions will ask for an administrator password.";
pub const DEFAULT_APPROVED_UPLOADERS: &[&str] = &["onedrive", "dropbox", "google drive"];

const PF_ANCHOR: &str = "com.sherkhan.sherwatch";
const PF_TABLE: &str = "sherwatch_block";

/// `~/Library/Application Support`.
pub fn default_data_base() -> Option<PathBuf> {
    unix::home_dir().map(|h| h.join("Library").join("Application Support"))
}

pub fn open_url(url: &str) {
    let _ = Command::new("open").arg(url).spawn();
}

// ---------- capture (nettop) ----------

static NETTOP: std::sync::Mutex<Option<u32>> = std::sync::Mutex::new(None);

/// Runs `nettop` continuously in CSV log mode and feeds per-connection byte deltas to the state.
/// nettop lists every process with its sockets ("name.pid" rows followed by "tcp4 a:b<->c:d" rows);
/// connection deltas go to the flow they belong to, the remainder of a process's delta (UDP without
/// a listed socket, sockets that closed between samples) is credited to the process itself.
pub fn start_capture(state: Arc<AppState>, admin: bool) {
    if !unix::have_tool("nettop") {
        let msg = "nettop was not found: per-process byte counts are unavailable on this Mac.";
        tracing::warn!("{msg}");
        *state.etw_error.write() = Some(msg.into());
        return;
    }
    if !admin {
        tracing::warn!("{NO_PRIVILEGE_MESSAGE}");
    }
    std::thread::Builder::new()
        .name("nettop".into())
        .spawn(move || {
            let mut failures = 0;
            loop {
                match run_nettop(&state) {
                    Ok(()) => failures = 0,
                    Err(e) => {
                        failures += 1;
                        state.etw_active.store(false, Ordering::Relaxed);
                        *state.etw_error.write() = Some(format!("nettop could not run: {e}"));
                        tracing::warn!("nettop: {e}");
                        if failures >= 5 {
                            return;
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        })
        .expect("spawn nettop thread");
}

fn run_nettop(state: &AppState) -> Result<(), String> {
    let mut child = Command::new("nettop")
        .args(["-L", "0", "-s", "2", "-x", "-J", "bytes_in,bytes_out"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    *NETTOP.lock().unwrap() = Some(child.id());
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let reader = std::io::BufReader::new(stdout);
    let mut proc_deltas: Deltas<u32> = Deltas::default();
    let mut conn_deltas: Deltas<(u32, Proto, std::net::SocketAddr, std::net::SocketAddr)> = Deltas::default();
    let mut col_in = 2usize;
    let mut col_out = 3usize;
    let mut sample: Vec<(u32, Option<(Proto, std::net::SocketAddr, std::net::SocketAddr)>, u64, u64)> = vec![];
    let mut first = true;
    let mut cur_time = String::new();
    use std::io::BufRead;
    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 3 {
            continue;
        }
        if fields[0] == "time" {
            // Header line (printed once): learn where the selected columns are.
            if let Some(i) = fields.iter().position(|f| *f == "bytes_in") { col_in = i; }
            if let Some(i) = fields.iter().position(|f| *f == "bytes_out") { col_out = i; }
            if !state.etw_active.load(Ordering::Relaxed) {
                state.etw_active.store(true, Ordering::Relaxed);
                *state.etw_error.write() = None;
                tracing::info!("nettop capture started (per-process and per-connection byte counts)");
            }
            continue;
        }
        // Every row carries the sample time; a new time means a new sample, so flush the previous one.
        if fields[0] != cur_time {
            if !sample.is_empty() {
                apply_sample(state, &sample, &mut proc_deltas, &mut conn_deltas, first);
                first = false;
                sample.clear();
            }
            cur_time = fields[0].to_string();
        }
        let name = fields[1].trim();
        let bytes_in: u64 = fields.get(col_in).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let bytes_out: u64 = fields.get(col_out).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        if let Some(conn) = parse_conn(name) {
            if let Some(last) = sample.last() {
                let pid = last.0;
                sample.push((pid, Some(conn), bytes_out, bytes_in));
            }
        } else if let Some((_, pid)) = name.rsplit_once('.') {
            if let Ok(pid) = pid.parse::<u32>() {
                sample.push((pid, None, bytes_out, bytes_in));
            }
        }
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    Err(format!("exited with {status}"))
}

/// "tcp4 192.168.1.5:50000<->17.253.144.10:443" / "udp6 [::1]:5353<->*:*"
fn parse_conn(s: &str) -> Option<(Proto, std::net::SocketAddr, std::net::SocketAddr)> {
    let (kind, rest) = s.split_once(' ')?;
    let proto = if kind.starts_with("tcp") { Proto::Tcp } else if kind.starts_with("udp") { Proto::Udp } else { return None };
    let (local, remote) = rest.split_once("<->")?;
    let local = unix::parse_sockaddr(local)?;
    let remote = unix::parse_sockaddr(remote)?;
    if remote.ip().is_unspecified() || remote.port() == 0 {
        return None;
    }
    Some((proto, local, remote))
}

fn apply_sample(
    state: &AppState,
    sample: &[(u32, Option<(Proto, std::net::SocketAddr, std::net::SocketAddr)>, u64, u64)],
    proc_deltas: &mut Deltas<u32>,
    conn_deltas: &mut Deltas<(u32, Proto, std::net::SocketAddr, std::net::SocketAddr)>,
    first: bool,
) {
    proc_deltas.begin();
    conn_deltas.begin();
    let mut credited: HashMap<u32, (u64, u64)> = HashMap::new();
    let mut proc_totals: Vec<(u32, u64, u64)> = vec![];
    for (pid, conn, out, inn) in sample {
        match conn {
            Some((proto, local, remote)) => {
                let (d_out, d_in) = conn_deltas.update((*pid, *proto, *local, *remote), *out, *inn);
                if first {
                    continue;
                }
                let c = credited.entry(*pid).or_default();
                c.0 += d_out;
                c.1 += d_in;
                if d_out > 0 {
                    state.record_flow(*pid, *proto, *local, *remote, Dir::Out, d_out.min(u32::MAX as u64) as u32);
                }
                if d_in > 0 {
                    state.record_flow(*pid, *proto, *local, *remote, Dir::In, d_in.min(u32::MAX as u64) as u32);
                }
                if d_out + d_in > 0 {
                    state.etw_events.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                let (d_out, d_in) = proc_deltas.update(*pid, *out, *inn);
                if !first {
                    proc_totals.push((*pid, d_out, d_in));
                }
            }
        }
    }
    for (pid, d_out, d_in) in proc_totals {
        let (c_out, c_in) = credited.get(&pid).copied().unwrap_or((0, 0));
        let rest_out = d_out.saturating_sub(c_out);
        let rest_in = d_in.saturating_sub(c_in);
        if rest_out + rest_in > 0 {
            state.record_process_bytes(pid, rest_out, rest_in);
            state.etw_events.fetch_add(1, Ordering::Relaxed);
        }
    }
    proc_deltas.end();
    conn_deltas.end();
}

pub fn stop_capture() {
    if let Some(pid) = NETTOP.lock().unwrap().take() {
        // SAFETY: terminating the child we spawned.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    }
}

// ---------- firewall (pf) ----------

/// Run a shell script as root: directly when we are root, otherwise through an administrator
/// password prompt (one prompt for the whole script).
fn priv_sh(script: &str) -> Result<String, String> {
    if is_admin() {
        return unix::run("sh", &["-c", script]);
    }
    let apple = format!("do shell script {} with administrator privileges", osascript_quote(script));
    unix::run("osascript", &["-e", &apple])
}

fn osascript_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn anchor_file() -> PathBuf {
    let root = crate::project_root().unwrap_or_else(|| default_data_base().map(|b| b.join("SherWatch")).unwrap_or_else(|| PathBuf::from(".")));
    root.join("data").join("pf-sherwatch.conf")
}

/// The pf rules loaded into our anchor: one table, drop in both directions.
fn ensure_anchor_script() -> Result<String, String> {
    let file = anchor_file();
    let _ = std::fs::create_dir_all(file.parent().unwrap_or(&file));
    let rules = format!("table <{PF_TABLE}> persist\nblock drop quick from any to <{PF_TABLE}>\nblock drop quick from <{PF_TABLE}> to any\n");
    std::fs::write(&file, rules).map_err(|e| format!("could not write {}: {e}", file.display()))?;
    Ok(format!("pfctl -a {PF_ANCHOR} -f {} >/dev/null 2>&1; pfctl -e >/dev/null 2>&1 || true", unix::sh_quote(&file.display().to_string())))
}

fn anchor_referenced() -> bool {
    unix::output_of("pfctl", &["-sr"]).map(|o| o.contains(PF_ANCHOR)).unwrap_or(true)
}

fn ip_rule_name(ip: &str) -> String {
    crate::actions::rule_name("ip", ip)
}

pub fn firewall_rules() -> Option<HashSet<String>> {
    if !is_admin() {
        return None;
    }
    let out = unix::output_of("pfctl", &["-a", PF_ANCHOR, "-t", PF_TABLE, "-T", "show"])?;
    Some(out.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).map(ip_rule_name).collect())
}

pub fn firewall_block_exe(_rule: &str, _exe: &str) -> Result<(), String> {
    Err("blocking by executable is not supported on this platform; block the address instead".into())
}

pub fn firewall_block_ip(_rule: &str, ip: IpAddr) -> Result<(), String> {
    let load = ensure_anchor_script()?;
    priv_sh(&format!("{load}; pfctl -a {PF_ANCHOR} -t {PF_TABLE} -T add {ip}"))?;
    if is_admin() && !anchor_referenced() {
        return Err(format!("the address is in the pf table but /etc/pf.conf does not reference the anchor; add the line  anchor \"{PF_ANCHOR}\"  to /etc/pf.conf and run  sudo pfctl -f /etc/pf.conf  once"));
    }
    Ok(())
}

pub fn firewall_unblock(rule: &str) -> Result<String, String> {
    // The rule name carries the address (colons are stripped for IPv6), so match it against the table.
    let entries: Vec<String> = match unix::output_of("pfctl", &["-a", PF_ANCHOR, "-t", PF_TABLE, "-T", "show"]) {
        Some(o) => o.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
        None => vec![],
    };
    let target = entries.iter().find(|e| ip_rule_name(e) == rule).cloned().or_else(|| rule.strip_prefix("SherWatch block ip ").map(str::to_string)).ok_or("rule not found")?;
    priv_sh(&format!("pfctl -a {PF_ANCHOR} -t {PF_TABLE} -T delete {target}")).map(|_| format!("{target} removed from the pf block table"))
}

// ---------- signatures (codesign) ----------

/// `codesign -dv` says whether the file is signed and by which authority; `codesign --verify`
/// checks that the signature still matches the file.
pub fn verify_signatures(paths: &[String]) -> HashMap<String, (SigStatus, Option<String>)> {
    let mut out = HashMap::new();
    for p in paths {
        let Ok(disp) = Command::new("codesign").args(["-dv", "--verbose=2", p]).stdin(Stdio::null()).output() else { continue };
        let text = String::from_utf8_lossy(&disp.stderr).to_string() + &String::from_utf8_lossy(&disp.stdout);
        let entry = if disp.status.success() {
            let authority = text.lines().find_map(|l| l.strip_prefix("Authority=")).map(|a| a.trim().trim_start_matches("Developer ID Application: ").to_string());
            match authority {
                Some(a) => {
                    let ok = Command::new("codesign").args(["--verify", p]).stdin(Stdio::null()).output().map(|o| o.status.success()).unwrap_or(false);
                    (if ok { SigStatus::Valid } else { SigStatus::Invalid }, Some(a))
                }
                // Ad-hoc signatures (no certificate chain) are what unsigned local builds carry.
                None => (SigStatus::NotSigned, None),
            }
        } else if text.contains("not signed at all") {
            (SigStatus::NotSigned, None)
        } else {
            (SigStatus::Invalid, None)
        };
        out.insert(p.to_ascii_lowercase(), entry);
    }
    out
}

// ---------- inventory ----------

fn app_bundle(path: &str) -> Option<String> {
    let i = path.find(".app/")?;
    Some(path[..i + 4].to_string())
}

fn bundle_value(bundle: &str, key: &str) -> Option<String> {
    let plist = format!("{bundle}/Contents/Info");
    unix::output_of("defaults", &["read", &plist, key]).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub fn collect_inventory(state: &AppState, exe_paths: &[String]) -> super::RawInventory {
    let mut inv = super::RawInventory::default();
    // Services: launchctl list prints "PID\tStatus\tLabel"; "-" when not running.
    if let Some(out) = unix::output_of("launchctl", &["list"]) {
        for line in out.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 3 {
                continue;
            }
            let pid: Option<u32> = cols[0].trim().parse().ok();
            let label = cols[2].trim().to_string();
            if label.is_empty() {
                continue;
            }
            let path = pid.and_then(|p| state.procs.get(&p).map(|pr| pr.exe.clone())).filter(|e| !e.is_empty());
            inv.services.push(super::RawService { name: Some(label.clone()), display: Some(label), pid: pid.filter(|p| *p > 0), path });
        }
    }
    // Programs: system_profiler is slow (seconds) but complete.
    if let Some(out) = unix::output_of("system_profiler", &["SPApplicationsDataType", "-json"]) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&out) {
            if let Some(apps) = v["SPApplicationsDataType"].as_array() {
                for a in apps {
                    let name = a["_name"].as_str().map(str::to_string);
                    if name.is_none() {
                        continue;
                    }
                    inv.programs.push(super::RawProgram {
                        name,
                        version: a["version"].as_str().map(str::to_string),
                        publisher: a["obtained_from"].as_str().map(|s| match s { "apple" => "Apple".into(), "identified_developer" => "Identified developer".into(), "mac_app_store" => "Mac App Store".into(), other => other.to_string() }),
                    });
                }
            }
        }
    }
    // Executables: version from the enclosing .app bundle's Info.plist, when there is one.
    let mut seen: HashSet<String> = HashSet::new();
    let service_paths: Vec<String> = inv.services.iter().filter_map(|s| s.path.clone()).collect();
    for p in exe_paths.iter().chain(service_paths.iter()) {
        if !seen.insert(p.clone()) {
            continue;
        }
        let (product, version, company) = match app_bundle(p) {
            Some(b) => (
                bundle_value(&b, "CFBundleName").or_else(|| std::path::Path::new(&b).file_stem().map(|s| s.to_string_lossy().to_string())),
                bundle_value(&b, "CFBundleShortVersionString").or_else(|| bundle_value(&b, "CFBundleVersion")),
                bundle_value(&b, "CFBundleIdentifier").and_then(|id| id.split('.').nth(1).map(|s| s.to_string())),
            ),
            None => (None, None, None),
        };
        inv.files.push(super::RawFile { path: Some(p.clone()), product, version, company, mtime: unix::mtime_iso(p) });
    }
    // OS
    let mut name = String::from("macOS");
    let mut version = String::new();
    let mut build = String::new();
    if let Some(out) = unix::output_of("sw_vers", &[]) {
        for line in out.lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            match k.trim() {
                "ProductName" => name = v.trim().to_string(),
                "ProductVersion" => version = v.trim().to_string(),
                "BuildVersion" => build = v.trim().to_string(),
                _ => {}
            }
        }
    }
    inv.os = Some(super::RawOs {
        caption: Some(format!("{name} {version}").trim().to_string()),
        version: Some(version),
        build: Some(build.clone()),
        ubr: build,
        display_version: None,
        last_hotfix: last_update(),
        last_boot: unix::boot_time_iso(),
    });
    inv
}

/// Date of the last installed update: newest `<date>` in the install history, else the last line of
/// `softwareupdate --history`.
fn last_update() -> Option<String> {
    if let Ok(body) = std::fs::read_to_string("/Library/Receipts/InstallHistory.plist") {
        let mut best: Option<String> = None;
        for part in body.split("<date>").skip(1) {
            if let Some(d) = part.split("</date>").next() {
                let d = d.trim().to_string();
                if chrono::DateTime::parse_from_rfc3339(&d).is_ok() && best.as_ref().map(|b| d > *b).unwrap_or(true) {
                    best = Some(d);
                }
            }
        }
        if best.is_some() {
            return best;
        }
    }
    let out = unix::output_of("softwareupdate", &["--history"])?;
    let last = out.lines().rev().find(|l| !l.trim().is_empty())?;
    // The row ends with a locale-formatted date; try the common shapes.
    let tokens: Vec<&str> = last.split_whitespace().collect();
    for n in 1..=2 {
        if tokens.len() < n {
            break;
        }
        let tail = tokens[tokens.len() - n..].join(" ").replace(',', "");
        for fmt in ["%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y", "%d.%m.%Y"] {
            if let Ok(d) = chrono::NaiveDateTime::parse_from_str(&tail, fmt) {
                return Some(d.and_utc().to_rfc3339());
            }
            if let Ok(d) = chrono::NaiveDate::parse_from_str(&tail, fmt) {
                return Some(d.and_hms_opt(0, 0, 0)?.and_utc().to_rfc3339());
            }
        }
    }
    None
}

pub fn is_os_kev_entry(vendor: &str, product: &str) -> bool {
    let p = product.to_ascii_lowercase();
    vendor.eq_ignore_ascii_case("apple") && (p.contains("macos") || p.contains("mac os") || p == "multiple products")
}
