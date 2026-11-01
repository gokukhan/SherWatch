//! Linux implementation: `ss` for per-connection TCP byte counts, nftables (iptables fallback)
//! for blocking, package ownership (dpkg / rpm) in place of code signatures, systemd and the
//! package managers for the inventory.

use super::unix::{self, Deltas};
use crate::model::{Proto, SigStatus};
use crate::state::{AppState, Dir};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub use super::unix::{
    hosts_file_path, is_admin, kill_process, path_flags, pseudo_process, quiet, relaunch_elevated, BROWSERS, DNS_SERVICES, LOLBINS, MAIL_CLIENTS, OFFICE_APPS,
    RDP_CLIENTS, SCRIPT_HOSTS, SSH_CLIENTS, SYSTEM_NAMES,
};

pub const OS_NAME: &str = "Linux";
pub const CAPTURE_BACKEND: &str = "ss";
pub const DNS_CAPTURE: bool = false;
pub const NO_PRIVILEGE_MESSAGE: &str = "Not running as root: connections and byte counts cover only your own processes, other users' processes show no owner, and firewall actions will ask for authorisation (pkexec).";
pub const DEFAULT_APPROVED_UPLOADERS: &[&str] = &["dropbox", "rclone"];

const NFT_TABLE: &str = "sherwatch";

/// `$XDG_DATA_HOME`, else `~/.local/share`.
pub fn default_data_base() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|p| p.is_absolute()) {
        return Some(x);
    }
    unix::home_dir().map(|h| h.join(".local").join("share"))
}

pub fn open_url(url: &str) {
    let _ = Command::new("xdg-open").arg(url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
}

// ---------- capture (ss) ----------

/// Polls `ss -tinpeHO` every two seconds: per TCP socket it reports bytes_sent / bytes_received
/// and the owning process, so deltas map straight onto the connection table. UDP sockets carry no
/// byte counters in ss, so UDP volume is not measured on Linux.
pub fn start_capture(state: Arc<AppState>, admin: bool) {
    if !unix::have_tool("ss") {
        let msg = "ss (iproute2) was not found: per-process byte counts are unavailable. Install iproute2.";
        tracing::warn!("{msg}");
        *state.etw_error.write() = Some(msg.into());
        return;
    }
    if !admin {
        tracing::warn!("{NO_PRIVILEGE_MESSAGE}");
    }
    std::thread::Builder::new()
        .name("ss-capture".into())
        .spawn(move || {
            let mut deltas: Deltas<(u32, u64, std::net::SocketAddr, std::net::SocketAddr)> = Deltas::default();
            let mut first = true;
            let mut failures = 0u32;
            loop {
                match Command::new("ss").args(["-tinpeHO"]).stdin(std::process::Stdio::null()).output() {
                    Ok(out) if out.status.success() => {
                        failures = 0;
                        if !state.etw_active.load(Ordering::Relaxed) {
                            state.etw_active.store(true, Ordering::Relaxed);
                            *state.etw_error.write() = None;
                            tracing::info!("ss capture started (per-connection TCP byte counts)");
                        }
                        let text = String::from_utf8_lossy(&out.stdout);
                        apply_ss(&state, &text, &mut deltas, first);
                        first = false;
                    }
                    Ok(out) => {
                        failures += 1;
                        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                        if failures == 1 || failures % 30 == 0 {
                            tracing::warn!("ss failed: {err}");
                        }
                        if failures >= 5 {
                            state.etw_active.store(false, Ordering::Relaxed);
                            *state.etw_error.write() = Some(format!("ss keeps failing: {err}"));
                        }
                    }
                    Err(e) => {
                        state.etw_active.store(false, Ordering::Relaxed);
                        *state.etw_error.write() = Some(format!("ss could not run: {e}"));
                        tracing::warn!("ss could not run: {e}");
                        return;
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        })
        .expect("spawn ss-capture thread");
}

/// One `ss -tinpeHO` line:
/// `ESTAB 0 0 10.0.0.5:43210 1.2.3.4:443 users:(("firefox",pid=1234,fd=56)) ino:12345 ... bytes_sent:1 bytes_acked:1 bytes_received:2`
fn apply_ss(state: &AppState, text: &str, deltas: &mut Deltas<(u32, u64, std::net::SocketAddr, std::net::SocketAddr)>, first: bool) {
    deltas.begin();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 || fields[0] == "LISTEN" {
            continue;
        }
        let (Some(local), Some(remote)) = (unix::parse_sockaddr(fields[3]), unix::parse_sockaddr(fields[4])) else { continue };
        if remote.ip().is_unspecified() || remote.port() == 0 {
            continue;
        }
        let mut pid = 0u32;
        let mut ino = 0u64;
        let mut sent: Option<u64> = None;
        let mut acked: Option<u64> = None;
        let mut received: Option<u64> = None;
        for f in &fields[5..] {
            if let Some(rest) = f.strip_prefix("users:(") {
                if let Some(i) = rest.find("pid=") {
                    pid = rest[i + 4..].split(|c: char| !c.is_ascii_digit()).next().and_then(|s| s.parse().ok()).unwrap_or(0);
                }
            } else if let Some(v) = f.strip_prefix("ino:") {
                ino = v.parse().unwrap_or(0);
            } else if let Some(v) = f.strip_prefix("bytes_sent:") {
                sent = v.parse().ok();
            } else if let Some(v) = f.strip_prefix("bytes_acked:") {
                acked = v.parse().ok();
            } else if let Some(v) = f.strip_prefix("bytes_received:") {
                received = v.parse().ok();
            }
        }
        let out = sent.or(acked).unwrap_or(0);
        let inn = received.unwrap_or(0);
        let (d_out, d_in) = deltas.update((pid, ino, local, remote), out, inn);
        if first {
            continue;
        }
        if d_out > 0 {
            state.record_flow(pid, Proto::Tcp, local, remote, Dir::Out, d_out.min(u32::MAX as u64) as u32);
        }
        if d_in > 0 {
            state.record_flow(pid, Proto::Tcp, local, remote, Dir::In, d_in.min(u32::MAX as u64) as u32);
        }
        if d_out + d_in > 0 {
            state.etw_events.fetch_add(1, Ordering::Relaxed);
        }
    }
    deltas.end();
}

pub fn stop_capture() {}

// ---------- firewall (nftables, iptables fallback) ----------

/// Run a shell script as root: directly when we are root, otherwise through pkexec (one prompt).
fn priv_sh(script: &str) -> Result<String, String> {
    if is_admin() {
        return unix::run("sh", &["-c", script]);
    }
    if !unix::have_tool("pkexec") {
        return Err("not running as root and pkexec is not installed; start SherWatch with sudo to use firewall actions".into());
    }
    unix::run("pkexec", &["sh", "-c", script])
}

fn use_nft() -> bool {
    unix::have_tool("nft")
}

fn nft_setup_script() -> String {
    // `nft -f` with a table declaration adds to an existing table, so the rules are only created
    // when the table does not exist yet.
    format!(
        "if ! nft list table inet {t} >/dev/null 2>&1; then nft -f - <<'EOF'\n\
table inet {t} {{\n\
  set blocked {{ type ipv4_addr; flags interval; }}\n\
  set blocked6 {{ type ipv6_addr; flags interval; }}\n\
  chain output {{ type filter hook output priority 0; policy accept; ip daddr @blocked drop; ip6 daddr @blocked6 drop; }}\n\
  chain input {{ type filter hook input priority 0; policy accept; ip saddr @blocked drop; ip6 saddr @blocked6 drop; }}\n\
}}\n\
EOF\nfi",
        t = NFT_TABLE
    )
}

fn ip_rule_name(ip: &str) -> String {
    crate::actions::rule_name("ip", ip)
}

fn set_for(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "blocked" } else { "blocked6" }
}

fn iptables_for(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "iptables" } else { "ip6tables" }
}

/// Addresses in our nft sets (or iptables rules with our comment). None without root.
fn blocked_addresses() -> Option<Vec<String>> {
    if !is_admin() {
        return None;
    }
    let mut out = vec![];
    if use_nft() {
        for set in ["blocked", "blocked6"] {
            if let Some(text) = unix::output_of("nft", &["list", "set", "inet", NFT_TABLE, set]) {
                if let Some(i) = text.find("elements") {
                    let body = text[i..].split('{').nth(1).and_then(|s| s.split('}').next()).unwrap_or("");
                    out.extend(body.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
                }
            }
        }
    } else {
        for tool in ["iptables", "ip6tables"] {
            if let Some(text) = unix::output_of(tool, &["-S", "OUTPUT"]) {
                for line in text.lines() {
                    if let Some(i) = line.find("SherWatch block ip ") {
                        let addr = line[i + "SherWatch block ip ".len()..].split('"').next().unwrap_or("").trim();
                        if !addr.is_empty() {
                            out.push(addr.to_string());
                        }
                    }
                }
            }
        }
    }
    Some(out)
}

pub fn firewall_rules() -> Option<HashSet<String>> {
    blocked_addresses().map(|v| v.iter().map(|a| ip_rule_name(a)).collect())
}

pub fn firewall_block_exe(_rule: &str, _exe: &str) -> Result<(), String> {
    Err("blocking by executable is not supported on this platform; block the address instead".into())
}

pub fn firewall_block_ip(rule: &str, ip: IpAddr) -> Result<(), String> {
    if use_nft() {
        priv_sh(&format!("{}\nnft add element inet {NFT_TABLE} {} {{ {ip} }}", nft_setup_script(), set_for(ip))).map(|_| ())
    } else if unix::have_tool("iptables") {
        let t = iptables_for(ip);
        let c = unix::sh_quote(rule);
        priv_sh(&format!("{t} -I OUTPUT -d {ip} -j DROP -m comment --comment {c} && {t} -I INPUT -s {ip} -j DROP -m comment --comment {c}")).map(|_| ())
    } else {
        Err("neither nft nor iptables is installed".into())
    }
}

pub fn firewall_unblock(rule: &str) -> Result<String, String> {
    let known = blocked_addresses().unwrap_or_default();
    let target: String = known
        .iter()
        .find(|a| ip_rule_name(a) == rule)
        .cloned()
        .or_else(|| rule.strip_prefix("SherWatch block ip ").map(str::to_string))
        .ok_or("rule not found")?;
    let ip: IpAddr = target.parse().map_err(|_| format!("cannot tell the address behind rule {rule}; remove it by hand"))?;
    if use_nft() {
        priv_sh(&format!("nft delete element inet {NFT_TABLE} {} {{ {ip} }}", set_for(ip))).map(|_| format!("{ip} removed from the nftables block set"))
    } else {
        let t = iptables_for(ip);
        let c = unix::sh_quote(rule);
        priv_sh(&format!("{t} -D OUTPUT -d {ip} -j DROP -m comment --comment {c}; {t} -D INPUT -s {ip} -j DROP -m comment --comment {c}")).map(|_| format!("{ip} rules removed from iptables"))
    }
}

// ---------- "signatures": package ownership ----------

/// Linux binaries carry no Authenticode-style signature. The closest useful fact is whether the
/// file belongs to an installed package (dpkg or rpm database), so a packaged file reports
/// `Valid` with signer "package: <name>" and anything else `NotSigned`. This is package
/// ownership, not a cryptographic check of the file itself.
pub fn verify_signatures(paths: &[String]) -> HashMap<String, (SigStatus, Option<String>)> {
    let mut out: HashMap<String, (SigStatus, Option<String>)> = HashMap::new();
    for p in paths {
        out.insert(p.to_ascii_lowercase(), (SigStatus::NotSigned, None));
    }
    if paths.is_empty() {
        return out;
    }
    let have_dpkg = unix::have_tool("dpkg");
    let have_rpm = unix::have_tool("rpm");
    for p in paths {
        // Merged-/usr systems record /usr/bin/x while the process may show /bin/x (or a symlink target).
        let mut candidates = vec![p.clone()];
        if let Ok(real) = std::fs::canonicalize(p) {
            let r = real.display().to_string();
            if r != *p {
                candidates.push(r);
            }
        }
        let mut pkg: Option<String> = None;
        for c in &candidates {
            if have_dpkg {
                if let Some(o) = unix::output_of("dpkg", &["-S", c]) {
                    pkg = o.lines().next().and_then(|l| l.split(':').next()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
                }
            }
            if pkg.is_none() && have_rpm {
                if let Some(o) = unix::output_of("rpm", &["-qf", "--qf", "%{NAME}\n", c]) {
                    pkg = o.lines().next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && !s.contains("not owned"));
                }
            }
            if pkg.is_some() {
                break;
            }
        }
        if let Some(name) = pkg {
            out.insert(p.to_ascii_lowercase(), (SigStatus::Valid, Some(format!("package: {name}"))));
        }
    }
    out
}

// ---------- inventory ----------

pub fn collect_inventory(state: &AppState, exe_paths: &[String]) -> super::RawInventory {
    let _ = state;
    let mut inv = super::RawInventory::default();
    // Services: running systemd units with their main PID and ExecStart.
    if let Some(out) = unix::output_of("systemctl", &["list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager"]) {
        let units: Vec<(String, String)> = out
            .lines()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                let unit = it.next()?.to_string();
                let desc: Vec<&str> = it.skip(3).collect();
                Some((unit, desc.join(" ")))
            })
            .collect();
        let mut pids: HashMap<String, (u32, String)> = HashMap::new();
        if !units.is_empty() {
            let mut args: Vec<&str> = vec!["show", "-p", "Id,MainPID,ExecStart", "--no-pager"];
            let names: Vec<&str> = units.iter().map(|(u, _)| u.as_str()).collect();
            args.extend(names);
            if let Some(out) = unix::output_of("systemctl", &args) {
                for block in out.split("\n\n") {
                    let mut id = String::new();
                    let mut pid = 0u32;
                    let mut exec = String::new();
                    for line in block.lines() {
                        if let Some(v) = line.strip_prefix("Id=") {
                            id = v.trim().to_string();
                        } else if let Some(v) = line.strip_prefix("MainPID=") {
                            pid = v.trim().parse().unwrap_or(0);
                        } else if let Some(v) = line.strip_prefix("ExecStart=") {
                            // "{ path=/usr/sbin/sshd ; argv[]=... }"
                            exec = v.split("path=").nth(1).and_then(|s| s.split(" ;").next()).map(|s| s.trim().to_string()).unwrap_or_default();
                        }
                    }
                    if !id.is_empty() {
                        pids.insert(id, (pid, exec));
                    }
                }
            }
        }
        for (unit, desc) in units {
            let (pid, exec) = pids.get(&unit).cloned().unwrap_or((0, String::new()));
            let name = unit.trim_end_matches(".service").to_string();
            inv.services.push(super::RawService {
                name: Some(name.clone()),
                display: Some(if desc.is_empty() { name } else { desc }),
                pid: if pid > 0 { Some(pid) } else { None },
                path: if exec.is_empty() { None } else { Some(exec) },
            });
        }
    }
    // Installed packages.
    let mut owners: HashMap<String, (String, String, String)> = HashMap::new(); // package -> (version, maintainer, source)
    if let Some(out) = unix::output_of("dpkg-query", &["-W", "-f", "${Package}\t${Version}\t${Maintainer}\n"]) {
        for line in out.lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 2 && !cols[0].is_empty() {
                owners.insert(cols[0].to_string(), (cols[1].to_string(), cols.get(2).unwrap_or(&"").to_string(), "dpkg".into()));
                inv.programs.push(super::RawProgram { name: Some(cols[0].to_string()), version: Some(cols[1].to_string()), publisher: cols.get(2).map(|s| s.to_string()) });
            }
        }
    } else if let Some(out) = unix::output_of("rpm", &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"]) {
        for line in out.lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 2 && !cols[0].is_empty() {
                owners.insert(cols[0].to_string(), (cols[1].to_string(), cols.get(2).unwrap_or(&"").to_string(), "rpm".into()));
                inv.programs.push(super::RawProgram { name: Some(cols[0].to_string()), version: Some(cols[1].to_string()), publisher: cols.get(2).map(|s| s.to_string()) });
            }
        }
    }
    if unix::have_tool("flatpak") {
        if let Some(out) = unix::output_of("flatpak", &["list", "--app", "--columns=name,version,origin"]) {
            for line in out.lines() {
                let cols: Vec<&str> = line.split('\t').collect();
                if !cols.is_empty() && !cols[0].trim().is_empty() {
                    inv.programs.push(super::RawProgram {
                        name: Some(cols[0].trim().to_string()),
                        version: cols.get(1).map(|s| s.trim().to_string()),
                        publisher: cols.get(2).map(|s| format!("flatpak: {}", s.trim())),
                    });
                }
            }
        }
    }
    // Executables: version and maintainer of the owning package.
    let mut seen: HashSet<String> = HashSet::new();
    let service_paths: Vec<String> = inv.services.iter().filter_map(|s| s.path.clone()).collect();
    let all: Vec<String> = exe_paths.iter().chain(service_paths.iter()).filter(|p| seen.insert((*p).clone())).cloned().collect();
    let pkg_of = owning_packages(&all);
    for p in &all {
        let (product, version, company) = match pkg_of.get(p).and_then(|pkg| owners.get(pkg).map(|o| (pkg.clone(), o.clone()))) {
            Some((pkg, (ver, maint, _))) => (Some(pkg), Some(ver), Some(maint)),
            None => (None, None, None),
        };
        inv.files.push(super::RawFile { path: Some(p.clone()), product, version, company, mtime: unix::mtime_iso(p) });
    }
    // OS
    let mut pretty = String::from("Linux");
    let mut version_id = String::new();
    if let Ok(body) = std::fs::read_to_string("/etc/os-release") {
        for line in body.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            let v = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "PRETTY_NAME" => pretty = v,
                "VERSION_ID" => version_id = v,
                _ => {}
            }
        }
    }
    let kernel = unix::output_of("uname", &["-r"]).map(|s| s.trim().to_string()).unwrap_or_default();
    inv.os = Some(super::RawOs {
        caption: Some(pretty),
        version: Some(if version_id.is_empty() { kernel.clone() } else { version_id }),
        build: Some(kernel.clone()),
        ubr: String::new(),
        display_version: Some(format!("kernel {kernel}")),
        last_hotfix: unix::newest_mtime_iso(&["/var/log/apt/history.log", "/var/log/dpkg.log", "/var/lib/dnf/history", "/var/log/dnf.log", "/var/log/pacman.log", "/var/log/zypp/history"]),
        last_boot: unix::boot_time_iso(),
    });
    inv
}

/// path -> owning package, from one dpkg -S / rpm -qf call over all paths.
fn owning_packages(paths: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if paths.is_empty() {
        return out;
    }
    if unix::have_tool("dpkg") {
        let mut args: Vec<&str> = vec!["-S"];
        args.extend(paths.iter().map(|s| s.as_str()));
        // dpkg -S exits non-zero when any path is unowned but still prints the owned ones.
        if let Ok(o) = Command::new("dpkg").args(&args).stdin(std::process::Stdio::null()).output() {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if let Some((pkgs, path)) = line.split_once(": ") {
                    let pkg = pkgs.split(',').next().unwrap_or("").split(':').next().unwrap_or("").trim().to_string();
                    if !pkg.is_empty() {
                        out.insert(path.trim().to_string(), pkg);
                    }
                }
            }
        }
    } else if unix::have_tool("rpm") {
        for p in paths {
            if let Some(o) = unix::output_of("rpm", &["-qf", "--qf", "%{NAME}\n", p]) {
                if let Some(name) = o.lines().next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && !s.contains("not owned")) {
                    out.insert(p.clone(), name);
                }
            }
        }
    }
    out
}

pub fn is_os_kev_entry(vendor: &str, product: &str) -> bool {
    let p = product.to_ascii_lowercase();
    vendor.eq_ignore_ascii_case("linux") && p.contains("kernel")
}
