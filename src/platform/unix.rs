//! Code shared by the macOS and Linux implementations: root check, sudo relaunch, kill, path flags,
//! command helpers and the rule name lists. `macos.rs` and `linux.rs` re-export what they use.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn is_admin() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Re-exec through `sudo -E` when a terminal is attached (so sudo can ask for the password).
/// Returns true when the elevated copy ran to completion; false when there is no terminal or the
/// user declined, in which case the caller carries on unprivileged.
pub fn relaunch_elevated() -> bool {
    // SAFETY: isatty only inspects the descriptor.
    let tty = unsafe { libc::isatty(0) == 1 };
    if !tty {
        return false;
    }
    let Ok(exe) = std::env::current_exe() else { return false };
    let args: Vec<String> = std::env::args().skip(1).collect();
    Command::new("sudo")
        .arg("-E")
        .arg(&exe)
        .args(&args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Nothing to hide on unix: there is no console window to suppress.
pub fn quiet(cmd: &mut Command) -> &mut Command {
    cmd
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| !p.as_os_str().is_empty())
}

/// Run a command, returning stdout on success and stdout+stderr on failure.
pub fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd).args(args).stdin(std::process::Stdio::null()).output().map_err(|e| format!("{cmd}: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!("{}{}", stdout.trim(), stderr.trim()))
    }
}

/// Stdout of a command when it succeeds, else None (tool missing or failed).
pub fn output_of(cmd: &str, args: &[&str]) -> Option<String> {
    run(cmd, args).ok()
}

/// True when the tool can be found on PATH.
pub fn have_tool(name: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    for extra in ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin"] {
        dirs.push(PathBuf::from(extra));
    }
    dirs.iter().any(|d| d.join(name).is_file())
}

/// Quote a string for a POSIX shell.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn kill_process(pid: u32) -> Result<String, String> {
    if pid <= 1 {
        return Err("refusing to terminate a core system process".into());
    }
    // SAFETY: kill with a positive pid and SIGKILL has no memory-safety concerns.
    let r = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if r == 0 {
        Ok(format!("SUCCESS: the process with PID {pid} has been terminated."))
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

/// Linux: sockets whose owner cannot be read (other users' processes without root) report pid 0.
/// macOS has its own version (nettop reports the kernel as pid 0).
#[cfg(not(target_os = "macos"))]
pub fn pseudo_process(pid: u32) -> Option<(&'static str, &'static str, &'static str)> {
    if pid == 0 { Some(("(unknown owner)", "", "")) } else { None }
}

pub fn hosts_file_path() -> String {
    "/etc/hosts".into()
}

/// Flags describing where an executable lives. The names match the Windows flags so the rules and
/// the dashboard treat them the same way.
pub fn path_flags(exe: &str) -> Vec<String> {
    let p = exe.to_string();
    let home = home_dir().map(|h| h.display().to_string()).unwrap_or_default();
    let mut f = vec![];
    if p.starts_with("/tmp/") || p.starts_with("/var/tmp/") || p.starts_with("/private/tmp/") || p.starts_with("/private/var/tmp/") || p.starts_with("/var/folders/") || p.starts_with("/private/var/folders/") || p.starts_with("/dev/shm/") || p.contains("/.cache/") {
        f.push("temp".into());
    } else if !home.is_empty() && (p.starts_with(&format!("{home}/.local/share/")) || p.starts_with(&format!("{home}/.config/")) || p.starts_with(&format!("{home}/Library/Application Support/"))) {
        f.push("appdata".into());
    }
    if p.contains("/Downloads/") { f.push("downloads".into()); }
    if p.starts_with("/Users/Shared/") { f.push("public".into()); }
    if p.contains("/.Trash/") || p.contains("/.local/share/Trash/") { f.push("recycle-bin".into()); }
    if p.contains("/Desktop/") { f.push("desktop".into()); }
    if p.starts_with("/usr/bin/") || p.starts_with("/usr/sbin/") || p.starts_with("/bin/") || p.starts_with("/sbin/") || p.starts_with("/usr/lib/") || p.starts_with("/usr/lib64/") || p.starts_with("/usr/libexec/") || p.starts_with("/System/") || p.starts_with("/Library/Apple/") {
        f.push("system".into());
    }
    if p.starts_with("/Applications/") || p.starts_with("/opt/") || p.starts_with("/usr/local/") || p.starts_with("/snap/") || p.starts_with("/var/lib/flatpak/") {
        f.push("program-files".into());
    }
    if p.ends_with(".sh") || p.ends_with(".command") || p.ends_with(".scpt") { f.push("odd-extension".into()); }
    // Executable straight in the home folder or in the file-system root.
    if !home.is_empty() && Path::new(&p).parent().map(|d| d == Path::new(&home)).unwrap_or(false) { f.push("profile-root".into()); }
    if Path::new(&p).parent().map(|d| d == Path::new("/")).unwrap_or(false) { f.push("drive-root".into()); }
    f
}

/// File modification time as RFC 3339 UTC, for the inventory.
pub fn mtime_iso(path: &str) -> Option<String> {
    let m = std::fs::metadata(path).ok()?.modified().ok()?;
    let t: chrono::DateTime<chrono::Utc> = m.into();
    Some(t.to_rfc3339())
}

/// Newest modification time among the given paths, as RFC 3339 UTC (Linux: package-manager logs).
#[cfg(not(target_os = "macos"))]
pub fn newest_mtime_iso(paths: &[&str]) -> Option<String> {
    let mut best: Option<std::time::SystemTime> = None;
    for p in paths {
        if let Ok(m) = std::fs::metadata(p).and_then(|m| m.modified()) {
            if best.map(|b| m > b).unwrap_or(true) {
                best = Some(m);
            }
        }
    }
    best.map(|m| { let t: chrono::DateTime<chrono::Utc> = m.into(); t.to_rfc3339() })
}

/// Boot time from the process table (pid 1), as RFC 3339 UTC.
pub fn boot_time_iso() -> Option<String> {
    let boot = sysinfo::System::boot_time();
    chrono::DateTime::from_timestamp(boot as i64, 0).map(|d| d.to_rfc3339())
}

/// Parse "host:port" as ss and nettop print it: "[::1]:443", "::ffff:1.2.3.4:443", "1.2.3.4:443",
/// "*:22", "127.0.0.1%lo:53". IPv4-mapped addresses come back as plain IPv4.
pub fn parse_sockaddr(s: &str) -> Option<std::net::SocketAddr> {
    let s = s.trim();
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.split('%').next().unwrap_or(host);
    let ip: std::net::IpAddr = if host == "*" || host.is_empty() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        host.parse().ok()?
    };
    Some(std::net::SocketAddr::new(crate::util::normalize_ip(ip), port))
}

/// Per-flow byte counters from the previous poll, for delta computation.
pub struct Deltas<K: std::hash::Hash + Eq> {
    last: HashMap<K, (u64, u64)>,
    seen: std::collections::HashSet<K>,
}
impl<K: std::hash::Hash + Eq> Default for Deltas<K> {
    fn default() -> Self {
        Self { last: HashMap::new(), seen: std::collections::HashSet::new() }
    }
}
impl<K: std::hash::Hash + Eq + Clone> Deltas<K> {
    pub fn begin(&mut self) {
        self.seen.clear();
    }
    /// Returns (delta_out, delta_in) for the new totals; counters that went backwards (socket reused)
    /// count from zero.
    pub fn update(&mut self, key: K, out: u64, inn: u64) -> (u64, u64) {
        self.seen.insert(key.clone());
        let (po, pi) = self.last.insert(key, (out, inn)).unwrap_or((0, 0));
        (out.saturating_sub(po), inn.saturating_sub(pi))
    }
    /// Forget flows that disappeared since `begin`.
    pub fn end(&mut self) {
        let seen = &self.seen;
        self.last.retain(|k, _| seen.contains(k));
    }
}

// ---------- name lists ----------
// Process names as sysinfo reports them: the executable's file name, no extension.

pub const LOLBINS: &[&str] = &["nc", "ncat", "netcat", "socat", "telnet", "tftp", "osascript"];

pub const SCRIPT_HOSTS: &[&str] = &["sh", "bash", "zsh", "dash", "fish", "python", "python3", "perl", "ruby", "node", "osascript", "pwsh"];

pub const OFFICE_APPS: &[&str] = &[
    "microsoft word", "microsoft excel", "microsoft powerpoint", "microsoft outlook", "soffice", "soffice.bin", "libreoffice", "pages", "numbers", "keynote", "acrobat", "adobe acrobat", "preview",
];

pub const SYSTEM_NAMES: &[&str] = &["launchd", "kernel_task", "mds", "mdworker", "systemd", "kthreadd", "sshd", "cron", "init"];

pub const BROWSERS: &[&str] = &[
    "google chrome", "google chrome helper", "chrome", "chromium", "chromium-browser", "firefox", "firefox-bin", "firefox-esr", "safari", "com.apple.webkit.networking",
    "brave browser", "brave", "brave-browser", "opera", "vivaldi", "vivaldi-bin", "microsoft edge", "msedge", "arc", "epiphany", "webkitnetworkprocess",
];
pub const MAIL_CLIENTS: &[&str] = &["mail", "microsoft outlook", "outlook", "thunderbird", "thunderbird-bin", "evolution", "geary", "mailspring", "spark", "apple mail"];
pub const DNS_SERVICES: &[&str] = &[
    "mdnsresponder", "systemd-resolve", "systemd-resolved", "dnsmasq", "unbound", "nscd", "resolved", "dnscrypt-proxy", "cloudflared", "adguard", "pihole", "nextdns",
    "stubby", "knot-resolver", "kresd", "bind", "named", "coredns", "avahi-daemon", "mullvad-daemon", "warp-svc", "tailscaled", "networkmanager",
];
pub const SSH_CLIENTS: &[&str] = &["ssh", "scp", "sftp", "git", "git-remote-https", "rsync", "mosh-client", "code", "code helper", "cyberduck", "termius"];
pub const RDP_CLIENTS: &[&str] = &["microsoft remote desktop", "windows app", "xfreerdp", "remmina", "rdesktop"];
