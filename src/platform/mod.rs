//! Operating-system layer. Everything else in the crate is platform-neutral and calls the
//! functions re-exported here; each operating system has its own file:
//!   - `windows.rs`: the original implementation (ETW, PowerShell, netsh, Authenticode), unchanged.
//!   - `unix.rs`: what macOS and Linux share (root check, sudo relaunch, data folders, kill, paths).
//!   - `macos.rs`: nettop byte counts, pf firewall, codesign, launchctl / system_profiler inventory.
//!   - `linux.rs`: ss byte counts, nftables / iptables firewall, dpkg / rpm ownership, systemd inventory.
//!
//! The public surface is the same on every platform so callers never need `cfg` attributes.

use crate::model::SigStatus;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(windows)]
mod windows;
#[cfg(unix)]
mod unix;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(unix, not(target_os = "macos")))]
mod linux;

#[cfg(windows)]
use self::windows as imp;
#[cfg(target_os = "macos")]
use self::macos as imp;
#[cfg(all(unix, not(target_os = "macos")))]
use self::linux as imp;

/// Human name of the operating system this build runs on.
pub const OS_NAME: &str = imp::OS_NAME;

/// Name of the per-process byte-count capture backend, reported in the status JSON.
pub const CAPTURE_BACKEND: &str = imp::CAPTURE_BACKEND;

/// True when the capture backend also records DNS queries (ETW DNS-Client on Windows).
pub const DNS_CAPTURE: bool = imp::DNS_CAPTURE;

/// Raw inventory as the operating system reports it, before KEV matching.
#[derive(Default)]
pub struct RawInventory {
    pub services: Vec<RawService>,
    pub programs: Vec<RawProgram>,
    pub files: Vec<RawFile>,
    pub os: Option<RawOs>,
}
pub struct RawService {
    pub name: Option<String>,
    pub display: Option<String>,
    pub pid: Option<u32>,
    pub path: Option<String>,
}
pub struct RawProgram {
    pub name: Option<String>,
    pub version: Option<String>,
    pub publisher: Option<String>,
}
pub struct RawFile {
    pub path: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub company: Option<String>,
    /// ISO-8601 / RFC 3339 UTC time of the file's last write.
    pub mtime: Option<String>,
}
pub struct RawOs {
    pub caption: Option<String>,
    pub version: Option<String>,
    pub build: Option<String>,
    pub ubr: String,
    pub display_version: Option<String>,
    pub last_hotfix: Option<String>,
    pub last_boot: Option<String>,
}

// ---------- privileges and process control ----------

/// True when the process has the rights needed for full capture (administrator / root).
pub fn is_admin() -> bool {
    imp::is_admin()
}

/// Re-launch the current executable with elevated rights. Returns true when the elevated copy ran
/// (the caller should exit); false when elevation is unavailable or was declined.
pub fn relaunch_elevated() -> bool {
    imp::relaunch_elevated()
}

/// Run an external tool without flashing a console window (Windows); no-op elsewhere.
pub fn quiet(cmd: &mut std::process::Command) -> &mut std::process::Command {
    imp::quiet(cmd)
}

/// Where an installed copy keeps its data when no config.toml sits next to the executable.
pub fn default_data_base() -> Option<PathBuf> {
    imp::default_data_base()
}

/// The message shown in the capture status when the monitor runs without elevated rights.
pub fn no_privilege_message() -> &'static str {
    imp::NO_PRIVILEGE_MESSAGE
}

/// Open a URL in the user's default browser.
pub fn open_url(url: &str) {
    imp::open_url(url)
}

pub fn kill_process(pid: u32) -> Result<String, String> {
    imp::kill_process(pid)
}

/// Processes the OS never lists the normal way (Windows pid 0 and 4): name, executable, user.
pub fn pseudo_process(pid: u32) -> Option<(&'static str, &'static str, &'static str)> {
    imp::pseudo_process(pid)
}

// ---------- capture ----------

/// Start the per-process byte-count (and, on Windows, DNS) capture. Sets `etw_active` or `etw_error`
/// on the state; never fails the start of the monitor.
pub fn start_capture(state: Arc<crate::state::AppState>, admin: bool) {
    imp::start_capture(state, admin)
}

/// Stop the capture cleanly before exit.
pub fn stop_capture() {
    imp::stop_capture()
}

// ---------- firewall ----------

/// Names of the SherWatch rules that exist in the firewall right now, or None when that cannot be
/// read without a privilege prompt (the caller then trusts its own records).
pub fn firewall_rules() -> Option<HashSet<String>> {
    imp::firewall_rules()
}

pub fn firewall_block_exe(rule: &str, exe: &str) -> Result<(), String> {
    imp::firewall_block_exe(rule, exe)
}

pub fn firewall_block_ip(rule: &str, ip: IpAddr) -> Result<(), String> {
    imp::firewall_block_ip(rule, ip)
}

pub fn firewall_unblock(rule: &str) -> Result<String, String> {
    imp::firewall_unblock(rule)
}

// ---------- files ----------

/// Code-signature status and signer for each path, keyed by the lower-cased path.
pub fn verify_signatures(paths: &[String]) -> HashMap<String, (SigStatus, Option<String>)> {
    imp::verify_signatures(paths)
}

/// Flags describing where an executable lives (temp, downloads, system, program-files...).
pub fn path_flags(exe: &str) -> Vec<String> {
    imp::path_flags(exe)
}

pub fn hosts_file_path() -> String {
    imp::hosts_file_path()
}

// ---------- inventory ----------

/// One inventory pass: running services, installed programs, details of the given executables and
/// the OS version / last update. Slow (seconds); runs on a blocking thread.
pub fn collect_inventory(state: &crate::state::AppState, exe_paths: &[String]) -> RawInventory {
    imp::collect_inventory(state, exe_paths)
}

/// True when a CISA KEV entry describes this operating system itself rather than an application.
pub fn is_os_kev_entry(vendor: &str, product: &str) -> bool {
    imp::is_os_kev_entry(vendor, product)
}

// ---------- name lists used by the rules ----------

pub const LOLBINS: &[&str] = imp::LOLBINS;
pub const SCRIPT_HOSTS: &[&str] = imp::SCRIPT_HOSTS;
pub const OFFICE_APPS: &[&str] = imp::OFFICE_APPS;
pub const SYSTEM_NAMES: &[&str] = imp::SYSTEM_NAMES;
pub const BROWSERS: &[&str] = imp::BROWSERS;
pub const MAIL_CLIENTS: &[&str] = imp::MAIL_CLIENTS;
pub const DNS_SERVICES: &[&str] = imp::DNS_SERVICES;
pub const SSH_CLIENTS: &[&str] = imp::SSH_CLIENTS;
pub const RDP_CLIENTS: &[&str] = imp::RDP_CLIENTS;
/// Programs allowed to upload freely unless config.toml says otherwise.
pub const DEFAULT_APPROVED_UPLOADERS: &[&str] = imp::DEFAULT_APPROVED_UPLOADERS;
