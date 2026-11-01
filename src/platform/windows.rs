//! Windows implementation: the code the monitor shipped with before it became cross-platform,
//! moved here unchanged. ETW (per-process bytes and DNS), PowerShell for signatures and the
//! software inventory, netsh for Windows Defender Firewall, taskkill, UAC elevation.

use crate::model::SigStatus;
use crate::state::AppState;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

pub const OS_NAME: &str = "Windows";
pub const CAPTURE_BACKEND: &str = "etw";
pub const DNS_CAPTURE: bool = true;
pub const NO_PRIVILEGE_MESSAGE: &str = "Not running as administrator: byte counts and DNS capture are unavailable.";

pub fn is_admin() -> bool {
    unsafe { ::windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

/// Re-launch the current executable with the same arguments through a UAC prompt.
pub fn relaunch_elevated() -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg_list = if args.is_empty() {
        String::new()
    } else {
        format!(
            " -ArgumentList @({})",
            args.iter().map(|a| format!("'{}'", a.replace('\'', "''"))).collect::<Vec<_>>().join(",")
        )
    };
    let cwd = std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default();
    let script = format!(
        "Start-Process -FilePath '{}' -WorkingDirectory '{}' -Verb RunAs{}",
        exe.display().to_string().replace('\'', "''"),
        cwd.replace('\'', "''"),
        arg_list
    );
    quiet(Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script]))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run an external tool (PowerShell, netsh, logman, taskkill) without flashing a console window.
/// Matters for the windowed desktop build, harmless for the console one.
pub fn quiet(cmd: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW)
}

/// `%LOCALAPPDATA%`.
pub fn default_data_base() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
}

pub fn open_url(url: &str) {
    let _ = Command::new("cmd").args(["/C", "start", "", url]).spawn();
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = quiet(Command::new(cmd).args(args).stdin(std::process::Stdio::null())).output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!("{}{}", stdout.trim(), stderr.trim()))
    }
}

pub fn kill_process(pid: u32) -> Result<String, String> {
    if pid <= 4 {
        return Err("refusing to terminate a core system process".into());
    }
    run("taskkill", &["/PID", &pid.to_string(), "/F", "/T"]).map(|s| s.trim().to_string())
}

pub fn pseudo_process(pid: u32) -> Option<(&'static str, &'static str, &'static str)> {
    match pid {
        0 => Some(("System Idle", "", "")),
        4 => Some(("System", "C:\\Windows\\System32\\ntoskrnl.exe", "SYSTEM")),
        _ => None,
    }
}

// ---------- capture (ETW) ----------

pub fn start_capture(state: Arc<AppState>, admin: bool) {
    if admin {
        crate::collectors::etw::start(state);
    } else {
        *state.etw_error.write() = Some(NO_PRIVILEGE_MESSAGE.into());
    }
}

pub fn stop_capture() {
    crate::collectors::etw::stop();
}

// ---------- firewall (netsh advfirewall) ----------

/// Names of the SherWatch rules that actually exist in Windows Firewall right now (outbound direction;
/// the inbound twin is created and deleted together with it).
pub fn firewall_rules() -> Option<HashSet<String>> {
    let mut set = HashSet::new();
    if let Ok(out) = run("netsh", &["advfirewall", "firewall", "show", "rule", "name=all", "dir=out"]) {
        for line in out.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("Rule Name:") {
                let name = rest.trim();
                if crate::actions::is_our_rule(name) {
                    set.insert(name.to_string());
                }
            }
        }
    }
    Some(set)
}

pub fn firewall_block_exe(rule: &str, exe: &str) -> Result<(), String> {
    for dir in ["out", "in"] {
        run(
            "netsh",
            &["advfirewall", "firewall", "add", "rule", &format!("name={rule}"), &format!("dir={dir}"), "action=block", &format!("program={exe}"), "enable=yes", "profile=any"],
        )?;
    }
    Ok(())
}

pub fn firewall_block_ip(rule: &str, ip: IpAddr) -> Result<(), String> {
    for dir in ["out", "in"] {
        run(
            "netsh",
            &["advfirewall", "firewall", "add", "rule", &format!("name={rule}"), &format!("dir={dir}"), "action=block", &format!("remoteip={ip}"), "enable=yes", "profile=any"],
        )?;
    }
    Ok(())
}

pub fn firewall_unblock(rule: &str) -> Result<String, String> {
    run("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={rule}")])
}

// ---------- signatures (Authenticode via PowerShell) ----------

/// Uses Get-AuthenticodeSignature so catalog-signed OS files verify correctly.
pub fn verify_signatures(paths: &[String]) -> HashMap<String, (SigStatus, Option<String>)> {
    let mut out = HashMap::new();
    if paths.is_empty() {
        return out;
    }
    let list = paths
        .iter()
        .map(|p| format!("'{}'", p.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; $p=@({list}); Get-AuthenticodeSignature -LiteralPath $p | ForEach-Object {{ [pscustomobject]@{{ Path=$_.Path; Status=$_.Status.ToString(); Signer=$(if($_.SignerCertificate){{$_.SignerCertificate.Subject}}else{{''}}) }} }} | ConvertTo-Json -Compress"
    );
    let output = quiet(
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
            .stdin(std::process::Stdio::null()),
    )
    .output();
    let Ok(output) = output else { return out };
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    if text.is_empty() {
        return out;
    }
    let parsed: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return out,
    };
    let items: Vec<serde_json::Value> = match parsed {
        serde_json::Value::Array(a) => a,
        other => vec![other],
    };
    for it in items {
        let path = it.get("Path").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let status = it.get("Status").and_then(|v| v.as_str()).unwrap_or("");
        let signer_raw = it.get("Signer").and_then(|v| v.as_str()).unwrap_or("");
        let signer = signer_raw
            .split(',')
            .map(|s| s.trim())
            .find(|s| s.starts_with("CN="))
            .map(|s| s.trim_start_matches("CN=").trim_matches('"').to_string())
            .filter(|s| !s.is_empty());
        let sig = match status {
            "Valid" => SigStatus::Valid,
            "NotSigned" => SigStatus::NotSigned,
            "HashMismatch" | "NotTrusted" | "UnknownError" | "Incompatible" | "NotSupportedFileFormat" => SigStatus::Invalid,
            _ => SigStatus::Unknown,
        };
        out.insert(path, (sig, signer));
    }
    out
}

// ---------- paths ----------

/// Flags describing where an executable lives.
pub fn path_flags(exe: &str) -> Vec<String> {
    let p = exe.replace('/', "\\").to_ascii_lowercase();
    let mut f = vec![];
    if p.contains("\\appdata\\local\\temp") { f.push("appdata-temp".into()); }
    else if p.contains("\\temp\\") || p.contains("\\tmp\\") { f.push("temp".into()); }
    else if p.contains("\\appdata\\") { f.push("appdata".into()); }
    if p.contains("\\downloads\\") { f.push("downloads".into()); }
    if p.contains("\\users\\public\\") { f.push("public".into()); }
    if p.contains("\\$recycle.bin\\") || p.contains("\\recycler\\") { f.push("recycle-bin".into()); }
    if p.contains("\\programdata\\") { f.push("programdata".into()); }
    if p.contains("\\desktop\\") { f.push("desktop".into()); }
    if p.starts_with("c:\\windows\\system32\\") || p.starts_with("c:\\windows\\syswow64\\") { f.push("system".into()); }
    else if p.starts_with("c:\\windows\\") { f.push("windows".into()); }
    if p.starts_with("c:\\program files\\") || p.starts_with("c:\\program files (x86)\\") { f.push("program-files".into()); }
    if p.contains("\\windowsapps\\") { f.push("store-app".into()); }
    if p.ends_with(".scr") || p.ends_with(".pif") || p.ends_with(".com") || p.ends_with(".bat") || p.ends_with(".cmd") { f.push("odd-extension".into()); }
    let parts: Vec<&str> = p.split('\\').collect();
    if parts.len() == 2 && !p.is_empty() { f.push("drive-root".into()); }
    if parts.len() == 4 && parts[1] == "users" { f.push("profile-root".into()); }
    f
}

pub fn hosts_file_path() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()) + "\\System32\\drivers\\etc\\hosts"
}

// ---------- inventory (one PowerShell query) ----------

#[derive(serde::Deserialize, Default)]
struct PsOut {
    #[serde(default)]
    services: Vec<PsService>,
    #[serde(default)]
    programs: Vec<PsProgram>,
    #[serde(default)]
    files: Vec<PsFile>,
    #[serde(default)]
    os: Option<PsOs>,
}
#[derive(serde::Deserialize)]
struct PsService {
    #[serde(rename = "Name", default)]
    name: Option<String>,
    #[serde(rename = "DisplayName", default)]
    display: Option<String>,
    #[serde(rename = "ProcessId", default)]
    pid: Option<u32>,
    #[serde(rename = "PathName", default)]
    path: Option<String>,
}
#[derive(serde::Deserialize)]
struct PsProgram {
    #[serde(rename = "DisplayName", default)]
    name: Option<String>,
    #[serde(rename = "DisplayVersion", default)]
    version: Option<String>,
    #[serde(rename = "Publisher", default)]
    publisher: Option<String>,
}
#[derive(serde::Deserialize)]
struct PsFile {
    #[serde(rename = "Path", default)]
    path: Option<String>,
    #[serde(rename = "Product", default)]
    product: Option<String>,
    #[serde(rename = "Version", default)]
    version: Option<String>,
    #[serde(rename = "Company", default)]
    company: Option<String>,
    #[serde(rename = "Mtime", default)]
    mtime: Option<String>,
}
#[derive(serde::Deserialize)]
struct PsOs {
    #[serde(rename = "Caption", default)]
    caption: Option<String>,
    #[serde(rename = "Version", default)]
    version: Option<String>,
    #[serde(rename = "Build", default)]
    build: Option<String>,
    #[serde(rename = "UBR", default)]
    ubr: serde_json::Value,
    #[serde(rename = "DisplayVersion", default)]
    display_version: Option<String>,
    #[serde(rename = "LastHotfix", default)]
    last_hotfix: Option<String>,
    #[serde(rename = "LastBoot", default)]
    last_boot: Option<String>,
}

fn ps_json(state: &AppState, script: &str) -> Option<serde_json::Value> {
    // The query is long and multi-line, so it runs from a file rather than the command line.
    let dir = state.root.join("data").join("logs");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("inventory-query.ps1");
    std::fs::write(&path, script).ok()?;
    let out = quiet(
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", &path.display().to_string()])
            .stdin(std::process::Stdio::null()),
    )
    .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim_start_matches('\u{feff}');
    match serde_json::from_str(text.trim()) {
        Ok(v) => Some(v),
        Err(e) => {
            let err = String::from_utf8_lossy(&out.stderr);
            tracing::warn!("inventory query returned no JSON ({e}); stdout {} bytes; stderr: {}", text.len(), crate::util::truncate(err.trim(), 600));
            None
        }
    }
}

pub fn collect_inventory(state: &AppState, exe_paths: &[String]) -> super::RawInventory {
    let list = exe_paths.iter().map(|p| format!("'{}'", p.replace('\'', "''"))).collect::<Vec<_>>().join(",");
    let script = format!(r#"
$ErrorActionPreference='SilentlyContinue'
$svc = Get-CimInstance Win32_Service | Where-Object {{ $_.ProcessId -gt 0 -or $_.State -eq 'Running' }} | Select-Object Name, DisplayName, ProcessId, PathName
$prog = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object {{ $_.DisplayName -and -not $_.SystemComponent }} | Select-Object DisplayName, DisplayVersion, Publisher
$paths = @({list}) + @($svc | ForEach-Object {{ $_.PathName }} | Where-Object {{ $_ }} | ForEach-Object {{ if ($_.StartsWith('"')) {{ $_.Split('"')[1] }} elseif ($_ -match '^(.*?\.exe)') {{ $matches[1] }} else {{ $_.Split(' ')[0] }} }})
$files = $paths | Sort-Object -Unique | ForEach-Object {{ $f = Get-Item -LiteralPath $_; if ($f) {{ [pscustomobject]@{{ Path=$_; Product=$f.VersionInfo.ProductName; Version=$(if ($f.VersionInfo.ProductVersion) {{ $f.VersionInfo.ProductVersion }} else {{ $f.VersionInfo.FileVersion }}); Company=$f.VersionInfo.CompanyName; Mtime=$f.LastWriteTimeUtc.ToString('o') }} }} }}
$o = Get-CimInstance Win32_OperatingSystem
$nt = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$hf = Get-HotFix | Where-Object {{ $_.InstalledOn }} | Sort-Object InstalledOn | Select-Object -Last 1
$os = [pscustomobject]@{{ Caption=$o.Caption; Version=$o.Version; Build=$o.BuildNumber; UBR=$nt.UBR; DisplayVersion=$nt.DisplayVersion; LastBoot=$o.LastBootUpTime.ToUniversalTime().ToString('o'); LastHotfix=$(if ($hf) {{ $hf.InstalledOn.ToUniversalTime().ToString('o') }} else {{ $null }}) }}
[pscustomobject]@{{ services=@($svc); programs=@($prog); files=@($files); os=$os }} | ConvertTo-Json -Depth 4 -Compress
"#);
    let parsed: PsOut = match ps_json(state, &script).map(serde_json::from_value::<PsOut>) {
        Some(Ok(p)) => p,
        Some(Err(e)) => {
            tracing::warn!("inventory JSON did not match the expected shape: {e}");
            PsOut::default()
        }
        None => PsOut::default(),
    };
    super::RawInventory {
        services: parsed.services.into_iter().map(|s| super::RawService { name: s.name, display: s.display, pid: s.pid, path: s.path }).collect(),
        programs: parsed.programs.into_iter().map(|p| super::RawProgram { name: p.name, version: p.version, publisher: p.publisher }).collect(),
        files: parsed.files.into_iter().map(|f| super::RawFile { path: f.path, product: f.product, version: f.version, company: f.company, mtime: f.mtime }).collect(),
        os: parsed.os.map(|o| super::RawOs {
            caption: o.caption,
            version: o.version,
            build: o.build,
            ubr: match o.ubr { serde_json::Value::Number(n) => n.to_string(), serde_json::Value::String(s) => s, _ => String::new() },
            display_version: o.display_version,
            last_hotfix: o.last_hotfix,
            last_boot: o.last_boot,
        }),
    }
}

pub fn is_os_kev_entry(vendor: &str, product: &str) -> bool {
    let p = product.to_ascii_lowercase();
    vendor.eq_ignore_ascii_case("microsoft") && (p.starts_with("windows") || p == "win32k" || p == "internet explorer" || p == "mshtml" || p.contains("print spooler") || p.contains("smb"))
}

// ---------- name lists ----------

pub const LOLBINS: &[&str] = &[
    "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe",
    "cmstp.exe", "bitsadmin.exe", "wscript.exe", "cscript.exe", "regasm.exe", "regsvcs.exe",
    "msiexec.exe", "wmic.exe", "hh.exe", "ieexec.exe", "presentationhost.exe", "forfiles.exe",
    "pcalua.exe", "scriptrunner.exe", "esentutl.exe", "expand.exe", "extrac32.exe", "findstr.exe",
    "makecab.exe", "xwizard.exe", "desktopimgdownldr.exe", "diantz.exe", "finger.exe", "ftp.exe",
    "tftp.exe", "mavinject.exe", "odbcconf.exe", "wab.exe", "at.exe", "schtasks.exe", "sc.exe",
];

pub const SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "python.exe", "pythonw.exe", "node.exe",
];

pub const OFFICE_APPS: &[&str] = &[
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe", "visio.exe", "acrord32.exe", "acrobat.exe",
];

pub const SYSTEM_NAMES: &[&str] = &[
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
    "explorer.exe", "spoolsv.exe", "dwm.exe", "taskhostw.exe", "runtimebroker.exe", "sihost.exe", "dllhost.exe",
    "conhost.exe", "searchindexer.exe", "wuauclt.exe", "msmpeng.exe",
];

pub const BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe", "msedgewebview2.exe", "chromium.exe"];
pub const MAIL_CLIENTS: &[&str] = &["outlook.exe", "thunderbird.exe", "olk.exe", "hxoutlook.exe", "mailspring.exe", "em client.exe"];
pub const DNS_SERVICES: &[&str] = &["svchost.exe", "system", "dnscache", "nscd", "unbound.exe", "dnscrypt-proxy.exe", "cloudflared.exe", "adguard.exe", "adguardsvc.exe", "pihole", "nextdns.exe", "nextdnsservice.exe", "acrylic", "simpledns", "dnsproxy.exe", "mullvad-daemon.exe", "warp-svc.exe"];
pub const SSH_CLIENTS: &[&str] = &["ssh.exe", "putty.exe", "winscp.exe", "git.exe", "code.exe", "kitty.exe", "mobaxterm.exe"];
pub const RDP_CLIENTS: &[&str] = &["mstsc.exe"];
pub const DEFAULT_APPROVED_UPLOADERS: &[&str] = &["onedrive.exe"];
