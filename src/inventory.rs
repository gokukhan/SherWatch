//! Software inventory and vulnerability exposure.
//!
//! Collects, through one PowerShell query every 30 minutes:
//!   - running Windows services with their process IDs and binaries,
//!   - installed programs from the registry Uninstall keys,
//!   - product / version / company / last-write time of every executable that uses the network,
//!   - Windows version, build and last installed update.
//! Matches all of it offline against CISA's Known Exploited Vulnerabilities catalogue
//! (downloaded as a feed) and, on request, looks up CVEs for exact versions online
//! through Shodan's free CVEDB (sends product names and versions; off by default).

use crate::db::DbMsg;
use crate::model::Severity;
use crate::state::AppState;
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Inventory rules re-evaluate every 30 minutes; one alert a day per item is enough.
const SLOW_RULE_COOLDOWN: i64 = 24 * 3600 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevEntry {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vendorProject")]
    pub vendor: String,
    pub product: String,
    #[serde(rename = "vulnerabilityName", default)]
    pub name: String,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    #[serde(rename = "shortDescription", default)]
    pub description: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    pub ransomware: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KevMatch {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub date_added: String,
    pub ransomware: bool,
    /// The binary on disk is older than the day the exploit was catalogued.
    pub likely_unpatched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CveInfo {
    pub cve_id: String,
    pub cvss: Option<f64>,
    pub epss: Option<f64>,
    pub kev: bool,
    pub summary: String,
    pub published: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct InventoryItem {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub product: String,
    pub version: String,
    pub company: String,
    pub exe: String,
    pub file_mtime: Option<i64>,
    pub pids: Vec<u32>,
    pub services: Vec<String>,
    pub network_active: bool,
    pub kev: Vec<KevMatch>,
    pub cves: Vec<CveInfo>,
    pub cve_checked: Option<i64>,
    pub cpe: Option<String>,
    pub max_cvss: f64,
    pub cve_note: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct OsInfo {
    pub caption: String,
    pub version: String,
    pub build: String,
    pub ubr: String,
    pub display_version: String,
    pub last_hotfix: Option<i64>,
    pub last_boot: Option<i64>,
    pub patch_age_days: Option<i64>,
    pub kev_since_patch: Vec<KevMatch>,
}

#[derive(Deserialize, Default)]
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
#[derive(Deserialize)]
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
#[derive(Deserialize)]
struct PsProgram {
    #[serde(rename = "DisplayName", default)]
    name: Option<String>,
    #[serde(rename = "DisplayVersion", default)]
    version: Option<String>,
    #[serde(rename = "Publisher", default)]
    publisher: Option<String>,
}
#[derive(Deserialize)]
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
#[derive(Deserialize)]
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

/// Executable path out of a service command line.
pub fn exe_from_command(cmd: &str) -> String {
    let c = cmd.trim();
    if let Some(rest) = c.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    let lower = c.to_ascii_lowercase();
    if let Some(i) = lower.find(".exe") {
        return c[..i + 4].to_string();
    }
    c.split_whitespace().next().unwrap_or("").to_string()
}

fn parse_iso(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp_millis()).or_else(|| {
        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").ok().map(|d| d.and_utc().timestamp_millis())
    })
}

fn tokens(s: &str) -> HashSet<String> {
    s.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_string())
        .collect()
}

const GENERIC_PRODUCTS: &[&str] = &["multiple products", "firmware", "routers", "router", "multiple", "products", "os", "kernel", "server", "software"];

fn is_os_entry(k: &KevEntry) -> bool {
    let p = k.product.to_ascii_lowercase();
    k.vendor.eq_ignore_ascii_case("microsoft") && (p.starts_with("windows") || p == "win32k" || p == "internet explorer" || p == "mshtml" || p.contains("print spooler") || p.contains("smb"))
}

fn match_kev(item: &InventoryItem, kev: &[KevEntry]) -> Vec<KevMatch> {
    let hay = tokens(&format!(
        "{} {} {} {}",
        item.product,
        item.name,
        std::path::Path::new(&item.exe).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
        item.company
    ));
    if hay.is_empty() {
        return vec![];
    }
    let mut out = vec![];
    for k in kev {
        if is_os_entry(k) {
            continue;
        }
        let pl = k.product.to_ascii_lowercase();
        if GENERIC_PRODUCTS.contains(&pl.as_str()) {
            continue;
        }
        let pt = tokens(&k.product);
        let vt = tokens(&k.vendor);
        if pt.is_empty() || !pt.iter().all(|t| hay.contains(t)) {
            continue;
        }
        // A product that is just the vendor name ("Microsoft", "Apple") would match every product of that vendor.
        if pt.is_subset(&vt) {
            continue;
        }
        let name_tokens = tokens(&format!("{} {}", item.product, item.name));
        // Product tokens must appear in the product/name, not only in the company field.
        if !pt.iter().any(|t| name_tokens.contains(t)) {
            continue;
        }
        let vendor_hit = vt.iter().any(|t| hay.contains(t) && !pt.contains(t));
        let short_product = pt.len() == 1 && pt.iter().all(|t| t.len() < 6);
        // Short single-word products ("Ray", "Edge", "Word") need the vendor to match as well.
        if !(vendor_hit || vt.is_empty() || vt.is_subset(&pt)) || (short_product && !vendor_hit) {
            continue;
        }
        let added = NaiveDate::parse_from_str(&k.date_added, "%Y-%m-%d").ok().map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis());
        // Fix date proxy: the CVE year plus one, or the catalogue date if earlier (old CVEs were backfilled in 2021-2022).
        let cve_year: Option<i32> = k.cve_id.split('-').nth(1).and_then(|y| y.parse().ok());
        let fix_proxy = cve_year.and_then(|y| NaiveDate::from_ymd_opt(y + 1, 12, 31)).map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis());
        let threshold = match (added, fix_proxy) {
            (Some(a), Some(f)) => Some(a.min(f)),
            (a, f) => a.or(f),
        };
        let likely_unpatched = match (item.file_mtime, threshold) {
            (Some(m), Some(t)) => m < t,
            _ => false,
        };
        out.push(KevMatch {
            cve_id: k.cve_id.clone(),
            vendor: k.vendor.clone(),
            product: k.product.clone(),
            name: k.name.clone(),
            date_added: k.date_added.clone(),
            ransomware: k.ransomware.eq_ignore_ascii_case("known"),
            likely_unpatched,
        });
    }
    out.sort_by(|a, b| b.date_added.cmp(&a.date_added));
    out.truncate(25);
    out
}

fn ps_json(state: &AppState, script: &str) -> Option<serde_json::Value> {
    // The query is long and multi-line, so it runs from a file rather than the command line.
    let dir = state.root.join("data").join("logs");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("inventory-query.ps1");
    std::fs::write(&path, script).ok()?;
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", &path.display().to_string()])
        .stdin(std::process::Stdio::null())
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

/// One collection pass. Runs on a blocking thread.
pub fn collect(state: &AppState) {
    {
        let mut inv = state.inventory.write();
        inv.scanning = true;
    }
    let exe_paths: Vec<String> = {
        let mut v: Vec<String> = state.procs.iter().filter(|p| !p.exe.is_empty()).map(|p| p.exe.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
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
    let kev = state.intel.kev_entries();
    let now = crate::util::now_ms();

    let files: HashMap<String, &PsFile> = parsed.files.iter().filter(|f| f.path.is_some()).map(|f| (f.path.clone().unwrap_or_default().to_ascii_lowercase(), f)).collect();
    let mut items: HashMap<String, InventoryItem> = HashMap::new();
    let mut pid_services: HashMap<u32, Vec<String>> = HashMap::new();

    // Network-active executables
    let mut procs_by_exe: HashMap<String, (String, Vec<u32>)> = HashMap::new();
    for p in state.procs.iter() {
        if p.exe.is_empty() {
            continue;
        }
        let e = procs_by_exe.entry(p.exe.to_ascii_lowercase()).or_insert_with(|| (p.exe.clone(), vec![]));
        e.1.push(p.pid);
    }
    for (key, (exe, pids)) in procs_by_exe {
        let f = files.get(&key);
        let stem = std::path::Path::new(&exe).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        items.insert(
            format!("app:{key}"),
            InventoryItem {
                id: format!("app:{key}"),
                kind: "app".into(),
                name: stem,
                product: f.and_then(|f| f.product.clone()).unwrap_or_default().trim().to_string(),
                version: f.and_then(|f| f.version.clone()).unwrap_or_default().trim().to_string(),
                company: f.and_then(|f| f.company.clone()).unwrap_or_default().trim().to_string(),
                exe: exe.clone(),
                file_mtime: f.and_then(|f| f.mtime.as_deref()).and_then(parse_iso),
                pids,
                network_active: true,
                ..Default::default()
            },
        );
    }
    // Services
    for s in &parsed.services {
        let sname = s.name.clone().unwrap_or_default();
        let sdisplay = s.display.clone().unwrap_or_else(|| sname.clone());
        let spid = s.pid.unwrap_or(0);
        let exe = exe_from_command(s.path.as_deref().unwrap_or(""));
        let key = exe.to_ascii_lowercase();
        if spid > 0 {
            pid_services.entry(spid).or_default().push(sname.clone());
        }
        let is_svchost = key.ends_with("\\svchost.exe");
        let id = if is_svchost { format!("svc:{}", sname.to_ascii_lowercase()) } else { format!("svc:{key}") };
        let f = files.get(&key);
        let e = items.entry(id.clone()).or_insert_with(|| InventoryItem {
            id: id.clone(),
            kind: "service".into(),
            name: if is_svchost { format!("{sdisplay} ({sname})") } else { sdisplay.clone() },
            product: f.and_then(|f| f.product.clone()).unwrap_or_default().trim().to_string(),
            version: f.and_then(|f| f.version.clone()).unwrap_or_default().trim().to_string(),
            company: f.and_then(|f| f.company.clone()).unwrap_or_default().trim().to_string(),
            exe: exe.clone(),
            file_mtime: f.and_then(|f| f.mtime.as_deref()).and_then(parse_iso),
            ..Default::default()
        });
        e.services.push(sname.clone());
        if spid > 0 && !e.pids.contains(&spid) {
            e.pids.push(spid);
        }
        if spid > 0 && state.procs.contains_key(&spid) {
            e.network_active = true;
        }
    }
    // Installed programs
    for p in &parsed.programs {
        let pname = p.name.clone().unwrap_or_default();
        if pname.is_empty() {
            continue;
        }
        let id = format!("prog:{}", pname.to_ascii_lowercase());
        items.entry(id.clone()).or_insert_with(|| InventoryItem {
            id,
            kind: "program".into(),
            name: pname.clone(),
            product: pname.clone(),
            version: p.version.clone().unwrap_or_default(),
            company: p.publisher.clone().unwrap_or_default(),
            ..Default::default()
        });
    }

    // Preserve online results from the previous pass and run KEV matching.
    let previous = state.inventory.read().items.clone();
    for item in items.values_mut() {
        if let Some(old) = previous.get(&item.id) {
            item.cves = old.cves.clone();
            item.cve_checked = old.cve_checked;
            item.cpe = old.cpe.clone();
            item.max_cvss = old.max_cvss;
            item.cve_note = old.cve_note.clone();
        }
        item.kev = match_kev(item, &kev);
    }

    // OS
    let mut os = OsInfo::default();
    if let Some(o) = parsed.os {
        os.caption = o.caption.unwrap_or_default();
        os.version = o.version.unwrap_or_default();
        os.build = o.build.unwrap_or_default();
        os.ubr = match o.ubr { serde_json::Value::Number(n) => n.to_string(), serde_json::Value::String(s) => s, _ => String::new() };
        os.display_version = o.display_version.unwrap_or_default();
        os.last_hotfix = o.last_hotfix.as_deref().and_then(parse_iso);
        os.last_boot = o.last_boot.as_deref().and_then(parse_iso);
        os.patch_age_days = os.last_hotfix.map(|t| (now - t) / 86_400_000);
        if let Some(t) = os.last_hotfix {
            os.kev_since_patch = kev
                .iter()
                .filter(|k| is_os_entry(k))
                .filter(|k| NaiveDate::parse_from_str(&k.date_added, "%Y-%m-%d").ok().map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis() > t).unwrap_or(false))
                .map(|k| KevMatch { cve_id: k.cve_id.clone(), vendor: k.vendor.clone(), product: k.product.clone(), name: k.name.clone(), date_added: k.date_added.clone(), ransomware: k.ransomware.eq_ignore_ascii_case("known"), likely_unpatched: true })
                .collect();
        }
    }

    // Hosted services onto processes (svchost gets its service names).
    for (pid, svcs) in &pid_services {
        if let Some(mut p) = state.procs.get_mut(pid) {
            p.services = svcs.clone();
        }
    }
    {
        let mut inv = state.inventory.write();
        inv.items = items;
        inv.os = os;
        inv.last_scan = Some(now);
        inv.scanning = false;
        inv.kev_count = kev.len();
        inv.pid_services = pid_services;
    }
    tracing::info!("inventory: {} items, {} services, {} programs", state.inventory.read().items.len(), parsed.services.len(), parsed.programs.len());
    raise_alerts(state);
}

fn raise_alerts(state: &AppState) {
    let inv = state.inventory.read().clone();
    for item in inv.items.values() {
        let exploited: Vec<&KevMatch> = item.kev.iter().filter(|k| k.likely_unpatched).collect();
        if !exploited.is_empty() && (item.network_active || item.kind == "service") {
            let ransomware = exploited.iter().any(|k| k.ransomware);
            let sev = if ransomware && item.network_active { Severity::Critical } else { Severity::High };
            let pid = item.pids.first().copied().unwrap_or(0);
            let ids: Vec<String> = exploited.iter().take(4).map(|k| k.cve_id.clone()).collect();
            state.push_alert_cd(
                sev,
                "R24-exploited-software",
                format!("{} {} has actively exploited vulnerabilities and looks unpatched", item.product.clone().if_empty(&item.name), item.version),
                format!(
                    "{} is older than {} CISA KEV entr{} for {} {} ({}{}). Update it or stop it until updated.",
                    if item.exe.is_empty() { item.name.clone() } else { item.exe.clone() },
                    exploited.len(),
                    if exploited.len() == 1 { "y" } else { "ies" },
                    exploited[0].vendor,
                    exploited[0].product,
                    ids.join(", "),
                    if ransomware { ", used by ransomware" } else { "" }
                ),
                pid,
                &item.id,
                Some(SLOW_RULE_COOLDOWN),
            );
        }
        if item.max_cvss >= 9.0 || item.cves.iter().any(|c| c.kev) {
            let worst = item.cves.iter().max_by(|a, b| a.cvss.unwrap_or(0.0).partial_cmp(&b.cvss.unwrap_or(0.0)).unwrap()).cloned().unwrap_or_default();
            let sev = if item.cves.iter().any(|c| c.kev) { Severity::High } else { Severity::Medium };
            state.push_alert_cd(
                sev,
                "R26-known-cve",
                format!("{} {} has {} published CVEs (worst CVSS {:.1})", item.product.clone().if_empty(&item.name), item.version, item.cves.len(), item.max_cvss),
                format!("{}: {}", worst.cve_id, crate::util::truncate(&worst.summary, 200)),
                item.pids.first().copied().unwrap_or(0),
                &item.id,
                Some(SLOW_RULE_COOLDOWN),
            );
        }
    }
    if let Some(age) = inv.os.patch_age_days {
        let since = inv.os.kev_since_patch.len();
        if age > 45 || since > 0 {
            let sev = if since > 0 && age > 30 { Severity::High } else { Severity::Medium };
            state.push_alert_cd(
                sev,
                "R25-os-patch",
                format!("Windows was last updated {age} days ago"),
                format!(
                    "{} build {}.{} ({}). {} Windows vulnerabilities were added to CISA's exploited list since the last update.",
                    inv.os.caption, inv.os.build, inv.os.ubr, inv.os.display_version, since
                ),
                0,
                "windows",
                Some(SLOW_RULE_COOLDOWN),
            );
        }
    }
}

trait IfEmpty {
    fn if_empty(self, alt: &str) -> String;
}
impl IfEmpty for String {
    fn if_empty(self, alt: &str) -> String {
        if self.trim().is_empty() { alt.to_string() } else { self }
    }
}

// ---------- online CVE lookup (Shodan CVEDB, opt-in) ----------

fn cpe_candidates(item: &InventoryItem) -> Vec<String> {
    let mut out = vec![];
    let norm = |s: &str| -> String {
        s.to_ascii_lowercase()
            .replace(['(', ')', ',', '®', '™'], " ")
            .split_whitespace()
            .filter(|w| !matches!(*w, "x64" | "x86" | "64-bit" | "32-bit" | "(x64)" | "edition" | "version"))
            .filter(|w| !w.chars().all(|c| c.is_ascii_digit() || c == '.'))
            .collect::<Vec<_>>()
            .join("_")
    };
    let company_tokens = tokens(&item.company);
    let product = if item.product.is_empty() { item.name.clone() } else { item.product.clone() };
    let full = norm(&product);
    if !full.is_empty() {
        out.push(full.clone());
    }
    let without_vendor: String = product
        .split_whitespace()
        .filter(|w| !company_tokens.contains(&w.to_ascii_lowercase()) && !matches!(w.to_ascii_lowercase().as_str(), "microsoft" | "google" | "mozilla" | "corporation" | "inc" | "inc." | "ltd" | "llc"))
        .collect::<Vec<_>>()
        .join(" ");
    let wv = norm(&without_vendor);
    if !wv.is_empty() && wv != full {
        out.push(wv);
    }
    if let Some(stem) = std::path::Path::new(&item.exe).file_stem().map(|s| s.to_string_lossy().to_ascii_lowercase()) {
        if !stem.is_empty() && !out.contains(&stem) {
            out.push(stem);
        }
    }
    out.truncate(3);
    out
}

pub async fn online_lookup(state: Arc<AppState>) {
    {
        let mut inv = state.inventory.write();
        if inv.online_running {
            return;
        }
        inv.online_running = true;
        inv.online_progress = "starting".into();
    }
    let client = reqwest::Client::builder().user_agent("NetMonitor/0.1").timeout(std::time::Duration::from_secs(20)).build().unwrap();
    let items: Vec<InventoryItem> = {
        let inv = state.inventory.read();
        let mut v: Vec<InventoryItem> = inv.items.values().filter(|i| !i.version.is_empty() && (i.network_active || i.kind != "program" || true)).cloned().collect();
        v.sort_by_key(|i| (!i.network_active, i.kind != "service", i.name.clone()));
        v
    };
    let total = items.len();
    let now = crate::util::now_ms();
    for (n, item) in items.iter().enumerate() {
        {
            let mut inv = state.inventory.write();
            inv.online_progress = format!("{}/{}: {}", n + 1, total, item.name);
        }
        // Cache for 7 days.
        if let Some(c) = item.cve_checked {
            if now - c < 7 * 86_400_000 {
                continue;
            }
        }
        let version = item.version.split_whitespace().next().unwrap_or("").trim_start_matches('v').to_string();
        let version = version.split(['-', '+', ' ']).next().unwrap_or("").to_string();
        let mut found_cpe: Option<String> = None;
        for cand in cpe_candidates(item) {
            let url = format!("https://cvedb.shodan.io/cpes?product={}&limit=200", urlencoding(&cand));
            let Ok(r) = client.get(&url).send().await else { continue };
            let Ok(v) = r.json::<serde_json::Value>().await else { continue };
            let list: Vec<String> = v["cpes"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
            if list.is_empty() {
                continue;
            }
            // cpe:2.3:a:vendor:product:version
            let company = tokens(&item.company);
            let mut best: Option<(String, String)> = None;
            for c in &list {
                let parts: Vec<&str> = c.split(':').collect();
                if parts.len() < 5 || parts[2] != "a" {
                    continue;
                }
                let (vendor, product) = (parts[3].to_string(), parts[4].to_string());
                let vendor_hit = company.iter().any(|t| vendor.contains(t.as_str())) || tokens(&vendor).iter().any(|t| company.contains(t));
                if best.is_none() || vendor_hit {
                    best = Some((vendor.clone(), product.clone()));
                    if vendor_hit {
                        break;
                    }
                }
            }
            if let Some((vendor, product)) = best {
                found_cpe = Some(format!("cpe:2.3:a:{vendor}:{product}"));
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        }
        let mut cves: Vec<CveInfo> = vec![];
        let mut note = String::new();
        if let Some(base) = &found_cpe {
            let mut tried = vec![];
            if !version.is_empty() {
                tried.push(version.clone());
                let mm: Vec<&str> = version.split('.').collect();
                if mm.len() > 2 {
                    tried.push(mm[..2].join("."));
                }
            }
            for ver in &tried {
                let url = format!("https://cvedb.shodan.io/cves?cpe23={}:{}&limit=100&sort_by=epss", urlencoding(base), urlencoding(ver));
                let Ok(r) = client.get(&url).send().await else { continue };
                let Ok(v) = r.json::<serde_json::Value>().await else { continue };
                if let Some(arr) = v["cves"].as_array() {
                    for c in arr {
                        cves.push(CveInfo {
                            cve_id: c["cve_id"].as_str().unwrap_or("").to_string(),
                            cvss: c["cvss"].as_f64(),
                            epss: c["epss"].as_f64(),
                            kev: c["kev"].as_bool().unwrap_or(false),
                            summary: c["summary"].as_str().unwrap_or("").to_string(),
                            published: c["published_time"].as_str().unwrap_or("").chars().take(10).collect(),
                        });
                    }
                }
                if !cves.is_empty() {
                    note = format!("matched {base}:{ver}");
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }
            if cves.is_empty() {
                note = format!("no CVEs listed for {base} {version}");
            }
        } else {
            note = "no CPE found for this product name".into();
        }
        let max_cvss = cves.iter().filter_map(|c| c.cvss).fold(0.0, f64::max);
        {
            let mut inv = state.inventory.write();
            if let Some(it) = inv.items.get_mut(&item.id) {
                it.cves = cves;
                it.cve_checked = Some(crate::util::now_ms());
                it.cpe = found_cpe.clone();
                it.max_cvss = max_cvss;
                it.cve_note = note;
            }
        }
        state.db.send(DbMsg::Query(Box::new({
            let id = item.id.clone();
            let cpe = found_cpe.clone().unwrap_or_default();
            move |sql| {
                let _ = sql.execute("INSERT OR REPLACE INTO cve_cache(id, cpe, ts) VALUES(?1, ?2, ?3)", rusqlite::params![id, cpe, crate::util::now_ms()]);
            }
        })));
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    }
    {
        let mut inv = state.inventory.write();
        inv.online_running = false;
        inv.online_progress = String::new();
        inv.online_last = Some(crate::util::now_ms());
    }
    raise_alerts(&state);
}

fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn start(state: Arc<AppState>) {
    let s = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(12)).await;
        loop {
            let st = s.clone();
            let _ = tokio::task::spawn_blocking(move || collect(&st)).await;
            if s.cfg.vuln.online_lookup {
                online_lookup(s.clone()).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(30 * 60)).await;
        }
    });
}
