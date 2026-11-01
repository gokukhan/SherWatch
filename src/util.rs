use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// True when the address is routable on the public internet.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(&v4);
            }
            is_public_v6(v6)
        }
    }
}

fn is_public_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)))
}

fn is_public_v6(ip: &Ipv6Addr) -> bool {
    let s = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] == 0x2001 && s[1] == 0x0db8))
}

/// Short label for the address scope.
pub fn ip_scope(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() { "loopback" }
            else if v4.is_private() { "lan" }
            else if v4.is_link_local() { "link-local" }
            else if v4.is_multicast() || v4.is_broadcast() { "multicast" }
            else if v4.is_unspecified() { "any" }
            else if is_public_v4(v4) { "public" }
            else { "reserved" }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_scope(&IpAddr::V4(v4));
            }
            if v6.is_loopback() { "loopback" }
            else if v6.is_unspecified() { "any" }
            else if v6.is_multicast() { "multicast" }
            else if (v6.segments()[0] & 0xffc0) == 0xfe80 { "link-local" }
            else if (v6.segments()[0] & 0xfe00) == 0xfc00 { "lan" }
            else if is_public_v6(v6) { "public" }
            else { "reserved" }
        }
    }
}

pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Small public-suffix approximation: returns the registrable domain (eTLD+1).
pub fn base_domain(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() <= 2 {
        return h;
    }
    const SECOND_LEVEL: &[&str] = &[
        "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "mil", "nic", "ltd", "plc", "sch",
    ];
    let n = labels.len();
    let tld = labels[n - 1];
    let sld = labels[n - 2];
    if tld.len() == 2 && SECOND_LEVEL.contains(&sld) && n >= 3 {
        return labels[n - 3..].join(".");
    }
    labels[n - 2..].join(".")
}

pub fn vowel_ratio(s: &str) -> f64 {
    let letters: Vec<char> = s.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    if letters.is_empty() {
        return 0.0;
    }
    let v = letters.iter().filter(|c| "aeiou".contains(c.to_ascii_lowercase())).count();
    v as f64 / letters.len() as f64
}

pub fn digit_ratio(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    s.chars().filter(|c| c.is_ascii_digit()).count() as f64 / s.chars().count() as f64
}

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

pub fn is_user_writable_location(flags: &[String]) -> bool {
    flags.iter().any(|f| {
        matches!(
            f.as_str(),
            "temp" | "appdata-temp" | "downloads" | "public" | "recycle-bin" | "desktop" | "drive-root" | "profile-root"
        )
    })
}

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

pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n).collect::<String>() + "..." }
}

/// Compare dotted versions like "0.3.1".
pub fn version_newer(candidate: &str, current: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> { s.trim_start_matches('v').split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    let a = parse(candidate);
    let b = parse(current);
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}
