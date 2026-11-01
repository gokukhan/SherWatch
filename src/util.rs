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

/// Approximate owner of well-known cloud and vendor address ranges. Coarse by design:
/// it labels the big networks a Windows PC talks to all day so they read as what they are.
pub fn ip_owner(ip: &IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let n = u32::from(*v4);
            let in_net = |net: [u8; 4], bits: u32| (n >> (32 - bits)) == (u32::from(Ipv4Addr::from(net)) >> (32 - bits));
            if in_net([13, 64, 0, 0], 11) || in_net([13, 104, 0, 0], 14) || in_net([20, 33, 0, 0], 16) || in_net([20, 34, 0, 0], 15) || in_net([20, 36, 0, 0], 14) || in_net([20, 40, 0, 0], 13) || in_net([20, 48, 0, 0], 12) || in_net([20, 64, 0, 0], 10) || in_net([20, 128, 0, 0], 16) || in_net([20, 184, 0, 0], 13) || in_net([20, 192, 0, 0], 10) || in_net([40, 64, 0, 0], 10) || in_net([51, 104, 0, 0], 15) || in_net([52, 96, 0, 0], 12) || in_net([52, 112, 0, 0], 14) || in_net([52, 136, 0, 0], 13) || in_net([52, 145, 0, 0], 16) || in_net([52, 146, 0, 0], 15) || in_net([52, 148, 0, 0], 14) || in_net([52, 152, 0, 0], 13) || in_net([52, 160, 0, 0], 11) || in_net([104, 40, 0, 0], 13) || in_net([104, 208, 0, 0], 13) || in_net([23, 96, 0, 0], 13) || in_net([131, 253, 0, 0], 16) || in_net([204, 79, 197, 0], 24) || in_net([150, 171, 0, 0], 16) || in_net([4, 144, 0, 0], 12) || in_net([4, 160, 0, 0], 11) || in_net([4, 192, 0, 0], 10) {
                return Some("Microsoft");
            }
            if in_net([8, 8, 8, 0], 24) || in_net([8, 8, 4, 0], 24) || in_net([34, 64, 0, 0], 10) || in_net([35, 184, 0, 0], 13) || in_net([35, 192, 0, 0], 11) || in_net([35, 224, 0, 0], 12) || in_net([64, 233, 160, 0], 19) || in_net([66, 102, 0, 0], 20) || in_net([74, 125, 0, 0], 16) || in_net([108, 177, 0, 0], 17) || in_net([142, 250, 0, 0], 15) || in_net([172, 217, 0, 0], 16) || in_net([173, 194, 0, 0], 16) || in_net([209, 85, 128, 0], 17) || in_net([216, 58, 192, 0], 19) || in_net([216, 239, 32, 0], 19) {
                return Some("Google");
            }
            if in_net([1, 1, 1, 0], 24) || in_net([1, 0, 0, 0], 24) || in_net([104, 16, 0, 0], 12) || in_net([172, 64, 0, 0], 13) || in_net([162, 158, 0, 0], 15) || in_net([188, 114, 96, 0], 20) || in_net([141, 101, 64, 0], 18) || in_net([190, 93, 240, 0], 20) || in_net([198, 41, 128, 0], 17) {
                return Some("Cloudflare");
            }
            if in_net([3, 0, 0, 0], 9) || in_net([3, 128, 0, 0], 9) || in_net([13, 32, 0, 0], 12) || in_net([13, 224, 0, 0], 14) || in_net([15, 160, 0, 0], 11) || in_net([18, 128, 0, 0], 9) || in_net([18, 32, 0, 0], 11) || in_net([34, 192, 0, 0], 10) || in_net([35, 152, 0, 0], 13) || in_net([44, 192, 0, 0], 10) || in_net([52, 0, 0, 0], 10) || in_net([52, 64, 0, 0], 11) || in_net([54, 64, 0, 0], 10) || in_net([54, 144, 0, 0], 12) || in_net([54, 160, 0, 0], 11) || in_net([54, 192, 0, 0], 10) || in_net([99, 77, 128, 0], 17) || in_net([99, 84, 0, 0], 16) || in_net([108, 128, 0, 0], 13) || in_net([143, 204, 0, 0], 16) || in_net([205, 251, 192, 0], 18) {
                return Some("Amazon AWS");
            }
            if in_net([23, 0, 0, 0], 12) || in_net([23, 32, 0, 0], 11) || in_net([23, 64, 0, 0], 14) || in_net([23, 192, 0, 0], 11) || in_net([104, 64, 0, 0], 10) || in_net([184, 24, 0, 0], 13) || in_net([184, 50, 0, 0], 15) || in_net([2, 16, 0, 0], 13) || in_net([95, 100, 0, 0], 15) || in_net([96, 16, 0, 0], 15) || in_net([72, 246, 0, 0], 15) {
                return Some("Akamai");
            }
            if o[0] == 17 {
                return Some("Apple");
            }
            if in_net([31, 13, 24, 0], 21) || in_net([31, 13, 64, 0], 18) || in_net([157, 240, 0, 0], 16) || in_net([69, 171, 224, 0], 19) || in_net([66, 220, 144, 0], 20) || in_net([179, 60, 192, 0], 22) || in_net([185, 60, 216, 0], 22) || in_net([163, 70, 128, 0], 17) {
                return Some("Meta");
            }
            if in_net([155, 133, 224, 0], 19) || in_net([162, 254, 192, 0], 21) || in_net([205, 196, 6, 0], 24) || in_net([208, 64, 200, 0], 22) {
                return Some("Valve / Steam");
            }
            if in_net([151, 101, 0, 0], 16) || in_net([199, 232, 0, 0], 16) || in_net([146, 75, 0, 0], 16) {
                return Some("Fastly");
            }
            None
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_owner(&IpAddr::V4(v4));
            }
            let s = v6.segments();
            if s[0] == 0x2603 && (0x1000..=0x10ff).contains(&s[1]) || s[0] == 0x2a01 && (s[1] == 0x0110 || s[1] == 0x0111) || s[0] == 0x2620 && s[1] == 0x01ec || s[0] == 0x2a01 && s[1] == 0x0111 {
                return Some("Microsoft");
            }
            if s[0] == 0x2607 && s[1] == 0xf8b0 || s[0] == 0x2a00 && s[1] == 0x1450 || s[0] == 0x2001 && s[1] == 0x4860 || s[0] == 0x2404 && s[1] == 0x6800 || s[0] == 0x2600 && s[1] == 0x1900 {
                return Some("Google");
            }
            if s[0] == 0x2606 && s[1] == 0x4700 || s[0] == 0x2a06 && (s[1] & 0xfff8) == 0x98c0 || s[0] == 0x2803 && s[1] == 0xf800 || s[0] == 0x2405 && (s[1] == 0x8100 || s[1] == 0xb500) {
                return Some("Cloudflare");
            }
            if s[0] == 0x2600 && (s[1] & 0xff00) == 0x1f00 || s[0] == 0x2600 && s[1] == 0x9000 || s[0] == 0x2a05 && (s[1] & 0xfff8) == 0xd018 || s[0] == 0x2406 && s[1] == 0xda00 {
                return Some("Amazon AWS");
            }
            if s[0] == 0x2a02 && s[1] == 0x26f0 || s[0] == 0x2600 && s[1] == 0x1400 || s[0] == 0x2600 && s[1] == 0x1480 {
                return Some("Akamai");
            }
            if s[0] == 0x2620 && s[1] == 0x0149 || s[0] == 0x2a01 && s[1] == 0xb740 {
                return Some("Apple");
            }
            if s[0] == 0x2a03 && s[1] == 0x2880 {
                return Some("Meta");
            }
            if s[0] == 0x2a04 && (s[1] & 0xfff8) == 0x4e40 {
                return Some("Fastly");
            }
            None
        }
    }
}

pub fn owner_from_hostname(host: &str) -> Option<&'static str> {
    let h = host.to_ascii_lowercase();
    let table: &[(&str, &str)] = &[
        ("1e100.net", "Google"), ("googleusercontent.com", "Google"), ("google.com", "Google"), ("gvt1.com", "Google"), ("youtube.com", "Google"),
        ("amazonaws.com", "Amazon AWS"), ("cloudfront.net", "Amazon CloudFront"), ("akamaitechnologies.com", "Akamai"), ("akamaiedge.net", "Akamai"), ("akadns.net", "Akamai"),
        ("microsoft.com", "Microsoft"), ("msedge.net", "Microsoft"), ("azure.com", "Microsoft"), ("windows.net", "Microsoft"), ("azureedge.net", "Microsoft"), ("trafficmanager.net", "Microsoft"), ("office.net", "Microsoft"), ("live.com", "Microsoft"), ("windowsupdate.com", "Microsoft"), ("msn.com", "Microsoft"), ("bing.com", "Microsoft"), ("office365.com", "Microsoft"), ("microsoftonline.com", "Microsoft"),
        ("cloudflare.com", "Cloudflare"), ("cloudflare.net", "Cloudflare"), ("apple.com", "Apple"), ("icloud.com", "Apple"), ("aaplimg.com", "Apple"),
        ("fbcdn.net", "Meta"), ("facebook.com", "Meta"), ("instagram.com", "Meta"), ("whatsapp.net", "Meta"), ("steamserver.net", "Valve / Steam"), ("steamcontent.com", "Valve / Steam"), ("steampowered.com", "Valve / Steam"),
        ("fastly.net", "Fastly"), ("discord.gg", "Discord"), ("discordapp.com", "Discord"), ("discord.com", "Discord"), ("anthropic.com", "Anthropic"), ("claude.ai", "Anthropic"), ("openai.com", "OpenAI"), ("github.com", "GitHub"), ("githubusercontent.com", "GitHub"), ("mozilla.net", "Mozilla"), ("mozilla.com", "Mozilla"), ("mozilla.org", "Mozilla"), ("teamviewer.com", "TeamViewer"), ("anydesk.com", "AnyDesk"), ("nvidia.com", "NVIDIA"), ("epicgames.com", "Epic Games"), ("oculus.com", "Meta"), ("meta.com", "Meta"),
    ];
    for (suffix, owner) in table {
        if h == *suffix || h.ends_with(&format!(".{suffix}")) {
            return Some(owner);
        }
    }
    None
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
