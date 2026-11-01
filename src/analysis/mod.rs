//! Rule engine. Runs every two seconds over the live state and raises alerts.
//! Rule IDs (R01..R23) are documented in docs/DETECTION-RULES.md.

use crate::model::{Proto, Severity, SigStatus};
use crate::state::AppState;
use crate::util::{self, now_ms};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

pub fn start(state: Arc<AppState>) {
    let s2 = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            tick.tick().await;
            let st = s2.clone();
            let _ = tokio::task::spawn_blocking(move || run_rules(&st)).await;
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tick.tick().await;
            check_hosts_file(&state);
        }
    });
}

const SUSPICIOUS_PORTS: &[(u16, &str, Severity)] = &[
    (445, "SMB", Severity::High),
    (139, "NetBIOS session", Severity::High),
    (135, "RPC endpoint mapper", Severity::Medium),
    (3389, "RDP", Severity::Medium),
    (23, "Telnet", Severity::High),
    (21, "FTP (clear text)", Severity::Low),
    (6667, "IRC", Severity::High),
    (6668, "IRC", Severity::High),
    (6669, "IRC", Severity::High),
    (4444, "Metasploit default", Severity::High),
    (1337, "elite", Severity::Medium),
    (31337, "elite", Severity::High),
    (5900, "VNC", Severity::Medium),
    (5938, "TeamViewer", Severity::Low),
    (1080, "SOCKS proxy", Severity::Medium),
    (9050, "Tor SOCKS", Severity::High),
    (9150, "Tor browser SOCKS", Severity::High),
    (9001, "Tor relay", Severity::High),
    (3333, "mining pool", Severity::Medium),
    (14444, "mining pool", Severity::Medium),
    (5555, "ADB / mining", Severity::Medium),
    (25, "SMTP", Severity::Medium),
    (587, "SMTP submission", Severity::Low),
    (1433, "MSSQL", Severity::Medium),
    (3306, "MySQL", Severity::Medium),
    (5432, "PostgreSQL", Severity::Medium),
    (6379, "Redis", Severity::Medium),
    (27017, "MongoDB", Severity::Medium),
    (2375, "Docker API", Severity::High),
    (5985, "WinRM", Severity::Medium),
    (5986, "WinRM TLS", Severity::Medium),
    (22, "SSH", Severity::Low),
];

const MAIL_CLIENTS: &[&str] = &["outlook.exe", "thunderbird.exe", "olk.exe", "hxoutlook.exe", "mailspring.exe", "em client.exe"];
const BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe", "msedgewebview2.exe", "chromium.exe"];
const DNS_SERVICES: &[&str] = &["svchost.exe", "system", "dnscache", "nscd", "unbound.exe", "dnscrypt-proxy.exe", "cloudflared.exe", "adguard.exe", "adguardsvc.exe", "pihole", "nextdns.exe", "nextdnsservice.exe", "acrylic", "simpledns", "dnsproxy.exe", "mullvad-daemon.exe", "warp-svc.exe"];

struct ProcSnap {
    pid: u32,
    name: String,
    lname: String,
    exe: String,
    parent_name: String,
    flags: Vec<String>,
    sig: SigStatus,
    info_loaded: bool,
    out_60: u64,
    out_300: u64,
    in_60: u64,
    first_net_seen: i64,
}

fn run_rules(state: &AppState) {
    let now = now_ms();
    let cfg = &state.cfg.analysis;
    let uptime = now - state.started;
    let etw = state.etw_active.load(std::sync::atomic::Ordering::Relaxed);

    let procs: HashMap<u32, ProcSnap> = state
        .procs
        .iter()
        .map(|p| {
            (
                p.pid,
                ProcSnap {
                    pid: p.pid,
                    name: p.name.clone(),
                    lname: p.name.to_ascii_lowercase(),
                    exe: p.exe.clone(),
                    parent_name: p.parent_name.to_ascii_lowercase(),
                    flags: p.path_flags.clone(),
                    sig: p.meta.sig,
                    info_loaded: p.info_loaded,
                    out_60: p.out_last(60),
                    out_300: p.out_last(300),
                    in_60: p.in_last(60),
                    first_net_seen: p.first_net_seen,
                },
            )
        })
        .collect();

    // ---- per-connection rules ----
    let conns: Vec<_> = state.conns.iter().map(|c| c.clone()).collect();
    let mut per_proc_public: HashMap<u32, usize> = HashMap::new();
    for c in &conns {
        if c.scope != "public" {
            continue;
        }
        *per_proc_public.entry(c.pid).or_default() += 1;
        let Some(p) = procs.get(&c.pid) else { continue };
        let remote = format!("{}:{}", c.remote_addr, c.remote_port);
        let host = c.hostname.clone().unwrap_or_default();
        let where_ = if host.is_empty() { remote.clone() } else { format!("{host} ({remote})") };
        let label = if p.name.is_empty() { format!("pid {}", p.pid) } else { p.name.clone() };

        // R01 threat-intel IP
        if let Some(src) = &c.intel {
            state.push_alert(
                Severity::Critical,
                "R01-intel-ip",
                format!("{label} is talking to a known malicious host"),
                format!("{where_} is listed by {src}. Country: {}.", c.country_name.clone().unwrap_or_else(|| "unknown".into())),
                p.pid,
                &remote,
            );
        }

        if !p.info_loaded {
            continue;
        }

        // R04 unsigned / invalid signature talking to the internet
        // (Store apps under WindowsApps are signed at package level, not per file.)
        let store_app = p.flags.iter().any(|f| f == "store-app");
        if matches!(p.sig, SigStatus::NotSigned | SigStatus::Invalid) && !(store_app && p.sig == SigStatus::NotSigned) {
            let sev = if p.sig == SigStatus::Invalid || util::is_user_writable_location(&p.flags) { Severity::High } else { Severity::Medium };
            state.push_alert(
                sev,
                "R04-unsigned",
                format!("Unsigned program {label} is sending data to the internet"),
                format!("{} ({}) connected to {where_}.", p.exe, if p.sig == SigStatus::Invalid { "invalid signature" } else { "not signed" }),
                p.pid,
                "",
            );
        }

        // R05 suspicious executable location
        if util::is_user_writable_location(&p.flags) {
            state.push_alert(
                Severity::High,
                "R05-suspicious-path",
                format!("{label} runs from a user-writable location and uses the network"),
                format!("{} [{}] connected to {where_}.", p.exe, p.flags.join(", ")),
                p.pid,
                "",
            );
        }

        // R06 LOLBin with network activity
        if util::LOLBINS.contains(&p.lname.as_str()) {
            state.push_alert(
                Severity::High,
                "R06-lolbin",
                format!("Living-off-the-land binary {label} is using the network"),
                format!("{} is a Windows tool often abused to download or run payloads. It connected to {where_}.", p.exe),
                p.pid,
                &remote,
            );
        }

        // R07 suspicious destination port
        if let Some((_, svc, sev)) = SUSPICIOUS_PORTS.iter().find(|(port, _, _)| *port == c.remote_port) {
            let mail_ok = (c.remote_port == 25 || c.remote_port == 587) && MAIL_CLIENTS.contains(&p.lname.as_str());
            let ssh_ok = c.remote_port == 22 && matches!(p.lname.as_str(), "ssh.exe" | "putty.exe" | "winscp.exe" | "git.exe" | "code.exe" | "kitty.exe" | "mobaxterm.exe");
            let rdp_ok = c.remote_port == 3389 && p.lname == "mstsc.exe";
            let vendor_ok = (c.remote_port == 5938 && p.lname.contains("teamviewer")) || (c.remote_port == 5900 && p.lname.contains("vnc"));
            if !mail_ok && !ssh_ok && !rdp_ok && !vendor_ok {
                state.push_alert(
                    *sev,
                    "R07-port",
                    format!("{label} connected to a {svc} port on the internet"),
                    format!("Outbound {} to {where_} (port {}, {svc}).", c.proto.as_str(), c.remote_port),
                    p.pid,
                    &remote,
                );
            }
        }

        // R08 direct DNS to an outside resolver (bypasses the system resolver)
        if (c.remote_port == 53 || c.remote_port == 853) && !DNS_SERVICES.iter().any(|d| p.lname.contains(d)) && !BROWSERS.contains(&p.lname.as_str()) {
            state.push_alert(
                Severity::Medium,
                "R08-direct-dns",
                format!("{label} is doing its own DNS to {}", c.remote_addr),
                format!("Port {} traffic to {where_} bypasses the Windows resolver, which hides the names it looks up.", c.remote_port),
                p.pid,
                &remote,
            );
        }

        // R16 watch-list country
        if let Some(cc) = &c.country {
            if cfg.watch_countries.iter().any(|w| w.eq_ignore_ascii_case(cc)) {
                state.push_alert(
                    Severity::Low,
                    "R16-watch-country",
                    format!("{label} connected to {}", c.country_name.clone().unwrap_or(cc.clone())),
                    format!("{where_} is in {} which is on your watch list.", c.country_name.clone().unwrap_or(cc.clone())),
                    p.pid,
                    &remote,
                );
            }
        }

        // R18 very long-lived session
        if c.proto == Proto::Tcp && now - c.first_seen > 6 * 3600_000 && c.remote_port != 443 && c.remote_port != 80 {
            state.push_alert(
                Severity::Low,
                "R18-long-session",
                format!("{label} has kept a session open for over 6 hours"),
                format!("Connection to {where_} started {} hours ago.", (now - c.first_seen) / 3600_000),
                p.pid,
                &remote,
            );
        }

        // R20 hard-coded IP: unsigned process, public IP, no DNS query seen (needs ETW DNS capture)
        if etw && uptime > 120_000 && c.hostname.is_none() && !state.dns_seen_ips.contains(&c.remote_addr)
            && matches!(p.sig, SigStatus::NotSigned | SigStatus::Invalid) && now - c.first_seen > 5_000
        {
            state.push_alert(
                Severity::Medium,
                "R20-hardcoded-ip",
                format!("{label} connected to an IP without any DNS lookup"),
                format!("No DNS query explains {remote}. Malware often embeds its server address directly."),
                p.pid,
                &remote,
            );
        }

        // R23 system process name running from the wrong place
        if util::SYSTEM_NAMES.contains(&p.lname.as_str()) && !p.flags.iter().any(|f| f == "system" || f == "windows") && !p.exe.is_empty() {
            state.push_alert(
                Severity::Critical,
                "R23-masquerade",
                format!("{label} is impersonating a Windows system process"),
                format!("A process named {} is running from {} instead of C:\\Windows and connected to {where_}.", p.name, p.exe),
                p.pid,
                "",
            );
        }

        // R19 suspicious parent
        if util::OFFICE_APPS.contains(&p.parent_name.as_str()) && !BROWSERS.contains(&p.lname.as_str()) && !util::OFFICE_APPS.contains(&p.lname.as_str()) {
            state.push_alert(
                Severity::High,
                "R19-office-child",
                format!("{label} was launched by {} and is using the network", p.parent_name),
                format!("Office documents that spawn network-active children are a classic macro / exploit chain. Destination {where_}."),
                p.pid,
                "",
            );
        }
        if util::SCRIPT_HOSTS.contains(&p.parent_name.as_str()) && util::is_user_writable_location(&p.flags) {
            state.push_alert(
                Severity::High,
                "R19-script-child",
                format!("{label} was started by {} from a user-writable folder", p.parent_name),
                format!("{} connected to {where_}.", p.exe),
                p.pid,
                "",
            );
        }
    }

    // ---- per-process rules ----
    for p in procs.values() {
        let label = if p.name.is_empty() { format!("pid {}", p.pid) } else { p.name.clone() };
        let public = per_proc_public.get(&p.pid).copied().unwrap_or(0);

        // R10 exfiltration volume
        if public > 0 && p.out_60 >= cfg.exfil_bytes_per_minute {
            let sev = if p.out_60 > p.in_60 * 5 { Severity::High } else { Severity::Medium };
            state.push_alert(
                sev,
                "R10-exfil",
                format!("{label} uploaded {} in the last minute", human(p.out_60)),
                format!("{} sent {} out and received {} in 60 s across {public} public connections.", p.exe, human(p.out_60), human(p.in_60)),
                p.pid,
                "",
            );
        } else if public > 0 && p.out_300 >= cfg.exfil_bytes_per_5min {
            state.push_alert(
                Severity::High,
                "R10-exfil-sustained",
                format!("{label} uploaded {} in five minutes", human(p.out_300)),
                format!("{} is sustaining a large upload.", p.exe),
                p.pid,
                "",
            );
        }

        // R17 many distinct destinations
        if let Some(w) = state.dst_window.get(&p.pid) {
            let distinct: HashSet<_> = w.iter().map(|(_, ip)| *ip).collect();
            if distinct.len() >= cfg.many_destinations_threshold && !BROWSERS.contains(&p.lname.as_str()) {
                state.push_alert(
                    Severity::Medium,
                    "R17-many-destinations",
                    format!("{label} contacted {} different hosts in one minute", distinct.len()),
                    format!("Fan-out like this looks like scanning, spraying or a peer-to-peer client. {}", p.exe),
                    p.pid,
                    "",
                );
            }
        }

        // R14 new listener from a non-system process
        for l in state.listeners.iter() {
            if l.pid != p.pid || now - l.first_seen > 90_000 || uptime < 15_000 || !p.info_loaded || p.sig == SigStatus::Pending {
                continue;
            }
            if l.addr.is_loopback() {
                continue;
            }
            // Local discovery protocols (mDNS, SSDP, LLMNR, WS-Discovery, NetBIOS, DHCP) are normal client behaviour.
            let discovery = l.proto == Proto::Udp && matches!(l.port, 5353 | 1900 | 5355 | 3702 | 137 | 138 | 67 | 68 | 5050 | 1024..=1030);
            let suspicious = util::is_user_writable_location(&p.flags) || p.sig != SigStatus::Valid;
            if (p.flags.iter().any(|f| f == "system") && p.sig == SigStatus::Valid) || (discovery && !suspicious) {
                continue;
            }
            let sev = if suspicious { Severity::High } else if l.proto == Proto::Udp { Severity::Info } else { Severity::Low };
            state.push_alert(
                sev,
                "R14-new-listener",
                format!("{label} opened a listening port {}/{}", l.proto.as_str(), l.port),
                format!("{} now accepts incoming connections on {}:{}. Backdoors and remote-access tools do this.", p.exe, l.addr, l.port),
                p.pid,
                &format!("{}:{}", l.addr, l.port),
            );
        }
        let _ = p.first_net_seen;
    }

    // ---- R09 beaconing ----
    for b in state.beacons.iter() {
        let (pid, ip) = *b.key();
        let times = b.value();
        if times.len() < cfg.beacon_min_intervals + 1 {
            continue;
        }
        let recent: Vec<i64> = times.iter().rev().take(24).copied().collect::<Vec<_>>().into_iter().rev().collect();
        let intervals: Vec<f64> = recent.windows(2).map(|w| (w[1] - w[0]) as f64 / 1000.0).collect();
        if intervals.len() < cfg.beacon_min_intervals {
            continue;
        }
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if !(5.0..=3600.0).contains(&mean) {
            continue;
        }
        let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let cv = var.sqrt() / mean;
        if cv <= cfg.beacon_max_cv {
            let Some(p) = procs.get(&pid) else { continue };
            if BROWSERS.contains(&p.lname.as_str()) {
                continue;
            }
            let label = if p.name.is_empty() { format!("pid {}", p.pid) } else { p.name.clone() };
            let host = state.ip_to_host.get(&ip).map(|h| h.clone()).unwrap_or_default();
            state.push_alert(
                Severity::High,
                "R09-beacon",
                format!("{label} is beaconing to {} every {:.0} s", if host.is_empty() { ip.to_string() } else { host.clone() }, mean),
                format!("{} new connections to {ip} at a very regular interval (jitter {:.0}%). Command-and-control implants check in like this.", intervals.len() + 1, cv * 100.0),
                pid,
                &ip.to_string(),
            );
        }
    }

    // ---- DNS rules (R11 tunnelling, R12 DGA) ----
    for w in state.dns_windows.iter() {
        let (pid, base) = w.key().clone();
        let ev = &w.value().events;
        if ev.is_empty() {
            continue;
        }
        let Some(p) = procs.get(&pid) else { continue };
        let label = if p.name.is_empty() { format!("pid {}", p.pid) } else { p.name.clone() };
        let n = ev.len();
        let unique: HashSet<&String> = ev.iter().map(|(_, q, _, _)| q).collect();
        let avg_len = ev.iter().map(|(_, q, _, _)| q.len() as f64).sum::<f64>() / n as f64;
        let txt = ev.iter().filter(|(_, _, t, _)| *t == 16 || *t == 10).count();
        let nx = ev.iter().filter(|(_, _, _, s)| *s == 9003 || *s == 9701).count();
        let longest_label = ev.iter().flat_map(|(_, q, _, _)| q.split('.')).map(|l| l.len()).max().unwrap_or(0);
        if (unique.len() >= 30 && avg_len >= 40.0) || txt >= 20 || longest_label >= 52 || (unique.len() >= 40 && n >= 40 && nx as f64 / n as f64 > 0.6) {
            state.push_alert(
                Severity::High,
                "R11-dns-tunnel",
                format!("{label} shows DNS tunnelling patterns under {base}"),
                format!("{} unique names, average length {avg_len:.0}, {txt} TXT/NULL queries, {nx} NXDOMAIN, longest label {longest_label} in 5 minutes.", unique.len()),
                pid,
                &base,
            );
        }
        // DGA: look at the newest query's registrable label
        if let Some((_, q, _, status)) = ev.back() {
            let label2 = base.split('.').next().unwrap_or("");
            if label2.len() >= 12 {
                let ent = util::shannon_entropy(label2);
                let vr = util::vowel_ratio(label2);
                let dr = util::digit_ratio(label2);
                if (ent >= 3.6 && vr < 0.22) || (ent >= 3.9 && dr > 0.3) {
                    let sev = if *status == 9003 { Severity::Medium } else { Severity::Low };
                    state.push_alert(
                        sev,
                        "R12-dga",
                        format!("{label} looked up an algorithm-like domain {q}"),
                        format!("Entropy {ent:.2}, vowel ratio {vr:.2}. Random-looking domains are typical of malware that generates its server names."),
                        pid,
                        &base,
                    );
                }
            }
        }
    }

    // ---- R22 inbound accepts on an unexpected process ----
    for a in state.inbound_accepts.iter() {
        let (pid, n) = (*a.key(), *a.value());
        if n < 1 {
            continue;
        }
        let Some(p) = procs.get(&pid) else { continue };
        if p.sig == SigStatus::Valid || !p.info_loaded {
            continue;
        }
        if util::is_user_writable_location(&p.flags) {
            let label = if p.name.is_empty() { format!("pid {}", p.pid) } else { p.name.clone() };
            state.push_alert(
                Severity::High,
                "R22-inbound-unsigned",
                format!("{label} accepted {n} incoming connections"),
                format!("An unsigned program in a user-writable folder ({}) is acting as a server.", p.exe),
                pid,
                "",
            );
        }
    }

    // Risk score on each live connection from its process.
    let risk: HashMap<u32, u32> = state.procs.iter().map(|p| (p.pid, p.risk)).collect();
    for mut c in state.conns.iter_mut() {
        let mut r = risk.get(&c.pid).copied().unwrap_or(0);
        if c.intel.is_some() {
            r = r.max(90);
        }
        c.risk = r.min(100);
    }
}

fn check_hosts_file(state: &AppState) {
    let path = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()) + "\\System32\\drivers\\etc\\hosts";
    let Ok(body) = std::fs::read_to_string(&path) else { return };
    let mut issues = vec![];
    for line in body.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let mut it = l.split_whitespace();
        let (Some(ip), Some(host)) = (it.next(), it.next()) else { continue };
        let hl = host.to_ascii_lowercase();
        let benign = hl == "localhost" || hl.ends_with(".localdomain") || hl == "broadcasthost" || hl.ends_with(".local");
        let loop_ip = ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0";
        // Redirecting a real site to a non-loopback IP is the dangerous case; blocking (0.0.0.0) is common for ad blockers.
        if !benign && !loop_ip {
            issues.push(format!("{host} -> {ip}"));
        } else if !benign && (hl.contains("microsoft") || hl.contains("windowsupdate") || hl.contains("defender") || hl.contains("virustotal") || hl.contains("avast") || hl.contains("kaspersky") || hl.contains("norton") || hl.contains("mcafee") || hl.contains("bitdefender") || hl.contains("eset")) {
            issues.push(format!("{host} -> {ip} (security vendor blocked)"));
        }
    }
    let changed = *state.hosts_issues.read() != issues;
    *state.hosts_issues.write() = issues.clone();
    if !issues.is_empty() && changed {
        state.push_alert(
            Severity::High,
            "R15-hosts-file",
            format!("hosts file redirects {} name(s)", issues.len()),
            format!("{} contains: {}", path, issues.iter().take(8).cloned().collect::<Vec<_>>().join("; ")),
            0,
            "hosts",
        );
    }
}

pub fn human(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < 4 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.1} {}", U[i]) }
}
