//! Response actions: terminate a process, block an executable or IP with Windows Firewall.

use crate::db::DbMsg;
use crate::state::AppState;
use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = crate::util::quiet(Command::new(cmd).args(args).stdin(std::process::Stdio::null())).output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!("{}{}", stdout.trim(), stderr.trim()))
    }
}

/// Record a response action in the audit log (Settings > Action log), successful or not.
pub fn audit(state: &AppState, action: &str, target: &str, detail: serde_json::Value, result: &Result<String, String>, revert_of: Option<i64>) {
    state.db.send(DbMsg::Audit(crate::db::AuditEntry {
        id: 0,
        ts: crate::util::now_ms(),
        action: action.into(),
        target: target.into(),
        detail: detail.to_string(),
        ok: result.is_ok(),
        result: match result {
            Ok(m) => m.clone(),
            Err(e) => e.clone(),
        },
        reverted_ts: None,
        revert_of,
    }));
}

pub fn kill_process(pid: u32) -> Result<String, String> {
    if pid <= 4 {
        return Err("refusing to terminate a core system process".into());
    }
    run("taskkill", &["/PID", &pid.to_string(), "/F", "/T"]).map(|s| s.trim().to_string())
}

/// Current rule prefix plus the one used before the project was renamed, so old rules stay manageable.
const RULE_PREFIXES: [&str; 2] = ["SherWatch block ", "NetMonitor block "];
fn is_our_rule(name: &str) -> bool {
    RULE_PREFIXES.iter().any(|p| name.starts_with(p))
}

fn rule_name(kind: &str, target: &str) -> String {
    let short: String = target.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').take(60).collect();
    format!("SherWatch block {kind} {short}")
}

/// The firewall rule name SherWatch uses for an executable (a short hash of the full path keeps two
/// programs with the same file name apart).
pub fn exe_rule_name(exe: &str) -> String {
    let digest = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(exe.to_ascii_lowercase().as_bytes()))[..8].to_string()
    };
    rule_name("app", &format!("{} {digest}", std::path::Path::new(exe).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default()))
}

/// Names of the SherWatch rules that actually exist in Windows Firewall right now (outbound direction;
/// the inbound twin is created and deleted together with it).
pub fn firewall_rules() -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if let Ok(out) = run("netsh", &["advfirewall", "firewall", "show", "rule", "name=all", "dir=out"]) {
        for line in out.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("Rule Name:") {
                let name = rest.trim();
                if is_our_rule(name) {
                    set.insert(name.to_string());
                }
            }
        }
    }
    set
}

pub fn block_exe(state: &AppState, exe: &str) -> Result<String, String> {
    if exe.is_empty() || !std::path::Path::new(exe).exists() {
        return Err("executable path not found".into());
    }
    let rule = exe_rule_name(exe);
    for dir in ["out", "in"] {
        run(
            "netsh",
            &["advfirewall", "firewall", "add", "rule", &format!("name={rule}"), &format!("dir={dir}"), "action=block", &format!("program={exe}"), "enable=yes", "profile=any"],
        )?;
    }
    state.db.send(DbMsg::Block { kind: "app".into(), target: exe.to_string(), rule: rule.clone(), ts: crate::util::now_ms() });
    Ok(rule)
}

pub fn block_ip(state: &AppState, ip: &str) -> Result<String, String> {
    let parsed: std::net::IpAddr = ip.parse().map_err(|_| "invalid IP address".to_string())?;
    let rule = rule_name("ip", &parsed.to_string());
    for dir in ["out", "in"] {
        run(
            "netsh",
            &["advfirewall", "firewall", "add", "rule", &format!("name={rule}"), &format!("dir={dir}"), "action=block", &format!("remoteip={parsed}"), "enable=yes", "profile=any"],
        )?;
    }
    state.db.send(DbMsg::Block { kind: "ip".into(), target: parsed.to_string(), rule: rule.clone(), ts: crate::util::now_ms() });
    Ok(rule)
}

pub fn unblock(state: &AppState, rule: &str) -> Result<String, String> {
    if !is_our_rule(rule) {
        return Err("not a SherWatch rule".into());
    }
    let r = run("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={rule}")]);
    state.db.send(DbMsg::Unblock { rule: rule.to_string() });
    r.map(|s| s.trim().to_string())
}
