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

pub fn kill_process(pid: u32) -> Result<String, String> {
    if pid <= 4 {
        return Err("refusing to terminate a core system process".into());
    }
    run("taskkill", &["/PID", &pid.to_string(), "/F", "/T"]).map(|s| s.trim().to_string())
}

fn rule_name(kind: &str, target: &str) -> String {
    let short: String = target.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').take(60).collect();
    format!("NetMonitor block {kind} {short}")
}

pub fn block_exe(state: &AppState, exe: &str) -> Result<String, String> {
    if exe.is_empty() || !std::path::Path::new(exe).exists() {
        return Err("executable path not found".into());
    }
    // Include a short hash of the full path so two programs with the same file name get distinct rules.
    let digest = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(exe.to_ascii_lowercase().as_bytes()))[..8].to_string()
    };
    let rule = rule_name("app", &format!("{} {digest}", std::path::Path::new(exe).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default()));
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
    if !rule.starts_with("NetMonitor block ") {
        return Err("not a NetMonitor rule".into());
    }
    let r = run("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={rule}")]);
    state.db.send(DbMsg::Unblock { rule: rule.to_string() });
    r.map(|s| s.trim().to_string())
}
