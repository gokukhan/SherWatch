//! Response actions: terminate a process, block an executable or IP in the firewall.
//! The rule naming and the audit / block records are shared; the firewall itself is
//! Windows Defender Firewall (netsh), pf (macOS) or nftables / iptables (Linux), see `crate::platform`.

use crate::db::DbMsg;
use crate::state::AppState;

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
    crate::platform::kill_process(pid)
}

/// Current rule prefix plus the one used before the project was renamed, so old rules stay manageable.
const RULE_PREFIXES: [&str; 2] = ["SherWatch block ", "NetMonitor block "];
pub(crate) fn is_our_rule(name: &str) -> bool {
    RULE_PREFIXES.iter().any(|p| name.starts_with(p))
}

pub(crate) fn rule_name(kind: &str, target: &str) -> String {
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

/// Names of the SherWatch rules that actually exist in the firewall right now, or None when the
/// firewall cannot be read without a privilege prompt (then every recorded rule is assumed present).
pub fn firewall_rules() -> Option<std::collections::HashSet<String>> {
    crate::platform::firewall_rules()
}

pub fn block_exe(state: &AppState, exe: &str) -> Result<String, String> {
    if exe.is_empty() || !std::path::Path::new(exe).exists() {
        return Err("executable path not found".into());
    }
    let rule = exe_rule_name(exe);
    crate::platform::firewall_block_exe(&rule, exe)?;
    state.db.send(DbMsg::Block { kind: "app".into(), target: exe.to_string(), rule: rule.clone(), ts: crate::util::now_ms() });
    Ok(rule)
}

pub fn block_ip(state: &AppState, ip: &str) -> Result<String, String> {
    let parsed: std::net::IpAddr = ip.parse().map_err(|_| "invalid IP address".to_string())?;
    let rule = rule_name("ip", &parsed.to_string());
    crate::platform::firewall_block_ip(&rule, parsed)?;
    state.db.send(DbMsg::Block { kind: "ip".into(), target: parsed.to_string(), rule: rule.clone(), ts: crate::util::now_ms() });
    Ok(rule)
}

pub fn unblock(state: &AppState, rule: &str) -> Result<String, String> {
    if !is_our_rule(rule) {
        return Err("not a SherWatch rule".into());
    }
    let r = crate::platform::firewall_unblock(rule);
    state.db.send(DbMsg::Unblock { rule: rule.to_string() });
    r.map(|s| s.trim().to_string())
}
