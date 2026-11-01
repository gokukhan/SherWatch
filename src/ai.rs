//! Built-in analyst assistant. Builds a compact, factual context from the live state
//! (process, alert, connection or the whole picture) and asks a language model to explain
//! it in plain words. Providers:
//!   - a free keyless web model (pollinations.ai) - the default, as the user asked,
//!   - Ollama (local, free, nothing leaves the PC),
//!   - any OpenAI-compatible endpoint (Groq, OpenRouter, Gemini, LM Studio...),
//!   - Anthropic Claude (Messages API over raw HTTP).

use crate::model::Severity;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
pub struct AiStatus {
    pub provider: String,
    pub model: String,
    pub ready: bool,
    pub local: bool,
    pub note: String,
    pub models: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChatTurn {
    pub role: String,
    pub content: String,
}

const SYSTEM_PROMPT: &str = "You are the analyst assistant built into SherWatch Command Center, a Windows network security monitor running on the user's own PC. The user owns the machine and asks what things are. \
Explain, in plain language, what a process, service, connection or alert is, what it is doing, why the monitor flagged it, and finish with a verdict (benign, probably benign, suspicious, or malicious) and one recommended action. \
Use your general knowledge of well-known software, Windows services (svchost hosts services like WpnService, DiagTrack, wuauserv), cloud providers and ports freely, but never invent facts about this specific machine beyond the context given. \
If the evidence is incomplete (for example the monitor was not running as administrator, or no bytes were captured), say so briefly. \
Be concise: usually 4 to 8 short lines, no headings, no markdown tables. Mention rule IDs only when useful.";

fn sev_str(s: Severity) -> &'static str {
    s.as_str()
}

fn rule_hint(rule: &str) -> &'static str {
    match rule.split('-').next().unwrap_or("") {
        "R01" => "destination IP is on a threat-intel blocklist",
        "R02" => "DNS query for a domain on a threat-intel blocklist",
        "R04" => "executable has no valid code signature and talks to the internet",
        "R05" => "executable runs from a user-writable folder (temp, downloads, appdata)",
        "R06" => "living-off-the-land Windows binary with network activity",
        "R07" => "destination port is unusual for normal software",
        "R08" => "process does its own DNS instead of using the Windows resolver",
        "R09" => "connects to the same host at a very regular interval (beaconing)",
        "R10" => "large upload volume",
        "R27" => "uploaded more than the file threshold while not on the approved-uploader list (possible file leaving the PC)",
        "R28" => "uploaded to a file-sharing or paste service",
        "R11" => "DNS traffic pattern typical of tunnelling",
        "R12" => "random-looking (algorithm-generated) domain name",
        "R13" => "first time this executable used the network on this PC",
        "R14" => "opened a listening port",
        "R15" => "hosts file redirects names",
        "R16" => "destination country on the user's watch list",
        "R17" => "many distinct destinations in a short time",
        "R18" => "very long-lived connection",
        "R19" => "launched by an Office app or a script host",
        "R20" => "connected to a public IP with no DNS lookup",
        "R21" => "VirusTotal engines flag the file hash",
        "R22" => "unsigned program accepting incoming connections",
        "R23" => "named like a Windows system process but runs from elsewhere",
        "R24" => "product matches CISA known-exploited vulnerabilities and the file predates the fix",
        "R25" => "Windows updates are stale",
        "R26" => "published CVEs exist for this exact version",
        _ => "",
    }
}

/// Facts about one process, formatted for the model.
pub fn context_process(state: &AppState, pid: u32) -> Option<String> {
    let p = state.procs.get(&pid)?.clone();
    let mut s = String::new();
    s.push_str(&format!("PROCESS {} (pid {})\n", if p.name.is_empty() { "unknown" } else { &p.name }, p.pid));
    if !p.exe.is_empty() {
        s.push_str(&format!("path: {}\n", p.exe));
    }
    if !p.cmdline.is_empty() {
        s.push_str(&format!("command line: {}\n", crate::util::truncate(&p.cmdline, 300)));
    }
    s.push_str(&format!("parent: {} (pid {})\n", if p.parent_name.is_empty() { "unknown" } else { &p.parent_name }, p.parent_pid));
    if !p.user.is_empty() {
        s.push_str(&format!("user: {}\n", p.user));
    }
    if !p.services.is_empty() {
        s.push_str(&format!("hosts Windows services: {}\n", p.services.join(", ")));
    }
    s.push_str(&format!(
        "signature: {:?}{}\n",
        p.meta.sig,
        p.meta.signer.as_ref().map(|x| format!(" by {x}")).unwrap_or_default()
    ));
    if let Some(sha) = &p.meta.sha256 {
        s.push_str(&format!("sha256: {sha}\n"));
    }
    if p.meta.vt_checked {
        s.push_str(&format!("virustotal: {} of {} engines flag it\n", p.meta.vt_positives.unwrap_or(0), p.meta.vt_total.unwrap_or(0)));
    }
    if !p.path_flags.is_empty() {
        s.push_str(&format!("location flags: {}\n", p.path_flags.join(", ")));
    }
    if state.is_trusted(&p.exe, p.meta.sha256.as_deref()) {
        s.push_str("user marked this file as trusted\n");
    }
    // Inventory facts
    {
        let inv = state.inventory.read();
        if let Some(it) = inv.items.get(&format!("app:{}", p.exe.to_ascii_lowercase())) {
            if !it.product.is_empty() || !it.version.is_empty() {
                s.push_str(&format!("product: {} version {} by {}\n", it.product, it.version, it.company));
            }
            if let Some(m) = it.file_mtime {
                s.push_str(&format!("file date: {}\n", chrono::DateTime::from_timestamp_millis(m).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default()));
            }
            for k in it.kev.iter().take(5) {
                s.push_str(&format!("known exploited vulnerability: {} {} {} (catalogued {}, {})\n", k.cve_id, k.vendor, k.product, k.date_added, if k.likely_unpatched { "file predates it" } else { "file is newer" }));
            }
            for c in it.cves.iter().take(5) {
                s.push_str(&format!("cve: {} cvss {} {}\n", c.cve_id, c.cvss.unwrap_or(0.0), crate::util::truncate(&c.summary, 120)));
            }
        }
    }
    s.push_str(&format!(
        "traffic: {} out, {} in, {} connections ({} public), {} listeners, {} DNS queries, risk score {}\n",
        crate::analysis::human(p.bytes_out),
        crate::analysis::human(p.bytes_in),
        p.conn_count,
        p.public_conn_count,
        p.listen_count,
        p.dns_count,
        p.risk
    ));
    let mut conns: Vec<_> = state.conns.iter().filter(|c| c.pid == pid).map(|c| c.clone()).collect();
    conns.sort_by(|a, b| (b.bytes_in + b.bytes_out).cmp(&(a.bytes_in + a.bytes_out)));
    if !conns.is_empty() {
        s.push_str("connections:\n");
        for c in conns.iter().take(15) {
            s.push_str(&format!(
                "- {}:{} {} {}{}{} state {} out {} in {}{}\n",
                c.remote_addr,
                c.remote_port,
                c.proto.as_str(),
                c.hostname.as_deref().unwrap_or(""),
                c.country.as_ref().map(|x| format!(" [{x}]")).unwrap_or_default(),
                c.owner.map(|o| format!(" ({o})")).unwrap_or_default(),
                c.state,
                crate::analysis::human(c.bytes_out),
                crate::analysis::human(c.bytes_in),
                c.intel.as_ref().map(|i| format!(" THREAT-INTEL: {i}")).unwrap_or_default()
            ));
        }
    }
    let listeners: Vec<String> = state.listeners.iter().filter(|l| l.pid == pid).map(|l| format!("{} {}:{}", l.proto.as_str(), l.addr, l.port)).collect();
    if !listeners.is_empty() {
        s.push_str(&format!("listening: {}\n", listeners.join(", ")));
    }
    let dns: Vec<String> = state.dns.read().iter().rev().filter(|d| d.pid == pid).take(10).map(|d| d.query.clone()).collect();
    if !dns.is_empty() {
        s.push_str(&format!("recent DNS queries: {}\n", dns.join(", ")));
    }
    let alerts: Vec<String> = state.alerts.read().iter().rev().filter(|a| a.pid == pid).take(8).map(|a| format!("- [{}] {} ({}: {})", sev_str(a.severity), a.title, a.rule, rule_hint(&a.rule))).collect();
    if !alerts.is_empty() {
        s.push_str("alerts:\n");
        s.push_str(&alerts.join("\n"));
        s.push('\n');
    }
    if !state.etw_active.load(std::sync::atomic::Ordering::Relaxed) {
        s.push_str("note: packet capture inactive (not administrator), byte counts and DNS are unavailable\n");
    }
    Some(s)
}

pub fn context_alert(state: &AppState, id: i64) -> Option<String> {
    let a = state.alerts.read().iter().find(|a| a.id == id)?.clone();
    let mut s = format!(
        "ALERT #{} [{}] rule {} ({})\ntitle: {}\ndetail: {}\nraised {} time(s), first at {}\n",
        a.id,
        sev_str(a.severity),
        a.rule,
        rule_hint(&a.rule),
        a.title,
        a.detail,
        a.count,
        chrono::DateTime::from_timestamp_millis(a.ts).map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default()
    );
    if !a.remote.is_empty() {
        s.push_str(&format!("target: {}\n", a.remote));
    }
    if a.pid > 0 {
        if let Some(pc) = context_process(state, a.pid) {
            s.push_str("\nRelated ");
            s.push_str(&pc);
        } else if !a.exe.is_empty() {
            s.push_str(&format!("process {} ({}) is no longer running\n", a.process, a.exe));
        }
    }
    Some(s)
}

pub fn context_overview(state: &AppState) -> String {
    let o = state.overview();
    let mut s = format!(
        "NETWORK OVERVIEW\nuptime {} min, administrator {}, packet capture {}\n{} connections ({} to the internet), {} processes online, {} listening ports\nrates: {} /s out, {} /s in; session {} out, {} in\ncountries: {}\n",
        (o.now - o.started) / 60_000,
        o.is_admin,
        o.etw_active,
        o.conns,
        o.public_conns,
        o.procs,
        o.listeners,
        crate::analysis::human(o.rate_out),
        crate::analysis::human(o.rate_in),
        crate::analysis::human(o.total_out),
        crate::analysis::human(o.total_in),
        o.countries.iter().map(|(c, n)| format!("{c}:{n}")).collect::<Vec<_>>().join(" ")
    );
    s.push_str("top processes by traffic:\n");
    for t in o.top.iter().take(10) {
        s.push_str(&format!("- {} (pid {}) out {} in {} conns {} risk {}\n", t.name, t.pid, crate::analysis::human(t.bytes_out), crate::analysis::human(t.bytes_in), t.conns, t.risk));
    }
    let alerts = state.alerts.read();
    let open: Vec<_> = alerts.iter().rev().filter(|a| !a.acked).take(20).collect();
    s.push_str(&format!("open alerts ({}):\n", alerts.iter().filter(|a| !a.acked).count()));
    for a in open {
        s.push_str(&format!("- [{}] {} | {} | {} ({})\n", sev_str(a.severity), a.title, a.process, a.rule, rule_hint(&a.rule)));
    }
    drop(alerts);
    let mut risky: Vec<_> = state.procs.iter().filter(|p| p.risk >= 10).map(|p| (p.risk, p.name.clone(), p.exe.clone(), p.meta.sig)).collect();
    risky.sort_by(|a, b| b.0.cmp(&a.0));
    if !risky.is_empty() {
        s.push_str("processes with risk:\n");
        for (r, n, e, sig) in risky.iter().take(10) {
            s.push_str(&format!("- {n} risk {r} sig {sig:?} {e}\n"));
        }
    }
    let inv = state.inventory.read();
    if !inv.os.caption.is_empty() {
        s.push_str(&format!(
            "windows: {} build {}.{} last update {} days ago, {} exploited Windows vulns since\n",
            inv.os.caption,
            inv.os.build,
            inv.os.ubr,
            inv.os.patch_age_days.unwrap_or(-1),
            inv.os.kev_since_patch.len()
        ));
    }
    let unpatched: Vec<String> = inv.items.values().filter(|i| i.kev.iter().any(|k| k.likely_unpatched)).map(|i| format!("{} {}", i.name, i.version)).take(10).collect();
    if !unpatched.is_empty() {
        s.push_str(&format!("software with exploited vulnerabilities and old files: {}\n", unpatched.join("; ")));
    }
    let hosts = state.hosts_issues.read();
    if !hosts.is_empty() {
        s.push_str(&format!("hosts file issues: {}\n", hosts.join("; ")));
    }
    s
}

pub fn context_connection(state: &AppState, pid: u32, remote: &str) -> Option<String> {
    let c = state.conns.iter().find(|c| c.pid == pid && format!("{}:{}", c.remote_addr, c.remote_port) == remote).map(|c| c.clone())?;
    let mut s = format!(
        "CONNECTION {} -> {}:{} {} state {} age {} s out {} in {}\nhostname: {}\nlocation: {} {}{}\n",
        c.local_port,
        c.remote_addr,
        c.remote_port,
        c.proto.as_str(),
        c.state,
        (crate::util::now_ms() - c.first_seen) / 1000,
        crate::analysis::human(c.bytes_out),
        crate::analysis::human(c.bytes_in),
        c.hostname.as_deref().unwrap_or("unknown"),
        c.city.as_deref().unwrap_or(""),
        c.country_name.as_deref().unwrap_or(""),
        c.owner.map(|o| format!(" network owner {o}")).unwrap_or_default()
    );
    if let Some(i) = &c.intel {
        s.push_str(&format!("THREAT INTEL MATCH: {i}\n"));
    }
    if let Some(pc) = context_process(state, pid) {
        s.push_str("\nOwning ");
        s.push_str(&pc);
    }
    Some(s)
}

// ---------- providers ----------

fn cfg(state: &AppState) -> crate::config::AiCfg {
    state.cfg.read().ai.clone()
}

async fn ollama_models(client: &reqwest::Client, base: &str) -> Vec<String> {
    match client.get(format!("{}/api/tags", base.trim_end_matches('/'))).timeout(std::time::Duration::from_secs(3)).send().await {
        Ok(r) => r
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v["models"].as_array().map(|a| a.iter().filter_map(|m| m["name"].as_str().map(|s| s.to_string())).collect()))
            .unwrap_or_default(),
        Err(_) => vec![],
    }
}

fn pick_ollama_model(models: &[String], preferred: &str) -> Option<String> {
    if !preferred.is_empty() && models.iter().any(|m| m == preferred) {
        return Some(preferred.to_string());
    }
    // Prefer general text models over vision or embedding ones.
    let order = ["gemma", "qwen3", "llama3", "mistral", "phi", "qwen", "llama"];
    for key in order {
        if let Some(m) = models.iter().find(|m| m.contains(key) && !m.contains("vision") && !m.contains("embed")) {
            return Some(m.clone());
        }
    }
    models.first().cloned()
}

/// Free, keyless web models (Pollinations.ai, OpenAI-compatible). No account needed.
const FREE_URL: &str = "https://text.pollinations.ai/openai";
const FREE_MODELS: &[(&str, &str)] = &[("openai", "GPT-class, balanced"), ("openai-fast", "GPT-OSS 20B, faster")];

#[derive(Debug, Clone, Serialize)]
pub struct Choice {
    pub id: String,
    pub label: String,
    pub provider: String,
    pub model: String,
    pub local: bool,
    pub ready: bool,
}

/// Every model the user can pick from the dropdown.
pub async fn choices(state: &AppState) -> Vec<Choice> {
    let c = cfg(state);
    let client = reqwest::Client::new();
    let mut out = vec![];
    for (m, desc) in FREE_MODELS {
        out.push(Choice { id: format!("free:{m}"), label: format!("Free web · {m} ({desc}) · no account"), provider: "free".into(), model: m.to_string(), local: false, ready: true });
    }
    let base = if c.base_url.is_empty() || !c.base_url.contains("11434") { "http://127.0.0.1:11434".to_string() } else { c.base_url.clone() };
    for m in ollama_models(&client, &base).await {
        out.push(Choice { id: format!("ollama:{m}"), label: format!("Local Ollama · {m} · offline"), provider: "ollama".into(), model: m.clone(), local: true, ready: true });
    }
    if !c.api_key.trim().is_empty() {
        if c.provider.eq_ignore_ascii_case("anthropic") || c.model.starts_with("claude") {
            let m = if c.model.starts_with("claude") { c.model.clone() } else { "claude-opus-5-5".into() };
            out.push(Choice { id: format!("anthropic:{m}"), label: format!("Anthropic · {m}"), provider: "anthropic".into(), model: m, local: false, ready: true });
        } else if !c.base_url.is_empty() && !c.model.is_empty() {
            out.push(Choice { id: format!("openai:{}", c.model), label: format!("{} · {}", c.base_url, c.model), provider: "openai".into(), model: c.model.clone(), local: false, ready: true });
        }
    }
    out
}

pub async fn status_for(state: &AppState, override_provider: Option<&str>, override_model: Option<&str>) -> AiStatus {
    let c = cfg(state);
    let client = reqwest::Client::new();
    let provider = override_provider.map(|p| p.to_ascii_lowercase()).unwrap_or_else(|| c.provider.to_ascii_lowercase());
    let wanted_model = override_model.map(|m| m.to_string()).unwrap_or_else(|| c.model.clone());
    if provider == "off" {
        return AiStatus { provider: "off".into(), model: String::new(), ready: false, local: true, note: "Assistant disabled in config.toml ([ai] provider = \"off\").".into(), models: vec![] };
    }
    if provider == "auto" || provider == "free" {
        let model = if FREE_MODELS.iter().any(|(m, _)| *m == wanted_model) { wanted_model } else { FREE_MODELS[0].0.to_string() };
        return AiStatus {
            provider: "free".into(),
            model,
            ready: true,
            local: false,
            note: "Free web model (pollinations.ai), no account needed. The context (process names, hosts, alerts) is sent to that service.".into(),
            models: FREE_MODELS.iter().map(|(m, _)| m.to_string()).collect(),
        };
    }
    if provider == "ollama" {
        let base = if c.base_url.is_empty() || !c.base_url.contains("11434") { "http://127.0.0.1:11434".to_string() } else { c.base_url.clone() };
        let models = ollama_models(&client, &base).await;
        if !models.is_empty() {
            let model = pick_ollama_model(&models, &wanted_model).unwrap_or_default();
            return AiStatus { provider: "ollama".into(), model, ready: true, local: true, note: "Local model via Ollama. Nothing leaves this PC.".into(), models };
        }
        return AiStatus { provider: "ollama".into(), model: wanted_model, ready: false, local: true, note: format!("Ollama is not responding at {base}. Start the Ollama app, or run `ollama serve`, then pull a model such as `ollama pull gemma3`."), models: vec![] };
    }
    if provider == "anthropic" {
        if c.api_key.trim().is_empty() {
            return AiStatus { provider: "anthropic".into(), model: String::new(), ready: false, local: false, note: "Set [ai] api_key in config.toml to use the Anthropic API.".into(), models: vec![] };
        }
        let model = if c.model.is_empty() || !c.model.starts_with("claude") { "claude-opus-5-5".to_string() } else { c.model.clone() };
        return AiStatus { provider: "anthropic".into(), model, ready: true, local: false, note: "Anthropic Claude API. The context (process names, hosts, alerts) is sent to Anthropic.".into(), models: vec![] };
    }
    if provider == "openai" {
        let ready = !c.api_key.trim().is_empty() && !c.base_url.is_empty() && !c.model.is_empty();
        return AiStatus { provider: "openai".into(), model: c.model.clone(), ready, local: c.base_url.contains("127.0.0.1") || c.base_url.contains("localhost"), note: if ready { format!("OpenAI-compatible endpoint {}. The context is sent there.", c.base_url) } else { "Set [ai] base_url, model and api_key in config.toml for an OpenAI-compatible service (Groq, OpenRouter, Gemini, LM Studio).".into() }, models: vec![] };
    }
    AiStatus { provider: provider.clone(), model: String::new(), ready: false, local: true, note: format!("Unknown provider '{provider}'. Use free, ollama, openai, anthropic or off."), models: vec![] }
}

/// Ask a model. `history` carries earlier turns of the same chat; `provider`/`model` override config for this call.
pub async fn ask(state: Arc<AppState>, context: String, question: String, history: Vec<ChatTurn>, provider: Option<String>, model: Option<String>) -> Result<(String, AiStatus), String> {
    let st = status_for(&state, provider.as_deref(), model.as_deref()).await;
    if !st.ready {
        return Err(st.note.clone());
    }
    let c = cfg(&state);
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(180)).build().map_err(|e| e.to_string())?;
    let user = format!("{context}\n\nQUESTION: {question}");
    let mut msgs: Vec<serde_json::Value> = history
        .iter()
        .filter(|t| t.role == "user" || t.role == "assistant")
        .map(|t| serde_json::json!({"role": t.role, "content": t.content}))
        .collect();
    msgs.push(serde_json::json!({"role": "user", "content": user}));
    let started = std::time::Instant::now();
    let answer = match st.provider.as_str() {
        "free" => {
            let mut all = vec![serde_json::json!({"role": "system", "content": SYSTEM_PROMPT})];
            all.extend(msgs);
            let body = serde_json::json!({"model": st.model, "messages": all, "temperature": 0.2, "private": true});
            let r = client.post(FREE_URL).header("content-type", "application/json").json(&body).send().await.map_err(|e| format!("free model request failed: {e}"))?;
            let status_code = r.status();
            let text = r.text().await.map_err(|e| format!("free model returned nothing: {e}"))?;
            if !status_code.is_success() {
                return Err(format!("free model service answered HTTP {status_code}: {}", crate::util::truncate(&text, 200)));
            }
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(v) => v["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string(),
                Err(_) => text,
            }
        }
        "ollama" => {
            let base = if c.base_url.is_empty() { "http://127.0.0.1:11434".to_string() } else { c.base_url.clone() };
            let mut all = vec![serde_json::json!({"role": "system", "content": SYSTEM_PROMPT})];
            all.extend(msgs);
            let body = serde_json::json!({"model": st.model, "messages": all, "stream": false, "think": false, "options": {"temperature": 0.2, "num_ctx": 8192}});
            let r = client.post(format!("{}/api/chat", base.trim_end_matches('/'))).json(&body).send().await.map_err(|e| format!("Ollama request failed: {e}"))?;
            let v: serde_json::Value = r.json().await.map_err(|e| format!("Ollama returned no JSON: {e}"))?;
            if let Some(err) = v["error"].as_str() {
                return Err(format!("Ollama: {err}"));
            }
            v["message"]["content"].as_str().unwrap_or("").to_string()
        }
        "anthropic" => {
            let body = serde_json::json!({
                "model": st.model,
                "max_tokens": 2048,
                "system": SYSTEM_PROMPT,
                "messages": msgs,
                "output_config": {"effort": "low"},
                "fallbacks": "default"
            });
            let r = client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", c.api_key.trim())
                .header("anthropic-version", "2026-10-21")
                .header("anthropic-beta", "server-side-fallback-2026-07-01")
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("Anthropic request failed: {e}"))?;
            let status_code = r.status();
            let v: serde_json::Value = r.json().await.map_err(|e| format!("Anthropic returned no JSON: {e}"))?;
            if !status_code.is_success() {
                return Err(format!("Anthropic API {}: {}", status_code, v["error"]["message"].as_str().unwrap_or("unknown error")));
            }
            if v["stop_reason"].as_str() == Some("refusal") {
                return Err("The model declined to answer this request.".into());
            }
            v["content"].as_array().map(|a| a.iter().filter(|b| b["type"] == "text").filter_map(|b| b["text"].as_str()).collect::<Vec<_>>().join("")).unwrap_or_default()
        }
        _ => {
            let mut all = vec![serde_json::json!({"role": "system", "content": SYSTEM_PROMPT})];
            all.extend(msgs);
            let body = serde_json::json!({"model": st.model, "messages": all, "temperature": 0.2});
            let r = client
                .post(format!("{}/chat/completions", c.base_url.trim_end_matches('/').trim_end_matches("/v1").to_string() + "/v1"))
                .bearer_auth(c.api_key.trim())
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("request failed: {e}"))?;
            let status_code = r.status();
            let v: serde_json::Value = r.json().await.map_err(|e| format!("no JSON: {e}"))?;
            if !status_code.is_success() {
                return Err(format!("API {}: {}", status_code, v["error"]["message"].as_str().unwrap_or("unknown error")));
            }
            v["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string()
        }
    };
    tracing::info!("ai answer via {} {} in {} ms", st.provider, st.model, started.elapsed().as_millis());
    Ok((answer.trim().to_string(), st))
}
