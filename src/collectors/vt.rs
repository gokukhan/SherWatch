//! Optional VirusTotal hash lookups. Only the SHA-256 of an unsigned executable is sent,
//! never the file. Free keys allow 4 requests a minute, so lookups are spaced out.

use crate::model::Severity;
use crate::state::AppState;
use std::sync::{Arc, Mutex, OnceLock};

static QUEUE: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();

pub fn enqueue(exe: String, sha256: String) {
    let q = QUEUE.get_or_init(|| Mutex::new(vec![]));
    let mut q = q.lock().unwrap();
    if !q.iter().any(|(_, s)| *s == sha256) {
        q.push((exe, sha256));
    }
}

pub fn start(state: Arc<AppState>) {
    let key = state.cfg.virustotal.api_key.trim().to_string();
    if key.is_empty() {
        tracing::info!("VirusTotal lookups disabled (no API key in config.toml)");
        return;
    }
    tokio::spawn(async move {
        let client = reqwest::Client::builder().user_agent("NetMonitor/0.1").build().unwrap();
        loop {
            let next = QUEUE.get_or_init(|| Mutex::new(vec![])).lock().unwrap().pop();
            let Some((exe, sha)) = next else {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            };
            let url = format!("https://www.virustotal.com/api/v3/files/{sha}");
            match client.get(&url).header("x-apikey", &key).send().await {
                Ok(r) if r.status().is_success() => {
                    if let Ok(v) = r.json::<serde_json::Value>().await {
                        let stats = &v["data"]["attributes"]["last_analysis_stats"];
                        let mal = stats["malicious"].as_u64().unwrap_or(0) as u32;
                        let sus = stats["suspicious"].as_u64().unwrap_or(0) as u32;
                        let total: u32 = ["malicious", "suspicious", "undetected", "harmless"]
                            .iter()
                            .map(|k| stats[k].as_u64().unwrap_or(0) as u32)
                            .sum();
                        let positives = mal + sus;
                        if let Some(mut m) = state.exe_meta.get_mut(&exe.to_ascii_lowercase()) {
                            m.vt_positives = Some(positives);
                            m.vt_total = Some(total);
                            m.vt_checked = true;
                            let meta = m.clone();
                            drop(m);
                            state.apply_exe_meta(&exe, meta);
                        }
                        if positives > 0 {
                            let pid = state.procs.iter().find(|p| p.exe.eq_ignore_ascii_case(&exe)).map(|p| p.pid).unwrap_or(0);
                            let sev = if mal >= 3 { Severity::Critical } else { Severity::High };
                            state.push_alert(
                                sev,
                                "R21-virustotal",
                                format!("VirusTotal flags {}", std::path::Path::new(&exe).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or(exe.clone())),
                                format!("{positives} of {total} engines flag {exe} (sha256 {sha})."),
                                pid,
                                "",
                            );
                        }
                    }
                }
                Ok(r) if r.status().as_u16() == 404 => {
                    if let Some(mut m) = state.exe_meta.get_mut(&exe.to_ascii_lowercase()) {
                        m.vt_checked = true;
                        m.vt_positives = Some(0);
                        m.vt_total = Some(0);
                    }
                }
                Ok(r) => tracing::warn!("VirusTotal returned {} for {sha}", r.status()),
                Err(e) => tracing::warn!("VirusTotal request failed: {e}"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(16)).await;
        }
    });
}
