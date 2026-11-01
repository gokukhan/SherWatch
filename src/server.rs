use crate::db;
use crate::model::{Alert, Connection, DnsEvent, Listener, ProcessInfo};
use crate::state::AppState;
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(rust_embed::RustEmbed)]
#[folder = "web/"]
struct Assets;

type S = State<Arc<AppState>>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/overview", get(overview))
        .route("/api/connections", get(connections))
        .route("/api/processes", get(processes))
        .route("/api/process/{pid}", get(process_detail))
        .route("/api/alerts", get(alerts))
        .route("/api/alerts/{id}/ack", post(ack_alert))
        .route("/api/alerts/ack-all", post(ack_all))
        .route("/api/dns", get(dns))
        .route("/api/series", get(series))
        .route("/api/geo", get(geo))
        .route("/api/listeners", get(listeners))
        .route("/api/home", get(home))
        .route("/api/inventory", get(inventory))
        .route("/api/inventory/scan", post(inventory_scan))
        .route("/api/inventory/cve-lookup", post(inventory_cve_lookup))
        .route("/api/intel", get(intel))
        .route("/api/intel/refresh", post(intel_refresh))
        .route("/api/config", get(config).post(config_save))
        .route("/api/history/traffic", get(history_traffic))
        .route("/api/history/alerts", get(history_alerts))
        .route("/api/history/connections", get(history_conns))
        .route("/api/blocks", get(blocks))
        .route("/api/audit", get(audit_list))
        .route("/api/audit/{id}/revert", post(audit_revert))
        .route("/api/action/kill", post(action_kill))
        .route("/api/action/block-exe", post(action_block_exe))
        .route("/api/action/block-ip", post(action_block_ip))
        .route("/api/action/unblock", post(action_unblock))
        .route("/api/action/trust", post(action_trust))
        .route("/api/action/untrust", post(action_untrust))
        .route("/api/trusted", get(trusted_list))
        .route("/api/ai/status", get(ai_status))
        .route("/api/ai/ask", post(ai_ask))
        .route("/api/export/{what}", get(export))
        .route("/api/shutdown", post(shutdown))
        .route("/ws", get(ws_handler))
        .fallback(static_file)
        .layer(axum::middleware::from_fn_with_state(state.clone(), guard_local))
        .with_state(state)
}

/// Only the dashboard itself may call the API: the Host header must be the local bind address and,
/// when a browser sends an Origin, it must be this server. This blocks DNS-rebinding and
/// cross-site requests from other pages open in the browser.
async fn guard_local(State(s): S, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let server_cfg = s.cfg.read().server.clone();
    let bind = server_cfg.bind.as_str();
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| {
            let h = h.trim_start_matches('[');
            let host = h.rsplit_once(':').map(|(a, _)| a).unwrap_or(h).trim_end_matches(']');
            host == "127.0.0.1" || host == "localhost" || host == "::1" || host == bind
        })
        .unwrap_or(false);
    // Origin must match scheme, host and port exactly (a prefix check would accept lookalike hosts).
    let port = server_cfg.port;
    let allowed_origins = [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
        format!("http://{bind}:{port}"),
    ];
    let origin_ok = match req.headers().get(header::ORIGIN).and_then(|o| o.to_str().ok()) {
        None => true,
        Some(o) => allowed_origins.iter().any(|a| a.eq_ignore_ascii_case(o.trim_end_matches('/'))),
    };
    if !host_ok || !origin_ok {
        return (StatusCode::FORBIDDEN, "SherWatch only answers the local dashboard").into_response();
    }
    next.run(req).await
}

async fn shutdown() -> Json<serde_json::Value> {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        crate::platform::stop_capture();
        std::process::exit(0);
    });
    Json(json!({"ok": true}))
}

async fn index() -> Response {
    static_response("index.html")
}

async fn static_file(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    static_response(path)
}

fn static_response(path: &str) -> Response {
    match Assets::get(path) {
        Some(f) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let cache = if path.starts_with("vendor/") { "public, max-age=86400" } else { "no-cache" };
            Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .header(header::CACHE_CONTROL, cache)
                .body(Body::from(f.data.into_owned()))
                .unwrap()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn overview(State(s): S) -> Json<serde_json::Value> {
    Json(serde_json::to_value(s.overview()).unwrap())
}

#[derive(Deserialize)]
struct ConnQuery {
    #[serde(default)]
    public: bool,
    pid: Option<u32>,
}

async fn connections(State(s): S, Query(q): Query<ConnQuery>) -> Json<Vec<Connection>> {
    let mut v: Vec<Connection> = s
        .conns
        .iter()
        .filter(|c| !q.public || c.scope == "public")
        .filter(|c| q.pid.map(|p| p == c.pid).unwrap_or(true))
        .map(|c| c.clone())
        .collect();
    v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    Json(v)
}

fn proc_json(p: &ProcessInfo) -> serde_json::Value {
    let mut v = serde_json::to_value(p).unwrap();
    // Trim the series to a sparkline-friendly 60 points for list views.
    if let Some(obj) = v.as_object_mut() {
        let spark: Vec<(u64, u64)> = p.series.iter().rev().take(60).copied().collect::<Vec<_>>().into_iter().rev().collect();
        obj.insert("series".into(), json!(spark));
    }
    v
}

async fn processes(State(s): S) -> Json<Vec<serde_json::Value>> {
    let mut v: Vec<(u64, serde_json::Value)> = s.procs.iter().map(|p| (p.bytes_in + p.bytes_out, proc_json(&p))).collect();
    v.sort_by(|a, b| b.0.cmp(&a.0));
    Json(v.into_iter().map(|(_, j)| j).collect())
}

async fn process_detail(State(s): S, Path(pid): Path<u32>) -> Response {
    let Some(p) = s.procs.get(&pid).map(|p| p.clone()) else {
        return (StatusCode::NOT_FOUND, "no such process").into_response();
    };
    let conns: Vec<Connection> = s.conns.iter().filter(|c| c.pid == pid).map(|c| c.clone()).collect();
    let dns: Vec<DnsEvent> = s.dns.read().iter().rev().filter(|d| d.pid == pid).take(100).cloned().collect();
    let alerts: Vec<Alert> = s.alerts.read().iter().rev().filter(|a| a.pid == pid).take(100).cloned().collect();
    let listeners: Vec<Listener> = s.listeners.iter().filter(|l| l.pid == pid).map(|l| l.clone()).collect();
    let mut v = serde_json::to_value(&p).unwrap();
    v["trusted"] = json!(!p.exe.is_empty() && s.is_trusted(&p.exe, p.meta.sha256.as_deref()));
    // Firewall state for the drawer button: the SherWatch rule recorded for this executable, if any.
    let blocked = if p.exe.is_empty() {
        None
    } else {
        s.db.query(db::blocks).await.unwrap_or_default().into_iter().find(|b| b.kind == "app" && b.target.eq_ignore_ascii_case(&p.exe)).map(|b| b.rule)
    };
    v["blocked_rule"] = json!(blocked);
    v["conns"] = json!(conns);
    v["dns"] = json!(dns);
    v["alerts"] = json!(alerts);
    v["listeners"] = json!(listeners);
    v["beacons"] = json!(s
        .beacons
        .iter()
        .filter(|b| b.key().0 == pid)
        .map(|b| json!({"ip": b.key().1.to_string(), "times": b.value().iter().copied().collect::<Vec<_>>()}))
        .collect::<Vec<_>>());
    Json(v).into_response()
}

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
    #[serde(default)]
    unacked: bool,
}

async fn alerts(State(s): S, Query(q): Query<LimitQuery>) -> Json<Vec<Alert>> {
    let lim = q.limit.unwrap_or(300);
    Json(s.alerts.read().iter().rev().filter(|a| !q.unacked || !a.acked).take(lim).cloned().collect())
}

async fn ack_alert(State(s): S, Path(id): Path<i64>) -> Json<serde_json::Value> {
    Json(json!({"ok": s.ack_alert(id)}))
}

async fn ack_all(State(s): S) -> Json<serde_json::Value> {
    s.ack_all();
    Json(json!({"ok": true}))
}

async fn dns(State(s): S, Query(q): Query<LimitQuery>) -> Json<Vec<DnsEvent>> {
    let lim = q.limit.unwrap_or(300);
    Json(s.dns.read().iter().rev().take(lim).cloned().collect())
}

async fn series(State(s): S) -> Json<serde_json::Value> {
    Json(json!(s.series.read().iter().cloned().collect::<Vec<_>>()))
}

async fn listeners(State(s): S) -> Json<Vec<Listener>> {
    let mut v: Vec<Listener> = s.listeners.iter().map(|l| l.clone()).collect();
    v.sort_by_key(|l| l.port);
    Json(v)
}

/// Destinations aggregated per remote IP, for the globe and the map.
async fn geo(State(s): S) -> Json<serde_json::Value> {
    let mut by_ip: HashMap<std::net::IpAddr, serde_json::Value> = HashMap::new();
    for c in s.conns.iter() {
        if c.scope != "public" {
            continue;
        }
        let name = s.process_name(c.pid);
        let e = by_ip.entry(c.remote_addr).or_insert_with(|| {
            json!({
                "ip": c.remote_addr.to_string(),
                "lat": c.lat, "lon": c.lon,
                "country": c.country, "country_name": c.country_name, "city": c.city,
                "hostname": c.hostname, "intel": c.intel, "owner": c.owner,
                "bytes_in": 0u64, "bytes_out": 0u64, "conns": 0u64, "risk": 0u32,
                "procs": Vec::<String>::new(),
                "last_seen": c.last_seen,
            })
        });
        e["bytes_in"] = json!(e["bytes_in"].as_u64().unwrap_or(0) + c.bytes_in);
        e["bytes_out"] = json!(e["bytes_out"].as_u64().unwrap_or(0) + c.bytes_out);
        e["conns"] = json!(e["conns"].as_u64().unwrap_or(0) + 1);
        e["risk"] = json!(e["risk"].as_u64().unwrap_or(0).max(c.risk as u64));
        if e["last_seen"].as_i64().unwrap_or(0) < c.last_seen {
            e["last_seen"] = json!(c.last_seen);
        }
        if let Some(arr) = e["procs"].as_array_mut() {
            if !arr.iter().any(|v| v.as_str() == Some(&name)) && arr.len() < 6 {
                arr.push(json!(name));
            }
        }
    }
    Json(json!(by_ip.into_values().collect::<Vec<_>>()))
}

async fn home(State(s): S) -> Json<serde_json::Value> {
    match s.home.read().clone() {
        Some((lat, lon, label)) => Json(json!({"lat": lat, "lon": lon, "label": label})),
        None => Json(json!({"lat": null, "lon": null, "label": "unknown"})),
    }
}

async fn inventory(State(s): S) -> Json<serde_json::Value> {
    let inv = s.inventory.read().clone();
    let mut items: Vec<_> = inv.items.values().cloned().collect();
    items.sort_by(|a, b| {
        let ka = (a.kev.iter().filter(|k| k.likely_unpatched).count(), a.kev.len(), a.max_cvss as i64);
        let kb = (b.kev.iter().filter(|k| k.likely_unpatched).count(), b.kev.len(), b.max_cvss as i64);
        kb.cmp(&ka).then_with(|| b.network_active.cmp(&a.network_active)).then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
    });
    Json(json!({
        "items": items,
        "os": inv.os,
        "last_scan": inv.last_scan,
        "scanning": inv.scanning,
        "online_running": inv.online_running,
        "online_progress": inv.online_progress,
        "online_last": inv.online_last,
        "online_enabled": s.cfg.read().vuln.online_lookup,
        "kev_count": inv.kev_count,
    }))
}

async fn inventory_scan(State(s): S) -> Json<serde_json::Value> {
    let st = s.clone();
    tokio::task::spawn_blocking(move || crate::inventory::collect(&st));
    Json(json!({"ok": true}))
}

async fn inventory_cve_lookup(State(s): S) -> Json<serde_json::Value> {
    if s.inventory.read().online_running {
        return Json(json!({"ok": false, "error": "a lookup is already running"}));
    }
    tokio::spawn(crate::inventory::online_lookup(s.clone()));
    Json(json!({"ok": true}))
}

async fn intel(State(s): S) -> Json<serde_json::Value> {
    let mut v = serde_json::to_value(s.intel.summary()).unwrap();
    v["hosts_issues"] = json!(s.hosts_issues.read().clone());
    Json(v)
}

async fn intel_refresh(State(s): S) -> Json<serde_json::Value> {
    s.intel.refresh(true).await;
    Json(serde_json::to_value(s.intel.summary()).unwrap())
}

async fn config(State(s): S) -> Json<serde_json::Value> {
    let cfg = s.cfg.read().clone();
    let mut v = serde_json::to_value(&cfg).unwrap();
    v["virustotal"]["api_key"] = json!(if cfg.virustotal.api_key.trim().is_empty() { "" } else { "(set)" });
    v["ai"]["api_key"] = json!(if cfg.ai.api_key.trim().is_empty() { "" } else { "(set)" });
    v["root"] = json!(s.root.display().to_string());
    v["app_version"] = json!(crate::intel::APP_VERSION);
    Json(v)
}

/// Save settings from the Settings page: validate, write config.toml (comments kept), apply live.
async fn config_save(State(s): S, Json(p): Json<crate::config::ConfigPatch>) -> Json<serde_json::Value> {
    let mut cfg = s.cfg.read().clone();
    let (changed, restart) = match crate::config::apply_patch(&mut cfg, &p) {
        Ok(v) => v,
        Err(e) => return Json(json!({"ok": false, "error": e})),
    };
    let path = s.root.join("config.toml");
    if let Err(e) = crate::config::write_keys(&path, &cfg, &changed) {
        return Json(json!({"ok": false, "error": format!("could not write {}: {e}", path.display())}));
    }
    s.intel.set_cfg(cfg.intel.clone());
    if let (Some(lat), Some(lon)) = (cfg.geo.home_lat, cfg.geo.home_lon) {
        *s.home.write() = Some((lat, lon, "configured".into()));
    }
    *s.cfg.write() = cfg;
    let s2 = s.clone();
    tokio::task::spawn_blocking(move || crate::resolve_sharing_hosts(&s2));
    let r = Ok(format!("{} setting{} saved", changed.len(), if changed.len() == 1 { "" } else { "s" }));
    crate::actions::audit(&s, "settings", &changed.join(", "), json!({"restart_required": !restart.is_empty()}), &r, None);
    Json(json!({"ok": true, "changed": changed, "restart_required": restart}))
}

#[derive(Deserialize)]
struct HistQuery {
    hours: Option<i64>,
    limit: Option<usize>,
}

async fn history_traffic(State(s): S, Query(q): Query<HistQuery>) -> Response {
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 30);
    let since = crate::util::now_ms() - hours * 3600_000;
    let bucket = if hours <= 6 { 300_000 } else if hours <= 48 { 3_600_000 } else { 6 * 3_600_000 };
    match s.db.query(move |sql| db::traffic_history(sql, since, bucket)).await {
        Ok(rows) => Json(json!({"bucket_ms": bucket, "rows": rows})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn history_alerts(State(s): S, Query(q): Query<HistQuery>) -> Response {
    let hours = q.hours.unwrap_or(24 * 7).clamp(1, 24 * 30);
    let since = crate::util::now_ms() - hours * 3600_000;
    match s.db.query(move |sql| db::alerts_since(sql, since)).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn history_conns(State(s): S, Query(q): Query<HistQuery>) -> Response {
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 30);
    let limit = q.limit.unwrap_or(1000).min(10000);
    let since = crate::util::now_ms() - hours * 3600_000;
    match s.db.query(move |sql| db::conn_history(sql, since, limit)).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn blocks(State(s): S) -> Response {
    // Reconcile with the firewall: a rule the user removed by hand shows as "missing". When the
    // firewall cannot be read without a privilege prompt (unix without root) the records are trusted.
    let present = tokio::task::spawn_blocking(crate::actions::firewall_rules).await.ok().flatten();
    match s.db.query(db::blocks).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|b| {
                    let mut v = serde_json::to_value(&b).unwrap();
                    v["present"] = json!(present.as_ref().map(|p| p.contains(&b.rule)).unwrap_or(true));
                    v
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn audit_list(State(s): S, Query(q): Query<LimitQuery>) -> Response {
    let lim = q.limit.unwrap_or(200);
    match s.db.query(move |sql| db::audit_list(sql, lim)).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Undo a logged action: unblock what was blocked, re-block what was unblocked, revoke or restore trust.
/// Terminations cannot be undone. The revert is itself logged and the original entry marked reverted.
async fn audit_revert(State(s): S, Path(id): Path<i64>) -> Json<serde_json::Value> {
    let Ok(Some(e)) = s.db.query(move |sql| db::audit_get(sql, id)).await else {
        return Json(json!({"ok": false, "error": "no such log entry"}));
    };
    if e.reverted_ts.is_some() {
        return Json(json!({"ok": false, "error": "already reverted"}));
    }
    if !e.ok {
        return Json(json!({"ok": false, "error": "that action did not succeed, so there is nothing to revert"}));
    }
    let d: serde_json::Value = serde_json::from_str(&e.detail).unwrap_or_default();
    let str_of = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let (action, target, detail, r) = match e.action.as_str() {
        "block-exe" | "block-ip" => {
            let rule = str_of("rule");
            let r = crate::actions::unblock(&s, &rule);
            ("unblock", e.target.clone(), json!({"rule": rule, "kind": if e.action == "block-exe" { "app" } else { "ip" }, "target": e.target}), r)
        }
        "unblock" => {
            let kind = str_of("kind");
            let r = if kind == "ip" { crate::actions::block_ip(&s, &e.target) } else { crate::actions::block_exe(&s, &e.target) };
            let rule = r.clone().unwrap_or_default();
            (if kind == "ip" { "block-ip" } else { "block-exe" }, e.target.clone(), json!({"rule": rule}), r)
        }
        "trust" => {
            s.untrust_exe(&e.target);
            ("untrust", e.target.clone(), json!({"sha256": str_of("sha256")}), Ok(format!("{} removed from the trust list", e.target)))
        }
        "untrust" => {
            let sha = str_of("sha256");
            if sha.is_empty() {
                return Json(json!({"ok": false, "error": "hash of the trusted file is not recorded; trust it again from its drawer"}));
            }
            s.trust_exe(&e.target, &sha);
            ("trust", e.target.clone(), json!({"sha256": sha}), Ok(format!("{} trusted again", e.target)))
        }
        _ => return Json(json!({"ok": false, "error": "a terminated process cannot be brought back; start it again yourself"})),
    };
    crate::actions::audit(&s, action, &target, detail, &r, Some(id));
    if r.is_ok() {
        s.db.send(db::DbMsg::AuditReverted { id, ts: crate::util::now_ms() });
    }
    action_result(r)
}

#[derive(Deserialize)]
struct ActionBody {
    pid: Option<u32>,
    exe: Option<String>,
    ip: Option<String>,
    rule: Option<String>,
}

fn action_result(r: Result<String, String>) -> Json<serde_json::Value> {
    match r {
        Ok(m) => Json(json!({"ok": true, "message": m})),
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

async fn action_kill(State(s): S, Json(b): Json<ActionBody>) -> Json<serde_json::Value> {
    let Some(pid) = b.pid else { return Json(json!({"ok": false, "error": "pid required"})) };
    let name = s.process_name(pid);
    let exe = s.process_exe(pid);
    let r = crate::actions::kill_process(pid);
    if r.is_ok() {
        s.mark_process_dead(pid);
    }
    crate::actions::audit(&s, "kill", &format!("{} ({pid})", if name.is_empty() { "pid".to_string() } else { name }), json!({"exe": exe, "pid": pid}), &r, None);
    action_result(r)
}

async fn action_block_exe(State(s): S, Json(b): Json<ActionBody>) -> Json<serde_json::Value> {
    let exe = b.exe.or_else(|| b.pid.map(|p| s.process_exe(p))).unwrap_or_default();
    let r = crate::actions::block_exe(&s, &exe);
    crate::actions::audit(&s, "block-exe", &exe, json!({"rule": crate::actions::exe_rule_name(&exe)}), &r, None);
    action_result(r)
}

async fn action_block_ip(State(s): S, Json(b): Json<ActionBody>) -> Json<serde_json::Value> {
    let ip = b.ip.unwrap_or_default();
    let r = crate::actions::block_ip(&s, &ip);
    crate::actions::audit(&s, "block-ip", &ip, json!({"rule": r.clone().unwrap_or_default()}), &r, None);
    action_result(r)
}

async fn action_unblock(State(s): S, Json(b): Json<ActionBody>) -> Json<serde_json::Value> {
    let rule = b.rule.unwrap_or_default();
    // Remember what the rule blocked so the removal can be reverted later.
    let known = s.db.query(db::blocks).await.unwrap_or_default().into_iter().find(|x| x.rule == rule);
    let r = crate::actions::unblock(&s, &rule);
    let (kind, target) = known.map(|k| (k.kind, k.target)).unwrap_or_default();
    crate::actions::audit(&s, "unblock", if target.is_empty() { &rule } else { &target }, json!({"rule": rule, "kind": kind, "target": target}), &r, None);
    action_result(r)
}

async fn action_trust(State(s): S, Json(b): Json<ActionBody>) -> Json<serde_json::Value> {
    let exe = b.exe.or_else(|| b.pid.map(|p| s.process_exe(p))).unwrap_or_default();
    if exe.is_empty() {
        return Json(json!({"ok": false, "error": "no executable path known"}));
    }
    let sha = s.exe_meta.get(&exe.to_ascii_lowercase()).and_then(|m| m.sha256.clone()).unwrap_or_default();
    if sha.is_empty() {
        return Json(json!({"ok": false, "error": "hash not computed yet, try again in a few seconds"}));
    }
    s.trust_exe(&exe, &sha);
    let r = Ok(format!("{exe} trusted (sha256 {}...)", &sha[..12]));
    crate::actions::audit(&s, "trust", &exe, json!({"sha256": sha}), &r, None);
    action_result(r)
}

async fn action_untrust(State(s): S, Json(b): Json<ActionBody>) -> Json<serde_json::Value> {
    let exe = b.exe.unwrap_or_default();
    let sha = s.trusted.read().get(&exe.to_ascii_lowercase()).cloned().or_else(|| s.trusted.read().get(&exe).cloned()).unwrap_or_default();
    s.untrust_exe(&exe);
    let r = Ok(format!("{exe} removed from the trust list"));
    crate::actions::audit(&s, "untrust", &exe, json!({"sha256": sha}), &r, None);
    action_result(r)
}

async fn ai_status(State(s): S, Query(q): Query<ProviderQuery>) -> Json<serde_json::Value> {
    let mut v = serde_json::to_value(crate::ai::status_for(&s, q.provider.as_deref(), q.model.as_deref()).await).unwrap();
    v["configured"] = json!(s.cfg.read().ai.provider.clone());
    v["choices"] = json!(crate::ai::choices(&s).await);
    Json(v)
}

#[derive(Deserialize)]
struct AskBody {
    /// process | alert | connection | overview | none
    #[serde(default)]
    kind: String,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    id: Option<i64>,
    #[serde(default)]
    remote: Option<String>,
    #[serde(default)]
    question: String,
    #[serde(default)]
    history: Vec<crate::ai::ChatTurn>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Deserialize)]
struct ProviderQuery {
    provider: Option<String>,
    model: Option<String>,
}

async fn ai_ask(State(s): S, Json(b): Json<AskBody>) -> Json<serde_json::Value> {
    let (context, default_q) = match b.kind.as_str() {
        "process" => (b.pid.and_then(|p| crate::ai::context_process(&s, p)), "What is this process, what is it doing, and should I worry?"),
        "alert" => (b.id.and_then(|i| crate::ai::context_alert(&s, i)), "What does this alert mean, why did it fire, and what should I do?"),
        "connection" => (b.pid.and_then(|p| crate::ai::context_connection(&s, p, b.remote.as_deref().unwrap_or(""))), "What is this connection for and is it safe?"),
        "overview" => (Some(crate::ai::context_overview(&s)), "Summarise the state of my network: what is normal, what deserves attention, and what should I do first?"),
        _ => (Some(crate::ai::context_overview(&s)), "Answer the question using the context."),
    };
    let Some(context) = context else {
        return Json(json!({"ok": false, "error": "that item is no longer available"}));
    };
    let question = if b.question.trim().is_empty() { default_q.to_string() } else { b.question.clone() };
    match crate::ai::ask(s.clone(), context, question.clone(), b.history, b.provider, b.model).await {
        Ok((answer, st)) => Json(json!({"ok": true, "answer": answer, "provider": st.provider, "model": st.model, "local": st.local, "question": question})),
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

async fn trusted_list(State(s): S) -> Json<serde_json::Value> {
    let t = s.trusted.read();
    Json(json!(t.iter().map(|(k, v)| json!({"exe": k, "sha256": v})).collect::<Vec<_>>()))
}

fn csv_escape(v: &str) -> String {
    if v.contains([',', '"', '\n']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

async fn export(State(s): S, Path(what): Path<String>) -> Response {
    let (name, body, mime) = match what.as_str() {
        "connections.csv" => {
            let mut out = String::from("process,pid,proto,local_port,remote_ip,remote_port,hostname,country,city,state,bytes_out,bytes_in,first_seen,intel,risk\n");
            for c in s.conns.iter() {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    csv_escape(&s.process_name(c.pid)), c.pid, c.proto.as_str(), c.local_port, c.remote_addr, c.remote_port,
                    csv_escape(c.hostname.as_deref().unwrap_or("")), c.country.as_deref().unwrap_or(""), csv_escape(c.city.as_deref().unwrap_or("")),
                    c.state, c.bytes_out, c.bytes_in, c.first_seen, csv_escape(c.intel.as_deref().unwrap_or("")), c.risk
                ));
            }
            ("connections.csv", out, "text/csv")
        }
        "alerts.csv" => {
            let mut out = String::from("id,time,severity,rule,title,detail,pid,process,exe,remote,count,acked\n");
            for a in s.alerts.read().iter() {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    a.id, a.ts, a.severity.as_str(), a.rule, csv_escape(&a.title), csv_escape(&a.detail), a.pid,
                    csv_escape(&a.process), csv_escape(&a.exe), csv_escape(&a.remote), a.count, a.acked
                ));
            }
            ("alerts.csv", out, "text/csv")
        }
        "alerts.json" => ("alerts.json", serde_json::to_string_pretty(&s.alerts.read().iter().collect::<Vec<_>>()).unwrap(), "application/json"),
        "processes.json" => ("processes.json", serde_json::to_string_pretty(&s.procs.iter().map(|p| p.clone()).collect::<Vec<_>>()).unwrap(), "application/json"),
        "dns.csv" => {
            let mut out = String::from("time,pid,process,query,qtype,status,results,flags\n");
            for d in s.dns.read().iter() {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    d.ts, d.pid, csv_escape(&d.process), csv_escape(&d.query), d.qtype, d.status,
                    csv_escape(&d.results.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(";")), d.flags.join(";")
                ));
            }
            ("dns.csv", out, "text/csv")
        }
        _ => return (StatusCode::NOT_FOUND, "unknown export").into_response(),
    };
    Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\""))
        .body(Body::from(body))
        .unwrap()
}

async fn ws_handler(ws: WebSocketUpgrade, State(s): S) -> Response {
    ws.on_upgrade(move |socket| ws_loop(socket, s))
}

async fn ws_loop(socket: WebSocket, s: Arc<AppState>) {
    let (mut sink, mut stream) = socket.split();
    let mut rx = s.ws_tx.subscribe();
    let hello = json!({"type": "hello", "overview": s.overview()}).to_string();
    if sink.send(Message::Text(hello.into())).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(m) => {
                        if sink.send(Message::Text(m.into())).await.is_err() { break; }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            incoming = stream.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}
