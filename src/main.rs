mod actions;
mod analysis;
mod collectors;
mod config;
mod db;
mod geo;
mod intel;
mod model;
mod server;
mod state;
mod util;

use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

fn is_admin() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

fn project_root() -> PathBuf {
    // Prefer the folder that holds config.toml: the exe's folder, its parent (target/release), or cwd.
    let exe = std::env::current_exe().ok();
    let mut candidates = vec![];
    if let Some(e) = &exe {
        let mut p = e.parent().map(|p| p.to_path_buf());
        for _ in 0..3 {
            if let Some(d) = p.clone() {
                candidates.push(d.clone());
                p = d.parent().map(|x| x.to_path_buf());
            }
        }
    }
    if let Ok(c) = std::env::current_dir() {
        candidates.push(c);
    }
    for c in &candidates {
        if c.join("config.toml").exists() {
            return c.clone();
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn relaunch_elevated() -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg_list = if args.is_empty() {
        String::new()
    } else {
        format!(
            " -ArgumentList @({})",
            args.iter().map(|a| format!("'{}'", a.replace('\'', "''"))).collect::<Vec<_>>().join(",")
        )
    };
    let cwd = std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default();
    let script = format!(
        "Start-Process -FilePath '{}' -WorkingDirectory '{}' -Verb RunAs{}",
        exe.display().to_string().replace('\'', "''"),
        cwd.replace('\'', "''"),
        arg_list
    );
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,netmon=info")))
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let no_elevate = args.iter().any(|a| a == "--no-elevate");
    let admin = is_admin();
    if !admin && !no_elevate {
        println!("NetMonitor needs administrator rights for per-process traffic capture. Requesting elevation...");
        if relaunch_elevated() {
            return Ok(());
        }
        println!("Elevation was declined. Continuing with reduced visibility (no byte counts, no DNS capture).");
    }

    let root = project_root();
    let cfg = config::load(&root.join("config.toml"));
    tracing::info!("NetMonitor Command Center v{} starting in {}", intel::APP_VERSION, root.display());
    tracing::info!("administrator: {admin}");

    let db = db::Db::open(root.join("data").join("netmon.db"))?;

    let geo_path = root.join(&cfg.geo.mmdb);
    if let Err(e) = geo::ensure_database(&geo_path, &cfg.geo.download_url).await {
        tracing::warn!("{e}");
    }
    let geo = geo::Geo::open(&geo_path);
    let intel = intel::Intel::new(cfg.intel.clone(), root.join("data").join("feeds"));
    intel.refresh(false).await;

    let (proc_tx, proc_rx) = std::sync::mpsc::channel();
    let (sig_tx, sig_rx) = std::sync::mpsc::channel();
    let (rdns_tx, rdns_rx) = std::sync::mpsc::channel();
    let state = Arc::new(state::AppState::new(cfg.clone(), root.clone(), admin, geo, intel, db, proc_tx, sig_tx, rdns_tx));

    collectors::procinfo::start_process_worker(state.clone(), proc_rx);
    collectors::procinfo::start_signature_worker(state.clone(), sig_rx);
    collectors::procinfo::start_rdns_worker(state.clone(), rdns_rx);
    collectors::conntable::start(state.clone());
    if admin {
        collectors::etw::start(state.clone());
    } else {
        *state.etw_error.write() = Some("Not running as administrator: byte counts and DNS capture are unavailable.".into());
    }
    collectors::vt::start(state.clone());
    analysis::start(state.clone());

    // Home location for the globe.
    {
        let s = state.clone();
        tokio::spawn(async move {
            if let (Some(lat), Some(lon)) = (s.cfg.geo.home_lat, s.cfg.geo.home_lon) {
                *s.home.write() = Some((lat, lon, "configured".into()));
                return;
            }
            if !s.cfg.geo.detect_public_ip {
                return;
            }
            let client = reqwest::Client::builder().user_agent("NetMonitor/0.1").timeout(std::time::Duration::from_secs(10)).build().unwrap();
            if let Ok(r) = client.get("https://api.ipify.org").send().await {
                if let Ok(text) = r.text().await {
                    if let Ok(ip) = text.trim().parse::<std::net::IpAddr>() {
                        let g = s.geo.lookup(ip);
                        if let (Some(lat), Some(lon)) = (g.lat, g.lon) {
                            let label = format!("{}{}", g.city.map(|c| c + ", ").unwrap_or_default(), g.country_name.unwrap_or_default());
                            tracing::info!("home location: {label}");
                            *s.home.write() = Some((lat, lon, label));
                        }
                    }
                }
            }
        });
    }

    // One-second ticker: rolls per-second counters and pushes live updates.
    {
        let s = state.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                t.tick().await;
                let s2 = s.clone();
                let _ = tokio::task::spawn_blocking(move || s2.tick()).await;
            }
        });
    }
    // Scheduled threat-feed refresh.
    {
        let s = state.clone();
        tokio::spawn(async move {
            let hours = s.intel.refresh_hours();
            let mut t = tokio::time::interval(std::time::Duration::from_secs(hours * 3600));
            t.tick().await;
            loop {
                t.tick().await;
                s.intel.refresh(false).await;
                let sum = s.intel.summary();
                if sum.update.update_required {
                    s.push_alert(
                        model::Severity::Info,
                        "SYS-update",
                        "App update needed to integrate new threat data".into(),
                        sum.update.reasons.join(" "),
                        0,
                        "update",
                    );
                }
            }
        });
    }

    let addr = format!("{}:{}", cfg.server.bind, cfg.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let url = format!("http://{addr}/");
    tracing::info!("dashboard at {url}");
    if cfg.server.open_browser && !args.iter().any(|a| a == "--no-browser") {
        let _ = std::process::Command::new("cmd").args(["/C", "start", "", &url]).spawn();
    }
    axum::serve(listener, server::router(state)).await?;
    Ok(())
}
