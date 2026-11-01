//! NetMonitor Command Center core: collectors, analysis, intel, database and the HTTP/WebSocket server.
//!
//! Two front ends share this library and therefore stay in sync by construction:
//! - `src/main.rs` (binary `netmon`): starts the server and opens the dashboard in the default browser.
//! - `desktop/` (binary `netmon-desktop`): a Tauri window and tray icon around the same server.

pub mod actions;
pub mod ai;
pub mod analysis;
pub mod collectors;
pub mod config;
pub mod db;
pub mod geo;
pub mod intel;
pub mod inventory;
pub mod model;
pub mod server;
pub mod state;
pub mod util;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

pub use intel::APP_VERSION;

/// The default configuration shipped with the app, written to a fresh data folder on first start.
pub const DEFAULT_CONFIG: &str = include_str!("../config.toml");

pub fn is_admin() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

/// Prefer the folder that holds config.toml: the exe's folder, its parents (target/release), or cwd.
pub fn project_root() -> Option<PathBuf> {
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
    candidates.into_iter().find(|c| c.join("config.toml").exists())
}

/// Root folder for an installed copy that has no config.toml next to it: `%LOCALAPPDATA%\NetMonitor`,
/// created with the default config on first use. Development checkouts keep using the project folder.
pub fn data_root() -> PathBuf {
    if let Some(r) = project_root() {
        return r;
    }
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let root = base.join("NetMonitor");
    let _ = std::fs::create_dir_all(root.join("data").join("logs"));
    let cfg = root.join("config.toml");
    if !cfg.exists() {
        let _ = std::fs::write(&cfg, DEFAULT_CONFIG);
    }
    root
}

/// Re-launch the current executable with the same arguments through a UAC prompt.
pub fn relaunch_elevated() -> bool {
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
    util::quiet(std::process::Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script]))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Console logging, or file logging for the windowed desktop build (which has no console).
pub fn init_logging(file: Option<&Path>) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,netmon=info"));
    match file.and_then(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).ok()) {
        Some(f) => tracing_subscriber::fmt().with_env_filter(filter).with_target(false).with_ansi(false).with_writer(std::sync::Mutex::new(f)).init(),
        None => tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init(),
    }
}

/// Bind the dashboard port. If another NetMonitor instance holds it (for example a test run, the browser
/// version while the desktop one starts, or an un-elevated copy), ask it to shut down and take the port:
/// the latest launch wins.
async fn bind_taking_over(addr: &str) -> anyhow::Result<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => return Ok(l),
        Err(e) if e.kind() != std::io::ErrorKind::AddrInUse => return Err(e.into()),
        Err(_) => {}
    }
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(3)).build()?;
    let probe = client.get(format!("http://{addr}/api/overview")).send().await;
    let is_netmon = match probe {
        Ok(r) => r.text().await.map(|t| t.contains("\"app_version\"")).unwrap_or(false),
        Err(_) => false,
    };
    if !is_netmon {
        anyhow::bail!("port {addr} is in use by another program; change [server] port in config.toml");
    }
    tracing::info!("another NetMonitor instance is on {addr}; asking it to stop");
    let _ = client.post(format!("http://{addr}/api/shutdown")).send().await;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        if let Ok(l) = tokio::net::TcpListener::bind(addr).await {
            return Ok(l);
        }
    }
    anyhow::bail!("could not take over port {addr}")
}

/// A started monitor: collectors and background tasks are running and the port is bound.
/// Call [`serve`] to run the HTTP server until the process exits.
pub struct Running {
    pub state: Arc<state::AppState>,
    pub url: String,
    pub listener: tokio::net::TcpListener,
}

/// Start everything except the HTTP accept loop. Must be called from inside a Tokio runtime.
pub async fn start(root: PathBuf, admin: bool) -> anyhow::Result<Running> {
    let cfg = config::load(&root.join("config.toml"));
    tracing::info!("NetMonitor Command Center v{} starting in {}", APP_VERSION, root.display());
    tracing::info!("administrator: {admin}");

    let db = db::Db::open(root.join("data").join("netmon.db"))?;

    // Fast start: open what is on disk now; downloads happen in the background after the server is up.
    let geo_path = root.join(&cfg.geo.mmdb);
    let geo = geo::Geo::open(&geo_path);
    let intel = intel::Intel::new(cfg.intel.clone(), root.join("data").join("feeds"));
    intel.load_local().await;

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
    inventory::start(state.clone());

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

    // Background downloads: GeoIP database (first run) and threat-feed refresh.
    {
        let s = state.clone();
        let geo_path = geo_path.clone();
        let url = cfg.geo.download_url.clone();
        tokio::spawn(async move {
            if !geo_path.exists() {
                match geo::ensure_database(&geo_path, &url).await {
                    Ok(()) => s.geo.load(&geo_path),
                    Err(e) => tracing::warn!("{e}"),
                }
            }
            s.intel.refresh(false).await;
        });
    }

    // Resolve the file-sharing service names to addresses (R28) now and every six hours.
    {
        let s = state.clone();
        tokio::task::spawn_blocking(move || loop {
            let domains = s.cfg.analysis.file_sharing_domains.clone();
            let mut n = 0;
            for d in &domains {
                for name in [d.clone(), format!("www.{d}")] {
                    if let Ok(addrs) = dns_lookup::lookup_host(&name) {
                        for ip in addrs {
                            s.sharing_ips.insert(ip, d.clone());
                            n += 1;
                        }
                    }
                }
            }
            tracing::info!("file-sharing services resolved: {} addresses for {} domains", n, domains.len());
            std::thread::sleep(std::time::Duration::from_secs(6 * 3600));
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
                    s.push_alert_cd(
                        model::Severity::Info,
                        "SYS-update",
                        "App update needed to integrate new threat data".into(),
                        sum.update.reasons.join(" "),
                        0,
                        "update",
                        Some(24 * 3600 * 1000),
                    );
                }
            }
        });
    }

    let addr = format!("{}:{}", cfg.server.bind, cfg.server.port);
    let listener = bind_taking_over(&addr).await?;
    let url = format!("http://{addr}/");
    tracing::info!("dashboard at {url}");
    Ok(Running { state, url, listener })
}

/// Run the HTTP server until the process exits.
pub async fn serve(r: Running) -> anyhow::Result<()> {
    axum::serve(r.listener, server::router(r.state)).await?;
    Ok(())
}

/// Stop the kernel trace session cleanly. Call before exiting.
pub fn shutdown() {
    tracing::info!("shutting down");
    collectors::etw::stop();
}
