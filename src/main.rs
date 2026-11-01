//! Browser version: starts the monitor and opens the dashboard in the default browser.
//! The desktop (Tauri) version in `desktop/` wraps the same library in a native window.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    netmon::init_logging(None);

    let args: Vec<String> = std::env::args().collect();
    let no_elevate = args.iter().any(|a| a == "--no-elevate");
    let admin = netmon::is_admin();
    if !admin && !no_elevate {
        println!("NetMonitor needs administrator rights for per-process traffic capture. Requesting elevation...");
        if netmon::relaunch_elevated() {
            return Ok(());
        }
        println!("Elevation was declined. Continuing with reduced visibility (no byte counts, no DNS capture).");
    }

    let root = netmon::data_root();
    let running = netmon::start(root, admin).await?;

    // Ctrl+C: stop the ETW session cleanly, then exit.
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            netmon::shutdown();
            std::process::exit(0);
        }
    });

    if running.state.cfg.server.open_browser && !args.iter().any(|a| a == "--no-browser") {
        let _ = std::process::Command::new("cmd").args(["/C", "start", "", &running.url]).spawn();
    }
    netmon::serve(running).await
}
