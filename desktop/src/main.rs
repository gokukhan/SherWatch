//! SherWatch desktop: a native window and tray icon around the shared `sherwatch` library.
//! The window simply shows the same dashboard the browser version serves, so both stay in sync.
//!
//! Platform notes:
//! - Windows: asks for administrator rights through UAC (byte counts and DNS capture need them),
//!   unless started with `--no-elevate`. Release builds have no console (`windows_subsystem`).
//! - macOS / Linux: never re-launches itself as root. Start it through `run.sh` (sudo) for the
//!   full feature set; without root it reports `admin = false` and runs with reduced collectors.
//! - Linux: the tray icon needs libayatana-appindicator at runtime. When no tray can be created
//!   the window stays usable and closing it quits the app instead of hiding to the tray.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

const TRAY_ID: &str = "main-tray";

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Privilege check, with the UAC re-launch on Windows only. Returns `None` when the elevated copy
/// has been started and this process should exit.
fn resolve_admin(no_elevate: bool) -> Option<bool> {
    let admin = sherwatch::is_admin();
    #[cfg(windows)]
    {
        if !admin && !no_elevate && sherwatch::relaunch_elevated() {
            return None;
        }
    }
    #[cfg(not(windows))]
    {
        // On unix the GUI is never re-launched as root; `run.sh` uses sudo on the console binary.
        let _ = no_elevate;
    }
    Some(admin)
}

/// Build the tray icon. Failure (no bundle icon, no indicator support on this desktop) is not fatal:
/// the window keeps working and the close button quits instead of hiding.
fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let Some(icon) = app.default_window_icon().cloned() else {
        tracing::warn!("no bundle icon available; running without a tray icon");
        return Ok(());
    };
    let open = MenuItem::with_id(app, "open", "Open SherWatch", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit (stops monitoring)", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip("SherWatch Command Center")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, e| match e.id.as_ref() {
            "open" => show_main(app),
            "quit" => {
                sherwatch::shutdown();
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let no_elevate = args.iter().any(|a| a == "--no-elevate");
    let Some(admin) = resolve_admin(no_elevate) else {
        return;
    };

    let root = sherwatch::data_root();
    let _ = std::fs::create_dir_all(root.join("data").join("logs"));
    sherwatch::init_logging(Some(&root.join("data").join("logs").join("sherwatch-desktop.log")));

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .setup(move |app| {
            // Start the monitor on Tauri's Tokio runtime and keep the HTTP server running in the background.
            let running = tauri::async_runtime::block_on(sherwatch::start(root.clone(), admin))?;
            let url: tauri::Url = running.url.parse()?;
            tauri::async_runtime::spawn(async move {
                if let Err(e) = sherwatch::serve(running).await {
                    tracing::error!("server stopped: {e}");
                }
            });

            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
                .title("SherWatch Command Center")
                .inner_size(1500.0, 950.0)
                .min_inner_size(900.0, 600.0)
                .build()?;

            if let Err(e) = build_tray(app.handle()) {
                tracing::warn!("tray icon unavailable ({e}); closing the window will quit the app");
            }
            Ok(())
        })
        // Closing the window hides it to the tray; monitoring continues. Quit from the tray menu to stop.
        // Without a tray (e.g. a Linux desktop without an indicator service) the close button quits.
        .on_window_event(|w, e| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = e {
                if w.app_handle().tray_by_id(TRAY_ID).is_some() {
                    api.prevent_close();
                    let _ = w.hide();
                }
            }
        })
        .build(tauri::generate_context!());

    match result {
        Ok(app) => app.run(|_app, event| match event {
            tauri::RunEvent::Exit => sherwatch::shutdown(),
            // macOS: clicking the Dock icon while the window is hidden brings it back.
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } => show_main(_app),
            _ => {}
        }),
        Err(e) => {
            tracing::error!("desktop start failed: {e}");
            std::process::exit(1);
        }
    }
}
