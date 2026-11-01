//! NetMonitor desktop: a native window and tray icon around the shared `netmon` library.
//! The window simply shows the same dashboard the browser version serves, so both stay in sync.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let no_elevate = args.iter().any(|a| a == "--no-elevate");
    let admin = netmon::is_admin();
    if !admin && !no_elevate && netmon::relaunch_elevated() {
        return;
    }

    let root = netmon::data_root();
    let _ = std::fs::create_dir_all(root.join("data").join("logs"));
    netmon::init_logging(Some(&root.join("data").join("logs").join("netmon-desktop.log")));

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .setup(move |app| {
            // Start the monitor on Tauri's Tokio runtime and keep the HTTP server running in the background.
            let running = tauri::async_runtime::block_on(netmon::start(root.clone(), admin))?;
            let url: tauri::Url = running.url.parse()?;
            tauri::async_runtime::spawn(async move {
                if let Err(e) = netmon::serve(running).await {
                    tracing::error!("server stopped: {e}");
                }
            });

            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
                .title("NetMonitor Command Center")
                .inner_size(1500.0, 950.0)
                .min_inner_size(900.0, 600.0)
                .build()?;

            let open = MenuItem::with_id(app, "open", "Open NetMonitor", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit (stops monitoring)", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            TrayIconBuilder::with_id("main-tray")
                .icon(app.default_window_icon().cloned().expect("bundle icon"))
                .tooltip("NetMonitor Command Center")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, e| match e.id.as_ref() {
                    "open" => show_main(app),
                    "quit" => {
                        netmon::shutdown();
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
        })
        // Closing the window hides it to the tray; monitoring continues. Quit from the tray menu to stop.
        .on_window_event(|w, e| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = e {
                api.prevent_close();
                let _ = w.hide();
            }
        })
        .build(tauri::generate_context!());

    match result {
        Ok(app) => app.run(|_, event| {
            if let tauri::RunEvent::Exit = event {
                netmon::shutdown();
            }
        }),
        Err(e) => {
            tracing::error!("desktop start failed: {e}");
            std::process::exit(1);
        }
    }
}
