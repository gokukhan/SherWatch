# Building from source

SherWatch builds on Windows, macOS and Linux from the same tree. The per-OS code is confined
to `src/platform/` (see ARCHITECTURE.md); everything else compiles unchanged on all three.

## Prerequisites

Rust stable on every platform (installed with rustup; `tools/rustup/rustup-init.exe` is the
Windows installer used for this project, on macOS and Linux use the one-line installer from
rustup.rs). The toolchain lives in `~/.cargo` and `~/.rustup` (`%USERPROFILE%` on Windows).
Node.js is needed only for the Tauri CLI (desktop build) and to re-vendor the frontend
libraries (`tools/npm`).

| OS | On top of Rust |
|---|---|
| Windows | Visual Studio Build Tools with the "Desktop development with C++" workload. The MSVC linker is required for the `x86_64-pc-windows-msvc` target. |
| macOS | Xcode command line tools (`xcode-select --install`). Apple Silicon and Intel both build natively; cross-building the other architecture needs the matching rustup target (`aarch64-apple-darwin` / `x86_64-apple-darwin`). |
| Linux (Debian/Ubuntu) | `sudo apt install libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf libgtk-3-dev libssl-dev build-essential curl wget file libxdo-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev`. Other distributions need the equivalent WebKitGTK 4.1, GTK 3, appindicator, librsvg, libsoup and OpenSSL development packages. The browser version alone needs only `build-essential` and `libssl-dev`. |

## Build

```
cargo build --release
```

Output: `target/release/sherwatch` (`sherwatch.exe` on Windows). The release build embeds
everything under `web/` into the executable (rust-embed), so the binary is self-contained
apart from `config.toml` and the `data/` folder, which it creates next to the project root it
finds.

The debug build (`cargo build`) reads `web/` from disk on every request, which is convenient
for dashboard work: edit a file, reload the page.

## Run during development

```
cargo run -- --no-elevate --no-browser
```

Without elevation there are no byte counts (and on Windows no DNS capture), but everything
else works. For the full feature set run the binary from an elevated terminal (Windows),
with `sudo` (macOS, Linux), or through the launcher: `run.cmd` on Windows, `./run.sh` on
macOS and Linux, which builds the release binary when it is missing and then runs
`sudo target/release/sherwatch` with any arguments you pass.

## Logging

The `RUST_LOG` environment variable controls verbosity, for example
`RUST_LOG=sherwatch=debug`. The launchers write to `data/logs/sherwatch.log`.

## Two front ends, one library

The crate is a library (`src/lib.rs`: collectors, analysis, intel, database, server) with
two thin binaries that cannot drift apart because neither contains any monitoring logic:

| Binary | Where | What it adds |
|---|---|---|
| `sherwatch` (browser version) | `src/main.rs` | console logging, Ctrl+C handling, opens the dashboard in the default browser |
| `SherWatch` (desktop version) | `desktop/` | a Tauri window showing the same dashboard, a tray icon, close-to-tray, single instance, the installers and packages |

The desktop window loads `http://127.0.0.1:<port>/` from the embedded server, exactly like a
browser tab would, so `web/` is shared unchanged and the dashboard's Host/Origin guard
applies to it too. The page has no access to Tauri commands (`desktop/capabilities/default.json`
grants only `core:default`), which keeps the blast radius of any rendering bug to the HTTP
API.

## Desktop build (Tauri)

Prerequisites on top of the Rust toolchain: Node.js for the Tauri CLI, installed into
`tools/npm` once with `cd tools/npm && npm install`, and the platform webview: on Windows the
Microsoft Edge WebView2 runtime (Windows 11 and updated Windows 10 machines already have it;
the installer downloads it when missing), on macOS the system WebKit, on Linux the
WebKitGTK packages from the table above.

The base configuration is `desktop/tauri.conf.json` (NSIS target for Windows). On macOS and
Linux the Tauri CLI merges `desktop/tauri.macos.conf.json` or `desktop/tauri.linux.conf.json`
on top of it automatically (platform-specific config files), which switches the bundle
targets, so the same command works everywhere, run from the repository root:

```
npx --prefix tools/npm tauri build
```

| OS | Output under `target/release/bundle/` |
|---|---|
| Windows | `nsis/SherWatch_<version>_x64-setup.exe` |
| macOS | `dmg/SherWatch_<version>_aarch64.dmg` on Apple Silicon, `dmg/SherWatch_<version>_x64.dmg` on Intel. For the Intel image on an Apple Silicon machine: `rustup target add x86_64-apple-darwin`, then `npx --prefix tools/npm tauri build --target x86_64-apple-darwin`. |
| Linux | `deb/SherWatch_<version>_amd64.deb` and `appimage/SherWatch_<version>_amd64.AppImage` |

`--config desktop/tauri.conf.json` may still be passed explicitly; it is no longer required.

Or without the CLI, for a plain executable with no installer:

```
cargo build --release -p sherwatch-desktop
```

which produces `target/release/sherwatch-desktop` (`.exe` on Windows; the bundles rename it
to `SherWatch`). The first `tauri build` on Windows downloads NSIS into the CLI's cache; on
Linux it downloads the AppImage tooling.

The packages are unsigned until signing is configured: on Windows SmartScreen shows
"unrecognised app" the first time (see `bundle.windows.certificateThumbprint` in the Tauri
documentation when a certificate is available); on macOS Gatekeeper refuses a double-click
and the app must be opened once with right-click, **Open** (a Developer ID certificate and
notarisation remove that step); Linux packages carry no signature by convention.

The app icon is drawn by `tools/make_icon.py` (Pillow) and the icon set under
`desktop/icons` is generated with `npx --prefix tools/npm tauri icon desktop/app-icon.png -o desktop/icons`.

Development run of the desktop version (debug build, reads `web/` from disk):

```
cargo run -p sherwatch-desktop -- --no-elevate
```

## Continuous integration and releases

`.github/workflows/build.yml` has two jobs:

- **check** runs `cargo check` on `ubuntu-22.04`, `macos-14` and `windows-latest` for every
  push and pull request to `main`, so a change that breaks one platform is caught without
  owning that machine.
- **bundle** runs on tags matching `v*` and on manual dispatch (`gh workflow run build.yml`,
  or the "Run workflow" button). Its matrix is `windows-x64` (NSIS), `macos-arm64` and
  `macos-x64` (both `.dmg` files, built on the arm64 runner), and `linux-x64` (`.deb` and
  `.AppImage`). The build artifacts are named `SherWatch-windows-x64`, `SherWatch-macos-arm64`,
  `SherWatch-macos-x64` and `SherWatch-linux-x64`; for a tag the five files
  (`SherWatch_<version>_x64-setup.exe`, `_aarch64.dmg`, `_x64.dmg`, `_amd64.deb`,
  `_amd64.AppImage`) are attached to a **draft** GitHub release named after the tag. Review
  the draft, write the notes and publish it from the Releases page.

To cut a release: bump `version` in `Cargo.toml`, `desktop/Cargo.toml` and
`desktop/tauri.conf.json`, commit, then

```
git tag v0.2.0
git push origin v0.2.0
```

While the repository is private these runs consume the account's GitHub Actions minutes
(macOS runners are billed at ten times, Windows at twice the Linux rate): one tagged release
costs roughly 300 to 350 billed minutes and each push 30 to 110, against the free quota of
2000 minutes a month on a private repository. On a public repository they are free.

## Where the app looks for its files

`data_root()` in `src/lib.rs` walks up from the executable's folder looking for
`config.toml`. Running from `target/release` or `target/debug` therefore finds the
project's `config.toml` and `data/`. An installed copy (no `config.toml` next to the
executable) uses the per-user data folder of the platform instead and writes the default
`config.toml` there on first start; the database, feeds, GeoIP file and logs
(`data/logs/sherwatch-desktop.log`) live under that folder:

| OS | Data folder |
|---|---|
| Windows | `%LOCALAPPDATA%\SherWatch` |
| macOS | `~/Library/Application Support/SherWatch` |
| Linux | `~/.local/share/SherWatch` (`$XDG_DATA_HOME/SherWatch` when set) |

## Frontend libraries

Vendored copies in `web/vendor/`:

| Library | Version | Use |
|---|---|---|
| chart.js | 4.5.0 | throughput, bars, histograms |
| globe.gl | 2.44.0 | 3D globe (bundles three.js) |
| d3 | 7.9.0 | geo centroids and areas for country labels |
| topojson-client | 3.1.0 | decode world-atlas |
| world-atlas | 2.0.2 | countries-110m.json (Natural Earth) |

To update them: `cd tools/npm && npm install <pkg>@<version>` and copy the dist files.

## Screenshot and smoke tests

`node tools/shot.mjs http://127.0.0.1:8787/ tmp/shot.png 1600 1000 7000 [view]` renders the
dashboard headlessly through Microsoft Edge (or Chrome), prints layout metrics (page scroll
width versus client width catches horizontal clipping) and any console errors.
`SHOT_SCALE=2` renders at 2x. `tmp/` is ignored by git.

## Presentation and explainer video

`docs/presentation/` holds the HTML deck (`index.html`, 18 slides) and its PDF
(`SherWatch-Command-Center.pdf`), the deck screenshots in `img/` (1600x1000), the video
screenshots in `img/video/` (3200x2000, device scale 2, each with a `.json` of element
rectangles), `VIDEO-SCRIPT.md` (the storyboard), `narration.json` (the spoken lines, one per
scene), `Natural_Ambience_60s.mp3` (background track) and the two rendered videos
`SherWatch-short.mp4` (1080x1920) and `SherWatch-short-landscape.mp4` (1920x1080), 16 scenes
and about 1:55 each.

The PDF is printed from the HTML with headless Edge, one 1600x1000 page per slide:

```
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless=new --disable-gpu ^
  --user-data-dir=D:\Projects\NetworkMonitor\tmp\edge-pdf --no-pdf-header-footer ^
  --print-to-pdf=D:\Projects\NetworkMonitor\docs\presentation\SherWatch-Command-Center.pdf ^
  file:///D:/Projects/NetworkMonitor/docs/presentation/index.html
```

Check afterwards that the page count equals the slide count (pypdf: `len(PdfReader(p).pages)`).

- `python tools/video_shots.py [shot ...]` captures the staged video screenshots from the
  running app on 127.0.0.1:8787 (it drives the dashboard through its test hooks; default: all
  shots).
- `python tools/make_video.py` renders the portrait video; `--landscape` the landscape one,
  `--silent` without narration, `--sapi` with the offline Windows voice "Microsoft David"
  instead of OpenAI, `--preview` a contact sheet (`tmp/video-preview.png`) instead of an
  encode, `--frame <scene> <t>` a single frame of one scene at time `t` (also written to
  `tmp/video-preview.png`) for a layout check.
  ffmpeg comes from `tools/npm` (ffmpeg-static; run `npm install` there once).

Narration uses OpenAI text-to-speech (voice "echo"). The key is read from the
`OPENAI_API_KEY` environment variable or `data/openai.key` (gitignored) and only needs the
text-to-speech permission. Clips are cached in `tmp/video-audio`, keyed by the spoken text, so only
changed lines are re-synthesised. The narration text is sent to api.openai.com; nothing else leaves the PC.

Commit the rendered videos only when they change for good: each re-render adds tens of MB
to the repository.
