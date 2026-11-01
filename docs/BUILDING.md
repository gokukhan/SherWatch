# Building from source

## Prerequisites

- Rust stable (installed with rustup; `tools/rustup/rustup-init.exe` is the installer used
  for this project). The toolchain lives in `%USERPROFILE%\.cargo` and `.rustup`.
- Visual Studio Build Tools with the "Desktop development with C++" workload. The MSVC
  linker is required for the `x86_64-pc-windows-msvc` target.
- Node.js only if you want to re-vendor the frontend libraries (`tools/npm`).

## Build

```
cargo build --release
```

Output: `target\release\sherwatch.exe`. The release build embeds everything under `web/` into
the executable (rust-embed), so the binary is self-contained apart from `config.toml` and
the `data/` folder, which it creates next to the project root it finds.

The debug build (`cargo build`) reads `web/` from disk on every request, which is convenient
for dashboard work: edit a file, reload the page.

## Run during development

```
cargo run -- --no-elevate --no-browser
```

Without elevation there are no byte counts and no DNS capture, but everything else works.
For the full feature set run the binary from an elevated terminal or through `run.cmd`.

## Logging

The `RUST_LOG` environment variable controls verbosity, for example
`RUST_LOG=sherwatch=debug`. `run.cmd` writes to `data\logs\sherwatch.log`.

## Two front ends, one library

The crate is a library (`src/lib.rs`: collectors, analysis, intel, database, server) with
two thin binaries that cannot drift apart because neither contains any monitoring logic:

| Binary | Where | What it adds |
|---|---|---|
| `sherwatch.exe` (browser version) | `src/main.rs` | console logging, Ctrl+C handling, opens the dashboard in the default browser |
| `SherWatch.exe` (desktop version) | `desktop/` | a Tauri window showing the same dashboard, a tray icon, close-to-tray, single instance, an NSIS installer |

The desktop window loads `http://127.0.0.1:<port>/` from the embedded server, exactly like a
browser tab would, so `web/` is shared unchanged and the dashboard's Host/Origin guard
applies to it too. The page has no access to Tauri commands (`desktop/capabilities/default.json`
grants only `core:default`), which keeps the blast radius of any rendering bug to the HTTP
API.

## Desktop build (Tauri)

Prerequisites on top of the Rust toolchain: Node.js (for the Tauri CLI, installed into
`tools/npm`) and the Microsoft Edge WebView2 runtime, which Windows 11 and updated Windows 10
machines already have; the installer downloads it when missing.

```
cd tools\npm && npm install            (once; installs @tauri-apps/cli)
npx --prefix tools/npm tauri build --config desktop/tauri.conf.json
```

Or without the CLI, for a plain executable with no installer:

```
cargo build --release -p sherwatch-desktop
```

Outputs:

- `target\release\sherwatch-desktop.exe`: the desktop app itself.
- `target\release\bundle\nsis\SherWatch_<version>_x64-setup.exe`: the installer (only
  from `tauri build`). The first `tauri build` downloads NSIS into the CLI's cache.

The installer is unsigned until a code-signing certificate is configured, so SmartScreen
shows "unrecognised app" the first time; see `bundle.windows.certificateThumbprint` in the
Tauri documentation when a certificate is available.

The app icon is drawn by `tools/make_icon.py` (Pillow) and the icon set under
`desktop/icons` is generated with `npx --prefix tools/npm tauri icon desktop/app-icon.png -o desktop/icons`.

Development run of the desktop version (debug build, reads `web/` from disk):

```
cargo run -p sherwatch-desktop -- --no-elevate
```

## Where the app looks for its files

`data_root()` in `src/lib.rs` walks up from the executable's folder looking for
`config.toml`. Running from `target\release` or `target\debug` therefore finds the
project's `config.toml` and `data/`. An installed copy (under Program Files, no
`config.toml` next to it) uses `%LOCALAPPDATA%\SherWatch\` instead and writes the default
`config.toml` there on first start; the database, feeds, GeoIP file and logs
(`data\logs\sherwatch-desktop.log`) live under that folder.

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
dashboard headlessly through Microsoft Edge, prints layout metrics (page scroll width versus
client width catches horizontal clipping) and any console errors. `SHOT_SCALE=2` renders at 2x.
`tmp/` is ignored by git.

## Presentation and explainer video

`docs/presentation/` holds the HTML deck (`index.html`, 16 slides) and its PDF
(`SherWatch-Command-Center.pdf`), the deck screenshots in `img/` (1600x1000), the video
screenshots in `img/video/` (3200x2000, device scale 2, each with a `.json` of element
rectangles), `VIDEO-SCRIPT.md` (the storyboard), `narration.json` (the spoken lines, one per
scene), `Natural_Ambience_60s.mp3` (background track) and the two rendered videos
`SherWatch-short.mp4` (1080x1920) and `SherWatch-short-landscape.mp4` (1920x1080).

- `python tools/video_shots.py [shot ...]` captures the staged video screenshots from the
  running app on 127.0.0.1:8787 (it drives the dashboard through its test hooks; default: all
  shots).
- `python tools/make_video.py` renders the portrait video; `--landscape` the landscape one,
  `--silent` without narration, `--sapi` with the offline Windows voice "Microsoft David"
  instead of OpenAI, `--preview` a contact sheet (`tmp/video-preview.png`) instead of an encode.
  ffmpeg comes from `tools/npm` (ffmpeg-static; run `npm install` there once).

Narration uses OpenAI text-to-speech (voice "echo"). The key is read from the
`OPENAI_API_KEY` environment variable or `data/openai.key` (gitignored) and only needs the
text-to-speech permission. Clips are cached in `tmp/video-audio` and re-synthesised only when
a line changes. The narration text is sent to api.openai.com; nothing else leaves the PC.

Commit the rendered videos only when they change for good: each re-render adds tens of MB
to the repository.
