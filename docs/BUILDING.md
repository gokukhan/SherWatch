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

Output: `target\release\netmon.exe`. The release build embeds everything under `web/` into
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
`RUST_LOG=netmon=debug`. `run.cmd` writes to `data\logs\netmon.log`.

## Where the app looks for its files

`project_root()` in `src/main.rs` walks up from the executable's folder looking for
`config.toml` and falls back to the current directory. Running from `target\release` or
`target\debug` therefore finds the project's `config.toml` and `data/`.

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
client width catches horizontal clipping) and any console errors. `tmp/` is ignored by git.
