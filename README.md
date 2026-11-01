# SherWatch Command Center

A network security monitor for Windows, macOS and Linux, written in Rust. It shows every
process that sends or receives data, attributes bytes to processes without any driver,
analyses the traffic for malware behaviour, and presents everything in a dark command-center
dashboard with a live 3D globe.

Everything runs locally. No data about your traffic leaves the machine. The only outbound
requests the app makes on its own are downloads of public threat feeds and the GeoIP
database, one public-IP lookup for the globe's home marker (can be turned off), and
optional VirusTotal hash lookups if you add an API key.

## Why this exists

In the age of AI, knowing what your own computer is doing matters more than it ever did.
Generative AI has turned writing malware, infostealers and phishing kits from weeks of work
into minutes, so attacks are cheaper, faster and more numerous than before, and the first
visible sign of one is usually the same: a program quietly sending data out. SherWatch
exists so that a normal user can see every program that sends data, where it goes, and act
on it.

It was built with the same kind of tool. SherWatch was designed and directed by Sher Khan
and written with Claude Code, Anthropic's AI coding agent, as a pair-programming partner.
The tools that make attacks cheap make defence cheap too, and because the project is open
source, every rule it applies can be read and checked rather than taken on trust.

## Features

- **Per-process visibility.** Every TCP and UDP flow with process name, executable path,
  command line, parent process, user, bytes in and out, remote host, port, state, age,
  hostname, country and city.
- **Driverless capture.** Byte counts come from the operating system's own accounting, so
  no Npcap, WinPcap or kernel extension is needed: Event Tracing for Windows (ETW) on
  Windows, `nettop` polling on macOS, `ss` polling on Linux. DNS queries are captured from
  the Windows DNS client; macOS and Linux DNS capture is not available yet.
- **Threat analysis engine.** 28 detection rules covering threat-feed matches, unsigned
  binaries, suspicious executable locations, living-off-the-land binaries, command-and-control
  beaconing, DNS tunnelling, algorithm-generated domains, data exfiltration volume, odd ports,
  resolver bypass, new listeners, process masquerading, suspicious parent chains, hosts-file
  tampering and more. See [docs/DETECTION-RULES.md](docs/DETECTION-RULES.md).
- **Self-updating threat intelligence.** Public blocklists refresh on a schedule. New feed
  definitions can be added without a rebuild, and the app tells you when a source changed in
  a way that needs a code update. See [docs/UPDATING.md](docs/UPDATING.md).
- **Software inventory and exploit exposure.** Versions of every network-active program,
  every service and every installed program (Windows services and registry; launchctl and
  `system_profiler` on macOS; systemd and dpkg/rpm/flatpak on Linux), matched offline against
  CISA's Known Exploited Vulnerabilities catalogue, with a "likely unpatched" verdict from
  file dates, operating-system patch age, and an opt-in online CVE lookup for exact versions.
- **Built-in analyst assistant.** Ask "what is this process doing?" or "summarise my
  network" and get a plain-language answer with a verdict and a recommended action. Free
  keyless web models by default, every local Ollama model, or your own Claude / Groq /
  OpenRouter / Gemini key, selectable from a dropdown.
- **Trust list.** Vouch for an unsigned program by its hash to silence reputation alerts for
  that exact file.
- **Code signing and hashing.** Every network-active executable is signature-checked and
  SHA-256 hashed: Authenticode on Windows (including catalog-signed system files),
  `codesign` on macOS, and package ownership (dpkg/rpm) on Linux, which names the owning
  package rather than verifying a cryptographic signature. Optional VirusTotal lookup.
- **Response actions.** Terminate a process, block an IP address in the system firewall
  (Windows Defender Firewall, a pf table on macOS, an nftables set on Linux), block an
  executable by path on Windows, remove blocks again, all from the dashboard.
- **Command-center dashboard.** Live throughput, top talkers, destinations by country, alert
  feed, connection stream, a 3D globe with traffic arcs from your location, sortable tables,
  a process drill-down drawer, DNS log, 30 days of history in SQLite, CSV and JSON exports.

## Platforms

Three separate downloads, one code base. What each one can see:

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Connections per process | OS TCP/UDP table | libproc | /proc |
| Byte counts | ETW kernel-network (driverless) | polling `nettop` | polling `ss` (iproute2), TCP only |
| DNS capture (DNS page, rules R08/R11/R12/R20) | ETW DNS-Client | not yet | not yet |
| Needs elevation for | byte counts and DNS (UAC prompt, auto-relaunch) | all-process byte counts (run the browser version with sudo; the desktop app runs unprivileged) | other users' sockets and byte counts (sudo; the desktop app runs unprivileged) |
| Code signature | Authenticode incl. catalog-signed files | `codesign` (Developer ID / Apple) | package ownership (dpkg/rpm) shown as the signer, not a cryptographic check |
| Terminate | taskkill | kill -9 | kill -9 |
| Block an IP | Windows Defender Firewall rule | pf table in anchor `com.sherkhan.sherwatch` | nftables set (iptables fallback) |
| Block a program by path | yes | not supported (pf has no per-app rules) | not supported |
| Inventory | services (WMI), installed programs (registry), file versions, hotfix age | launchctl services, `system_profiler` apps, `sw_vers`, `softwareupdate` history | systemd services, dpkg/rpm/flatpak packages, /etc/os-release, package-manager log age |
| Exploit exposure (CISA KEV) | Windows and apps | macOS and apps | Linux kernel and apps |
| Data folder | `%LOCALAPPDATA%\SherWatch` | `~/Library/Application Support/SherWatch` | `~/.local/share/SherWatch` (XDG) |
| Desktop package | NSIS installer, WebView2 | .dmg, unsigned (Gatekeeper: right-click, Open) | .deb / .AppImage, needs libwebkit2gtk-4.1 and libayatana-appindicator3 |
| Launcher (browser version) | `run.cmd` | `run.sh` (sudo) | `run.sh` (sudo) |

Notes for macOS and Linux: the desktop app starts unprivileged and stays that way; only a
firewall action asks for a password, once per action, through the system dialog. The pf
table on macOS takes effect only after the line `anchor "com.sherkhan.sherwatch"` has been
added to `/etc/pf.conf` once (the browser version run as root reports when it is missing).
On Linux the signature column is package ownership, so unpackaged binaries (AppImages, Steam
games, tools in `~/.local/bin`) are reported as unsigned.

## Requirements

- **Windows**: Windows 10 or 11, 64-bit. Administrator rights for byte counts and DNS
  capture; without them the app still shows connections, processes, signatures, GeoIP and
  most rules, but no byte counts. The desktop app needs the WebView2 runtime (already on
  Windows 11; the installer fetches it otherwise).
- **macOS**: macOS 11 or newer, Apple Silicon or Intel. `sudo` for byte counts of other
  users' processes (`nettop` only reports your own without it).
- **Linux**: a 64-bit distribution with systemd, iproute2 (`ss`) and nftables or iptables.
  The desktop app needs WebKitGTK 4.1 and the Ayatana AppIndicator library: the `.deb`
  depends on `libwebkit2gtk-4.1-0` and `libayatana-appindicator3-1` (Ubuntu 22.04+, Debian
  12+); the AppImage needs the same libraries plus `libfuse2` (or run it with
  `--appimage-extract-and-run`). Without a tray host (GNOME needs the AppIndicator
  extension) the app runs windowed and closing the window quits it. `sudo` for other users'
  sockets and byte counts.
- To build: Rust (stable) plus the platform toolchain (MSVC build tools, Xcode command line
  tools, or the GTK/WebKit development packages). See [docs/BUILDING.md](docs/BUILDING.md).

## Downloads

Installers for every release are attached to the GitHub release page at
<https://github.com/gokukhan/SherWatch/releases>:

| Platform | File |
|---|---|
| Windows | `SherWatch_<version>_x64-setup.exe` (NSIS installer) |
| macOS, Apple Silicon | `SherWatch_<version>_aarch64.dmg` |
| macOS, Intel | `SherWatch_<version>_x64.dmg` |
| Linux, Debian/Ubuntu | `SherWatch_<version>_amd64.deb` |
| Linux, any distribution | `SherWatch_<version>_amd64.AppImage` |

The packages are not code-signed yet: Windows SmartScreen shows "unrecognised app" the
first time (**More info**, **Run anyway**), and macOS Gatekeeper needs a right-click,
**Open** on the first launch (or `xattr -d com.apple.quarantine /Applications/SherWatch.app`).
Linux: `sudo apt install ./SherWatch_<version>_amd64.deb`, or `chmod +x` the AppImage and run it.

## Quick start

Windows:

```
run.cmd
```

macOS and Linux:

```
./run.sh
```

The launcher starts the release binary (`target/release/sherwatch`), building it first when
it is missing. On Windows the app asks for administrator rights (UAC prompt) and relaunches
itself elevated; on macOS and Linux `run.sh` runs it under `sudo`.
The first run downloads the GeoIP database (about 120 MB, once), refreshes the threat feeds
and opens the dashboard at <http://127.0.0.1:8787/>.

Flags:

| Flag | Effect |
|---|---|
| `--no-elevate` | Do not request administrator rights (Windows). Reduced visibility. |
| `--no-browser` | Do not open the dashboard in a browser. |

### Desktop app

The same monitor is also available as a desktop app (Tauri 2) for all three platforms: a
native window with the dashboard, a tray icon, and an installer or package. Closing the
window hides it to the tray while monitoring continues; **Quit** in the tray menu stops it.
On Windows it asks for administrator rights like the browser version; on macOS and Linux it
never elevates itself, so byte counts of other users' processes need the browser version
under `sudo` (on macOS, clicking the Dock icon brings a hidden window back). Build it with
`npx --prefix tools/npm tauri build` from the repository root, which picks the platform's
bundle settings itself (see docs/BUILDING.md); the packages land under
`target/release/bundle/`. Both versions share one code base and one dashboard, so features
arrive in both at the same time.

## Configuration

All settings live in [config.toml](config.toml) and most of them are editable on the
dashboard's Settings page, which validates, saves to the file (comments kept) and applies
them at once: the file-upload and file-sharing thresholds and approved uploaders, the
exfiltration, fan-out and beaconing thresholds, the country watch list, alert cooldown,
feed refresh interval, online CVE lookup, VirusTotal and assistant keys, model and provider,
and the home location for the globe. Port and browser launch need a restart. Feed
definitions are edited in the file.

## Project layout

```
config.toml          settings
run.cmd, run.sh      start the app (release build): Windows, macOS/Linux
src/                 Rust library + browser-version binary (see docs/ARCHITECTURE.md)
src/platform/        the per-OS layer: windows.rs, macos.rs, linux.rs, unix.rs
desktop/             Tauri desktop version (window, tray, installers) over the same library
web/                 dashboard (plain HTML, CSS, JS; embedded in the binary at release build)
web/vendor/          chart.js, globe.gl, d3, topojson, world-atlas (vendored, offline)
data/feeds/          downloaded threat feeds and feeds.json (runtime-added feeds)
data/geo/            DB-IP Lite city database
data/sherwatch.db    SQLite history (alerts, traffic, connections, DNS, blocks, known apps)
data/logs/           log output when started through run.cmd or run.sh
docs/                documentation
tools/               rustup installer, npm packages (frontend libraries, Tauri CLI, ffmpeg),
                     screenshot and explainer-video scripts
.github/workflows/   CI: cargo check on all three OSes, installers on tags
```

## Documentation

- [docs/USER-GUIDE.md](docs/USER-GUIDE.md): the dashboard, every view and action.
- [docs/DETECTION-RULES.md](docs/DETECTION-RULES.md): what each alert means and how to tune it.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the backend works.
- [docs/UPDATING.md](docs/UPDATING.md): how threat data stays current and when the app needs a code change.
- [docs/BUILDING.md](docs/BUILDING.md): building from source on each OS, CI and releases.
- [docs/THIRD-PARTY.md](docs/THIRD-PARTY.md): licences and data-source attributions.
- [LICENSE](LICENSE) and [NOTICE](NOTICE): the project licence (Apache 2.0) and the attribution to keep.
- [docs/presentation/](docs/presentation/): the slide deck (HTML and PDF), the explainer video
  (portrait and landscape) and its storyboard; how they are made is in docs/BUILDING.md.

## Privacy

- Traffic metadata, alerts and history are stored only in `data/sherwatch.db` on this machine.
- The local API answers only the dashboard: requests from other origins or with a foreign
  Host header are rejected.
- The assistant's default free web model receives the facts about the item you ask about.
  Choose a local Ollama model in its dropdown to keep everything on the PC.
- Threat feeds and the GeoIP database are downloaded to disk and queried offline.
- The home location is derived once from your public IP via api.ipify.org (a plain request
  with no payload). Set `home_lat` and `home_lon` in `config.toml` or
  `detect_public_ip = false` to avoid this call.
- Reverse DNS lookups for unexplained IPs go through your normal resolver and can be turned
  off with `reverse_dns = false`.
- VirusTotal is off until you add a key; only SHA-256 hashes are ever sent, never files.

## License

SherWatch is open source under the [Apache License 2.0](LICENSE). Copyright 2026 Sher Khan.

- Free to use, copy, modify and redistribute, for personal and for commercial purposes.
- Credit is required: keep the copyright notice, the LICENSE and the NOTICE file with any copy
  or derivative, and state what you changed. Showing "based on SherWatch by Sher Khan" in your
  own product's about screen or documentation is the right way to do it.
- No warranty and no commitments: the software is provided "as is", without support, service
  levels or liability, as the licence states. It is a monitoring aid, not a guarantee against
  intrusion or data loss.
- Contributions are accepted under the same licence.

Third-party libraries, feeds and data sources keep their own licences; see
[docs/THIRD-PARTY.md](docs/THIRD-PARTY.md).
