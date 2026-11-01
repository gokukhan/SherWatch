# SherWatch Command Center

A Windows network security monitor written in Rust. It shows every process that sends or
receives data, attributes bytes to processes without any driver, analyses the traffic for
malware behaviour, and presents everything in a dark command-center dashboard with a live
3D globe.

Everything runs locally. No data about your traffic leaves the machine. The only outbound
requests the app makes on its own are downloads of public threat feeds and the GeoIP
database, one public-IP lookup for the globe's home marker (can be turned off), and
optional VirusTotal hash lookups if you add an API key.

## Features

- **Per-process visibility.** Every TCP and UDP flow with process name, executable path,
  command line, parent process, user, bytes in and out, remote host, port, state, age,
  hostname, country and city.
- **Driverless capture.** Byte counts and DNS queries come from Event Tracing for Windows
  (ETW), the same source Windows uses internally. No Npcap or WinPcap needed.
- **Threat analysis engine.** 23 detection rules covering threat-feed matches, unsigned
  binaries, suspicious executable locations, living-off-the-land binaries, command-and-control
  beaconing, DNS tunnelling, algorithm-generated domains, data exfiltration volume, odd ports,
  resolver bypass, new listeners, process masquerading, suspicious parent chains, hosts-file
  tampering and more. See [docs/DETECTION-RULES.md](docs/DETECTION-RULES.md).
- **Self-updating threat intelligence.** Public blocklists refresh on a schedule. New feed
  definitions can be added without a rebuild, and the app tells you when a source changed in
  a way that needs a code update. See [docs/UPDATING.md](docs/UPDATING.md).
- **Software inventory and exploit exposure.** Versions of every network-active program,
  every Windows service and every installed program, matched offline against CISA's Known
  Exploited Vulnerabilities catalogue, with a "likely unpatched" verdict from file dates,
  Windows patch age, and an opt-in online CVE lookup for exact versions.
- **Built-in analyst assistant.** Ask "what is this process doing?" or "summarise my
  network" and get a plain-language answer with a verdict and a recommended action. Free
  keyless web models by default, every local Ollama model, or your own Claude / Groq /
  OpenRouter / Gemini key, selectable from a dropdown.
- **Trust list.** Vouch for an unsigned program by its hash to silence reputation alerts for
  that exact file.
- **Code signing and hashing.** Every network-active executable is Authenticode-verified
  (including catalog-signed Windows files) and SHA-256 hashed. Optional VirusTotal lookup.
- **Response actions.** Terminate a process, block an executable or an IP address in Windows
  Defender Firewall, remove blocks again, all from the dashboard.
- **Command-center dashboard.** Live throughput, top talkers, destinations by country, alert
  feed, connection stream, a 3D globe with traffic arcs from your location, sortable tables,
  a process drill-down drawer, DNS log, 30 days of history in SQLite, CSV and JSON exports.

## Requirements

- Windows 10 or 11, 64-bit.
- Administrator rights for packet-level byte counts and DNS capture. Without them the app
  still shows connections, processes, signatures, GeoIP and most rules, but no byte counts.
- To build: Rust (stable) and the Visual Studio C++ build tools. See
  [docs/BUILDING.md](docs/BUILDING.md).

## Quick start

```
run.cmd
```

`run.cmd` starts the release binary. The app asks for administrator rights (UAC prompt),
downloads the GeoIP database on the first run (about 120 MB, once), refreshes the threat
feeds and opens the dashboard at <http://127.0.0.1:8787/>.

Flags:

| Flag | Effect |
|---|---|
| `--no-elevate` | Do not request administrator rights. Reduced visibility. |
| `--no-browser` | Do not open the dashboard in a browser. |

### Desktop app

The same monitor is also available as a Windows desktop app (Tauri): a native window with
the dashboard, a tray icon, and an installer. Closing the window hides it to the tray while
monitoring continues; **Quit** in the tray menu stops it. Build it with
`npx --prefix tools/npm tauri build --config desktop/tauri.conf.json` (see docs/BUILDING.md);
the installer lands in `target\release\bundle\nsis\`. Both versions share one code base and
one dashboard, so features arrive in both at the same time.

## Configuration

All settings live in [config.toml](config.toml). Edit and restart. The main knobs are the
listening port, alert cooldown, exfiltration thresholds, beaconing sensitivity, the country
watch list, feed definitions, the VirusTotal key and the home location for the globe.
The file is commented.

## Project layout

```
config.toml          settings
run.cmd              start the app (release build)
src/                 Rust library + browser-version binary (see docs/ARCHITECTURE.md)
desktop/             Tauri desktop version (window, tray, installer) over the same library
web/                 dashboard (plain HTML, CSS, JS; embedded in the binary at release build)
web/vendor/          chart.js, globe.gl, d3, topojson, world-atlas (vendored, offline)
data/feeds/          downloaded threat feeds and feeds.json (runtime-added feeds)
data/geo/            DB-IP Lite city database
data/sherwatch.db       SQLite history (alerts, traffic, connections, DNS, blocks, known apps)
data/logs/           log output when started through run.cmd
docs/                documentation
tools/               rustup installer and npm packages used to vendor the frontend libraries
```

## Documentation

- [docs/USER-GUIDE.md](docs/USER-GUIDE.md): the dashboard, every view and action.
- [docs/DETECTION-RULES.md](docs/DETECTION-RULES.md): what each alert means and how to tune it.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the backend works.
- [docs/UPDATING.md](docs/UPDATING.md): how threat data stays current and when the app needs a code change.
- [docs/BUILDING.md](docs/BUILDING.md): building from source.
- [docs/THIRD-PARTY.md](docs/THIRD-PARTY.md): licences and data-source attributions.

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
