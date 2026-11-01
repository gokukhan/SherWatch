# Architecture

SherWatch is a single Rust binary that embeds its web dashboard. It has four layers:
collectors, shared state, analysis, and the HTTP/WebSocket server. The collectors sit on a
thin platform layer (`src/platform/`) that supplies the OS-specific parts for Windows, macOS
and Linux; everything above it is shared.

```
 OS (via src/platform)        sherwatch                                       browser
 ─────────────────────        ─────────                                       ───────
 socket tables ──► conntable ─┐                                    ┌─► REST /api/*
 byte counter ──► traffic ────┼──► AppState (DashMaps, ring        │
 DNS capture ──► dns ─────────┤      buffers, alert queue) ───────┼─► WebSocket /ws (1 Hz ticks,
 process list ──► procinfo ───┤          │        ▲                │     alerts, DNS events)
 signature, SHA-256 ──► sig ──┤          │        │                └─► embedded static files
 reverse DNS ──► rdns ────────┘          ▼        │
                                      analysis (rules, every 2 s)
                                          │
 feeds (HTTP) ──► intel ◄─────────────────┘ lookups
 DB-IP mmdb ──► geo   ◄───────────────────┘
                                      db thread ──► SQLite data/sherwatch.db
```

## Source map

| File | Responsibility |
|---|---|
| `src/lib.rs` | Startup shared by both front ends: `start()` loads config, opens the database, kicks off the GeoIP download and feed refresh, spawns every worker, the 1 Hz ticker and the scheduled feed refresh, and binds the port (taking it over from an older instance); `serve()` runs the HTTP server; `shutdown()` stops the capture. Also elevation, logging and `data_root()`. |
| `src/platform/mod.rs` | The platform layer: one shared surface (socket table, byte counter, DNS capture, process details, signature check, terminate, firewall block/unblock, inventory, elevation check, data folder) with `#[cfg(target_os)]` re-exports of the implementation below. Nothing outside this folder names an OS API. |
| `src/platform/windows.rs` | `GetExtendedTcpTable`/`GetExtendedUdpTable` socket tables, ETW Kernel-Network and DNS-Client consumers (ferrisetw), Authenticode via `Get-AuthenticodeSignature`, `taskkill`, `netsh advfirewall`, WMI services, registry programs, hotfix age, UAC relaunch, `%LOCALAPPDATA%\SherWatch`. |
| `src/platform/macos.rs` | libproc socket tables, streamed `nettop` for per-process bytes, `codesign` verification, `kill -9`, pf table in anchor `com.sherkhan.sherwatch` (via `osascript … with administrator privileges` when not root), launchctl services, `system_profiler` apps with versions from each bundle's `Info.plist`, `sw_vers`, last update from `/Library/Receipts/InstallHistory.plist` (fallback `softwareupdate --history`), `~/Library/Application Support/SherWatch`. No DNS capture yet. |
| `src/platform/linux.rs` | `/proc` socket ownership, `ss -tinpeHO` polling for TCP bytes, dpkg/rpm ownership as the "signer", `kill -9`, nftables set (iptables fallback; via `pkexec` when not root), systemd services, dpkg/rpm/flatpak packages, `/etc/os-release` (the kernel version is shown as the OS build), last update from the newest apt/dpkg/dnf/pacman/zypp log, `~/.local/share/SherWatch`. No DNS capture yet. |
| `src/platform/unix.rs` | What macOS and Linux share: uid-based elevation check, `kill`, the `/etc/hosts` path, home-folder resolution, running a tool without a terminal. |
| `src/main.rs` | Browser version: console logging, Ctrl+C, opens the dashboard in the default browser. |
| `desktop/src/main.rs` | Desktop version (Tauri): the same `start()`/`serve()`, shown in a native window that loads the local server URL; tray icon, close-to-tray, single instance. No Tauri commands are exposed to the page. |
| `src/config.rs` | `config.toml` schema with defaults. |
| `src/model.rs` | Data types: `Connection`, `ProcessInfo`, `Alert`, `DnsEvent`, `Severity`, `FlowKey`... |
| `src/state.rs` | `AppState`, the hub. Upserts from collectors, enrichment (GeoIP, intel, hostname), per-second accounting, alert creation with cooldown, overview aggregation, expiry. |
| `src/collectors/conntable.rs` | Polls the OS socket tables once a second through the platform layer (Windows: netstat2 over `GetExtendedTcpTable`/`GetExtendedUdpTable`; macOS: libproc; Linux: `/proc`). Source of connection state, listeners and local addresses. |
| `src/collectors/etw.rs` | Windows byte and DNS collector: ETW consumer (ferrisetw). Kernel-Network events 10/11/26/27 (TCP send/recv), 42/43/58/59 (UDP), 12/28 (connect), 15/31 (accept). DNS-Client event 3008. Decides the port byte order at runtime by matching against the socket table. |
| `src/collectors/procinfo.rs` | Resolves PIDs with sysinfo (name, exe, command line, parent, user, start time). Signature worker: batches paths through the platform signature check (Authenticode via `Get-AuthenticodeSignature` so catalog-signed Windows files verify; `codesign` on macOS; package ownership on Linux), hashes files with SHA-256. Reverse-DNS worker. |
| `src/collectors/vt.rs` | Optional VirusTotal v3 hash lookups, rate limited for free keys. |
| `src/analysis/mod.rs` | The rule engine and the hosts-file check. See DETECTION-RULES.md. |
| `src/intel.rs` | Feed download, parsing (CSV, IP lines, CIDR lines, IPsum, domain lines, hosts lines, URL lines, JSON, CISA KEV), lookup sets, remote manifest, update-needed detection. |
| `src/inventory.rs` | Software inventory: services, installed programs, executable version info and OS patch state every 30 min, collected by the platform layer (one PowerShell query on Windows; launchctl, `system_profiler`, `sw_vers` and `softwareupdate` on macOS; systemd, dpkg/rpm/flatpak and `/etc/os-release` on Linux); offline matching against the KEV catalogue; optional online CVE lookup (Shodan CVEDB) with 7-day cache; rules R24 to R26. Also maps svchost PIDs to the services they host on Windows. |
| `src/geo.rs` | DB-IP Lite city lookups (maxminddb) and first-run download. |
| `src/db.rs` | SQLite schema, a single writer thread fed by a channel, batched traffic inserts, 30-day pruning, history queries. |
| `src/actions.rs` | Response actions and their audit log, delegating to the platform layer: terminate (taskkill / `kill -9`), block and unblock an IP (Windows Defender Firewall rule / pf table / nftables set with iptables fallback), block an executable by path (Windows only). |
| `src/ai.rs` | Assistant: builds factual context (process, alert, connection, overview) and queries a model. Providers: free keyless web models (pollinations.ai, OpenAI-compatible), local Ollama (`/api/chat`), Anthropic Messages API (raw HTTP, `claude-opus-5-5`, low effort, server-side fallbacks), any OpenAI-compatible endpoint. The dropdown choices come from `/api/ai/status`. |
| `src/server.rs` | axum router, JSON API, CSV/JSON exports, WebSocket broadcast, embedded assets (rust-embed). |
| `web/` | Dashboard: `index.html`, `styles.css`, `app.js`, vendored libraries. |

## Data flow in detail

### Connections

A flow is keyed by `(pid, protocol, local port, remote address:port)`. The local *address*
is deliberately left out of the key because UDP sockets are bound to `0.0.0.0` in the socket
table while ETW reports the concrete interface address.

- The socket table poller upserts TCP rows (state, pid) and marks them seen. A TCP flow
  disappears when it has been missing from the table for 4 s.
- ETW send/receive events add bytes and packets. UDP flows exist only through ETW and
  expire after 60 s idle. TCP flows that ETW saw but the table never did (very short-lived)
  expire after 30 s.
- On creation a flow is enriched: scope (public, lan, loopback...), GeoIP, threat-intel
  match, hostname from the DNS capture map, and a reverse-DNS request if nothing is known.
- Closed flows with traffic or a public destination are written to `conn_log`.

### Byte attribution

Each platform attributes bytes differently; the shared code only ever sees `(flow key,
bytes out, bytes in)` deltas.

- **Windows**: Kernel-Network ETW events carry the owning PID in the payload (the header
  PID is often 4 or 0 because completion runs on a kernel worker thread). Ports in the
  payload are in network byte order on current Windows builds; because this is poorly
  documented, the consumer compares the first dozen TCP events against the socket table
  and picks the interpretation that matches. Event driven, no polling.
- **macOS**: `nettop -L 0 -s 2 -x -J bytes_in,bytes_out` is kept running and streams a
  sample every 2 s: one row per connection with cumulative bytes in and out, which the
  collector turns into deltas, plus a per-process remainder for traffic `nettop` does not
  attribute to a listed connection. Without root it only reports the processes of the
  current user.
- **Linux**: `ss -tinpeHO` is polled every 2 s; its per-socket `bytes_sent` /
  `bytes_received` counters become deltas and are matched to the owning PID. UDP sockets
  carry no byte counters in `ss`, so UDP flows on Linux appear with connection data but no
  bytes. Sockets of other users need root.

On macOS and Linux the capture starts even without root and shows partial data (your own
processes); `/api/overview` reports `capture_backend` (`etw`, `nettop` or `ss`) and
`dns_capture` (bool), which the dashboard turns into the "Capture (nettop)" / "Capture
(ss)" light and a "no DNS capture on this platform" note. When `nettop` or `ss` is missing
the capture is reported inactive with a message saying so.

### Platform layer

`src/platform/mod.rs` defines what the rest of the program may ask of the operating
system; `windows.rs`, `macos.rs` and `linux.rs` implement it, `unix.rs` holds what the two
Unix ports share. The split, and what each OS supplies:

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Connections per process | OS TCP/UDP table (GetExtendedTcpTable) | libproc | /proc |
| Byte counts | ETW kernel-network (driverless) | polling `nettop` | polling `ss` (iproute2), TCP only |
| DNS capture | ETW DNS-Client | not yet | not yet |
| Elevation | UAC prompt, auto-relaunch | `sudo` for the browser version; the desktop app runs unprivileged | `sudo` for the browser version; the desktop app runs unprivileged |
| Code signature | Authenticode incl. catalog-signed files | `codesign` (Developer ID / Apple) | package ownership (dpkg/rpm) reported as the signer, not a cryptographic check |
| Terminate | taskkill | kill -9 | kill -9 |
| Block an IP | Windows Defender Firewall rule | pf table in anchor `com.sherkhan.sherwatch` | nftables set (iptables fallback) |
| Block a program by path | yes | not supported (pf has no per-app rules) | not supported |
| Inventory | services (WMI), installed programs (registry), file versions, hotfix age | launchctl services, `system_profiler` apps, `sw_vers`, `softwareupdate` history | systemd services, dpkg/rpm/flatpak packages, `/etc/os-release`, package-manager log age |
| Exploit exposure (CISA KEV) | Windows + apps | macOS + apps | Linux kernel + apps |
| Data folder | `%LOCALAPPDATA%\SherWatch` | `~/Library/Application Support/SherWatch` | `~/.local/share/SherWatch` (XDG) |

A capability an OS does not have (DNS capture, per-program blocks) is reported as such by
the platform layer, so the server can tell the dashboard, and the rules that depend on it
(R08, R11, R12, R20 and the DNS page) stay quiet instead of failing. External tools
(`nettop`, `ss`, `pfctl`, `nft`, `codesign`, `launchctl`, PowerShell) are run without a
terminal window and with a fixed argument list. The one exception is firewall actions on
macOS and Linux when the app is not root: they run through
`osascript -e 'do shell script "…" with administrator privileges'` (macOS) or
`pkexec sh -c …` (Linux), one password prompt per action. The address is parsed as an
`IpAddr` before it is interpolated into that command and the rule name is derived from it,
so nothing typed by the user reaches the shell as text.

The macOS pf table only takes effect if `/etc/pf.conf` contains the line
`anchor "com.sherkhan.sherwatch"`; when running as root the app checks this and returns a
clear error, without root it cannot check. Without root, the "in firewall / missing"
reconciliation of recorded blocks is skipped on macOS and Linux (listing pf or nft rules
needs root and would prompt on every page load), so recorded rules are shown as present.

### Processes

`AppState::touch_process` creates a `ProcessInfo` the first time a PID appears and queues it
for the process worker. The worker fills in details, derives path flags (temp, downloads,
system...), asks the signature worker for the executable, and records first-ever-seen
executables in `known_apps` (rule R13). Signature results are cached per executable path in
`exe_meta` and copied to every process with that path.

Each process keeps a 300-second ring of per-second (out, in) byte pairs. The ticker rolls it
once a second, computes smoothed rates, and every 10 s sends a traffic sample for each active
process to the database.

### Alerts

`AppState::push_alert` builds a key from rule, executable and target. If the key fired
within the cooldown window, the existing alert's count and timestamp are bumped. Otherwise a
new alert gets the next ID, goes to the in-memory ring (2000), the database, the WebSocket
clients, and raises the process risk score.

### Threat intelligence

`Intel::refresh` runs at startup and every `refresh_hours`. For each feed definition
(config.toml, then `data/feeds/feeds.json`, then the remote manifest if configured) it
downloads when the local copy is older than the interval, parses into IP, CIDR and domain
sets, and records per-feed status. HTML responses, HTTP errors and unknown feed kinds are
recorded and surface as "update needed".

### Locking rules

`AppState` uses `DashMap` for the hot maps. Never take a second reference into the *same*
map while holding an iterator or entry on it from the same thread: collect keys first, then
mutate. `parking_lot` locks are not reentrant.

## Threads and tasks

| Name | Kind | Period |
|---|---|---|
| conn-table | OS thread | 1 s |
| byte counter | OS thread: ETW trace owned by ferrisetw (Windows); `nettop` stream / `ss` poller (macOS / Linux) | event driven (Windows) or 2 s |
| proc-info | OS thread | on demand + full refresh every 15 s |
| sig-worker | OS thread | batches of up to 40 paths |
| rdns | OS thread | on demand |
| db-writer | OS thread | event driven, traffic flushed every 10 s |
| ticker | tokio task | 1 s |
| analysis | tokio task (spawn_blocking) | 2 s |
| hosts-file check | tokio task | 5 min |
| feed refresh | tokio task | `refresh_hours` |
| VirusTotal | tokio task | 16 s between requests |
| HTTP server | tokio | - |

## API

| Method | Path | Returns |
|---|---|---|
| GET | `/api/overview` | rates, counts, alert totals, top processes, countries, capture status (`capture_backend`: etw / nettop / ss, `dns_capture`) |
| GET | `/api/connections?public=1&pid=` | live flows |
| GET | `/api/processes` | per-process aggregates with a 60-point sparkline |
| GET | `/api/process/{pid}` | full process detail: connections, DNS, alerts, listeners, repeated contacts |
| GET | `/api/alerts?limit=&unacked=` | alerts, newest first |
| POST | `/api/alerts/{id}/ack`, `/api/alerts/ack-all` | acknowledge |
| GET | `/api/dns?limit=` | captured DNS events |
| GET | `/api/series` | last 10 minutes of per-second totals |
| GET | `/api/geo` | destinations aggregated per remote IP, for the globe |
| GET | `/api/home` | home coordinates for the globe |
| GET | `/api/listeners` | listening sockets |
| GET | `/api/inventory`, POST `/api/inventory/scan`, POST `/api/inventory/cve-lookup` | software inventory, rescan, opt-in online CVE lookup |
| GET | `/api/ai/status?provider=&model=`, POST `/api/ai/ask` | assistant status and model choices; ask with `{kind, pid|id|remote, question, history, provider, model}` |
| GET | `/api/trusted`, POST `/api/action/trust`, `/api/action/untrust` | trust list |
| GET | `/api/intel`, POST `/api/intel/refresh` | feed status and update-needed state |
| GET | `/api/config` | effective configuration (API key masked) |
| GET | `/api/history/traffic?hours=`, `/api/history/alerts?hours=`, `/api/history/connections?hours=&limit=` | SQLite history |
| GET | `/api/blocks` | firewall rules created by the app |
| POST | `/api/action/kill`, `/api/action/block-exe`, `/api/action/block-ip`, `/api/action/unblock` | response actions |
| GET | `/api/export/connections.csv`, `alerts.csv`, `alerts.json`, `processes.json`, `dns.csv` | exports |
| WS | `/ws` | `hello`, `tick` (1 Hz), `alert`, `dns` messages |

The server binds to 127.0.0.1 only. There is no authentication, but a middleware rejects
any request whose Host header is not the local bind address or whose Origin (when a
browser sends one) is not this server, which blocks DNS-rebinding and cross-site requests
from other pages open in the user's browser. Do not change the bind address to a network
interface without putting something in front of it.

`POST /api/shutdown` makes the instance exit after closing its capture (the ETW session on
Windows, the poller elsewhere); a newly started instance uses it to take over the port from
an older one (latest launch wins).

### Startup order

Config, database, GeoIP (opened if present), feeds parsed from disk, workers, HTTP server.
GeoIP download (first run) and the first feed refresh run in a background task after the
server is listening, so the dashboard never waits on the network.
