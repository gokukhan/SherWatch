# Architecture

NetMonitor is a single Rust binary that embeds its web dashboard. It has four layers:
collectors, shared state, analysis, and the HTTP/WebSocket server.

```
 Windows                      netmon.exe                                     browser
 ───────                      ──────────                                     ───────
 TCP/UDP tables ──► conntable ─┐                                   ┌─► REST /api/*
 ETW kernel-network ──► etw ───┼──► AppState (DashMaps, ring       │
 ETW DNS-client ──► etw ───────┤      buffers, alert queue) ──────┼─► WebSocket /ws (1 Hz ticks,
 process list ──► procinfo ────┤          │        ▲               │     alerts, DNS events)
 Authenticode, SHA-256 ► sig ──┤          │        │               └─► embedded static files
 reverse DNS ──► rdns ─────────┘          ▼        │
                                      analysis (rules, every 2 s)
                                          │
 feeds (HTTP) ──► intel ◄─────────────────┘ lookups
 DB-IP mmdb ──► geo   ◄───────────────────┘
                                      db thread ──► SQLite data/netmon.db
```

## Source map

| File | Responsibility |
|---|---|
| `src/main.rs` | Startup: elevation, config, database, GeoIP download, feed refresh, spawning every worker, the 1 Hz ticker, the scheduled feed refresh, the HTTP server. |
| `src/config.rs` | `config.toml` schema with defaults. |
| `src/model.rs` | Data types: `Connection`, `ProcessInfo`, `Alert`, `DnsEvent`, `Severity`, `FlowKey`... |
| `src/state.rs` | `AppState`, the hub. Upserts from collectors, enrichment (GeoIP, intel, hostname), per-second accounting, alert creation with cooldown, overview aggregation, expiry. |
| `src/collectors/conntable.rs` | Polls the OS socket tables once a second (netstat2 over `GetExtendedTcpTable`/`GetExtendedUdpTable`). Source of connection state, listeners and local addresses. |
| `src/collectors/etw.rs` | ETW consumer (ferrisetw). Kernel-Network events 10/11/26/27 (TCP send/recv), 42/43/58/59 (UDP), 12/28 (connect), 15/31 (accept). DNS-Client event 3008. Decides the port byte order at runtime by matching against the socket table. |
| `src/collectors/procinfo.rs` | Resolves PIDs with sysinfo (name, exe, command line, parent, user, start time). Signature worker: batches paths through `Get-AuthenticodeSignature` so catalog-signed Windows files verify, hashes files with SHA-256. Reverse-DNS worker. |
| `src/collectors/vt.rs` | Optional VirusTotal v3 hash lookups, rate limited for free keys. |
| `src/analysis/mod.rs` | The rule engine and the hosts-file check. See DETECTION-RULES.md. |
| `src/intel.rs` | Feed download, parsing (CSV, IP lines, CIDR lines, IPsum, domain lines, hosts lines, URL lines, JSON), lookup sets, remote manifest, update-needed detection. |
| `src/geo.rs` | DB-IP Lite city lookups (maxminddb) and first-run download. |
| `src/db.rs` | SQLite schema, a single writer thread fed by a channel, batched traffic inserts, 30-day pruning, history queries. |
| `src/actions.rs` | taskkill, netsh advfirewall add/delete rule. |
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

Kernel-Network events carry the owning PID in the payload (the header PID is often 4 or 0
because completion runs on a kernel worker thread). Ports in the payload are in network
byte order on current Windows builds; because this is poorly documented, the consumer
compares the first dozen TCP events against the socket table and picks the interpretation
that matches.

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
| ETW trace | OS thread owned by ferrisetw | event driven |
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
| GET | `/api/overview` | rates, counts, alert totals, top processes, countries, capture status |
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
| GET | `/api/intel`, POST `/api/intel/refresh` | feed status and update-needed state |
| GET | `/api/config` | effective configuration (API key masked) |
| GET | `/api/history/traffic?hours=`, `/api/history/alerts?hours=`, `/api/history/connections?hours=&limit=` | SQLite history |
| GET | `/api/blocks` | firewall rules created by the app |
| POST | `/api/action/kill`, `/api/action/block-exe`, `/api/action/block-ip`, `/api/action/unblock` | response actions |
| GET | `/api/export/connections.csv`, `alerts.csv`, `alerts.json`, `processes.json`, `dns.csv` | exports |
| WS | `/ws` | `hello`, `tick` (1 Hz), `alert`, `dns` messages |

The server binds to 127.0.0.1 only. There is no authentication; do not change the bind
address to a network interface without putting something in front of it.
