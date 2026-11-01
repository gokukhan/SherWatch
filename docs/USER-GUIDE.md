# User guide

SherWatch shows every program on this computer that sends or receives data, where the data
goes, and whether that should worry you. It exists because, in the age of AI, attacks are
cheap: generative AI has made writing malware, infostealers and phishing kits a matter of
minutes, so there are more of them and the first sign is usually a program quietly sending
data out. The same kind of tool built the defence: SherWatch was designed and directed by
Sher Khan and written with Claude Code, Anthropic's AI coding agent, as a pair-programming
partner, and it is open source so every rule it applies can be read and checked. (The
assistant inside the dashboard, which explains processes and alerts on request, is a
separate feature; see the Assistant section.)

The dashboard, the rules and the actions are the same on Windows, macOS and Linux. The
sections below say where a platform differs.

## Installing

Download the package for your system from the GitHub releases page
(<https://github.com/gokukhan/SherWatch/releases>) or build it from source (BUILDING.md).

| OS | Desktop app | Browser version |
|---|---|---|
| Windows 10/11 | `SherWatch_<version>_x64-setup.exe`. SmartScreen shows "unrecognised app" once; choose **More info**, **Run anyway**. Start SherWatch from the Start menu. | `run.cmd` in the project folder. |
| macOS 11+ (Apple Silicon `_aarch64.dmg`, Intel `_x64.dmg`) | Open the `.dmg`, drag SherWatch to Applications. The app is not notarised yet, so the first launch must be right-click, **Open** (or run `xattr -d com.apple.quarantine /Applications/SherWatch.app` once). | `./run.sh` in the project folder. |
| Linux x64 | `.deb` for Ubuntu 22.04+ / Debian 12+ (`sudo apt install ./SherWatch_<version>_amd64.deb`; it depends on `libwebkit2gtk-4.1-0` and `libayatana-appindicator3-1`) or the `.AppImage` for any distribution (`chmod +x`, then run; needs the same WebKitGTK plus `libfuse2`, or start it with `--appimage-extract-and-run`). Without a tray host (GNOME needs the AppIndicator extension) the app runs windowed and the close button quits instead of hiding to the tray. | `./run.sh` in the project folder. |

## Starting and stopping

**Windows**: double-click `run.cmd` or run it from a terminal. Windows asks for
administrator permission; accept it to get byte counts and DNS capture. A console window
shows the log; closing it stops the monitor. The desktop app asks for the same permission
when it starts.

**macOS and Linux**: run `./run.sh` from a terminal; it builds the release binary if it is
missing and asks for your password (`sudo`) so the monitor can see the traffic of every
process, not only your own. Ctrl+C stops it. The desktop app starts unprivileged and stays that way (it never asks
for a password at start): it shows all connections but byte counts only for your own
processes (macOS) or your own sockets (Linux); use the browser version under `sudo` when
you need the full picture. The only thing that prompts for a password is a firewall action
(block or allow an address), once per action, through the system's own dialog (`osascript`
on macOS, `pkexec` on Linux). On macOS, clicking the Dock icon brings a hidden window back.

The dashboard opens at <http://127.0.0.1:8787/> and can be reopened at any time in any
browser on this computer.

### What differs per platform

| | Windows | macOS | Linux |
|---|---|---|---|
| Byte counts | with administrator rights | all processes with `sudo`, otherwise your own | TCP only; other users need `sudo` |
| DNS page and DNS rules (R02, R08, R11, R12, R20) | yes | not yet | not yet |
| Signature column | Authenticode publisher | `codesign` identity (Apple, Developer ID) | the package that owns the file (dpkg/rpm); this is ownership, not a cryptographic signature. Unpackaged binaries (AppImages, Steam games, tools in `~/.local/bin`) count as unsigned and raise a Medium R04 alert when they go online |
| Block an IP | Windows Defender Firewall rule | pf table (anchor `com.sherkhan.sherwatch`; needs a one-time line in `/etc/pf.conf`, see Settings) | nftables set, or iptables where nftables is missing |
| Block a program | yes | no (pf has no per-program rules) | no |
| Inventory | Windows edition and update age, services, installed programs | macOS version and update history, launchd services, applications | distribution and package-manager age, systemd services, dpkg/rpm/flatpak packages |
| Data folder | `%LOCALAPPDATA%\SherWatch` | `~/Library/Application Support/SherWatch` | `~/.local/share/SherWatch` |

The first start downloads the GeoIP database (about 120 MB) and the threat feeds in the
background; the dashboard is usable immediately and locations fill in once the download
finishes. Later starts are instant.

Starting the app while another copy is already running (for example an un-elevated test
instance) hands the port over to the new copy: the latest launch wins. Ctrl+C in the console
stops the monitor and closes its capture (the Windows trace session, or the poller on macOS
and Linux) cleanly.

The first run on a PC learns quietly: "new application on the network" alerts (R13) are
suppressed for the first hour so the known-application list can fill up.

## The sidebar

The four status dots at the bottom tell you what the monitor can see:

- **Live feed**: the dashboard is connected to the app (WebSocket).
- **Packet capture**: the byte counter is running. On Windows this is the ETW trace and red
  means no administrator rights. On macOS and Linux the light reads **Capture (nettop)** or
  **Capture (ss)**; it runs even without root (showing your own processes) and only turns
  red when `nettop` or `ss` is missing, with a message saying so. A note next to it says
  that there is no DNS capture on this platform.
- **Administrator**: the app was elevated (administrator on Windows, root on macOS and Linux).
- **Threat intel**: feeds are loaded.

The version line says `limited (not admin)` when visibility is reduced.

## Top bar

The title, a clock, red and orange pills with the count of open critical and high alerts,
the yellow **App update needed** pill when threat data needs a code change (see
UPDATING.md), and a search box. The search box filters whatever table is on screen:
connections, processes, alerts, DNS or inventory. The term stays set when you change
view (clicking a destination on the globe fills it with that IP), so a ✕ appears in the
box whenever a term is active; click it to see everything again. Clicking the critical or
high pill opens the Alerts view filtered to that severity.

## Overview

The command-center view.

- **Tiles**: current upload and download rate with 60-second sparklines, connection count
  (and how many go to the internet), processes seen on the network, listening ports, open
  alerts by severity, and the session total.
- **Live destinations**: the 3D globe. Blue dots are destinations, sized by traffic. Arcs
  run from your location (the pulsing ring) to hosts that were active in the last 30
  seconds. Arc colour follows risk: blue to green is normal, orange is elevated, red is a
  threat-intel match or critical risk. Countries are drawn as solid shapes with names:
  grey when quiet, blue when they host active connections, red when they host a
  threat-feed match. City labels show the number of hosts in a cluster. Hover anything
  to pause rotation and read details; click a dot to jump to its connections.
- **Latest alerts**: the newest open alerts. Click one to open its process.
- **Top talkers**: processes by bytes this session. Click a bar to open the process.
- **Throughput**: upload and download over the last five minutes, one second resolution.
- **Destinations by country**: active internet connections per country.
- **Connection stream**: new connections as they appear, newest first. A red host is a
  threat-intel match.

## Globe

The same globe at full size with a destination table beside it. Toggles for auto-rotate,
arcs and labels sit at the bottom left. Drag to rotate, scroll to zoom. Hovering a point or
label shows a short tooltip; **clicking** a point, a city label or a country name opens the
destination card in the corner of the globe: the address or place, its network owner and any
threat-feed match, the open connections and bytes, and every process sending there. Click a
process to open its drawer, ✦ to ask the assistant about that connection, or **All
connections** to jump to the Connections view filtered to that address or place. The card
stays open (rotation pauses) until you close it, press Escape or click the globe. The table lists
every public host with location, processes, bytes and risk; click a row to see its
connections.

## Connections

Every live flow. The cards across the top count connections by scope (internet, local),
protocol, threat-intel matches and risky processes; click a card to filter (internet is
selected by default), combine cards, click again to remove. Sort buttons sit below. Columns:
process, PID, protocol, remote IP (with an **intel** tag when listed by a feed), hostname
(from the DNS capture or reverse DNS), port, location, TCP state, bytes out and in, age and
the risk meter. Click a row for the process drawer; the **block IP** button blocks that address in both
directions in the system firewall (a Windows Defender Firewall rule, a pf table entry on
macOS, an nftables set entry on Linux). **Export CSV** downloads the table.

## Processes

Every process that has used the network since the app started. Cards count the processes
that are running (selected by default), online now, unsigned, in an odd location, risky or
carrying alerts; click to filter, combine, click again to remove. Sort buttons sit below.
Columns: name and
executable path, PID, signature status (signed with publisher on hover, unsigned,
invalid, or checking), location flags (temp, downloads, appdata, store-app...), a 60-second
activity sparkline (blue upload, green download), bytes, connection count, DNS query count,
risk meter and the **kill** and **block** actions. "Running only" hides exited processes.

### Process drawer

Opens from any table or alert. Shows the risk score, parent process, user, start time,
full command line, signer, SHA-256 (with a VirusTotal link you can open yourself),
location flags, traffic, listening sockets, the process's alerts with acknowledge buttons,
its connections, its DNS queries and any repeated contacts (candidates for beaconing).
**✦ Explain** asks the assistant about the process and shows the answer in the drawer
itself, with a follow-up box. **Terminate process** ends the process tree (taskkill on
Windows, `kill -9` on macOS and Linux) and reads **Not running** once the process is gone.
**Block in firewall** adds inbound and outbound block rules for the executable; when a
block exists the button turns green and reads **Blocked in firewall ✓ (click to allow)**,
which removes the rules again. This button exists on Windows only: pf and nftables have no
per-program rules, so on macOS and Linux block the addresses the program talks to (from the
Connections view or the drawer) or terminate it. Every
action lands in the Settings action log, where it can be reverted. **Trust this program** marks the exact file
(by SHA-256) as known-good: the unsigned-program, suspicious-location, hard-coded-IP and
new-listener rules stop firing for it, while threat-intel, beaconing, exfiltration and port
rules still apply. A replaced or updated file has a new hash and alerts again until you
re-trust it. The trust list is in Settings and in `data/trusted.json`.

## Alerts

All alerts, newest first, with a 24-hour histogram by severity. The cards across the top
count alerts per severity (total and still open). Click a card to show only that severity,
click more cards to combine them, click a selected card again to remove it, or click
**All** to reset; the **Unacknowledged only** box narrows the list further. The counter
next to it reads "n of m alerts" whenever a filter or the top-bar search is narrowing the
list, and an empty list offers **Clear filters**. Each alert shows the title, the explanation, the process, the target,
the rule ID (see DETECTION-RULES.md) and a counter when the same condition repeated within
the cooldown window. **ack** acknowledges one alert, **Acknowledge all** clears the list.
Alerts persist in the database and reload at startup. Export as CSV or JSON.

Critical and high alerts also pop up as toasts in the bottom-right corner on every view.

## DNS

Live DNS queries captured from the Windows DNS client, per process, with type, status,
and answers, plus a chart of the most queried domains. Cards filter by query type, failed
lookups and flagged names. Needs packet capture. On macOS and Linux there is no DNS
capture yet: the page stays empty, the DNS-based rules (R02, R08, R11, R12, R20) do not
fire, and hostnames on the Connections view come from reverse DNS only. Queries for
domains in a threat feed carry an **intel** tag and raise a critical alert. The monitor's
own lookups (reverse DNS for the globe, resolving the file-sharing hosts) are not listed.

## Inventory

Software on this PC and its vulnerability exposure, collected every 30 minutes (or with
**Rescan**):

- **Operating system**: edition and build (Windows), version (macOS) or distribution with
  the kernel version as the build (Linux), the date of the last installed update with its
  age (Windows hotfixes; on macOS `/Library/Receipts/InstallHistory.plist`, falling back to
  `softwareupdate --history`; on Linux the newest apt, dpkg, dnf, pacman or zypper log), and
  the OS vulnerabilities CISA catalogued as actively exploited after that date (meaning the
  fix is probably not installed yet): Windows entries, Apple and macOS products, or the Linux
  kernel.
- **Exposure summary**: counts of items with exploited history and items that look
  unpatched, and the state of the online check.
- **The table**: every network-active executable (with product name, version and publisher
  read from the file on Windows, from the app bundle's `Info.plist` on macOS, from the
  owning package on Linux), every service with its binary (Windows services, launchd jobs,
  systemd units), and every installed program (the Windows registry, `system_profiler`
  applications on macOS, dpkg/rpm/flatpak packages on Linux). "KEV" tags show how many entries of CISA's Known Exploited
  Vulnerabilities catalogue name that product. Red means the file on disk predates at
  least one of them (likely unpatched); orange means the file is newer than all of them.
  Click a row to see the entries with links to NVD.

**Check CVEs online** is opt-in because it sends product names and versions to Shodan's
free CVEDB. It finds the CPE for each product, queries published CVEs for the exact
installed version, and tags items with the count and the worst CVSS score. Results are
cached for seven days. Set `online_lookup = true` under `[vuln]` in `config.toml` to run it
automatically after every scan.

On Windows, processes named svchost.exe show the services they host (for example
`svchost.exe (WpnService)`), and destinations show the owner of well-known networks
(Microsoft, Google, Cloudflare, Amazon, Akamai, Apple, Meta...) next to the country.

## Assistant

A built-in analyst that answers the questions you would otherwise ask a security person:
"what is this process?", "why was this flagged?", "is this connection safe?", "summarise my
network". Every ✦ button (process drawer, process rows, connection rows, alerts) asks with
the facts about that item already attached: path, signature, publisher and version, parent,
hosted services, connections with hostnames and network owners, DNS, alerts with rule
meanings, vulnerability matches. The answer ends with a verdict and a recommended action.

A ✦ on anything that belongs to a process answers inside that process's drawer on the right,
so you stay on the view you were reading. The answer appears in an **Assistant** panel at the
top of the drawer with a box for follow-up questions about that process; ✕ closes the
panel, and the conversation is dropped when the drawer closes. Alerts without a process
(hosts file, operating-system updates, the app-update notice) and the Assistant view's own chat box
use the full Assistant view.

The dropdown picks which model answers:

- **Free web models** (default): a keyless public service (pollinations.ai), no account
  needed. The facts about the item are sent to that service.
- **Local Ollama models**: every model installed in Ollama on this PC appears here. Fully
  offline, nothing leaves the machine. Start the Ollama app first.
- **Anthropic Claude** or any **OpenAI-compatible** service (Groq, OpenRouter, Gemini, LM
  Studio): appear once `api_key` (and `base_url`, `model`) are set under `[ai]` in
  `config.toml`.

The chat keeps the last few turns as context, so follow-up questions work. "Summarise my
network now" sends the whole picture: rates, top talkers, open alerts, risky processes,
operating-system patch state and software with exploited vulnerabilities.

## Sorting tables

Click any column header to sort that table; click again to flip the direction. Sorting
understands bytes (1.2 MB), ages (3m, 2h 10m), risk meters and numbers. The sort stays
applied while the table refreshes.

## History

Everything older than the live window comes from `data/sherwatch.db`. Pick a range (1 h to
30 days). The traffic chart stacks the top seven applications and folds the rest into
"Other"; colours stay attached to the same application across ranges. Below it: alerts
over time and the closed-connection log with duration, bytes and flags. History is pruned
after 30 days.

## Settings

- **App update needed** (only when relevant): what changed and what to ask for.
- **Threat intelligence feeds**: counts, last and next refresh, every feed with its
  source (config, feeds.json or manifest), entry count, last update and status.
  **Refresh now** forces a download.
- **Settings**: every tunable the app has, grouped: the file-upload threshold and approved
  uploaders (R27; names without extension, with per-platform defaults: OneDrive on Windows,
  onedrive, dropbox and google drive on macOS, dropbox and rclone on Linux), the
  file-sharing threshold and service list (R28), the volume and
  behaviour thresholds (R10, R17, R09, R16), the alert cooldown, reverse DNS, feed refresh
  interval, IPsum score, online CVE lookup, VirusTotal key, assistant provider, model, URL
  and key, home coordinates, port and browser launch. **Save settings** validates the values,
  writes them to config.toml (comments kept) and applies them immediately; the few marked
  **restart** (port, browser launch, VirusTotal key) take effect at the next start. Every save
  is recorded in the action log. Nothing in the rules is hard-coded: the same keys can still be
  edited in config.toml by hand.
- **Firewall blocks**: rules the app created, each checked against the system firewall
  (Windows Defender Firewall, the pf table, the nftables set): **in firewall** or
  **missing** when removed by hand, with **allow again**. Block any IP by hand. On macOS
  the pf table lives in the anchor `com.sherkhan.sherwatch`, which only takes effect once
  `/etc/pf.conf` contains the line `anchor "com.sherkhan.sherwatch"` (add it once with
  `sudo`; the browser version run as root checks this and reports a clear error, the
  unprivileged desktop app cannot check). When the app is not root on macOS or Linux, the
  **in firewall / missing** check is skipped, because listing pf or nft rules needs root
  and would prompt for a password on every page load; recorded rules are shown as present.
- **Action log**: every terminate, block, allow, trust and revoke the app performed, with
  time, target and result, newest first. **revert** undoes blocks, allows and trust changes
  and is itself logged; a terminated process cannot be brought back.
- **Notifications**: opt in to desktop notifications for critical and high alerts while the
  dashboard tab is open (uses the browser's notification permission).
- **Trusted programs**: the hash-pinned trust list with revoke buttons.
- **Capture status**: administrator or root, the capture event counter, GeoIP, home
  location, start time, project folder.
- **Configuration**: the effective settings (API key masked).
- **Hosts file**: suspicious entries, if any.

## Reading the risk meter

The small bar next to connections and processes is the process risk score, 0 to 100,
accumulated from its alerts (critical adds 60, high 25, medium 10, low 3, info 1) and
decaying by one point a minute. Blue is quiet, yellow is worth a look, orange needs
attention, red is serious. A connection to a threat-feed host is always at least 90.

## What to do when something looks wrong

1. Open the process drawer. Check the path (is it where that program should live?), the
   signature, the parent, and the command line.
2. Look at its connections and DNS: do the hostnames make sense for that program?
3. Check VirusTotal with the SHA-256 link if you are unsure.
4. **Block in firewall** stops further traffic without killing the program, which keeps
   evidence (on macOS and Linux block its addresses instead, since per-program blocks are
   not available there). **Terminate** stops it outright.
5. Keep the alert; it stays in the database for your records, and the export buttons give
   you a copy to share with someone who can help.
