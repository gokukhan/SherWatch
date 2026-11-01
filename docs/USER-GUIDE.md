# User guide

## Starting and stopping

Double-click `run.cmd` or run it from a terminal. Windows asks for administrator
permission; accept it to get byte counts and DNS capture. A console window shows the log;
closing it stops the monitor. The dashboard opens at <http://127.0.0.1:8787/> and can be
reopened at any time in any browser on this PC.

The first start downloads the GeoIP database (about 120 MB) and the threat feeds. Later
starts are instant.

## The sidebar

The four status dots at the bottom tell you what the monitor can see:

- **Live feed**: the dashboard is connected to the app (WebSocket).
- **Packet capture**: ETW tracing is running. Red means no administrator rights.
- **Administrator**: the app was elevated.
- **Threat intel**: feeds are loaded.

The version line says `limited (not admin)` when visibility is reduced.

## Top bar

The title, a clock, red and orange pills with the count of open critical and high alerts,
the yellow **App update needed** pill when threat data needs a code change (see
UPDATING.md), and a search box. The search box filters whatever table is on screen:
connections, processes, alerts or DNS.

## Overview

The command-center view.

- **Tiles**: current upload and download rate with 60-second sparklines, connection count
  (and how many go to the internet), processes seen on the network, listening ports, open
  alerts by severity, and the session total.
- **Live destinations**: the 3D globe. Blue dots are destinations, sized by traffic. Arcs
  run from your location (the pulsing ring) to hosts that were active in the last 30
  seconds. Arc colour follows risk: blue to green is normal, orange is elevated, red is a
  threat-intel match or critical risk. Countries with active connections are tinted blue;
  countries hosting a threat-feed match are tinted red. City labels show the number of
  hosts in a cluster. Hover anything to pause rotation and read details; click a dot to
  jump to its connections.
- **Latest alerts**: the newest open alerts. Click one to open its process.
- **Top talkers**: processes by bytes this session. Click a bar to open the process.
- **Throughput**: upload and download over the last five minutes, one second resolution.
- **Destinations by country**: active internet connections per country.
- **Connection stream**: new connections as they appear, newest first. A red host is a
  threat-intel match.

## Globe

The same globe at full size with a destination table beside it. Toggles for auto-rotate,
arcs and labels sit at the bottom left. Drag to rotate, scroll to zoom. The table lists
every public host with location, processes, bytes and risk; click a row to see its
connections.

## Connections

Every live flow. Filters: internet only (default on), protocol, sort order. Columns:
process, PID, protocol, remote IP (with an **intel** tag when listed by a feed), hostname
(from the DNS capture or reverse DNS), port, location, TCP state, bytes out and in, age and
the risk meter. Click a row for the process drawer; the **block IP** button adds a Windows
Firewall rule for that address in both directions. **Export CSV** downloads the table.

## Processes

Every process that has used the network since the app started. Columns: name and
executable path, PID, signature status (signed with publisher on hover, unsigned,
invalid, or checking), location flags (temp, downloads, appdata, store-app...), a 60-second
activity sparkline (blue upload, green download), bytes, connection count, DNS query count,
risk meter and the **kill** and **block** actions. "Running only" hides exited processes.

### Process drawer

Opens from any table or alert. Shows the risk score, parent process, user, start time,
full command line, signer, SHA-256 (with a VirusTotal link you can open yourself),
location flags, traffic, listening sockets, the process's alerts with acknowledge buttons,
its connections, its DNS queries and any repeated contacts (candidates for beaconing).
**Terminate process** runs taskkill on the process tree. **Block in firewall** adds inbound
and outbound block rules for the executable.

## Alerts

All alerts, newest first, with a 24-hour histogram by severity. Filter by severity and by
acknowledged state. Each alert shows the title, the explanation, the process, the target,
the rule ID (see DETECTION-RULES.md) and a counter when the same condition repeated within
the cooldown window. **ack** acknowledges one alert, **Acknowledge all** clears the list.
Alerts persist in the database and reload at startup. Export as CSV or JSON.

Critical and high alerts also pop up as toasts in the bottom-right corner on every view.

## DNS

Live DNS queries captured from the Windows DNS client, per process, with type, status,
and answers, plus a chart of the most queried domains. Needs packet capture. Queries for
domains in a threat feed carry an **intel** tag and raise a critical alert.

## History

Everything older than the live window comes from `data/netmon.db`. Pick a range (1 h to
30 days). The traffic chart stacks the top seven applications and folds the rest into
"Other"; colours stay attached to the same application across ranges. Below it: alerts
over time and the closed-connection log with duration, bytes and flags. History is pruned
after 30 days.

## Settings

- **App update needed** (only when relevant): what changed and what to ask for.
- **Threat intelligence feeds**: counts, last and next refresh, every feed with its
  source (config, feeds.json or manifest), entry count, last update and status.
  **Refresh now** forces a download.
- **Firewall blocks**: rules the app created, with **remove**. Block any IP by hand.
- **Capture status**: administrator, ETW event counter, GeoIP, home location, start time,
  project folder.
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
   evidence. **Terminate** stops it outright.
5. Keep the alert; it stays in the database for your records, and the export buttons give
   you a copy to share with someone who can help.
