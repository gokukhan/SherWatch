# Detection rules

The analysis engine runs every two seconds over the live state. Each rule has an ID that
appears on the alert, a default severity and a cooldown: the same rule for the same
executable and target fires once per cooldown window (`alert_cooldown_minutes`, default 10)
and later occurrences bump the alert's counter instead of creating duplicates.

The alert keeps the time it first fired; while the condition persists, its counter grows at
most once a minute. Inventory rules (R24 to R26) and the update notice use a 24-hour
cooldown because they re-evaluate every 30 minutes.

Severity weights feed a per-process **risk score** (0 to 100) that decays slowly over time:
info 1, low 3, medium 10, high 25, critical 60. A connection to a threat-feed host is pinned
at risk 90 or higher.

The rules are the same on Windows, macOS and Linux. Where a rule depends on something only
one platform provides, the **Platform** column says so; "DNS capture" means the DNS-Client
trace that exists on Windows only for now (see ARCHITECTURE.md, platform layer), so the
rules that need it stay silent on macOS and Linux until that capture exists there.

| ID | Severity | Name | What it looks for | Why it matters | Platform |
|---|---|---|---|---|---|
| R01-intel-ip | Critical | Threat-intel IP | A connection to an IP or network listed in a loaded feed (Feodo, Spamhaus DROP, IPsum, Tor exits, OpenPhish...). | Known botnet C2, hijacked ranges, phishing hosts. Tor exits are listed by their own feed so you can tell them apart. | All. |
| R02-intel-domain | Critical | Threat-intel domain | A DNS query (captured via ETW) for a domain, or a parent of it, in a domain feed (Blackbook, OpenPhish). | Catches malware before the connection, and hosts behind CDNs that an IP list cannot. | Needs DNS capture: Windows only for now. |
| R04-unsigned | Medium / High | Unsigned program on the internet | A process whose executable has no Authenticode signature, or an invalid one, talking to a public IP. High when the signature is invalid or the file sits in a user-writable folder. Store apps under WindowsApps are exempt (package-signed). | Most commercial software is signed. Unsigned plus internet is the first thing an analyst checks. Expect some noise from open-source tools. | All. Windows: Authenticode. macOS: `codesign`; apps from the App Store and notarised Developer ID apps count as signed. Linux: no code signatures; "signed" means the file belongs to an installed dpkg/rpm package, so every unpackaged binary (AppImages, Steam games, tools in `~/.local/bin`, anything hand-installed) raises R04 at Medium when it goes online. |
| R05-suspicious-path | High | User-writable location | Network-active executable running from Temp, AppData\Local\Temp, Downloads, Public, Desktop, the Recycle Bin, a drive root or a profile root. | Malware droppers run from where the user or a script can write. Legitimate installers trigger this briefly. | All. The user-writable folders are per OS: Windows as listed; macOS and Linux: temp (`/tmp`, `/var/tmp`, `/private/tmp`, `/var/folders`, `/dev/shm`, `~/.cache`), `~/Downloads`, public (`/Users/Shared`), `.Trash`, `Desktop`, an executable directly in `$HOME` or in `/`, and `.sh`, `.command` or `.scpt` as odd extensions for a network-active executable. |
| R06-lolbin | High | Living-off-the-land binary | A system tool that attackers reuse, with a public connection: on Windows the LOLBAS list (certutil, mshta, rundll32, regsvr32, msbuild, bitsadmin, wscript, cscript, cmstp, installutil, msiexec, wmic...); on macOS and Linux the raw network tools nc, ncat, netcat, socat, telnet, tftp and osascript. | These tools are abused to download and execute payloads while looking like part of the operating system. MITRE ATT&CK T1218, T1105. | All, with a per-OS list. Windows: the LOLBAS set above. macOS and Linux: a small, deliberate list (nc, ncat, netcat, socat, telnet, tftp, osascript). curl, wget, python, perl, ruby, php, bash, base64 and openssl are not flagged: they are far too common in normal use. |
| R07-port | Low to High | Suspicious destination port | Outbound to SMB 445/139, RPC 135, RDP 3389, Telnet 23, IRC 6667-6669, 4444, 1337/31337, VNC 5900, SOCKS 1080, Tor 9001/9050/9150, mining pools 3333/14444/5555, SMTP 25/587 from a non-mail client, database ports, Docker 2375, WinRM, SSH from a non-SSH client. | Lateral movement, remote access, IRC bots, cryptominers, spam engines. Mail clients, SSH tools and mstsc are excluded for their own ports. | All. |
| R08-direct-dns | Medium | Resolver bypass | A process other than the system DNS service, a browser or a known DNS tool sends to port 53 or 853 on a public IP. | Malware runs its own DNS to hide lookups from the system log and from this monitor's DNS capture. | Needs UDP flow events, which only the Windows capture provides: Windows only for now. The exempt resolvers are the DNS_SERVICES list: svchost (Dnscache) on Windows, plus mDNSResponder, systemd-resolved, unbound and dnsmasq-style names on macOS and Linux. |
| R09-beacon | High | Beaconing | At least `beacon_min_intervals` (6) new connections from one process to one public IP with a mean interval between 5 s and 1 h and a coefficient of variation at or below `beacon_max_cv` (0.25), and the last contact is recent (within three intervals or 5 min). Browsers are excluded; connections that existed when the monitor started are not counted. | Command-and-control implants check in on a timer. Jitter tolerance is the CV setting; raise it to catch sloppier beacons at the cost of noise from update checkers. | All. |
| R10-exfil | Medium / High | Exfiltration volume | More than `exfil_bytes_per_minute` (25 MB) uploaded by one process in 60 s to public IPs (High when upload is 5x download), or more than `exfil_bytes_per_5min` (200 MB) in five minutes. | Bulk data theft. Cloud backup clients and video calls will trigger this; acknowledge or raise the threshold. | All; needs byte counts (elevation, see USER-GUIDE.md). Linux: TCP only. |
| R11-dns-tunnel | High | DNS tunnelling | Per process and registrable domain over 5 min: 30+ unique names with average length 40+, or 20+ TXT/NULL queries, or a label 52+ characters, or 40+ queries with over 60 % NXDOMAIN. Reverse lookups (`.arpa`) and the monitor's own queries are excluded. | DNS tunnels encode data in subdomains. Requires DNS capture. | Needs DNS capture: Windows only for now. |
| R12-dga | Low / Medium | Algorithm-generated domain | Second-level label 12+ characters with entropy 3.6+ and vowel ratio under 0.22, or entropy 3.9+ with 30 %+ digits. Medium when the lookup failed (NXDOMAIN). | Malware families generate daily random domains and query many until one resolves. CDN hostnames can look similar; the NXDOMAIN condition separates them. | Needs DNS capture: Windows only for now. |
| R13-new-app | Info | New application on the network | An executable path seen contacting the network for the first time ever on this machine (stored in the database). Suppressed for the first hour of the first run on a PC and for the first 20 s of every start. | The Little Snitch idea: you should know when something new starts talking. | All. |
| R14-new-listener | Info / High | New listening port | A process opened a non-loopback listening socket. Fires once per executable and port per session. High when the executable is unsigned (store apps count as signed) or in a user-writable folder; Info for signed software; local discovery ports (mDNS 5353, SSDP 1900, LLMNR, WS-Discovery, NetBIOS, DHCP) and signed System32 binaries are skipped. | Backdoors and remote-access tools wait for inbound connections. Games, VR runtimes and chat apps open ports too, which is why signed software only gets an info entry. | All. The skipped signed system folder is `System32` on Windows; on macOS and Linux the system folders are `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/lib`, `/usr/lib64`, `/usr/libexec`, `/System/` and `/Library/Apple`. On Linux "signed" means package-owned. |
| R15-hosts-file | High | Hosts file tampering | Entries in the hosts file that redirect a name to a non-loopback IP, or that block a security vendor or the OS update service. Checked every 5 min. | A classic way to hijack sites or disable antivirus updates. Ad-blocker style 0.0.0.0 entries are ignored. | All. The file is `System32\drivers\etc\hosts` on Windows and `/etc/hosts` on macOS and Linux. |
| R16-watch-country | Low | Watch-list country | Connection to a country in `watch_countries`. | Whatever you decide is unusual for your machine. Default list is a starting point; edit freely. | All. |
| R17-many-destinations | Medium | Fan-out | One process contacted `many_destinations_threshold` (100) distinct public IPs within 60 s. Browsers excluded. | Scanning, password spraying, peer-to-peer swarms, spam. | All. |
| R18-long-session | Low | Very long session | A TCP connection open for over 6 h to a port other than 80/443. | Persistent tunnels and reverse shells stay up for days. | All. |
| R19-office-child / R19-script-child | High | Suspicious parent | A network-active process launched by Word, Excel, PowerPoint, Outlook, Acrobat..., or by a script host (powershell, cmd, wscript, mshta...) from a user-writable folder. | Macro and exploit chains spawn a downloader from the document viewer. | All. The script hosts are per OS (powershell, cmd, wscript, mshta on Windows; bash, sh, zsh, python, perl, osascript on macOS and Linux). |
| R20-hardcoded-ip | Medium | No DNS for destination | An unsigned process connects to a public IP that no captured DNS query resolved to, 2 min after start. Requires DNS capture. | Malware often embeds its server IP to avoid DNS-based detection. | Needs DNS capture: Windows only for now. |
| R21-virustotal | High / Critical | VirusTotal detection | One or more engines flag the SHA-256 of an unsigned executable. Only with an API key. Critical at 3+ "malicious" verdicts. | Independent second opinion on anything unsigned. | All. |
| R22-inbound-unsigned | High | Unsigned server | An unsigned program in a user-writable folder accepted incoming TCP connections from another machine within the last 10 minutes (loopback peers are ignored). | A listener that actually receives connections is a working backdoor. | Windows: ETW accept events. macOS and Linux: inbound connections seen in the socket table with a non-loopback peer; needs elevation to see other users’ sockets on Linux. |
| R23-masquerade | Critical | Process name masquerade | A process named like a core system binary (on Windows svchost, lsass, csrss, explorer, dwm, RuntimeBroker...) running from outside the system folders without a valid OS-vendor signature (Defender's MsMpEng under ProgramData is signed and therefore exempt). | Malware names itself after system processes to hide in Task Manager. | All, with per-OS names and system folders. Windows: the names above outside `C:\Windows`. macOS and Linux: launchd, kernel_task, mds, mdworker, systemd, kthreadd, sshd, cron and init running outside the system folders (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/lib`, `/usr/lib64`, `/usr/libexec`, `/System/`, `/Library/Apple`). On Linux "valid signature" means owned by a package. |
| R24-exploited-software | High / Critical | Exploited software, likely unpatched | A network-active program or a service matches a product in CISA's Known Exploited Vulnerabilities catalogue and its executable on disk is older than the likely fix date (the earlier of the catalogue date and the end of the year after the CVE's year). Product names must match the product, not just the vendor, and short names such as "Ray" or "Edge" also need the vendor to match. Critical when the entry is tied to ransomware campaigns and the program is online. | These are vulnerabilities attackers are using right now. An old binary means the fix is not installed. Update the program or stop it until updated. | All. The catalogue is matched against Windows programs and services, macOS apps and launchd services, or Linux packages and systemd services. |
| R25-os-patch | Medium / High | OS updates stale | The last operating-system update is older than 45 days, or vulnerabilities in the OS were added to the KEV catalogue after that date. High when both. | An unpatched operating system is the most common entry point. Run the system update. | All, with a per-OS source. Windows: the newest installed hotfix (older than 45 days) and Windows entries in KEV after it. macOS: the last entry in `/Library/Receipts/InstallHistory.plist` (fallback `softwareupdate --history`) and the Apple / macOS products in KEV. Linux: the newest of `/var/log/apt/history.log`, `/var/log/dpkg.log`, `/var/lib/dnf/history`, `/var/log/dnf.log`, `/var/log/pacman.log` and `/var/log/zypp/history`, and the Linux-kernel entries in KEV. |
| R27-file-upload | Critical | File leaving this PC | A program not listed in `approved_uploaders` (default: OneDrive only) sent more than `file_upload_bytes_per_minute` (5 MB) to public addresses within 60 s. Requires byte counts (administrator or sudo). | Any transfer of a file-sized amount out of the machine by something you did not approve. Backup clients, video calls, game launchers and browser uploads will trip it until you add them to the approved list; that is the point: you decide who may upload. | All; needs byte counts (elevation). Linux: TCP only. Approved uploaders are matched by name without extension, so the shipped `onedrive.exe` also matches OneDrive on a Mac; the platform defaults are OneDrive (Windows), onedrive, dropbox and google drive (macOS), dropbox and rclone (Linux). |
| R28-file-sharing | Critical / Medium | Upload to a file-sharing service | A non-approved program uploaded at least `file_sharing_min_bytes` (256 KB) on one connection to a host in the file-sharing and paste list (WeTransfer, Mega, Dropbox, Box, MediaFire, GoFile, transfer.sh, Pastebin, Telegram API, Discord, S3...; extend with `file_sharing_domains`). Without administrator rights the size is unknown, so a connection to such a service raises Medium instead. Hosts are matched by the captured or reverse-resolved hostname, and by address: the service names are resolved forward at start and every six hours. | The common way files are moved out of a PC by a person or a stealer. Simply browsing one of these sites stays silent when byte counts are available. | All; the critical variant needs byte counts. Linux: TCP only. |
| R26-known-cve | Medium / High | Published CVEs for this version | The optional online lookup found CVEs for the exact installed version with CVSS 9 or higher (High when one is actively exploited). Only after "Check CVEs online" or with `online_lookup = true`. | Version-exact confirmation that a known weakness applies to what is installed. | All. |
| SYS-update | Info | App update needed | The threat-feed manifest requires a newer app version, a feed uses an unsupported format, or a source returned 404/410/401/403. | Tells you to ask for a code update so new threat data keeps flowing. | All. |

## Tuning

All thresholds are in `config.toml` under `[analysis]` and editable on the Settings page of the
dashboard (changes apply at once and are written back to the file). Typical adjustments:

- Backup or sync clients: raise `exfil_bytes_per_minute` or acknowledge their R10 alerts.
- Programs that legitimately upload (backup, cloud sync other than OneDrive, video calls,
  game launchers, dev tools pushing to Git hosting): add their executable name to
  `approved_uploaders`, otherwise R27 flags every transfer above 5 MB as critical.
- Development machines with many unsigned tools: expect R04; the cooldown keeps it to one
  alert per executable per 10 minutes.
- Update checkers that poll on a fixed timer trigger R09. Lower `beacon_max_cv` (stricter)
  or raise `beacon_min_intervals`.
- The watch-list is political by nature. Set `watch_countries = []` to disable R16.

## What the rules cannot see

- Without administrator rights (Windows) or `sudo` (macOS, Linux) there are no byte counts,
  and on Windows no DNS capture and no accept events. R02, R08 (partly), R10, R11, R12, R20,
  R22 and R27 stay silent; R28 drops to Medium.
- On macOS and Linux there is no DNS capture yet, so R02, R08, R11, R12 and R20 do not fire
  there and the DNS page stays empty; hostnames on connections come from reverse DNS only.
  On Linux, byte counts cover TCP only, so UDP uploads do not count towards R10, R27 and R28.
- On Linux "signed" means "owned by an installed package": R04, R14, R22 and R23 treat a
  package-owned binary as signed and everything else as unsigned. This is a plausibility
  check, not a cryptographic one.
- Files leaving by USB stick, Bluetooth, a network share, printing or the remote-desktop
  clipboard are not network traffic and are not seen.
- Loopback traffic (127.0.0.1 / ::1, for example the dashboard itself or a local dev server)
  shows on connection rows but is not counted as upload or download, so it cannot trigger the
  volume rules R10, R27 and R28.
- The monitor's own DNS lookups are not recorded, so they can neither clutter the DNS page
  nor trigger R11.
- Encrypted traffic contents are never inspected; the rules work on metadata, timing, volume
  and reputation.
- A signed binary from a reputable vendor that is itself malicious (supply chain) only shows
  through its behaviour: beaconing, odd ports, feed matches.
