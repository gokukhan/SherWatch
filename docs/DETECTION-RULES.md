# Detection rules

The analysis engine runs every two seconds over the live state. Each rule has an ID that
appears on the alert, a default severity and a cooldown: the same rule for the same
executable and target fires once per cooldown window (`alert_cooldown_minutes`, default 10)
and later occurrences bump the alert's counter instead of creating duplicates.

Severity weights feed a per-process **risk score** (0 to 100) that decays slowly over time:
info 1, low 3, medium 10, high 25, critical 60. A connection to a threat-feed host is pinned
at risk 90 or higher.

| ID | Severity | Name | What it looks for | Why it matters |
|---|---|---|---|---|
| R01-intel-ip | Critical | Threat-intel IP | A connection to an IP or network listed in a loaded feed (Feodo, Spamhaus DROP, IPsum, Tor exits, OpenPhish...). | Known botnet C2, hijacked ranges, phishing hosts. Tor exits are listed by their own feed so you can tell them apart. |
| R02-intel-domain | Critical | Threat-intel domain | A DNS query (captured via ETW) for a domain, or a parent of it, in a domain feed (Blackbook, OpenPhish). | Catches malware before the connection, and hosts behind CDNs that an IP list cannot. |
| R04-unsigned | Medium / High | Unsigned program on the internet | A process whose executable has no Authenticode signature, or an invalid one, talking to a public IP. High when the signature is invalid or the file sits in a user-writable folder. Store apps under WindowsApps are exempt (package-signed). | Most commercial software is signed. Unsigned plus internet is the first thing an analyst checks. Expect some noise from open-source tools. |
| R05-suspicious-path | High | User-writable location | Network-active executable running from Temp, AppData\Local\Temp, Downloads, Public, Desktop, the Recycle Bin, a drive root or a profile root. | Malware droppers run from where the user or a script can write. Legitimate installers trigger this briefly. |
| R06-lolbin | High | Living-off-the-land binary | A Windows tool from the LOLBAS list (certutil, mshta, rundll32, regsvr32, msbuild, bitsadmin, wscript, cscript, cmstp, installutil, msiexec, wmic...) with a public connection. | These tools are abused to download and execute payloads while looking like Windows. MITRE ATT&CK T1218, T1105. |
| R07-port | Low to High | Suspicious destination port | Outbound to SMB 445/139, RPC 135, RDP 3389, Telnet 23, IRC 6667-6669, 4444, 1337/31337, VNC 5900, SOCKS 1080, Tor 9001/9050/9150, mining pools 3333/14444/5555, SMTP 25/587 from a non-mail client, database ports, Docker 2375, WinRM, SSH from a non-SSH client. | Lateral movement, remote access, IRC bots, cryptominers, spam engines. Mail clients, SSH tools and mstsc are excluded for their own ports. |
| R08-direct-dns | Medium | Resolver bypass | A process other than the Windows DNS service, a browser or a known DNS tool sends to port 53 or 853 on a public IP. | Malware runs its own DNS to hide lookups from the system log and from this monitor's DNS capture. |
| R09-beacon | High | Beaconing | At least `beacon_min_intervals` (6) new connections from one process to one public IP with a mean interval between 5 s and 1 h and a coefficient of variation at or below `beacon_max_cv` (0.25). Browsers are excluded. | Command-and-control implants check in on a timer. Jitter tolerance is the CV setting; raise it to catch sloppier beacons at the cost of noise from update checkers. |
| R10-exfil | Medium / High | Exfiltration volume | More than `exfil_bytes_per_minute` (25 MB) uploaded by one process in 60 s to public IPs (High when upload is 5x download), or more than `exfil_bytes_per_5min` (200 MB) in five minutes. | Bulk data theft. Cloud backup clients and video calls will trigger this; acknowledge or raise the threshold. |
| R11-dns-tunnel | High | DNS tunnelling | Per process and registrable domain over 5 min: 30+ unique names with average length 40+, or 20+ TXT/NULL queries, or a label 52+ characters, or 40+ queries with over 60 % NXDOMAIN. | DNS tunnels encode data in subdomains. Requires ETW DNS capture. |
| R12-dga | Low / Medium | Algorithm-generated domain | Second-level label 12+ characters with entropy 3.6+ and vowel ratio under 0.22, or entropy 3.9+ with 30 %+ digits. Medium when the lookup failed (NXDOMAIN). | Malware families generate daily random domains and query many until one resolves. CDN hostnames can look similar; the NXDOMAIN condition separates them. |
| R13-new-app | Info | New application on the network | An executable path seen contacting the network for the first time ever on this machine (stored in the database). Suppressed during the first 20 s of the first run. | The Little Snitch idea: you should know when something new starts talking. |
| R14-new-listener | Info / High | New listening port | A process opened a non-loopback listening socket. Fires once per executable and port per session. High when the executable is unsigned (store apps count as signed) or in a user-writable folder; Info for signed software; local discovery ports (mDNS 5353, SSDP 1900, LLMNR, WS-Discovery, NetBIOS, DHCP) and signed System32 binaries are skipped. | Backdoors and remote-access tools wait for inbound connections. Games, VR runtimes and chat apps open ports too, which is why signed software only gets an info entry. |
| R15-hosts-file | High | Hosts file tampering | Entries in `System32\drivers\etc\hosts` that redirect a name to a non-loopback IP, or that block a security vendor or Windows Update. Checked every 5 min. | A classic way to hijack sites or disable antivirus updates. Ad-blocker style 0.0.0.0 entries are ignored. |
| R16-watch-country | Low | Watch-list country | Connection to a country in `watch_countries`. | Whatever you decide is unusual for your machine. Default list is a starting point; edit freely. |
| R17-many-destinations | Medium | Fan-out | One process contacted `many_destinations_threshold` (100) distinct public IPs within 60 s. Browsers excluded. | Scanning, password spraying, peer-to-peer swarms, spam. |
| R18-long-session | Low | Very long session | A TCP connection open for over 6 h to a port other than 80/443. | Persistent tunnels and reverse shells stay up for days. |
| R19-office-child / R19-script-child | High | Suspicious parent | A network-active process launched by Word, Excel, PowerPoint, Outlook, Acrobat..., or by a script host (powershell, cmd, wscript, mshta...) from a user-writable folder. | Macro and exploit chains spawn a downloader from the document viewer. |
| R20-hardcoded-ip | Medium | No DNS for destination | An unsigned process connects to a public IP that no captured DNS query resolved to, 2 min after start. Requires ETW. | Malware often embeds its server IP to avoid DNS-based detection. |
| R21-virustotal | High / Critical | VirusTotal detection | One or more engines flag the SHA-256 of an unsigned executable. Only with an API key. Critical at 3+ "malicious" verdicts. | Independent second opinion on anything unsigned. |
| R22-inbound-unsigned | High | Unsigned server | An unsigned program in a user-writable folder accepted incoming TCP connections (seen via ETW accept events). | A listener that actually receives connections is a working backdoor. |
| R23-masquerade | Critical | Process name masquerade | A process named like a core Windows binary (svchost, lsass, csrss, explorer, dwm, RuntimeBroker...) running from outside C:\Windows. | Malware names itself after system processes to hide in Task Manager. |
| R24-exploited-software | High / Critical | Exploited software, likely unpatched | A network-active program or a Windows service matches a product in CISA's Known Exploited Vulnerabilities catalogue and its executable on disk is older than the likely fix date (the earlier of the catalogue date and the end of the year after the CVE's year). Product names must match the product, not just the vendor, and short names such as "Ray" or "Edge" also need the vendor to match. Critical when the entry is tied to ransomware campaigns and the program is online. | These are vulnerabilities attackers are using right now. An old binary means the fix is not installed. Update the program or stop it until updated. |
| R25-os-patch | Medium / High | Windows updates stale | The newest installed hotfix is older than 45 days, or Windows vulnerabilities were added to the KEV catalogue after that date. High when both. | Unpatched Windows is the most common entry point. Run Windows Update. |
| R26-known-cve | Medium / High | Published CVEs for this version | The optional online lookup found CVEs for the exact installed version with CVSS 9 or higher (High when one is actively exploited). Only after "Check CVEs online" or with `online_lookup = true`. | Version-exact confirmation that a known weakness applies to what is installed. |
| SYS-update | Info | App update needed | The threat-feed manifest requires a newer app version, a feed uses an unsupported format, or a source returned 404/410/401/403. | Tells you to ask for a code update so new threat data keeps flowing. |

## Tuning

All thresholds are in `config.toml` under `[analysis]`. Typical adjustments:

- Backup or sync clients: raise `exfil_bytes_per_minute` or acknowledge their R10 alerts.
- Development machines with many unsigned tools: expect R04; the cooldown keeps it to one
  alert per executable per 10 minutes.
- Update checkers that poll on a fixed timer trigger R09. Lower `beacon_max_cv` (stricter)
  or raise `beacon_min_intervals`.
- The watch-list is political by nature. Set `watch_countries = []` to disable R16.

## What the rules cannot see

- Without administrator rights there are no byte counts, no DNS capture, no accept events.
  R02, R08 (partly), R10, R11, R12, R20 and R22 stay silent.
- Encrypted traffic contents are never inspected; the rules work on metadata, timing, volume
  and reputation.
- A signed binary from a reputable vendor that is itself malicious (supply chain) only shows
  through its behaviour: beaconing, odd ports, feed matches.
