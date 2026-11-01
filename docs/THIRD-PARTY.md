# Third-party components and data sources

## Data sources

| Source | What | Licence / terms | URL |
|---|---|---|---|
| DB-IP IP to City Lite | GeoIP database (country, city, coordinates) | Creative Commons Attribution 4.0. Attribution: "IP Geolocation by DB-IP" (https://db-ip.com) | https://db-ip.com/db/download/ip-to-city-lite |
| abuse.ch Feodo Tracker | Botnet C2 IP blocklist | CC0 | https://feodotracker.abuse.ch/ |
| abuse.ch SSL Blacklist | Botnet C2 IPs from SSL certificates (deprecated January 2025, kept for compatibility) | CC0 | https://sslbl.abuse.ch/ |
| Spamhaus DROP | Hijacked and criminal netblocks | Free for non-commercial use, see spamhaus.org terms | https://www.spamhaus.org/drop/ |
| IPsum | Aggregate of public IP blocklists with a hit score | Unlicense | https://github.com/stamparm/ipsum |
| Tor exit nodes | SecOps-Institute mirror of the Tor exit list | Public | https://github.com/SecOps-Institute/Tor-IP-Addresses |
| Blackbook | Malicious domains | Unlicense | https://github.com/stamparm/blackbook |
| OpenPhish | Community phishing feed | Free for non-commercial use | https://openphish.com/ |
| VirusTotal (optional) | File hash reputation | Requires your own API key and acceptance of VirusTotal terms | https://www.virustotal.com/ |
| api.ipify.org (optional) | Public IP for the globe's home marker | Public | https://www.ipify.org/ |

## Rust crates

tokio, axum, serde, serde_json, rusqlite (bundled SQLite), ferrisetw, maxminddb,
rust-embed, mime_guess, reqwest (rustls), dashmap, sha2, hex, parking_lot, chrono, ipnet,
tracing, tracing-subscriber, anyhow, toml, netstat2, sysinfo, dns-lookup, futures, flate2,
windows. All are MIT and/or Apache-2.0 licensed; see `Cargo.lock` for exact versions and
`cargo license` for the full tree.

## Frontend libraries (vendored in web/vendor)

| Library | Licence |
|---|---|
| Chart.js | MIT (LICENSE-chartjs.md) |
| globe.gl, three.js | MIT (LICENSE-globe.gl) |
| D3 | ISC (LICENSE-d3) |
| topojson-client | ISC |
| world-atlas (Natural Earth data) | ISC (LICENSE-world-atlas); Natural Earth is public domain |

## Windows components used at runtime

Event Tracing for Windows providers Microsoft-Windows-Kernel-Network and
Microsoft-Windows-DNS-Client, the IP Helper API socket tables, PowerShell's
`Get-AuthenticodeSignature`, `taskkill`, `netsh advfirewall` and `logman`.
