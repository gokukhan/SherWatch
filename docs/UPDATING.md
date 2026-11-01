# Keeping threat data current

The app is designed so that new threat data flows in without a rebuild wherever possible,
and so that it tells you clearly when a code change is needed.

## What updates itself

| Data | How | When |
|---|---|---|
| Threat feeds (malicious IPs, ranges, domains) | Downloaded to `data/feeds/`, parsed into memory | At startup if the local copy is older than `refresh_hours` (default 6), then every `refresh_hours`. "Refresh now" in Settings forces it. |
| Feed definitions | `config.toml` `[[intel.feeds]]`, plus `data/feeds/feeds.json`, plus a remote manifest | Every refresh. New feeds appear in Settings with their source. |
| GeoIP database | DB-IP Lite city, downloaded once | When `data/geo/dbip-city-lite.mmdb` is missing. Delete the file to fetch the newest monthly release. |
| Known applications | SQLite `known_apps` | Continuously. |

## Adding a feed without a rebuild

Any source in one of the supported formats can be added by editing `config.toml` or by
dropping a `feeds.json` into `data/feeds/`:

```json
{
  "version": "2026.11",
  "min_app_version": "0.1.0",
  "notes": "",
  "feeds": [
    { "name": "My blocklist", "url": "https://example.org/bad-ips.txt", "kind": "ip_lines", "file": "my-blocklist.txt" }
  ]
}
```

Supported `kind` values:

| kind | Format |
|---|---|
| `csv_ip` | CSV with a header; `column` names the IP column (falls back to the first IP-looking column). Comment lines starting with `#` ignored. |
| `ip_lines` | One IP per line. |
| `cidr_lines` | One CIDR or IP per line, optional `;` comment. Spamhaus DROP style. |
| `ipsum` | `IP<tab>score`; entries with score at or above `ipsum_min_score` are used. |
| `domain_lines` | One domain per line. |
| `hosts_lines` | hosts-file style `0.0.0.0 domain`. |
| `url_lines` | One URL per line; the host part is used. |
| `json_ip` | Any JSON; every string that parses as an IP or CIDR is used. |

## The remote manifest

Set `manifest_url` under `[intel]` to a JSON document in the format above. The app fetches it
at every refresh, merges its feeds, stores a copy as `data/feeds/feeds.json` so it survives
offline starts, and compares `min_app_version` with its own version.

A natural place for the manifest is a file in this project's GitHub repository, published via
a raw URL. Keep in mind that a private repository's raw URLs need a token; a small public
gist works without one.

## When the app says "update needed"

The yellow **App update needed** pill in the top bar, the Settings panel and an
`SYS-update` alert appear when:

1. The manifest's `min_app_version` is newer than the running version. The manifest's
   `notes` explain what the new version adds.
2. A feed definition uses a `kind` this build cannot parse.
3. A feed source answered 404, 410, 401 or 403, which means it moved, was retired, or now
   requires an API key (abuse.ch did this with URLhaus and ThreatFox in 2025).
4. A source returned an HTML page instead of data.

In each case the Settings view lists the reasons. Copy them into a request to update the app;
the feed parser or the rule engine then gets extended, the version is bumped, and the
condition clears on the next refresh.

## Rule packs and future data types

Detection rules are compiled into the binary (`src/analysis/mod.rs`). Thresholds are
configurable, the rules themselves are not data-driven. New categories of threat data (for
example JA3 fingerprints, certificate blocklists, YARA matches) need a code change; the
manifest's `min_app_version` is the mechanism to announce that.

## Changing the app version

Bump `version` in `Cargo.toml`. The value is reported in the dashboard footer, in
`/api/overview` and compared with manifests.
