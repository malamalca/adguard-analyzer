# AdGuard Activity

Two Python scripts for analysing an [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) `querylog.json` file from the command line.

| Script | Purpose |
|---|---|
| `adguard_activity.py` | Shows **time blocks of activity** for a client IP on a given date |
| `adguard_top_domains.py` | Shows the **top queried domains** for a client IP on a given date |

## Requirements

Python 3.10+ — no third-party packages required.

## Quick start

```bash
# Activity blocks
python adguard_activity.py 192.168.1.10 2026-02-24 --log /path/to/querylog.json

# Top domains
python adguard_top_domains.py 192.168.1.10 2026-02-24 --log /path/to/querylog.json
```

## Configuration file

Copy `adguard_config.json.example` to `adguard_config.json` and edit as needed.
Both scripts look for it automatically beside the script or in the current working directory,
so you usually don't need to pass `--log` on every run.

```jsonc
{
    "log": "/path/to/AdGuardHome/data/querylog.json",

    "bg_filter": true,        // strip background/keep-alive hostnames
    "query_filter": "all",    // "all" | "allowed" | "blocked"

    // adguard_activity.py
    "gap": 5,                 // inactivity gap (minutes) that starts a new block
    "min_queries": 5,         // drop blocks with fewer queries (background noise)
    "active_rate": 5,         // queries/min threshold for "active" in domain mode
    "idle_gap": 3,            // consecutive idle minutes allowed inside an active sub-block

    // adguard_top_domains.py
    "top_n": 10,              // number of top domains to show
    "exact": false,           // true = count exact hostnames; false = group by root domain
    "show_subdomains": false  // true = show per-subdomain breakdown under each root
}
```

Settings priority: **CLI flag > config file > built-in default**.

## `adguard_activity.py`

```
usage: adguard_activity.py [-h] [--config FILE] [--log FILE] [--gap MINUTES]
                           [--min-queries N] [--no-bg-filter]
                           [--domain DOMAIN] [--active-rate N] [--idle-gap MINS]
                           [--only-allowed | --only-blocked]
                           ip date
```

### Positional arguments

| Argument | Description |
|---|---|
| `ip` | Client IP address to analyse (e.g. `192.168.1.10`) |
| `date` | Date in `YYYY-MM-DD` format |

### Options

| Flag | Default | Description |
|---|---|---|
| `--log FILE` | config / required | Path to `querylog.json` |
| `--config FILE` | auto-detected | Path to a JSON config file |
| `--gap MINUTES` | `5` | Inactivity gap (minutes) that starts a new activity block; also sets the chart bin width |
| `--min-queries N` | `5` | Drop blocks with fewer queries |
| `--no-bg-filter` | off | Disable background-hostname filtering |
| `--domain DOMAIN` | — | Restrict to one domain and its subdomains |
| `--active-rate N` | `5` | Queries/min threshold for `[ACTIVE]` in the activity breakdown and chart coloring |
| `--idle-gap MINS` | `3` | Consecutive idle minutes allowed inside an active sub-block before it is closed |
| `--only-allowed` | — | Count only queries **not** blocked by AdGuard |
| `--only-blocked` | — | Count only queries **blocked** by AdGuard |

### Example output

```
============================================================
  AdGuard Activity Report
  Client IP : 192.168.1.10
  Date      : 2026-02-24 (Tuesday)
  Gap split : 10 minutes of inactivity
  Activity  : ≥5 queries/min = active,  idle gap ≤3 min
  BG filter : on  (hostname patterns + min 5 queries/block)
============================================================

  Block  1
    Start      : 08:14:22  (+0100)
    End        : 14:58:44
    Duration   : 6h 44m 22s
    DNS queries: 399

    Activity breakdown  (≥5 queries/min = active, idle gap ≤3 min [≡ chart bins]):
      [ACTIVE]  08:10 – 09:50  1h 40m 0s  312 queries  avg 3.1/min  peak 18/min
      [ IDLE ]  09:50 – 14:00  4h 10m 0s  12 queries  avg 0.0/min
      [ACTIVE]  14:00 – 15:00  1h 0m 0s  87 queries  avg 1.5/min  peak 9/min
      ────────────────────────────────────────────────
      Active sub-blocks : 2
      Active time       : 2h 40m 0s (40% of block)
      Idle time         : 4h 4m 22s

------------------------------------------------------------
  Total blocks  : 1
  Total queries : 399
  Total active  : 6h 44m 22s
  Active time   : 2h 40m 0s  (40% of session)
  Idle time     : 4h 4m 22s
============================================================

  ── Daily query chart  bin=10 min  peak=18.0 q/min  threshold=≥5 q/min  idle gap ≤3 min
  18.0 │                 █
       │                 █                         █
   9.0 │                 █  █                      █
       │                 ████ █                █    █
       │                 ████████              ███████
     0 │                 █████████             ████████
       └────────────────────────────────────────────────────
        ░░░░░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░▓▓▓▓▓▓▓▓░░░░░
        00h         06h         12h         18h         24h
```

Bars are **green** when the bin is inside a kept block. The top portion of each
bar turns **red** when the bin's query rate exceeds `--active-rate`. The
indicator row below the X axis shows `▓` for kept blocks and `░` for inactive
periods.

## `adguard_top_domains.py`

```
usage: adguard_top_domains.py [-h] [--config FILE] [--log FILE] [--top N]
                              [--no-bg-filter] [--exact] [--show-subdomains]
                              [--only-allowed | --only-blocked]
                              ip date
```

### Positional arguments

| Argument | Description |
|---|---|
| `ip` | Client IP address to analyse |
| `date` | Date in `YYYY-MM-DD` format |

### Options

| Flag | Default | Description |
|---|---|---|
| `--log FILE` | config / required | Path to `querylog.json` |
| `--config FILE` | auto-detected | Path to a JSON config file |
| `--top N` / `-n N` | `10` | Number of top domains to display |
| `--no-bg-filter` | off | Disable background-hostname filtering |
| `--exact` | off | Count exact hostnames instead of grouping under root domain |
| `--show-subdomains` | off | Show per-subdomain breakdown under each root domain |
| `--only-allowed` | — | Count only queries **not** blocked by AdGuard |
| `--only-blocked` | — | Count only queries **blocked** by AdGuard |

### Example output

```
======================================================================
  AdGuard Top-Domains Report
  Client IP  : 192.168.1.10
  Date       : 2026-02-24 (Tuesday)
  Top        : 10
  BG filter  : on  (43 of 890 queries removed, 5%)
  Grouping   : by root domain
  Queries    : 847 counted  (890 total)
======================================================================

  #   Domain                    Queries   % of total   Bar
  --------------------------------------------------------------------
  1   youtube.com                   210       24.8%   ████████
  2   roblox.com                    158       18.7%   ██████
  3   netflix.com                    94       11.1%   ████
  ...
```

## Background-hostname filtering

Both scripts silently drop DNS queries that match known background / keep-alive patterns
(Microsoft telemetry, NTP, OCSP, Apple push, Google connectivity checks, etc.) before
building blocks or counting domains. Disable with `--no-bg-filter` or `"bg_filter": false`
in the config file.

## Common locations for `querylog.json`

| Platform | Default path |
|---|---|
| Linux (package) | `/var/lib/AdGuardHome/data/querylog.json` |
| macOS (manual install) | `/Applications/AdGuardHome/data/querylog.json` |
| Docker | mapped volume, e.g. `./adguard/data/querylog.json` |
| Windows | `C:\AdGuardHome\data\querylog.json` |
