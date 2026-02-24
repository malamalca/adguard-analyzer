# AdGuard Activity Analyzer

A Python command-line tool that reads an AdGuard Home `querylog.json` file and
shows **when** a specific client (IP address) was online on a given day, broken
down into activity blocks and — in domain mode — into active/idle sub-periods.

---

## Requirements

- Python 3.10 or newer (uses `type | None` union syntax)
- No third-party packages — standard library only

---

## Quick Start

```powershell
python D:\adguard_activity.py <IP> <YYYY-MM-DD>
```

---

## Log Format

Each line in `querylog.json` is a self-contained JSON object:

```json
{
  "T":        "2025-11-30T08:26:26.428561+01:00",
  "QH":       "www.roblox.com",
  "QT":       "A",
  "QC":       "IN",
  "CP":       "",
  "Upstream": "https://dns10.quad9.net:443/dns-query",
  "Answer":   "<base64>",
  "IP":       "192.168.88.20",
  "Result":   {},
  "Elapsed":  9845500
}
```

| Field      | Description                                  |
|------------|----------------------------------------------|
| `T`        | ISO-8601 timestamp with timezone offset      |
| `QH`       | Queried hostname                             |
| `QT`       | DNS query type (`A`, `AAAA`, `HTTPS`, …)     |
| `IP`       | Client IP address                            |
| `Result`   | Filtering result (blocked / allowed / empty) |
| `Elapsed`  | Response time in nanoseconds                 |

---

## Options Reference

| Option | Default | Description |
|---|---|---|
| `ip` | *(required)* | Client IP to analyse |
| `date` | *(required)* | Date in `YYYY-MM-DD` format |
| `--config FILE` | auto | Path to a JSON config file (see [Config File](#config-file)) |
| `--log FILE` | `D:\querylog.json` | Path to the querylog file; overrides config |
| `--gap MINUTES` | `5` | Minutes of inactivity that split a new usage block |
| `--min-queries N` | `5` | Drop blocks with fewer than N queries (noise filter) |
| `--no-bg-filter` | off | Disable background-hostname filtering |
| `--domain DOMAIN` / `-d` | off | Restrict analysis to one domain + its subdomains |
| `--active-rate N` | `5` | Queries/min threshold for "active" in domain mode |
| `--idle-gap MINS` | `3` | Consecutive idle minutes tolerated inside an active sub-block |
| `--only-allowed` | off | Count only queries that were **allowed** (not blocked) |
| `--only-blocked` | off | Count only queries that were **blocked** by AdGuard |

> `--only-allowed` and `--only-blocked` are mutually exclusive.

---

---

## Config File

Both scripts look for `adguard_config.json` automatically — first in the same
directory as the script, then in the current working directory.  You can also
point to any file with `--config path/to/file.json`.

A sample file is provided as **`adguard_config.json.example`** beside the scripts.
Copy it, rename to `adguard_config.json`, and edit to suit your setup:

```json
{
    "log":          "D:\\querylog.json",
    "bg_filter":    true,
    "query_filter": "all",
    "gap":          5,
    "min_queries":  5,
    "active_rate":  5,
    "idle_gap":     3
}
```

| Key | Type | Default | Description |
|---|---|---|---|
| `log` | string | `D:\querylog.json` | Path to `querylog.json` |
| `bg_filter` | bool | `true` | Set `false` to disable background-hostname filtering |
| `query_filter` | string | `"all"` | `"all"` \| `"allowed"` \| `"blocked"` |
| `gap` | int | `5` | Inactivity gap in minutes that splits usage blocks |
| `min_queries` | int | `5` | Minimum queries per block (below = dropped as noise) |
| `active_rate` | int | `5` | Queries/min threshold for "active" in domain mode |
| `idle_gap` | int | `3` | Idle minutes tolerated inside an active sub-block |

> **Priority:** CLI flag > config file > hard-coded default.
> Any key absent from the config file simply uses the hard-coded default.
> The `top_n` key is supported in config but only used by `adguard_top_domains.py`.

## Use Cases

### 1. General daily activity — when was a device online?

Shows all DNS-based activity blocks for a device on a given day.
Background noise (OS telemetry, NTP, OCSP, etc.) is filtered automatically.

```powershell
python D:\adguard_activity.py 192.168.88.20 2026-02-21
```

**Sample output:**
```
============================================================
  AdGuard Activity Report
  Client IP : 192.168.88.20
  Date      : 2026-02-21 (Saturday)
  Gap split : 5 minutes of inactivity
  BG filter : on  (hostname patterns + min 5 queries/block)
============================================================

  Block  1
    Start      : 13:27:42  (+0100)
    End        : 23:56:12
    Duration   : 10h 28m 29s
    DNS queries: 13415

------------------------------------------------------------
  Total blocks  : 1
  Total queries : 13415
  Total active  : 10h 28m 29s

  [filtered]  100 background-hostname queries removed
  [filtered]  1 thin block(s) dropped (< 5 queries each, 2 queries total):
              00:00:31 – 00:00:54  (2 queries)
============================================================
```

---

### 2. Today's activity

```powershell
python D:\adguard_activity.py 192.168.88.20 2026-02-22
```

---

### 3. Adjust the inactivity gap

By default a 5-minute gap splits blocks. Increase to 10 minutes to merge
sessions with short pauses:

```powershell
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --gap 10
```

---

### 4. Raw view — disable all filtering

See exactly what is in the log, including background noise and thin blocks:

```powershell
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --no-bg-filter --min-queries 1
```

---

### 5. Domain activity — when was a specific site used?

Only queries for `roblox.com` and all its subdomains
(`www.roblox.com`, `clientsettings.roblox.com`, etc.) are counted.
Background filtering is automatically disabled in domain mode.

```powershell
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --domain roblox.com
```

The header shows how many of the day's total queries matched:

```
  Domain    : roblox.com  (5286 of 13517 queries matched)
```

---

### 6. Domain activity with active/idle breakdown (default thresholds)

In domain mode the report automatically adds an **Activity breakdown** under
each block. A 1-minute bin is **active** when it receives ≥ `--active-rate`
queries (default 5). Consecutive cold bins ≤ `--idle-gap` minutes (default 3)
are tolerated inside an active sub-block before it is closed.

```powershell
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --domain roblox.com
```

```
    Activity breakdown  (≥5 queries/min = active, idle gap ≤3 min):
      [ACTIVE]  13:28 – 16:04  2h 36m 0s   1051 queries  avg 6.7/min  peak 71/min
      [ IDLE ]  16:04 – 18:20  2h 16m 0s
      [ACTIVE]  18:20 – 20:06  1h 46m 0s   1328 queries  avg 12.5/min  peak 66/min
      ...
      ────────────────────────────────────────────────
      Active sub-blocks : 21
      Active time       : 8h 10m 0s (78% of block)
      Idle time         : 2h 17m 50s
```

---

### 7. Domain activity — separate real gameplay from background heartbeats

Many games (Roblox, for example) keep sending periodic DNS pings even when the
user is AFK or in a menu. These show up as short 1-min blips of exactly 6–10
queries. Raising `--active-rate` to 10 and `--idle-gap` to 5 filters them out,
revealing only genuine play sessions:

```powershell
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --domain roblox.com --active-rate 10 --idle-gap 5
```

```
    Activity breakdown  (≥10 queries/min = active, idle gap ≤5 min):
      [ACTIVE]  13:28 – 13:33   5m 0s    109 queries  avg 21.8/min  peak 71/min
      [ IDLE ]  13:33 – 14:10  37m 0s
      [ACTIVE]  18:20 – 19:48  1h 28m 0s  1204 queries  avg 13.7/min  peak 66/min
      [ACTIVE]  20:45 – 21:26  41m 0s     616 queries  avg 15.0/min  peak 80/min
      [ACTIVE]  21:37 – 22:28  51m 0s     539 queries  avg 10.6/min  peak 65/min
      [ACTIVE]  22:35 – 23:50  1h 15m 0s 1153 queries  avg 15.4/min  peak 81/min
      ────────────────────────────────────────────────
      Active sub-blocks : 14
      Active time       : 4h 51m 0s (46% of block)
      Idle time         : 5h 36m 50s

  Domain active : 4h 51m 0s  (46% of session)
  Domain idle   : 5h 36m 50s
```

---

### 8. Domain activity on a different site (e.g. YouTube)

```powershell
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --domain youtube.com
```

---

### 9. Use a different log file

```powershell
python D:\adguard_activity.py 192.168.88.23 2025-12-01 --log C:\AdGuard\querylog.json
```

---

### 10. Activity blocks for blocked queries only

Shows sessions made up exclusively of requests that AdGuard **blocked** —
useful for finding when a device was actively trying to reach ad/tracking
servers or blocked content.

```powershell
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --only-blocked
```

The report header will confirm the filter is active:

```
  Queries   : blocked only
```

---

### 11. Activity blocks for allowed queries only

Excludes every request that AdGuard blocked, leaving only legitimate traffic.
Combine with `--domain` to see when a specific site was actually reachable:

```powershell
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --domain roblox.com --only-allowed
```

---

## How It Works

### Step 1 — Event collection

The log is streamed line by line (handles arbitrarily large files). Each entry
is filtered by:
1. **IP match** — only lines where `IP == <client_ip>` are kept.
2. **Date match** — the timestamp's local date must equal `<date>`.
3. **Background filter** (normal mode) — hostnames matching known OS/app
   keep-alive patterns are dropped (see list below).
4. **Domain filter** (domain mode) — only hostnames that are `<domain>` or a
   subdomain of it pass through.
5. **Allowed/blocked filter** (\--only-allowed\ / \--only-blocked\) — checked
   via \Result.IsFiltered\ in each log entry (\	rue\ = blocked by AdGuard).

### Step 2 — Block detection

Surviving timestamps are sorted. Consecutive events with a gap **≥ `--gap`
minutes** start a new block. Blocks with fewer than `--min-queries` events are
then dropped as noise.

### Step 3 — Active/idle breakdown (domain mode only)

Events are binned into 1-minute slots. Each bin is labelled:
- **Hot** — query count ≥ `--active-rate`
- **Cold** — below the threshold

Hot bins (with up to `--idle-gap` cold bins tolerated between them) are merged
into **active sub-blocks**. Long cold stretches become `[ IDLE ]` periods.

---

## Background Filter Patterns

The following hostname patterns are removed before building activity blocks
(in normal mode only; domain mode is unaffected):

| Category | Examples |
|---|---|
| Microsoft telemetry | `msftconnecttest.com`, `vortex.data.microsoft.com`, `smartscreen.microsoft.com` |
| Windows Update | `windowsupdate.com`, `update.microsoft.com` |
| NTP / time sync | `time.windows.com`, `*.ntp.org`, `time.cloudflare.com` |
| Certificate checks | `ocsp.*`, `*.crl.*`, `crl.*` |
| Apple background | `captive.apple.com`, `push.apple.com`, `mesu.apple.com` |
| Google connectivity | `connectivitycheck.gstatic.com`, `clients[N].google.com` |
| Generic | `connectivity-check.*`, `captive.*` |

To add your own patterns, edit the `BACKGROUND_PATTERNS` list at the top of
[adguard_activity.py](adguard_activity.py).

---

## Tuning Guide

| Goal | Recommendation |
|---|---|
| Merge short breaks into one session | Increase `--gap` (e.g. `--gap 15`) |
| Only count sustained usage | Increase `--min-queries` (e.g. `--min-queries 10`) |
| Detect light browsing as "active" | Lower `--active-rate` (e.g. `--active-rate 3`) |
| Filter out game heartbeats | Raise `--active-rate` (e.g. `--active-rate 10`) |
| Allow brief pauses in gameplay | Raise `--idle-gap` (e.g. `--idle-gap 8`) |
| See all raw data | `--no-bg-filter --min-queries 1` |
| Show only blocked-query sessions | `--only-blocked` |
| Show domain usage excluding blocked requests | `--domain example.com --only-allowed` |

---

## Combining with Top-Domains Report

Run [`adguard_top_domains.py`](adguard_top_domains.py) alongside this script
for a fuller picture of a device's day:

```powershell
# What domains were most queried (allowed traffic only)?
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --only-allowed

# What did AdGuard block most on the same day?
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --only-blocked

# Activity timeline for the blocked traffic found above
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --only-blocked
```
