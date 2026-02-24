# AdGuard Top Domains Analyzer

A Python command-line tool that reads an AdGuard Home `querylog.json` file and
reports the **most-queried domains** for a specific client (IP address) on a
given day, excluding background / keep-alive traffic.

Companion to [adguard_activity.py](adguard_activity.py) — use that tool to
analyse *when* a device was online; use this tool to analyse *what* it was
doing.

---

## Requirements

- Python 3.10 or newer
- No third-party packages — standard library only

---

## Quick Start

```powershell
python D:\adguard_top_domains.py <IP> <YYYY-MM-DD>
```

---

## Options Reference

| Option | Default | Description |
|---|---|---|
| `ip` | *(required)* | Client IP to analyse |
| `date` | *(required)* | Date in `YYYY-MM-DD` format |
| `--config FILE` | auto | Path to a JSON config file (see [Config File](#config-file)) |
| `--log FILE` | `D:\querylog.json` | Path to the querylog file; overrides config |
| `--top N` / `-n N` | `10` | Number of top domains to display |
| `--no-bg-filter` | off | Disable background-hostname filtering |
| `--exact` | off | Count exact hostnames instead of grouping subdomains under root domain |
| `--show-subdomains` | off | Under each root domain, list the top contributing subdomains |
| `--only-allowed` | off | Count only queries **allowed** by AdGuard (mutually exclusive with `--only-blocked`) |
| `--only-blocked` | off | Count only queries **blocked** by AdGuard (mutually exclusive with `--only-allowed`) |

---

---

## Config File

Both scripts share the same config file format — place `adguard_config.json`
in the same directory as the scripts (or in cwd) and it is loaded automatically.
Use `--config path/to/file.json` to point to any other location.

A sample file is provided as **`adguard_config.json.example`**.

```json
{
    "log":          "D:\\querylog.json",
    "bg_filter":    true,
    "query_filter": "all",
    "top_n":        10
}
```

| Key | Type | Default | Description |
|---|---|---|---|
| `log` | string | `D:\querylog.json` | Path to `querylog.json` |
| `bg_filter` | bool | `true` | Set `false` to disable background-hostname filtering |
| `query_filter` | string | `"all"` | `"all"` \| `"allowed"` \| `"blocked"` |
| `top_n` | int | `10` | Number of top domains to display |

The keys `gap`, `min_queries`, `active_rate`, and `idle_gap` are also valid in
the shared config file but are used only by `adguard_activity.py`.

> **Priority:** CLI flag > config file > hard-coded default.

## Use Cases

### 1. Top 10 domains for a device on a given day

Background / keep-alive traffic is filtered automatically.
Subdomains are grouped under their root domain by default
(e.g. `cdn.roblox.com` and `www.roblox.com` both count toward `roblox.com`).

```powershell
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21
```

**Sample output:**
```
======================================================================
  AdGuard Top-Domains Report
  Client IP  : 192.168.88.20
  Date       : 2026-02-21 (Saturday)
  Top        : 10
  BG filter  : on  (100 of 13517 queries removed, 1%)
  Grouping   : by root domain
  Queries    : 13417 counted  (13517 total)
======================================================================

  #    Domain                Queries   % of total   Bar
  ---------------------------------------------------------------------------
  1    roblox.com             5286        39.4%   ████████████
  2    microsoft.com           956         7.1%   ██
  3    cloudflare-dns.com      734         5.5%   ██
  4    discordapp.com          707         5.3%   ██
  5    steamserver.net         636         4.7%   █
  6    nvidia.com              556         4.1%   █
  7    rbxcdn.com              378         2.8%   █
  8    youtube.com             376         2.8%   █
  9    opera.com               366         2.7%   █
  10   ytimg.com               349         2.6%   █

----------------------------------------------------------------------
  Top 10 coverage : 10344 queries  (77.1% of filtered total)
  Distinct domains  : 91
======================================================================
```

---

### 2. Show more domains

```powershell
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --top 20
```

---

### 3. Subdomain breakdown

Expand each root domain with the top 5 subdomains that contributed to its
count, including each subdomain's share as a percentage of the root total.
Up to 5 subdomains are shown; a summary line covers any remaining ones.

```powershell
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --show-subdomains
```

```
  1   roblox.com            5286        39.4%   ████████████
        ↳ ecsv2.roblox.com    1865        35.3%
        ↳ presence.roblox.com   755        14.3%
        ↳ thumbnails.roblox.com 350         6.6%
        ↳ www.roblox.com        307         5.8%
        ↳ users.roblox.com      238         4.5%
        ↳ … and 35 more        1737

  2   microsoft.com          956         7.1%   ██
        ↳ watson.events.data.microsoft.com  561  58.7%
        ↳ eu-mobile.events.data.microsoft.com 188 19.7%
        ...
```

---

### 4. Fewer domains with subdomain detail

Combine `--top` and `--show-subdomains` for a focused deep-dive:

```powershell
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --top 5 --show-subdomains
```

---

### 5. Exact hostname ranking (no grouping)

Count each full hostname independently without rolling them up to the root.
Useful to see exactly which specific subdomains are the busiest.

```powershell
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --exact
```

```
  1   ecsv2.roblox.com                  1865        13.9%   ████
  2   p2p-fra1.discovery.steamserver.net  629         4.7%   █
  3   presence.roblox.com                755         5.6%   █
  ...
```

---

### 6. Raw view — disable background filtering

Include OS telemetry, NTP, OCSP and other keep-alive queries in the counts.

```powershell
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --no-bg-filter
```

---

### 7. Use a different log file

```powershell
python D:\adguard_top_domains.py 192.168.88.23 2025-12-01 --log C:\AdGuard\querylog.json
```

---

### 8. Today's top domains

```powershell
python D:\adguard_top_domains.py 192.168.88.20 2026-02-22
```

---

### 9. Top blocked domains — what AdGuard is protecting against

See which domains are being actively blocked most often for a device.
Useful for understanding ad/tracker exposure or confirming block-lists are working.

```powershell
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --only-blocked
```

**Sample output:**
```
======================================================================
  AdGuard Top-Domains Report
  Client IP  : 192.168.88.20
  Date       : 2026-02-21 (Saturday)
  Top        : 10
  Queries    : blocked only
  BG filter  : on  (1 of 13517 queries removed, 0%)
  Grouping   : by root domain
  Queries    : 4153 counted  (13517 total)
======================================================================

  #    Domain               Queries   % of total   Bar
  ---------------------------------------------------------------------------
  1    roblox.com            2128        51.2%   ███████████████
  2    microsoft.com          764        18.4%   ██████
  3    opera.software         270         6.5%   ██
  4    opera.com              253         6.1%   ██
  5    doubleclick.net        230         5.5%   ██
  ...
======================================================================
```

---

### 10. Top allowed domains — actual browsing/app traffic only

Exclude all blocked queries to see only what the device successfully resolved.

```powershell
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --only-allowed
```

Combine with `--show-subdomains` for full detail:

```powershell
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --only-allowed --show-subdomains --top 5
```

---

## How It Works

### Step 1 — Event collection

The log is streamed line by line. Each entry is filtered by:

1. **IP match** — only lines where `IP == <client_ip>` are kept.
2. **Date match** — the timestamp's local date must equal `<date>`.
3. **Allowed/blocked filter** — when `--only-allowed` or `--only-blocked` is set,
   the entry's `Result.IsFiltered` field is checked to include or exclude it.
4. **Background filter** — hostnames matching known OS/app keep-alive patterns
   are dropped (see list below). Disable with `--no-bg-filter`.

### Step 2 — Domain counting

For each surviving entry the queried hostname (`QH`) is counted.

- **Default (grouped)** — the hostname is reduced to its *root domain*
  (last two labels: `sub.example.com` → `example.com`) before counting.
  All subdomains are aggregated.
- **`--exact`** — the full hostname is counted as-is.

### Step 3 — Ranking and display

Domains are sorted by count descending. The top N are displayed in a table
with query count, percentage of total filtered queries, and an ASCII bar chart.
`--show-subdomains` adds a breakdown of up to 5 contributing subdomains per
root domain.

---

## Background Filter Patterns

The following hostname patterns are removed before counting
(same list as `adguard_activity.py`):

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
[adguard_top_domains.py](adguard_top_domains.py).

---

## Output Fields

| Column | Description |
|---|---|
| `#` | Rank (1 = most queried) |
| `Domain` | Root domain or exact hostname depending on `--exact` |
| `Queries` | Total DNS query count for this domain on the selected date |
| `% of total` | Share of all filtered queries for this IP/date |
| `Bar` | Proportional ASCII bar (max width = 30 chars = 100%) |

**Footer lines:**

| Line | Description |
|---|---|
| `Top N coverage` | Combined query count and % for the displayed domains |
| `Distinct domains` | Total unique root domains (or hostnames in `--exact` mode) seen that day |

---

## Combining with adguard_activity.py

Use both tools together for a complete picture:

```powershell
# When was the device online and in what blocks?
python D:\adguard_activity.py 192.168.88.20 2026-02-21

# What was it doing all day?
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21

# How long was Roblox specifically being played?
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --domain roblox.com --active-rate 10 --idle-gap 5

# What sites were actually reached (allowed only)?
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --only-allowed

# What was AdGuard blocking most?
python D:\adguard_top_domains.py 192.168.88.20 2026-02-21 --only-blocked --show-subdomains

# Activity blocks for allowed traffic only (ignore blocked-query noise)
python D:\adguard_activity.py 192.168.88.20 2026-02-21 --only-allowed
```
