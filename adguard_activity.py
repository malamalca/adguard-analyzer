#!/usr/bin/env python3
"""
AdGuard DNS Query Log - Client Activity Analyzer
Reads querylog.json and outputs time blocks of activity for a given IP and date.
A gap of >= GAP_MINUTES minutes of inactivity starts a new usage block.
"""

import json
import re
import sys
import argparse
import os
from datetime import datetime, timedelta, timezone, date


# ── Configuration ──────────────────────────────────────────────────────────────
DEFAULT_LOG_FILE  = None   # no built-in default; use --log or set 'log' in adguard_config.json
GAP_MINUTES       = 5    # inactivity gap that splits usage blocks
MIN_BLOCK_QUERIES = 5    # blocks with fewer queries are considered background noise
DEFAULT_ACTIVE_RATE = 5  # queries/min threshold considered "active" (domain mode)
DEFAULT_IDLE_GAP    = 3  # consecutive idle 1-min bins allowed inside an active sub-block

# Hostname patterns (regex) that indicate background / keep-alive traffic.
# Matching DNS queries are excluded before building activity blocks.
BACKGROUND_PATTERNS = [
    # Microsoft connectivity checks & telemetry
    r"msftconnecttest\.com$",
    r"msftncsi\.com$",
    r"windowsupdate\.com$",
    r"update\.microsoft\.com$",
    r"telemetry\.microsoft\.com$",
    r"vortex\.data\.microsoft\.com$",
    r"settings-win\.data\.microsoft\.com$",
    r"watson\.telemetry\.microsoft\.com$",
    r"smartscreen\.microsoft\.com$",
    # NTP / time sync
    r"time\.windows\.com$",
    r"time\.apple\.com$",
    r"time\.cloudflare\.com$",
    r"\.ntp\.org$",
    r"^ntp\.org$",
    # Certificate revocation (OCSP / CRL)
    r"ocsp\.",
    r"\.crl\.",
    r"^crl\.",
    # Apple background services
    r"captive\.apple\.com$",
    r"appleanalytics\.com$",
    r"apple-cloudkit\.com$",
    r"push\.apple\.com$",
    r"configuration\.apple\.com$",
    r"mesu\.apple\.com$",
    # Google connectivity check
    r"connectivitycheck\.gstatic\.com$",
    r"clients\d+\.google\.com$",
    # Generic keep-alive patterns
    r"^connectivity-check\.",
    r"^captive\.",
]

_BG_COMPILED = [re.compile(p, re.IGNORECASE) for p in BACKGROUND_PATTERNS]

# ── Config file ───────────────────────────────────────────────────────────────
import os as _os

def _find_default_config() -> str | None:
    """Return path to adguard_config.json if it exists beside this script or in cwd."""
    candidates = [
        _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "adguard_config.json"),
        _os.path.join(_os.getcwd(), "adguard_config.json"),
    ]
    for p in candidates:
        if _os.path.isfile(p):
            return p
    return None


def load_config(path: str | None) -> tuple[dict, str | None]:
    """Load settings from a JSON config file.

    If *path* is None the function looks for ``adguard_config.json`` in the
    same directory as this script, then in the current working directory.

    Priority for every setting: CLI flag > config file > hard-coded default.

    Supported keys
    --------------
    log          (str)   – path to querylog.json
    bg_filter    (bool)  – false disables background-hostname filtering
    query_filter (str)   – "all" | "allowed" | "blocked"
    gap          (int)   – inactivity gap in minutes  [activity only]
    min_queries  (int)   – minimum queries per block  [activity only]
    active_rate  (int)   – queries/min threshold for "active" [activity only]
    idle_gap     (int)   – idle minutes allowed inside active sub-block [activity only]
    top_n          (int)   – number of top domains to display [top_domains only]
    exact          (bool)  – true counts exact hostnames (no subdomain grouping) [top_domains only]
    show_subdomains (bool) – true shows per-subdomain breakdown under each root [top_domains only]

    Returns (config_dict, resolved_path).  resolved_path is None when no file
    was found or loaded.
    """
    explicit = path is not None
    if path is None:
        path = _find_default_config()
    if path is None:
        return {}, None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            print(f"  [warn] Config {path}: expected a JSON object – ignored",
                  file=sys.stderr)
            return {}, None
        return data, path
    except FileNotFoundError:
        if explicit:
            print(f"Error: config file not found: {path}", file=sys.stderr)
            sys.exit(1)
        return {}, None
    except json.JSONDecodeError as exc:
        print(f"  [warn] Config {path}: JSON parse error – {exc}", file=sys.stderr)
        sys.exit(1)




def is_background(hostname: str) -> bool:
    """Return True if the hostname matches any known background-traffic pattern."""
    return any(rx.search(hostname) for rx in _BG_COMPILED)


def is_blocked(entry: dict) -> bool:
    """Return True if AdGuard filtered/blocked this query."""
    result = entry.get("Result", {})
    return bool(result) and result.get("IsFiltered", False)


def matches_domain(hostname: str, domain: str) -> bool:
    """Return True if hostname equals domain or is any subdomain of it.

    Examples:
        matches_domain('roblox.com',        'roblox.com') → True
        matches_domain('www.roblox.com',    'roblox.com') → True
        matches_domain('cdn.roblox.com',    'roblox.com') → True
        matches_domain('notroblox.com',     'roblox.com') → False
    """
    hostname = hostname.lower().rstrip(".")
    domain   = domain.lower().rstrip(".")
    return hostname == domain or hostname.endswith("." + domain)


# ── Helpers ────────────────────────────────────────────────────────────────────
def parse_ts(ts_str: str) -> datetime:
    """Parse ISO-8601 timestamp that may carry a UTC-offset (+HH:MM)."""
    # Python < 3.11 doesn't support ':' in offset directly for all formats,
    # so we normalise '+01:00' → '+0100' before parsing.
    ts_str = ts_str.strip()
    if len(ts_str) > 6 and ts_str[-3] == ":" and ts_str[-6] in ("+", "-"):
        ts_str = ts_str[:-3] + ts_str[-2:]   # remove the colon from offset
    return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")


def fmt_duration(seconds: float) -> str:
    """Format a duration in seconds as  Hh Mm Ss."""
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s   = divmod(rem, 60)
    parts  = []
    if h:
        parts.append(f"{h}h")
    if m or h:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def local_date(dt: datetime) -> date:
    """Return the local-time date of an aware datetime (keeps its own offset)."""
    return dt.date()


# ── Core logic ─────────────────────────────────────────────────────────────────
def collect_events(
    log_file: str,
    client_ip: str,
    target_date: date,
    bg_filter: bool = True,
    domain: str | None = None,
    query_filter: str = "all",   # "all" | "allowed" | "blocked"
) -> tuple[list[datetime], int, int]:
    """Stream through the log and collect all timestamps for the given IP/date.

    When *domain* is set only queries whose QH matches that domain (exact or
    subdomain) are counted; bg_filter is automatically skipped in that mode.

    query_filter controls which entries are counted:
      "all"     – both allowed and blocked queries
      "allowed" – only queries that were NOT blocked by AdGuard
      "blocked" – only queries that WERE blocked by AdGuard

    Returns:
        (events, bg_filtered_count, total_seen_count)
    """
    events: list[datetime] = []
    bg_filtered = 0
    total_seen  = 0

    with open(log_file, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                print(f"  [warn] line {lineno}: JSON parse error – skipped", file=sys.stderr)
                continue

            if entry.get("IP") != client_ip:
                continue

            ts_str = entry.get("T", "")
            if not ts_str:
                continue

            try:
                ts = parse_ts(ts_str)
            except ValueError:
                print(f"  [warn] line {lineno}: cannot parse timestamp '{ts_str}' – skipped",
                      file=sys.stderr)
                continue

            if local_date(ts) != target_date:
                continue

            # ── allowed / blocked filter ──
            if query_filter == "allowed" and is_blocked(entry):
                continue
            if query_filter == "blocked" and not is_blocked(entry):
                continue

            hostname = entry.get("QH", "")

            # ── domain mode: keep only queries for the requested domain ──
            if domain is not None:
                total_seen += 1
                if not matches_domain(hostname, domain):
                    continue
            else:
                # ── normal mode: drop known background traffic ──
                if bg_filter and is_background(hostname):
                    bg_filtered += 1
                    continue

            events.append(ts)

    events.sort()
    return events, bg_filtered, total_seen


def build_blocks(
    events: list[datetime],
    gap_minutes: int = GAP_MINUTES,
    min_queries: int = MIN_BLOCK_QUERIES,
) -> tuple[list, list]:
    """Group sorted timestamps into activity blocks separated by >= gap_minutes.

    Returns:
        (kept_blocks, dropped_blocks) — blocks with >= min_queries queries and
        those below the threshold.  Each block is (start, end, query_count).
    """
    if not events:
        return [], []

    gap = timedelta(minutes=gap_minutes)
    raw_blocks  = []
    block_start = events[0]
    block_end   = events[0]
    query_count = 1

    for ts in events[1:]:
        if ts - block_end >= gap:
            raw_blocks.append((block_start, block_end, query_count))
            block_start = ts
            query_count = 1
        else:
            query_count += 1
        block_end = ts

    raw_blocks.append((block_start, block_end, query_count))

    kept    = [(s, e, c) for s, e, c in raw_blocks if c >= min_queries]
    dropped = [(s, e, c) for s, e, c in raw_blocks if c <  min_queries]
    return kept, dropped


def find_active_subblocks(
    events: list[datetime],
    min_rate: int = DEFAULT_ACTIVE_RATE,
    idle_gap: int = DEFAULT_IDLE_GAP,
) -> list[tuple]:
    """Within a sorted list of event timestamps, identify 'active' sub-periods
    based on per-minute query rate.

    A 1-minute bin is 'hot' when it contains >= min_rate queries.
    Hot bins separated by at most idle_gap consecutive cold bins are merged into
    one active sub-block.

    Returns list of (start, end, total_queries, peak_rate_per_min).
    """
    if not events:
        return []

    origin: datetime = events[0].replace(second=0, microsecond=0)

    # Count queries per 1-minute bin
    bin_counts: dict[int, int] = {}
    for ts in events:
        idx = int((ts - origin).total_seconds() / 60)
        bin_counts[idx] = bin_counts.get(idx, 0) + 1

    max_idx = max(bin_counts)
    subblocks: list[tuple] = []
    active_start: int | None = None
    last_hot: int | None    = None
    cold_run: int           = 0

    for i in range(max_idx + 1):
        is_hot = bin_counts.get(i, 0) >= min_rate
        if is_hot:
            if active_start is None:
                active_start = i
            last_hot = i
            cold_run = 0
        else:
            if active_start is not None:
                cold_run += 1
                if cold_run > idle_gap:
                    # Close sub-block at last_hot
                    s = origin + timedelta(minutes=active_start)
                    e = origin + timedelta(minutes=last_hot + 1)
                    q = sum(bin_counts.get(j, 0) for j in range(active_start, last_hot + 1))
                    p = max(bin_counts.get(j, 0) for j in range(active_start, last_hot + 1))
                    subblocks.append((s, e, q, p))
                    active_start = None
                    last_hot     = None
                    cold_run     = 0

    # Close any open sub-block
    if active_start is not None and last_hot is not None:
        s = origin + timedelta(minutes=active_start)
        e = origin + timedelta(minutes=last_hot + 1)
        q = sum(bin_counts.get(j, 0) for j in range(active_start, last_hot + 1))
        p = max(bin_counts.get(j, 0) for j in range(active_start, last_hot + 1))
        subblocks.append((s, e, q, p))

    return subblocks


# ── Output ─────────────────────────────────────────────────────────────────────
def _print_activity_breakdown(
    block_start: datetime,
    block_end: datetime,
    subblocks: list[tuple],
    min_rate: int,
    idle_gap: int,
    block_events: list[datetime],
):
    """Print active/idle sub-periods for one domain block."""
    print(f"\n    Activity breakdown  "
          f"(\u2265{min_rate} queries/min = active, idle gap \u2264{idle_gap} min):")

    if not subblocks:
        print(f"      No active periods detected "
              f"(all query bursts below {min_rate}/min threshold)")
        return

    total_active_s = sum((e - s).total_seconds() for s, e, *_ in subblocks)
    total_block_s  = max((block_end - block_start).total_seconds(), 1)
    active_pct     = total_active_s / total_block_s * 100

    def idle_stats(t_start: datetime, t_end: datetime) -> str:
        """Return '  N queries  avg R/min' for the idle window [t_start, t_end)."""
        dur_s = (t_end - t_start).total_seconds()
        if dur_s <= 0:
            return ""
        count = sum(1 for ts in block_events if t_start <= ts < t_end)
        if count == 0:
            return "  0 queries"
        avg_r = count / (dur_s / 60)
        return f"  {count} queries  avg {avg_r:.1f}/min"

    cursor = block_start
    for sub_start, sub_end, queries, peak in subblocks:
        # Idle gap before this active period
        if sub_start > cursor + timedelta(seconds=30):   # ignore rounding noise
            idle_s = (sub_start - cursor).total_seconds()
            stats  = idle_stats(cursor, sub_start)
            print(f"      [ IDLE ]  {cursor.strftime('%H:%M')} \u2013 "
                  f"{sub_start.strftime('%H:%M')}  "
                  f"{fmt_duration(idle_s)}{stats}")
        dur_s   = (sub_end - sub_start).total_seconds()
        avg_r   = queries / max(dur_s / 60, 1)
        print(f"      [ACTIVE]  {sub_start.strftime('%H:%M')} \u2013 "
              f"{sub_end.strftime('%H:%M')}  "
              f"{fmt_duration(dur_s)}  "
              f"{queries} queries  "
              f"avg {avg_r:.1f}/min  peak {peak}/min")
        cursor = sub_end

    # Trailing idle
    if block_end > cursor + timedelta(seconds=30):
        idle_s = (block_end - cursor).total_seconds()
        stats  = idle_stats(cursor, block_end)
        print(f"      [ IDLE ]  {cursor.strftime('%H:%M')} \u2013 "
              f"{block_end.strftime('%H:%M')}  "
              f"{fmt_duration(idle_s)}{stats}")

    print(f"      ────────────────────────────────────────────────")
    print(f"      Active sub-blocks : {len(subblocks)}")
    print(f"      Active time       : {fmt_duration(total_active_s)} "
          f"({active_pct:.0f}% of block)")
    print(f"      Idle time         : {fmt_duration(total_block_s - total_active_s)}")


def _print_filter_summary(bg_filtered: int, dropped_blocks, min_queries: int, bg_filter: bool):
    """Print a summary of what was filtered out."""
    if not bg_filter and not dropped_blocks:
        return
    print()
    if bg_filter and bg_filtered:
        print(f"  [filtered]  {bg_filtered} background-hostname queries removed")
    if dropped_blocks:
        dropped_queries = sum(c for _, _, c in dropped_blocks)
        print(f"  [filtered]  {len(dropped_blocks)} thin block(s) dropped "
              f"(< {min_queries} queries each, {dropped_queries} queries total):")
        for start, end, count in dropped_blocks:
            s = start.strftime("%H:%M:%S")
            e = end.strftime("%H:%M:%S")
            print(f"              {s} – {e}  "
                  f"({count} quer{'y' if count == 1 else 'ies'})")


def print_report(
    client_ip: str,
    target_date: date,
    blocks,
    dropped_blocks,
    gap_minutes: int,
    bg_filtered: int,
    min_queries: int,
    bg_filter: bool,
    domain: str | None = None,
    total_seen: int = 0,
    active_subblocks: list | None = None,
    active_rate: int = DEFAULT_ACTIVE_RATE,
    idle_gap: int = DEFAULT_IDLE_GAP,
    block_events_list: list | None = None,
    query_filter: str = "all",
):
    print()
    print("=" * 60)
    print(f"  AdGuard Activity Report")
    print(f"  Client IP : {client_ip}")
    print(f"  Date      : {target_date.strftime('%Y-%m-%d (%A)')}")
    if query_filter != "all":
        print(f"  Queries   : {query_filter} only")
    if domain:
        total_matched = sum(c for _, _, c in blocks) + sum(c for _, _, c in dropped_blocks)
        print(f"  Domain    : {domain}  ({total_matched} of {total_seen} queries matched)")
        print(f"  Activity  : \u2265{active_rate} queries/min = active,  idle gap \u2264{idle_gap} min")
    print(f"  Gap split : {gap_minutes} minutes of inactivity")
    if not domain:
        if bg_filter:
            print(f"  BG filter : on  (hostname patterns + min {min_queries} queries/block)")
        else:
            print(f"  BG filter : off")
    print("=" * 60)

    if not blocks:
        print("\n  No activity found for this IP on the selected date.")
        if bg_filtered or dropped_blocks:
            _print_filter_summary(bg_filtered, dropped_blocks, min_queries, bg_filter)
        print()
        return

    total_active_seconds  = 0
    total_queries         = 0
    grand_active_s        = 0.0   # sum of active sub-block durations (domain mode)

    for i, (start, end, count) in enumerate(blocks, 1):
        duration_s = (end - start).total_seconds()
        display_dur = max(duration_s, 1)
        total_active_seconds += display_dur
        total_queries        += count

        start_local = start.strftime("%H:%M:%S")
        end_local   = end.strftime("%H:%M:%S")
        tz_name     = start.strftime("%z")

        print(f"\n  Block {i:>2}")
        print(f"    Start      : {start_local}  ({tz_name})")
        print(f"    End        : {end_local}")
        print(f"    Duration   : {fmt_duration(display_dur)}")
        print(f"    DNS queries: {count}")

        if active_subblocks is not None:
            subs        = active_subblocks[i - 1]
            blk_events  = block_events_list[i - 1] if block_events_list else []
            _print_activity_breakdown(start, end, subs, active_rate, idle_gap, blk_events)
            grand_active_s += sum((e2 - s2).total_seconds() for s2, e2, *_ in subs)

    print()
    print("-" * 60)
    print(f"  Total blocks  : {len(blocks)}")
    print(f"  Total queries : {total_queries}")
    print(f"  Total active  : {fmt_duration(total_active_seconds)}")
    if active_subblocks is not None and total_active_seconds > 0:
        idle_s = total_active_seconds - grand_active_s
        pct    = grand_active_s / total_active_seconds * 100
        print(f"  Domain active : {fmt_duration(grand_active_s)}  ({pct:.0f}% of session)")
        print(f"  Domain idle   : {fmt_duration(idle_s)}")
    _print_filter_summary(bg_filtered, dropped_blocks, min_queries, bg_filter)
    print("=" * 60)
    print()


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Analyze AdGuard querylog.json for client activity blocks."
    )
    parser.add_argument(
        "ip",
        help="Client IP address to analyse (e.g. 192.168.88.23)"
    )
    parser.add_argument(
        "date",
        help="Date to analyse in YYYY-MM-DD format (e.g. 2025-11-30)"
    )
    parser.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help="Path to a JSON config file (default: adguard_config.json beside "
             "this script or in cwd)"
    )
    parser.add_argument(
        "--log",
        default=None,
        metavar="FILE",
        help="Path to querylog.json  (default: 'log' key in adguard_config.json; overrides config)"
    )
    parser.add_argument(
        "--gap",
        type=int,
        default=None,
        metavar="MINUTES",
        help=f"Inactivity gap in minutes that starts a new block "
             f"(default: {GAP_MINUTES}; overrides config)"
    )
    parser.add_argument(
        "--min-queries",
        type=int,
        default=None,
        metavar="N",
        dest="min_queries",
        help=f"Drop blocks with fewer than N queries after filtering "
             f"(default: {MIN_BLOCK_QUERIES}; overrides config)"
    )
    parser.add_argument(
        "--no-bg-filter",
        action="store_true",
        default=None,
        dest="no_bg_filter",
        help="Disable background-hostname filtering (overrides config bg_filter)"
    )
    parser.add_argument(
        "--domain", "-d",
        default=None,
        metavar="DOMAIN",
        help="Only count queries for this domain and its subdomains "
             "(e.g. roblox.com).  Implies --min-queries 1 and disables bg-filter."
    )
    parser.add_argument(
        "--active-rate",
        type=int,
        default=None,
        metavar="N",
        dest="active_rate",
        help=f"Queries/min threshold for 'active' in domain mode "
             f"(default: {DEFAULT_ACTIVE_RATE}; overrides config)"
    )
    parser.add_argument(
        "--idle-gap",
        type=int,
        default=None,
        metavar="MINS",
        dest="idle_gap",
        help=f"Consecutive idle minutes allowed inside an active sub-block "
             f"(default: {DEFAULT_IDLE_GAP}; overrides config)"
    )

    qf_group = parser.add_mutually_exclusive_group()
    qf_group.add_argument(
        "--only-allowed",
        action="store_true", dest="only_allowed",
        help="Count only queries that were allowed (not blocked) by AdGuard"
    )
    qf_group.add_argument(
        "--only-blocked",
        action="store_true", dest="only_blocked",
        help="Count only queries that were blocked by AdGuard"
    )

    args = parser.parse_args()

    # ── Load config ────────────────────────────────────────────────────────────
    cfg, cfg_path = load_config(args.config)

    # ── Resolve settings: CLI > config > hard-coded default ───────────────────
    log_file    = args.log         if args.log         is not None else cfg.get("log",         DEFAULT_LOG_FILE)
    gap         = args.gap         if args.gap         is not None else cfg.get("gap",         GAP_MINUTES)
    active_rate = args.active_rate if args.active_rate is not None else cfg.get("active_rate", DEFAULT_ACTIVE_RATE)
    idle_gap    = args.idle_gap    if args.idle_gap    is not None else cfg.get("idle_gap",    DEFAULT_IDLE_GAP)

    # --no-bg-filter (store_true, default=None) beats config; config beats True
    if args.no_bg_filter:
        bg_filter = False
    elif "bg_filter" in cfg:
        bg_filter = bool(cfg["bg_filter"])
    else:
        bg_filter = True

    # min_queries: CLI > config; domain mode defaults to 1 if not set anywhere
    if args.min_queries is not None:
        min_queries = args.min_queries
    elif "min_queries" in cfg:
        min_queries = cfg["min_queries"]
    elif args.domain:
        min_queries = 1
    else:
        min_queries = MIN_BLOCK_QUERIES

    # query_filter: --only-allowed / --only-blocked > config query_filter > "all"
    if args.only_allowed:
        query_filter = "allowed"
    elif args.only_blocked:
        query_filter = "blocked"
    else:
        qf = cfg.get("query_filter", "all")
        if qf in ("all", "allowed", "blocked"):
            query_filter = qf
        else:
            print(f"  [warn] Config: invalid query_filter {qf!r} – using 'all'",
                  file=sys.stderr)
            query_filter = "all"

    try:
        target_date = datetime.strptime(args.date, "%Y-%m-%d").date()
    except ValueError:
        print(f"Error: date '{args.date}' is not in YYYY-MM-DD format.",
              file=sys.stderr)
        sys.exit(1)

    if cfg_path:
        print(f"\nUsing config : {cfg_path}")

    if not log_file:
        print("Error: no log file specified.", file=sys.stderr)
        print("  Use --log /path/to/querylog.json  or set  \"log\": \"/path/to/querylog.json\"  in adguard_config.json",
              file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(log_file):
        print(f"Error: log file not found: {log_file}", file=sys.stderr)
        print("  Check the path and make sure the file exists.", file=sys.stderr)
        if log_file == cfg.get("log"):
            print(f"  (path came from config file: {cfg_path})", file=sys.stderr)
        else:
            print("  Tip: set the correct path with --log or via 'log' in adguard_config.json",
                  file=sys.stderr)
        sys.exit(1)

    print(f"Reading log  : {log_file}  (this may take a moment for large files)\u2026")
    events, bg_filtered, total_seen = collect_events(
        log_file, args.ip, target_date, bg_filter, args.domain, query_filter
    )
    blocks, dropped = build_blocks(events, gap, min_queries)

    # In domain mode compute per-block activity sub-blocks
    active_subblocks  = None
    block_events_list = None
    if args.domain and blocks:
        active_subblocks  = []
        block_events_list = []
        for (b_start, b_end, _) in blocks:
            be = [ts for ts in events if b_start <= ts <= b_end]
            block_events_list.append(be)
            active_subblocks.append(
                find_active_subblocks(be, active_rate, idle_gap)
            )

    print_report(
        args.ip, target_date, blocks, dropped, gap,
        bg_filtered, min_queries, bg_filter,
        domain=args.domain, total_seen=total_seen,
        active_subblocks=active_subblocks,
        active_rate=active_rate,
        idle_gap=idle_gap,
        block_events_list=block_events_list,
        query_filter=query_filter,
    )


if __name__ == "__main__":
    main()
