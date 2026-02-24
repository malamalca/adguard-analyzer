#!/usr/bin/env python3
"""
AdGuard DNS Query Log - Top Domains Analyzer
Reports the N most-queried domains for a given client IP on a given date,
excluding background / keep-alive traffic.
"""

import json
import re
import sys
import argparse
import os
from collections import Counter
from datetime import datetime, date, timedelta


# ── Configuration ──────────────────────────────────────────────────────────────
DEFAULT_LOG_FILE = None   # no built-in default; use --log or set 'log' in adguard_config.json
DEFAULT_TOP_N    = 10

# ── Background / keep-alive hostname patterns (same as adguard_activity.py) ───
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




# ── Helpers ────────────────────────────────────────────────────────────────────
def is_background(hostname: str) -> bool:
    return any(rx.search(hostname) for rx in _BG_COMPILED)


def is_blocked(entry: dict) -> bool:
    """Return True if AdGuard filtered/blocked this query."""
    result = entry.get("Result", {})
    return bool(result) and result.get("IsFiltered", False)


def parse_ts(ts_str: str) -> datetime:
    """Parse ISO-8601 timestamp that may carry a UTC-offset (+HH:MM).

    Handles both sub-second precision (e.g. '2025-12-20T08:05:52.123456+01:00')
    and whole-second timestamps (e.g. '2025-12-20T08:05:52+01:00').
    """
    ts_str = ts_str.strip()
    if len(ts_str) > 6 and ts_str[-3] == ":" and ts_str[-6] in ("+", "-"):
        ts_str = ts_str[:-3] + ts_str[-2:]
    try:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S%z")


def root_domain(hostname: str) -> str:
    """Return the registrable root domain (last two labels) of a hostname.

    Examples:
        cdn.roblox.com        → roblox.com
        www.google.com        → google.com
        s3.eu-west-1.amazonaws.com → amazonaws.com
        localhost             → localhost
    """
    parts = hostname.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


# ── Core ───────────────────────────────────────────────────────────────────────
def collect_domain_counts(
    log_file: str,
    client_ip: str,
    target_date: date,
    bg_filter: bool = True,
    group_subdomains: bool = True,
    query_filter: str = "all",   # "all" | "allowed" | "blocked"
) -> tuple[Counter, Counter, int, int]:
    """Stream the log and count queried hostnames for the given IP/date.

    query_filter controls which entries are counted:
      "all"     – both allowed and blocked queries
      "allowed" – only queries that were NOT blocked by AdGuard
      "blocked" – only queries that WERE blocked by AdGuard

    Returns:
        (hostname_counts, root_counts, total_raw, bg_filtered_count)
    """
    hostname_counts: Counter = Counter()
    root_counts:     Counter = Counter()
    total_raw    = 0
    bg_filtered  = 0

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
                continue

            if ts.date() != target_date:
                continue

            total_raw += 1

            # ── allowed / blocked filter ──
            if query_filter == "allowed" and is_blocked(entry):
                continue
            if query_filter == "blocked" and not is_blocked(entry):
                continue

            hostname = entry.get("QH", "").lower().rstrip(".")

            if bg_filter and is_background(hostname):
                bg_filtered += 1
                continue

            hostname_counts[hostname] += 1
            if group_subdomains:
                root_counts[root_domain(hostname)] += 1

    return hostname_counts, root_counts, total_raw, bg_filtered


# ── Output ─────────────────────────────────────────────────────────────────────
def print_report(
    client_ip: str,
    target_date: date,
    hostname_counts: Counter,
    root_counts: Counter,
    total_raw: int,
    bg_filtered: int,
    top_n: int,
    bg_filter: bool,
    group_subdomains: bool,
    show_subdomains: bool,
    query_filter: str = "all",
):
    total_filtered = sum(hostname_counts.values())
    bar_max        = 30   # max bar width in characters

    print()
    print("=" * 70)
    print(f"  AdGuard Top-Domains Report")
    print(f"  Client IP  : {client_ip}")
    print(f"  Date       : {target_date.strftime('%Y-%m-%d (%A)')}")
    print(f"  Top        : {top_n}")
    if query_filter != "all":
        print(f"  Queries    : {query_filter} only")
    if bg_filter:
        pct_bg = bg_filtered / total_raw * 100 if total_raw else 0
        print(f"  BG filter  : on  ({bg_filtered} of {total_raw} queries removed, {pct_bg:.0f}%)")
    else:
        print(f"  BG filter  : off")
    print(f"  Grouping   : {'by root domain' if group_subdomains else 'exact hostname'}")
    print(f"  Queries    : {total_filtered} counted  ({total_raw} total)")
    print("=" * 70)

    counts = root_counts if group_subdomains else hostname_counts
    top    = counts.most_common(top_n)

    if not top:
        print("\n  No queries found for this IP on the selected date.\n")
        return

    # Column widths
    rank_w   = len(str(top_n)) + 1
    domain_w = max(len(d) for d, _ in top)
    domain_w = max(domain_w, 20)
    count_w  = len(str(top[0][1]))

    header = (f"  {'#':<{rank_w}}  {'Domain':<{domain_w}}  "
              f"{'Queries':>{count_w}}   {'% of total':>10}   Bar")
    print(f"\n{header}")
    print("  " + "-" * (len(header) - 2 + bar_max))

    for rank, (domain, count) in enumerate(top, 1):
        pct      = count / total_filtered * 100 if total_filtered else 0
        bar_len  = round(pct / 100 * bar_max)
        bar      = "█" * bar_len
        print(f"  {rank:<{rank_w}}  {domain:<{domain_w}}  "
              f"{count:>{count_w}}   {pct:>9.1f}%   {bar}")

        # Optionally show subdomain breakdown
        if show_subdomains and group_subdomains and domain in root_counts:
            subs = [(h, c) for h, c in hostname_counts.items()
                    if root_domain(h) == domain and h != domain]
            subs.sort(key=lambda x: -x[1])
            for sub_host, sub_count in subs[:5]:   # cap at 5 per root
                sub_pct = sub_count / count * 100
                print(f"  {'':{rank_w}}    {'↳ ' + sub_host:<{domain_w}}  "
                      f"{sub_count:>{count_w}}   {sub_pct:>9.1f}%")
            if len(subs) > 5:
                rest = sum(c for _, c in subs[5:])
                print(f"  {'':{rank_w}}    {'↳ … and ' + str(len(subs) - 5) + ' more':<{domain_w}}  "
                      f"{rest:>{count_w}}")

    print()
    print("-" * 70)
    # Coverage: what % of total queries does the top-N account for?
    top_total = sum(c for _, c in top)
    coverage  = top_total / total_filtered * 100 if total_filtered else 0
    print(f"  Top {top_n} coverage : {top_total} queries  ({coverage:.1f}% of filtered total)")
    print(f"  Distinct domains  : {len(counts)}")
    print("=" * 70)
    print()


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Show top queried domains for a client IP on a given date."
    )
    parser.add_argument("ip",   help="Client IP address (e.g. 192.168.88.20)")
    parser.add_argument("date", help="Date in YYYY-MM-DD format")
    parser.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help="Path to a JSON config file (default: adguard_config.json beside "
             "this script or in cwd)"
    )
    parser.add_argument(
        "--log", default=None, metavar="FILE",
        help="Path to querylog.json (default: 'log' key in adguard_config.json; overrides config)"
    )
    parser.add_argument(
        "--top", "-n", type=int, default=None, metavar="N", dest="top_n",
        help=f"Number of top domains to show (default: {DEFAULT_TOP_N}; overrides config)"
    )
    parser.add_argument(
        "--no-bg-filter", action="store_true", default=None, dest="no_bg_filter",
        help="Disable background-hostname filtering (overrides config bg_filter)"
    )
    parser.add_argument(
        "--exact", action="store_true",
        help="Count exact hostnames instead of grouping subdomains under their root domain"
    )
    parser.add_argument(
        "--show-subdomains", action="store_true", dest="show_subdomains",
        help="Under each root domain also list the top contributing subdomains"
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
    log_file = args.log   if args.log   is not None else cfg.get("log",   DEFAULT_LOG_FILE)
    top_n    = args.top_n if args.top_n is not None else cfg.get("top_n", DEFAULT_TOP_N)

    # --no-bg-filter (store_true, default=None) beats config; config beats True
    if args.no_bg_filter:
        bg_filter = False
    elif "bg_filter" in cfg:
        bg_filter = bool(cfg["bg_filter"])
    else:
        bg_filter = True

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

    group_subdomains = not (args.exact or cfg.get("exact", False))
    show_subdomains   = args.show_subdomains or cfg.get("show_subdomains", False)

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
    hostname_counts, root_counts, total_raw, bg_filtered = collect_domain_counts(
        log_file, args.ip, target_date, bg_filter, group_subdomains, query_filter
    )

    print_report(
        args.ip, target_date,
        hostname_counts, root_counts,
        total_raw, bg_filtered,
        top_n, bg_filter,
        group_subdomains, show_subdomains,
        query_filter=query_filter,
    )


if __name__ == "__main__":
    main()
