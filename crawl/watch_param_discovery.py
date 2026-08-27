#!/usr/bin/env python3
"""
watch_param_discovery.py -- Hidden Parameter Discovery with x8, on unique endpoints

Why Endpoints and not Urls?
Urls is full-URL level (with query) and has 800k+ records -- running x8 on all of
them is both pointless (testing the same path repeatedly with different query
values) and would exhaust server resources. Endpoints is path-level unique
(after migration/crawl updates) -- far fewer targets.

Usage:
  python3 watch_param_discovery.py --max-minutes 180
  python3 watch_param_discovery.py --filter dell.com --max-minutes 20   # test
"""

import os
import sys
import json
import time
import argparse
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import requests

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config
from database.db import Endpoints

WORDLIST = os.getenv(
    "X8_WORDLIST",
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
)
# If SecLists isn't installed, build a small wordlist yourself or override
# the path with: export X8_WORDLIST=/opt/watch/wordlists/params_base.txt

WORDLIST_DIR = Path("/opt/watch/wordlists")
WORDLIST_DIR.mkdir(parents=True, exist_ok=True)

X8_TIMEOUT = 60            # seconds, per endpoint
X8_RATE_LIMIT_DELAY = 0.5  # delay between x8 targets, gentle on the server
CHECKPOINT_EVERY = 200     # send one Telegram progress ping every N endpoints,
                           # not per-endpoint -- avoids the notification spam
                           # you already ran into with upsert_lives

START_TIME = time.time()


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def elapsed_minutes():
    return (time.time() - START_TIME) / 60


def send_telegram(text):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": text[:4000]},
            timeout=30
        )
    except Exception as e:
        log(f"Telegram error: {e}")


def get_wordlist_for_program(program_name):
    """Just the base (burp) wordlist for now -- there's no per-program extra
    source anymore (fallparams was tried and dropped). Kept as a function
    (not a bare constant) so a future per-program source can slot back in
    without touching call sites."""
    return WORDLIST


def run_x8(url, wordlist_path):
    """
    Run x8 on a URL, return the list of discovered params.
    Parses x8's JSON output; verify exact flags with `x8 --help` since they
    can differ across versions.
    """
    if subprocess.call(["which", "x8"], stdout=subprocess.DEVNULL) != 0:
        log("x8 not found in PATH")
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        "x8",
        "-u", url,
        "-w", wordlist_path,
        "-O", "json",
        "-o", out_path,
        "-c", "5",           # concurrency per url (default 1 was too slow for 82k endpoints)
        "-W", "1",            # concurrent urls -- keep at 1, server is resource-limited
        "--timeout", "10",
        "--verify",           # re-verifies found params, fewer false positives
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=X8_TIMEOUT)
    except subprocess.TimeoutExpired:
        log(f"x8 timeout: {url}")
        return []
    except Exception as e:
        log(f"x8 error on {url}: {e}")
        return []

    params = set()
    try:
        with open(out_path, "r", errors="ignore") as f:
            data = json.load(f)
        # x8's actual format: [{"method":..,"url":..,"status":..,"found_params":[...],"injection_place":..}]
        if isinstance(data, list):
            for item in data:
                for p in item.get("found_params", []):
                    params.add(p)
        elif isinstance(data, dict):
            for p in data.get("found_params", []):
                params.add(p)
    except Exception:
        log(f"Could not parse x8 JSON output for {url} -- check manually: {out_path}")
        return []
    finally:
        try:
            os.remove(out_path)
        except Exception:
            pass

    return sorted(params)


def get_pending_endpoints(filter_arg=None, limit=None):
    query = Endpoints.objects(x8_checked=False)
    if filter_arg:
        f = filter_arg.lower()
        query = query.filter(subdomain__icontains=f)
    query = query.order_by('-hit_count')  # highest-traffic endpoints first
    if limit:
        query = query[:limit]
    return list(query)


def export_wordlists():
    """Write one wordlist file per program from discovered params."""
    programs = Endpoints.objects.distinct("program_name")
    saved = []
    for prog in programs:
        params = set()
        for ep in Endpoints.objects(program_name=prog).only("params"):
            params.update(ep.params or [])
        if not params:
            continue
        out_file = WORDLIST_DIR / f"{prog}_params.txt"
        out_file.write_text("\n".join(sorted(params)) + "\n")
        log(f"Wordlist saved: {out_file} ({len(params)} params)")
        saved.append(f"  - {prog}: {len(params)} params")
    return saved


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filter", default=None, help="only this subdomain/keyword")
    parser.add_argument("--max-minutes", type=float, default=None)
    parser.add_argument("--limit", type=int, default=None, help="max endpoints this run")
    args = parser.parse_args()

    if not os.path.exists(WORDLIST):
        log(f"Wordlist not found: {WORDLIST} -- set a valid one before continuing (env: X8_WORDLIST)")
        return

    log(f"=== Param Discovery Started | filter={args.filter or 'NONE'} | "
        f"max_minutes={args.max_minutes or 'unlimited'} ===")

    endpoints = get_pending_endpoints(args.filter, args.limit)
    log(f"Pending endpoints: {len(endpoints)}")

    send_telegram(
        f"Starting paramDiscovery run\n"
        f"Time budget: {args.max_minutes or 'unlimited'} min\n"
        f"Pending endpoints: {len(endpoints)}"
    )

    checked = 0
    found_total = 0

    for ep in endpoints:
        if args.max_minutes and elapsed_minutes() >= args.max_minutes:
            log(f"Time budget hit after {checked} endpoints -- rest next run")
            break

        if not ep.example_url:
            continue

        new_params = run_x8(ep.example_url, get_wordlist_for_program(ep.program_name))
        if new_params:
            merged = sorted(set((ep.params_from_x8 or []) + new_params))
            ep.params_from_x8 = merged
            ep.params = sorted(set((ep.params or []) + merged))
            found_total += len(new_params)
            log(f"[+] {ep.example_url} -> {new_params}")

        ep.x8_checked = True
        ep.x8_last_checked = datetime.now()
        ep.last_update = datetime.now()
        ep.save()

        checked += 1
        if checked % CHECKPOINT_EVERY == 0:
            send_telegram(
                f"paramDiscovery progress: {checked}/{len(endpoints)} checked, "
                f"{found_total} new params found so far"
            )
        time.sleep(X8_RATE_LIMIT_DELAY)

    log(f"=== Done | Endpoints checked: {checked} | New params found: {found_total} ===")

    wordlist_summary = export_wordlists()

    remaining = len(endpoints) - checked
    summary = (
        f"paramDiscovery run finished\n"
        f"Endpoints checked: {checked}/{len(endpoints)}\n"
        f"New params found: {found_total}\n"
        f"Elapsed: {elapsed_minutes():.1f} min"
    )
    if remaining:
        summary += f"\n{remaining} endpoints left for next scheduled run"
    if wordlist_summary:
        summary += "\n\nWordlists updated:\n" + "\n".join(wordlist_summary)

    log(summary)
    send_telegram(summary)


if __name__ == "__main__":
    main()