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
from urllib.parse import urlsplit, urlunsplit

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

def build_x8_target_url(url):
    """
    Build a stable x8 target from an endpoint example URL.

    Discovery should run against the endpoint path itself, not against
    previously observed query values. Query parameters are discovered
    separately by x8.
    """
    try:
        parsed = urlsplit(url)
        if not parsed.scheme or not parsed.netloc:
            return url

        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path or "/",
                "",
                "",
            )
        )
    except Exception:
        return url

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
    Run x8 on a URL, return raw discovery records.

    Returns a list of dicts preserving the per-discovery
    provenance emitted by x8:
        {"name": str, "method": str, "injection_place": str}

    Injection-place → internal location mapping happens in
    :func:`map_x8_location`, NOT here, so the raw values stay
    inspectable. Parses x8's JSON output; verify exact flags
    with `x8 --help` since they can differ across versions.
    Compatible with x8 4.3.1-main (the installed version).
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
        "-c", "8",           # concurrency per url (bumped from 5 -- most of the slowdown was
                             # wasted time on low-value duplicate endpoints, not raw x8 speed)
        "-W", "2",            # concurrent urls -- bumped from 1; watch memory (free -h) on the
                             # next scheduled run and drop back to 1 if the 4GB box struggles
        "--timeout", "10",
        "--verify",           # re-verifies found params, fewer false positives
        # Discover hidden parameters across GET, POST and PUT.
        # x8 sends parameters in the body only for POST/PUT and in
        # the query for GET (verified against x8 4.3.1-main's CLI).
        "-X", "GET", "POST", "PUT", "PATCH",
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=X8_TIMEOUT)
    except subprocess.TimeoutExpired:
        log(f"x8 timeout: {url}")
        return []
    except Exception as e:
        log(f"x8 error on {url}: {e}")
        return []

    records = []
    try:
        with open(out_path, "r", errors="ignore") as f:
            data = json.load(f)
        # x8 JSON format: [{"method":..,"url":..,"status":..,
        #   "found_params":[{"name":..,..}],"injection_place":
        #   "Query|Body|Path|Headers|HeaderValue"}]
        # found_params items are dicts with a "name" key in x8
        # 4.3.1; older formats may emit bare name strings.
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            # Never invent a default HTTP method: a missing method or
            # a missing injection_place means we cannot attribute the
            # finding, so the whole item is discarded rather than
            # silently downgraded to GET/query.
            method = (item.get("method") or "").strip().upper()
            place = (item.get("injection_place") or "").strip()
            if not method or not place:
                continue
            for p in item.get("found_params", []):
                name = p.get("name") if isinstance(p, dict) else p
                if not name:
                    continue
                records.append(
                    {
                        "name": str(name),
                        "method": method,
                        "injection_place": place,
                    }
                )
    except Exception:
        log(f"Could not parse x8 JSON output for {url} -- check manually: {out_path}")
        return []
    finally:
        try:
            os.remove(out_path)
        except Exception:
            pass

    return records


def map_x8_location(injection_place, method):
    """
    Map x8's injection_place label to the internal location
    vocabulary ("query" | "body"); return None for anything
    unsupported so it never becomes an XSS case.

    Compatible mapping for the installed x8 4.3.1-main:

    - ``Query`` -> query
    - ``Body`` -> body
    - ``Path`` with method GET -> query
      In x8 4.3.1 the default ``-u <url>`` template injects
      GET parameters into the URL query string but LABELS the
      injection point "Path" (empirically verified against the
      installed binary). With our invocation the GET injection
      point is always the query string, so GET/"Path" means
      query. Non-GET "Path", "Headers", "HeaderValue" and any
      unknown value are deliberately NOT converted.
    """
    place = (injection_place or "").strip().lower()
    method = (method or "").strip().upper()

    if place == "query":
        return "query"
    if place == "body":
        return "body"
    if place == "path" and method == "GET":
        return "query"
    return None


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

        x8_target = build_x8_target_url(ep.example_url)
        log(
            f"[x8] program={ep.program_name} "
            f"endpoint={ep.example_url} "
            f"target={x8_target}"
        )
        raw_records = run_x8(
            x8_target,
            get_wordlist_for_program(ep.program_name)
        )

        if raw_records:
            # Map x8 injection places to our internal vocabulary.
            # Unsupported places (Headers/HeaderValue/non-GET Path/...)
            # are dropped here and never become cases.
            new_records = []
            seen = {
                (
                    rec.get("name"),
                    rec.get("method"),
                    rec.get("location"),
                    rec.get("source"),
                )
                for rec in (ep.param_records or [])
                if isinstance(rec, dict)
            }
            for rec in raw_records:
                location = map_x8_location(
                    rec.get("injection_place"), rec.get("method")
                )
                if location is None:
                    continue
                name = (rec.get("name") or "").strip()
                method = (rec.get("method") or "").strip().upper()
                if not name or not method:
                    continue
                key = (name, method, location, "x8")
                if key in seen:
                    continue
                seen.add(key)
                new_records.append(
                    {
                        "name": name,
                        "method": method,
                        "location": location,
                        "source": "x8",
                    }
                )

            if new_records:
                ep.param_records = list((ep.param_records or [])) + new_records
                new_x8_names = sorted({
                    r["name"]
                    for r in new_records
                })

                ep.params_from_x8 = sorted(
                    set(ep.params_from_x8 or []) | set(new_x8_names)
                )

                ep.params = sorted(
                    set(ep.params or []) | set(new_x8_names)
                )

                found_total += len(new_x8_names)

                log(
                    f"[+] {ep.example_url} -> "
                    f"new={new_x8_names} "
                    f"total_x8={len(ep.params_from_x8)}"
                )

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
    from backend.task_report import mark_finished
    try:
        main()
        mark_finished("success", 0)
    except Exception:
        mark_finished("failed", 1)
        raise