#!/usr/bin/env python3
"""
watch_health.py -- watchdog for the Watch services. Runs from the watch-health timer.

Checks:
  - each systemd unit/timer in WATCH_HEALTH_UNITS is `active`
  - MongoDB answers a ping
  - each URL in WATCH_HEALTH_URLS answers without a 5xx

Alerts are per transition: one message when a check goes from ok to failing, one when
it recovers. A check that stays down does not repeat itself every run. State lives in
logs/health_state.json.

Usage:
  python3 scripts/watch_health.py            # run checks, alert on transitions
  python3 scripts/watch_health.py --dry-run  # print results, touch nothing

Env knobs:
  WATCH_HEALTH_UNITS    comma list of units/timers
                        (default watch-heavy.service,watch-ct-stream.service,watch.timer)
  WATCH_HEALTH_URLS     comma list of URLs to probe (default empty)
  WATCH_HEALTH_TIMEOUT  per-check timeout seconds (default 10)
  WATCH_HEALTH_STATE    state file path (default logs/health_state.json)
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(ROOT)

import requests  # noqa: E402

from database.db import Programs  # noqa: E402
from utils.recon import alert, env_int, log  # noqa: E402

STATE_PATH = os.environ.get("WATCH_HEALTH_STATE") or os.path.join(ROOT, "logs", "health_state.json")
DEFAULT_UNITS = "watch-heavy.service,watch-ct-stream.service,watch.timer"


def _csv(name, default=""):
    return [v.strip() for v in os.environ.get(name, default).split(",") if v.strip()]


def check_units(units, timeout_s):
    results = {}
    for unit in units:
        try:
            proc = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True, text=True, timeout=timeout_s,
            )
            state = proc.stdout.strip() or "unknown"
        except subprocess.TimeoutExpired:
            state = "timeout"
        results[f"unit:{unit}"] = (state == "active", state)
    return results


def check_mongo():
    try:
        Programs._get_db().command("ping")
        return True, "ok"
    except Exception as exc:  # noqa: BLE001 -- any failure is a DOWN signal
        return False, type(exc).__name__


def check_urls(urls, timeout_s):
    results = {}
    for url in urls:
        try:
            resp = requests.get(url, timeout=timeout_s, allow_redirects=True)
            results[f"url:{url}"] = (resp.status_code < 500, f"HTTP {resp.status_code}")
        except requests.RequestException as exc:
            results[f"url:{url}"] = (False, type(exc).__name__)
    return results


def load_state():
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except ValueError:
        return {}


def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, STATE_PATH)


def evaluate(results, state, now):
    alerts = 0
    for name, (ok, detail) in results.items():
        prev = state.get(name, {"ok": True, "alerted": False, "since": now})
        was_ok = prev.get("ok", True)
        alerted = prev.get("alerted", False)
        since = prev.get("since", now) if was_ok == ok else now

        if not ok and was_ok:
            alert(f"[health] DOWN · {name} · {detail}")
            alerts += 1
            alerted = True
        elif ok and not was_ok and alerted:
            alert(f"[health] RECOVERED · {name} · {detail}")
            alerts += 1
            alerted = False

        state[name] = {"ok": ok, "detail": detail, "since": since, "alerted": alerted}
        log(f"{name}: {'ok' if ok else 'DOWN'} ({detail})")
    return alerts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    timeout_s = env_int("WATCH_HEALTH_TIMEOUT", 10)
    results = {}
    results.update(check_units(_csv("WATCH_HEALTH_UNITS", DEFAULT_UNITS), timeout_s))
    results["mongo:ping"] = check_mongo()
    results.update(check_urls(_csv("WATCH_HEALTH_URLS"), timeout_s))

    if args.dry_run:
        for name, (ok, detail) in results.items():
            print(f"{'ok  ' if ok else 'DOWN'} {name} ({detail})")
        return

    state = load_state()
    now = datetime.now().isoformat(timespec="seconds")
    sent = evaluate(results, state, now)
    save_state(state)
    log(f"=== health: {sum(1 for ok, _ in results.values() if not ok)} down, {sent} alerts sent ===")


if __name__ == "__main__":
    main()
