#!/usr/bin/env python3
"""
watch_heavy_worker.py -- one serialized, always-on heavy worker.

Runs the three heavy lanes ONE AT A TIME, round-robin, forever:

    brute  ->  crawl  ->  param  ->  brute  -> ...

Each lane is given a bounded time slice (WATCH_HEAVY_LANE_MINUTES) and is driven
by the existing, resumable per-lane scripts, so a lane always picks up where it
left off and no lane starves the others:

  - brute : ns/watch_brute_worker.py   --max-minutes N   (fair round-robin over
            feasible domains, marks each at the start of its turn)
  - crawl : crawl/watch_crawl_all.py   --max-minutes N   (least-recently-crawled
            domain first)
  - param : crawl/watch_param_discovery.py --max-minutes N  (unchecked endpoints
            first, x8 at a polite rate)

Why one worker instead of three 24/7 services: the VPS is small (2 cores / 4 GB)
and param discovery is ACTIVE scanning. Serializing the heavy work keeps exactly
one heavy job running at any moment, bounds CPU/RAM/IO (via watch-heavy.slice in
the unit) and keeps the outbound scan footprint controlled, while still making
continuous progress on every lane.

Env knobs:
  WATCH_HEAVY_LANE_MINUTES  per-lane time slice   (default 20)
  WATCH_HEAVY_IDLE_SLEEP    sleep when a whole cycle found nothing to do (default 900)
  WATCH_HEAVY_LANES         comma list to restrict/reorder lanes (default brute,crawl,param)

Usage:
  python3 watch_heavy_worker.py                 # continuous (service default)
  python3 watch_heavy_worker.py --once          # one brute+crawl+param cycle, then exit
  python3 watch_heavy_worker.py --lane-minutes 10 --once   # quick test
"""
import os
import sys
import time
import argparse
import subprocess
from datetime import datetime

ROOT = "/opt/watch"
VENV_PY = "/opt/watch/venv/bin/python3"
sys.path.insert(0, ROOT)
from config import config  # noqa: E402

import requests  # noqa: E402


def _env_int(name, default):
    try:
        v = int(os.environ.get(name, ""))
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


DEFAULT_LANE_MIN = _env_int("WATCH_HEAVY_LANE_MINUTES", 20)
DEFAULT_IDLE_SLEEP = _env_int("WATCH_HEAVY_IDLE_SLEEP", 900)

# lane name -> argv (without the --max-minutes value, appended per run)
LANE_CMDS = {
    "brute": [VENV_PY, "ns/watch_brute_worker.py", "--max-minutes"],
    "crawl": [VENV_PY, "crawl/watch_crawl_all.py", "--max-minutes"],
    "param": [VENV_PY, "crawl/watch_param_discovery.py", "--max-minutes"],
}


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def send_telegram(text):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": text[:4000]}, timeout=30,
        )
    except Exception as exc:
        log(f"telegram error: {exc}")


def run_lane(name, lane_min):
    """Run one lane for up to lane_min minutes. Returns its wall-clock minutes.
    The per-lane script honours --max-minutes; a generous hard timeout is a
    safety net if one ever ignores it. One lane failing never stops the worker.
    """
    cmd = LANE_CMDS[name] + [str(lane_min)]
    log(f"--- lane '{name}' starting (budget {lane_min}m): {' '.join(cmd)}")
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, cwd=ROOT, timeout=lane_min * 60 + 300)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        rc = "HARD-TIMEOUT(killed)"
    except Exception as exc:
        rc = f"ERROR({exc})"
    mins = (time.time() - t0) / 60
    log(f"--- lane '{name}' done in {mins:.1f}m (rc={rc})")
    if isinstance(rc, str):  # hard-timeout or spawn error -> worth a ping
        send_telegram(f"HeavyWorker: lane '{name}' ended abnormally (rc={rc})")
    return mins


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true",
                        help="run one brute+crawl+param cycle, then exit")
    parser.add_argument("--lane-minutes", type=float, default=DEFAULT_LANE_MIN,
                        help="per-lane time slice in minutes")
    parser.add_argument("--idle-sleep", type=int, default=DEFAULT_IDLE_SLEEP,
                        help="sleep seconds when a whole cycle did ~nothing")
    args = parser.parse_args()

    lanes = [l.strip() for l in os.environ.get(
        "WATCH_HEAVY_LANES", "brute,crawl,param").split(",") if l.strip() in LANE_CMDS]
    if not lanes:
        lanes = ["brute", "crawl", "param"]

    log(f"=== Heavy worker starting | lanes={lanes} | lane_minutes={args.lane_minutes} "
        f"| mode={'once' if args.once else 'continuous'} ===")
    if not args.once:
        send_telegram(f"HeavyWorker started (24/7) -- lanes {'/'.join(lanes)}, "
                      f"{args.lane_minutes:g}m each")

    cycle = 0
    # A cycle where every lane returned almost immediately means there was
    # nothing to do anywhere; only then do we sleep (so new work is picked up
    # promptly without busy-spinning).
    near_instant = max(0.2, args.lane_minutes * 0.05)  # 5% of a slice
    while True:
        cycle += 1
        total = 0.0
        for name in lanes:
            total += run_lane(name, args.lane_minutes)
        log(f"=== Heavy cycle {cycle} complete: {total:.1f}m across {len(lanes)} lanes ===")

        if args.once:
            break
        if total <= near_instant * len(lanes):
            log(f"Whole cycle idle; sleeping {args.idle_sleep}s")
            time.sleep(args.idle_sleep)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Heavy worker interrupted -- exiting")
    except Exception as exc:
        try:
            send_telegram(f"HeavyWorker crashed: {exc}")
        except Exception:
            pass
        raise
