#!/usr/bin/env python3
"""
watch_heavy_worker.py -- one serialized, always-on heavy worker.

Runs the heavy lanes ONE AT A TIME, round-robin, forever:

    brute  ->  crawl  ->  param  ->  nuclei  ->  brute  -> ...

Each lane is given a bounded time slice (WATCH_HEAVY_LANE_MINUTES) and is driven
by the existing, resumable per-lane scripts, so a lane always picks up where it
left off and no lane starves the others:

  - brute : ns/watch_brute_worker.py   --max-minutes N   (fair round-robin over
            feasible domains, marks each at the start of its turn)
  - crawl : crawl/watch_crawl_all.py   --max-minutes N   (least-recently-crawled
            domain first)
  - param : crawl/watch_param_discovery.py --max-minutes N  (unchecked endpoints
            first, x8 at a polite rate)
  - nuclei: nuclei/watch_nuclei_run.py --max-minutes N  (subdomain takeover pass,
            then never-scanned / stalest live services)
  - secret: secret/watch_secret_run.py --max-minutes N  (opt-in: JS bundles, redacted
            secret matches)
  - ffuf  : content/watch_ffuf_run.py --max-minutes N  (opt-in: bounded content
            discovery on live hosts)

Why one worker instead of three 24/7 services: the VPS is small (2 cores / 4 GB)
and param discovery is ACTIVE scanning. Serializing the heavy work keeps exactly
one heavy job running at any moment, bounds CPU/RAM/IO (via watch-heavy.slice in
the unit) and keeps the outbound scan footprint controlled, while still making
continuous progress on every lane.

Live status and control (shared with the dashboard, see backend/task_runner.py):
  logs/heavy_state.json    current lane, target, paused / hold flags
  logs/heavy_control.json  last command: skip | pause | resume | stop-after-lane

Env knobs:
  WATCH_HEAVY_LANE_MINUTES  per-lane time slice   (default 20)
  WATCH_HEAVY_IDLE_SLEEP    sleep when a whole cycle found nothing to do (default 900)
  WATCH_HEAVY_LANES         comma list to restrict/reorder lanes (default brute,crawl,nuclei).
                            secret and ffuf are opt-in: add them here to enable them.

Usage:
  python3 watch_heavy_worker.py                 # continuous (service default)
  python3 watch_heavy_worker.py --once          # one pass over the configured lanes, then exit
  python3 watch_heavy_worker.py --lane-minutes 10 --once   # quick test
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

ROOT = "/opt/watch"
VENV_PY = "/opt/watch/venv/bin/python3"
STATE_PATH = os.path.join(ROOT, "logs", "heavy_state.json")
CONTROL_PATH = os.path.join(ROOT, "logs", "heavy_control.json")
sys.path.insert(0, ROOT)
from config import config  # noqa: E402

import requests  # noqa: E402

HARD_GRACE_SECONDS = 300
KILL_GRACE_SECONDS = 10
STATE_REFRESH_SECONDS = 10
TICK_SECONDS = 1


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
    "nuclei": [VENV_PY, "nuclei/watch_nuclei_run.py", "--max-minutes"],
    "secret": [VENV_PY, "secret/watch_secret_run.py", "--max-minutes"],
    "ffuf": [VENV_PY, "content/watch_ffuf_run.py", "--max-minutes"],
}

# lane name -> (regex on a log line, extractor returning the target)
TARGET_PATTERNS = {
    "brute": (re.compile(r"--- Brute turn: (\S+) -> (\S+) \("), lambda m: m.group(2)),
    "crawl": (re.compile(r"--- Crawling (\S+) \("), lambda m: m.group(1)),
    "param": (re.compile(r"\[x8\] program=\S+ endpoint=(\S+)"),
              lambda m: urlparse(m.group(1)).hostname),
    "nuclei": (re.compile(r"--- Nuclei (?:takeover pass|batch): (\S+)"), lambda m: m.group(1)),
    "secret": (re.compile(r"--- Secret scan: (\S+)"), lambda m: m.group(1)),
    "ffuf": (re.compile(r"--- ffuf host: (\S+)"), lambda m: m.group(1)),
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


def _write_json(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    os.replace(tmp, path)


def read_control():
    try:
        with open(CONTROL_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _signal_group(pid, sig):
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        pass


def _group_alive(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _kill_group(proc):
    # SIGCONT first so a SIGSTOPped group can receive SIGTERM.
    _signal_group(proc.pid, signal.SIGCONT)
    _signal_group(proc.pid, signal.SIGTERM)
    deadline = time.monotonic() + KILL_GRACE_SECONDS
    while time.monotonic() < deadline:
        proc.poll()
        if not _group_alive(proc.pid):
            return
        time.sleep(0.5)
    _signal_group(proc.pid, signal.SIGKILL)
    proc.wait()


class Heavy:
    def __init__(self):
        self.lock = threading.Lock()
        self.proc = None
        self.lane = None
        self.target = None
        self.since = None
        self.cycle = 0
        self.paused = False
        self.hold = False
        self.skip_requested = False
        self.dirty = True
        self.last_write = 0.0
        # Commands left over from before this start are not replayed.
        self.seen_at = read_control().get("at")

    def begin_lane(self, name):
        with self.lock:
            self.lane = name
            self.target = None
            self.since = datetime.now().isoformat(timespec="seconds")
            self.paused = False
            self.skip_requested = False
            self.dirty = True

    def end_lane(self):
        with self.lock:
            self.lane = self.target = self.since = None
            self.paused = False
            self.skip_requested = False
            self.dirty = True

    def clear(self):
        self.end_lane()
        with self.lock:
            self.hold = False
        self.tick()

    def tick(self):
        with self.lock:
            if not self.dirty and time.monotonic() - self.last_write < STATE_REFRESH_SECONDS:
                return
            _write_json(STATE_PATH, {
                "lane": self.lane,
                "target": self.target,
                "since": self.since,
                "cycle": self.cycle,
                "paused": self.paused,
                "hold_after_lane": self.hold,
                "updated_at": datetime.now().isoformat(timespec="seconds"),
            })
            self.dirty = False
            self.last_write = time.monotonic()

    def apply(self, command):
        with self.lock:
            running = self.proc is not None and self.proc.poll() is None
            if command == "stop-after-lane":
                self.hold = True
            elif command == "resume":
                self.hold = False
                if running and self.paused:
                    _signal_group(self.proc.pid, signal.SIGCONT)
                    self.paused = False
            elif command == "pause" and running and not self.paused:
                _signal_group(self.proc.pid, signal.SIGSTOP)
                self.paused = True
            elif command == "skip" and running:
                self.skip_requested = True
            else:
                return
            self.dirty = True
        log(f"control: {command}")

    def poll_control(self):
        data = read_control()
        at = data.get("at")
        if at and at != self.seen_at:
            self.seen_at = at
            self.apply(data.get("command"))

    def _pump(self, proc, name):
        regex, extract = TARGET_PATTERNS[name]
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            match = regex.search(line)
            if not match:
                continue
            target = extract(match)
            if target:
                with self.lock:
                    if self.proc is proc:
                        self.target = target
                        self.dirty = True

    def supervise(self, proc, name, budget):
        """Watch one lane process. `budget` counts only unpaused seconds."""
        with self.lock:
            self.proc = proc
        pump = threading.Thread(target=self._pump, args=(proc, name), daemon=True)
        pump.start()
        active = 0.0
        last = time.monotonic()
        while True:
            time.sleep(TICK_SECONDS)
            now = time.monotonic()
            with self.lock:
                if not self.paused:
                    active += now - last
            last = now
            self.poll_control()
            if proc.poll() is not None:
                rc = proc.returncode
                break
            if self.skip_requested:
                _kill_group(proc)
                rc = "SKIPPED"
                break
            if active >= budget:
                _kill_group(proc)
                rc = "HARD-TIMEOUT(killed)"
                break
            self.tick()
        pump.join(timeout=5)
        with self.lock:
            self.proc = None
            self.paused = False
            self.skip_requested = False
        return rc

    def idle(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.poll_control()
            self.tick()
            time.sleep(TICK_SECONDS)

    def wait_while_held(self):
        if self.hold:
            log("holding after lane (stop-after-lane); send resume to continue")
        while self.hold:
            self.poll_control()
            self.tick()
            time.sleep(TICK_SECONDS)


def run_lane(heavy, name, lane_min):
    """Run one lane for up to lane_min minutes. Returns its wall-clock minutes.
    The per-lane script honours --max-minutes; a generous hard timeout (counted
    without paused time) is a safety net if one ever ignores it. One lane failing
    never stops the worker.
    """
    cmd = LANE_CMDS[name] + [str(lane_min)]
    log(f"--- lane '{name}' starting (budget {lane_min}m): {' '.join(cmd)}")
    heavy.begin_lane(name)
    t0 = time.time()
    try:
        proc = subprocess.Popen(
            cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
            start_new_session=True, env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
    except Exception as exc:
        rc = f"ERROR({exc})"
    else:
        rc = heavy.supervise(proc, name, lane_min * 60 + HARD_GRACE_SECONDS)
    mins = (time.time() - t0) / 60
    heavy.end_lane()
    heavy.tick()
    log(f"--- lane '{name}' done in {mins:.1f}m (rc={rc})")
    # A hard-timeout is an expected, benign cutoff for continuous resumable work:
    # the lane used its whole slice and resumes next rotation -- log it, don't
    # alarm. Only a genuine spawn failure (ERROR) is worth a Telegram ping.
    if isinstance(rc, str) and rc.startswith("ERROR"):
        send_telegram(f"HeavyWorker: lane '{name}' failed to start (rc={rc})")
    return mins


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true",
                        help="run one cycle over the configured lanes, then exit")
    parser.add_argument("--lane-minutes", type=float, default=DEFAULT_LANE_MIN,
                        help="per-lane time slice in minutes")
    parser.add_argument("--idle-sleep", type=int, default=DEFAULT_IDLE_SLEEP,
                        help="sleep seconds when a whole cycle did ~nothing")
    args = parser.parse_args()

    lanes = [l.strip() for l in os.environ.get(
        "WATCH_HEAVY_LANES", "brute,crawl,nuclei").split(",") if l.strip() in LANE_CMDS]
    if not lanes:
        lanes = ["brute", "crawl", "nuclei"]

    log(f"=== Heavy worker starting | lanes={lanes} | lane_minutes={args.lane_minutes} "
        f"| mode={'once' if args.once else 'continuous'} ===")
    if not args.once:
        send_telegram(f"HeavyWorker started (24/7) -- lanes {'/'.join(lanes)}, "
                      f"{args.lane_minutes:g}m each")

    heavy = Heavy()
    cycle = 0
    # A cycle where every lane returned almost immediately means there was
    # nothing to do anywhere; only then do we sleep (so new work is picked up
    # promptly without busy-spinning).
    near_instant = max(0.2, args.lane_minutes * 0.05)  # 5% of a slice
    try:
        while True:
            cycle += 1
            heavy.cycle = cycle
            total = 0.0
            for name in lanes:
                heavy.wait_while_held()
                total += run_lane(heavy, name, args.lane_minutes)
            log(f"=== Heavy cycle {cycle} complete: {total:.1f}m across {len(lanes)} lanes ===")

            if args.once:
                break
            if total <= near_instant * len(lanes):
                log(f"Whole cycle idle; sleeping {args.idle_sleep}s")
                heavy.idle(args.idle_sleep)
            heavy.wait_while_held()
    finally:
        heavy.clear()


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
