#!/usr/bin/env python3
"""
watch_digest.py -- one Telegram summary per day (watch-digest timer).

Counts what appeared since the previous digest: new subdomains, new live hosts,
new HTTP services and new findings by severity, per program. Routine re-sightings
of known assets are not counted, so the message stays short.

The state file is only advanced after Telegram accepts the message, so a failed
send is retried on the next run. A run within 20 hours of the last successful one
is skipped unless --force is given.

Usage:
  python3 scripts/watch_digest.py              # send the digest if one is due
  python3 scripts/watch_digest.py --dry-run    # print the message, send nothing
  python3 scripts/watch_digest.py --force      # send now regardless of last run

Env knobs:
  WATCH_DIGEST_WINDOW_HOURS  window when there is no previous run (default 24)
  WATCH_DIGEST_STATE         state file path (default logs/digest_state.json)
"""
import argparse
import html
import json
import os
import sys
from datetime import datetime, timedelta

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(ROOT)

from database.db import Finding, Http, LiveSubdomains, Subdomains  # noqa: E402
from database.telegram import send_message  # noqa: E402
from utils.recon import env_int, log  # noqa: E402

STATE_PATH = os.environ.get("WATCH_DIGEST_STATE") or os.path.join(ROOT, "logs", "digest_state.json")
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
MIN_GAP = timedelta(hours=20)
MAX_MESSAGE = 3900


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


def _count_by_program(collection, field, since):
    rows = collection._get_collection().aggregate([
        {"$match": {field: {"$gte": since}}},
        {"$group": {"_id": "$program_name", "n": {"$sum": 1}}},
    ])
    return {r["_id"]: r["n"] for r in rows}


def _findings_by_program(since):
    rows = Finding._get_collection().aggregate([
        {"$match": {"first_seen": {"$gte": since}}},
        {"$group": {"_id": {"program": "$program_name", "severity": "$severity"}, "n": {"$sum": 1}}},
    ])
    out = {}
    for r in rows:
        out.setdefault(r["_id"]["program"], {})[r["_id"]["severity"]] = r["n"]
    return out


def build_message(since, now):
    subs = _count_by_program(Subdomains, "created_date", since)
    lives = _count_by_program(LiveSubdomains, "created_date", since)
    https = _count_by_program(Http, "created_date", since)
    findings = _findings_by_program(since)

    programs = sorted(set(subs) | set(lives) | set(https) | set(findings))
    header = (
        f"Watch daily digest · {now:%Y-%m-%d %H:%M}\n"
        f"Window: {since:%Y-%m-%d %H:%M} to {now:%Y-%m-%d %H:%M}"
    )
    if not programs:
        return f"{header}\nNo new subdomains, live hosts, HTTP services or findings."

    lines = [header, ""]
    totals = {"subs": 0, "lives": 0, "https": 0}
    total_findings = {}
    for prog in programs:
        s, l, h = subs.get(prog, 0), lives.get(prog, 0), https.get(prog, 0)
        totals["subs"] += s
        totals["lives"] += l
        totals["https"] += h
        sev_parts = []
        for sev in SEVERITIES:
            n = findings.get(prog, {}).get(sev, 0)
            if n:
                sev_parts.append(f"{sev} {n}")
                total_findings[sev] = total_findings.get(sev, 0) + n
        sev_text = ", ".join(sev_parts) if sev_parts else "none"
        lines.append(f"{prog}: +{s} subdomains, +{l} live, +{h} HTTP | findings: {sev_text}")

    lines.append("")
    total_sev = ", ".join(f"{sev} {total_findings[sev]}" for sev in SEVERITIES if sev in total_findings) or "none"
    lines.append(f"Total: +{totals['subs']} subdomains, +{totals['lives']} live, "
                 f"+{totals['https']} HTTP | findings: {total_sev}")
    return "\n".join(lines)


def _truncate(text):
    if len(text) <= MAX_MESSAGE:
        return text
    return text[:MAX_MESSAGE - 20] + "\n... (truncated)"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    now = datetime.now()
    state = load_state()
    last_run = state.get("last_run")
    last_dt = datetime.fromisoformat(last_run) if last_run else None

    if last_dt and not args.force and not args.dry_run and now - last_dt < MIN_GAP:
        log(f"digest already sent at {last_dt:%Y-%m-%d %H:%M}; skipping")
        return

    default_hours = env_int("WATCH_DIGEST_WINDOW_HOURS", 24)
    since = last_dt or (now - timedelta(hours=default_hours))
    message = _truncate(build_message(since, now))

    if args.dry_run:
        print(message)
        return

    if not send_message(html.escape(message)):
        log("digest not delivered (Telegram send failed or token missing); state unchanged")
        return
    state["last_run"] = now.isoformat(timespec="seconds")
    save_state(state)
    log("digest sent")


if __name__ == "__main__":
    main()
