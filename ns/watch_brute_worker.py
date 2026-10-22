#!/usr/bin/env python3
"""
watch_brute_worker.py -- continuous (24/7) DNS bruteforce worker

Replaces the old "watch-brute.timer fires every 20 min with a 7-minute budget"
model, which had three structural faults:

  1. Starvation -- domains were ordered by last_static_run but only marked on
     *completion*. A domain whose brute never finished inside the budget (e.g.
     dell.com: ~13M candidates / ~26 min) kept last_static_run=None, so it was
     always picked first and no other domain (indeed.*) ever ran.
  2. The 7-minute budget was only checked *between* domains, so it never
     interrupted the one oversized domain that consumed every run.
  3. Re-firing every 20 minutes re-started the same domain from scratch and
     re-sent the same Telegram banners -> spam.

This worker instead walks every feasible domain in round-robin order, fairly:

  - order by least-recently-worked (max of last_static_run / last_dynamic_run);
  - MARK THE DOMAIN AT THE START of its turn, so a slow or crashing domain moves
    to the back of the queue immediately and never starves the others;
  - run static + dynamic for that one domain to completion (no mid-domain
    budget -- this is a 24/7 worker, thoroughness is the point);
  - move to the next least-recently-worked domain;
  - once every domain is within the cooldown window, sleep until the oldest
    becomes eligible again, then keep going -- forever.

Whether there is 1 target or 10, domains are bruteforced one after another and
each is revisited about once per cooldown.

Telegram is quiet by design: per-domain progress banners are suppressed (set
WATCH_BRUTE_VERBOSE=1 to restore them); only genuine new findings, errors, and
a once-per-cycle heartbeat are sent.

Usage:
  python3 ns/watch_brute_worker.py                 # continuous (service default)
  python3 ns/watch_brute_worker.py --once          # one pass over eligible domains, then exit
  python3 ns/watch_brute_worker.py --filter indeed # only domains matching substring
  python3 ns/watch_brute_worker.py --cooldown-hours 12 --idle-sleep 600
"""

import sys
import os
import argparse
import time
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import (
    get_feasible_domains_brute_ordered, mark_static_run, mark_dynamic_run,
)
from dns_brute_common import log, send_telegram, require_tools

import watch_dns_static
import watch_dns_dynamic


def _env_int(name, default):
    try:
        v = int(os.environ.get(name, ""))
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


DEFAULT_COOLDOWN_HOURS = _env_int("WATCH_BRUTE_COOLDOWN_HOURS", 12)
DEFAULT_IDLE_SLEEP = _env_int("WATCH_BRUTE_IDLE_SLEEP", 600)


def process_one_domain(program_name, domain):
    """Run static then dynamic for a single domain. Marks the domain at the
    start (fairness) and returns the count of newly confirmed-live subdomains.
    Never raises: a failure on one domain must not kill the worker."""
    # Mark first: even if this turn crashes or runs long, the domain goes to the
    # back of the round-robin queue and cannot starve the others.
    mark_static_run(domain)
    mark_dynamic_run(domain)

    new_live = 0
    for label, module in (("staticBF", watch_dns_static), ("dynamicBF", watch_dns_dynamic)):
        try:
            result = module.process_domain(program_name, domain)
            if isinstance(result, int):
                new_live += result
        except Exception as exc:
            log(f"{domain}: {label} FAILED -- {exc}")
            send_telegram(f"BruteWorker: {label} FAILED on {program_name} ({domain}): {exc}")
    return new_live


def run_pass(filter_arg, cooldown, mark_only_eligible=True, deadline=None):
    """Process every currently-eligible domain once, oldest first.

    Returns (processed, total_new, seconds_until_next_eligible_or_None).
    A domain is eligible when it was last worked more than `cooldown` ago (or
    never). When nothing is eligible, returns the wait until the oldest becomes
    eligible so the caller can sleep instead of busy-looping.

    `deadline` (time.monotonic seconds) time-boxes the pass: once reached, it
    stops between domains and returns. Used by the heavy worker to give the
    brute lane a bounded slice before rotating to crawl/param.
    """
    rows = get_feasible_domains_brute_ordered()
    if filter_arg:
        rows = [r for r in rows if filter_arg.lower() in r[1].lower()]

    if not rows:
        return 0, 0, None  # nothing feasible yet (run watch_dns_precheck.py)

    now = datetime.now()
    cutoff = now - cooldown
    processed = 0
    total_new = 0

    for program_name, domain, last_worked in rows:
        if deadline is not None and time.monotonic() >= deadline:
            log(f"Brute time budget reached after {processed} domain(s) -- yielding")
            return processed, total_new, None
        if mark_only_eligible and last_worked is not None and last_worked > cutoff:
            # rows are sorted oldest-first, so the first fresh one means the
            # rest are fresh too: report how long until it becomes eligible.
            wait = (last_worked + cooldown - now).total_seconds()
            return processed, total_new, max(1, wait)
        log(f"--- Brute turn: {program_name} -> {domain} "
            f"(last worked: {last_worked or 'never'}) ---")
        total_new += process_one_domain(program_name, domain)
        processed += 1

    return processed, total_new, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filter", default=None,
                        help="only domains whose name contains this substring")
    parser.add_argument("--once", action="store_true",
                        help="process all currently-eligible domains once, then exit")
    parser.add_argument("--cooldown-hours", type=float, default=DEFAULT_COOLDOWN_HOURS,
                        help="minimum hours between brute runs of the same domain")
    parser.add_argument("--idle-sleep", type=int, default=DEFAULT_IDLE_SLEEP,
                        help="seconds to sleep when every domain is within cooldown")
    parser.add_argument("--max-minutes", type=float, default=None,
                        help="time-box the run (implies a single bounded pass); "
                             "used by the heavy worker's brute lane")
    args = parser.parse_args()

    cooldown = timedelta(hours=args.cooldown_hours)
    # --max-minutes bounds a single pass and exits (lane mode for the heavy
    # worker). Without it, behaviour is unchanged (--once = one full pass,
    # otherwise continuous).
    deadline = time.monotonic() + args.max_minutes * 60 if args.max_minutes else None
    bounded = args.once or args.max_minutes is not None

    # Preflight once: the tools every turn needs. Missing binaries abort the
    # worker loudly instead of marking every domain as a failed turn forever.
    require_tools(["puredns", "dnsx", "alterx"])

    log(f"=== Brute worker starting | mode={'bounded' if bounded else 'continuous'} "
        f"| cooldown={args.cooldown_hours}h | idle_sleep={args.idle_sleep}s "
        f"| filter={args.filter or 'none'} | max_minutes={args.max_minutes or 'none'} ===")
    # Only the standalone continuous service announces itself; the heavy worker
    # invokes this as a bounded lane repeatedly, which would spam Telegram.
    if not bounded:
        send_telegram(f"BruteWorker started (24/7) -- cooldown {args.cooldown_hours}h")

    cycle = 0
    while True:
        cycle += 1
        started = time.time()
        processed, total_new, wait = run_pass(args.filter, cooldown, deadline=deadline)

        if processed:
            summary = (
                f"BruteWorker cycle {cycle}: {processed} domain(s) bruteforced, "
                f"{total_new} new live subdomain(s), "
                f"{(time.time() - started) / 60:.1f} min"
            )
            log(summary)
            # Heartbeat only when something was actually processed; keep it to
            # one line per cycle (findings themselves are sent per-domain).
            send_telegram(summary)

        if bounded:
            if not processed and wait is None:
                log("No feasible domains (run watch_dns_precheck.py first)")
            break

        if processed == 0:
            # Everything is within cooldown (or nothing feasible). Sleep until
            # the oldest domain is eligible again, bounded by idle_sleep so a
            # newly-added target is still picked up promptly.
            nap = args.idle_sleep if wait is None else min(args.idle_sleep, int(wait))
            log(f"All domains fresh (or none feasible); sleeping {nap}s")
            time.sleep(max(1, nap))


if __name__ == "__main__":
    try:
        from backend.task_report import mark_finished
    except Exception:
        def mark_finished(*a, **k):
            pass
    try:
        main()
        mark_finished("success", 0)
    except KeyboardInterrupt:
        log("Brute worker interrupted -- exiting")
    except Exception as exc:
        try:
            send_telegram(f"BruteWorker crashed: {exc}")
        except Exception:
            pass
        mark_finished("failed", 1)
        raise
