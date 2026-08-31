#!/usr/bin/env python3
"""
watch_dns_precheck.py -- Step 1 of the DNSBrute flowchart

Checks whether a random, nonexistent subdomain (e.g. xk3f9d81jd.domain.tld)
resolves to an A record. If it does, the domain has a blanket wildcard and
bruteforcing it is pointless (everything will resolve). If not, the domain
is a good bruteforce candidate.

Reuses the existing get_wildcard_ips() from wildcard_detector.py (dnsx-based,
same resolvers/rate-limit as the rest of the pipeline) instead of reimplementing
wildcard detection from scratch.

Resumable, just like watch_crawl_all.py:
- Domains are checked least-recently-checked first (DnsBruteStatus.last_checked).
- --max-minutes lets it stop cleanly and pick up where it left off next run.
- Results are stored in DnsBruteStatus (feasible=True/False), which is what
  watch_dns_static.py / watch_dns_dynamic.py read to know which domains to run on.

Usage:
  python3 ns/watch_dns_precheck.py --max-minutes 60
  python3 watch_dns_precheck.py --filter dell.com --max-minutes 10
"""

import sys
import os
import argparse
import time
from datetime import datetime

import requests

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config
from database.db import Programs, DnsBruteStatus, upsert_dns_brute_status
from wildcard_detector import get_wildcard_ips

START_TIME = time.time()


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def elapsed_minutes():
    return (time.time() - START_TIME) / 60


def send_telegram(text):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        log("Telegram not configured")
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": text[:4000]},
            timeout=30
        )
    except Exception as e:
        log(f"Telegram error: {e}")


def get_ordered_domains(filter_arg=None):
    """(program_name, domain) pairs, least-recently-checked first (never-checked first)."""
    pairs = []
    for p in Programs.objects().only("program_name", "scopes"):
        for domain in (p.scopes or []):
            if filter_arg and filter_arg.lower() not in domain.lower():
                continue
            pairs.append((p.program_name, domain))

    statuses = {s.domain: s.last_checked for s in DnsBruteStatus.objects().only("domain", "last_checked")}
    pairs.sort(key=lambda pd: statuses.get(pd[1], datetime.min))
    return pairs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filter", default=None, help="only domains containing this substring")
    parser.add_argument("--max-minutes", type=float, default=None)
    args = parser.parse_args()

    pairs = get_ordered_domains(args.filter)
    log(f"=== DNS Bruteforce Feasibility Check | {len(pairs)} domains | "
        f"max_minutes={args.max_minutes or 'unlimited'} ===")

    checked, feasible_list, infeasible_list = [], [], []
    skipped = []

    for program_name, domain in pairs:
        if args.max_minutes and elapsed_minutes() >= args.max_minutes:
            skipped.append(f"{program_name} -> {domain}")
            continue

        wildcard_ips = get_wildcard_ips(domain, num_tests=3)
        feasible = len(wildcard_ips) == 0

        upsert_dns_brute_status(program_name, domain, feasible, wildcard_ips)
        checked.append(domain)

        label = f"{program_name} -> {domain}"
        if feasible:
            feasible_list.append(label)
            log(f"[ok] {domain} -- can bruteforce")
        else:
            infeasible_list.append(label)
            log(f"[wildcard] {domain} -- cannot bruteforce ({len(wildcard_ips)} wildcard IPs)")

    lines = [f"DNS Bruteforce Feasibility Check ({len(checked)}/{len(pairs)} domains this run)"]
    if feasible_list:
        lines.append("\nBruteforce-able:")
        lines += [f"  - {d}" for d in feasible_list]
    if infeasible_list:
        lines.append("\nBlocked by blanket wildcard:")
        lines += [f"  - {d}" for d in infeasible_list]
    if skipped:
        lines.append(f"\nTime budget hit -- {len(skipped)} domains left for next run:")
        lines += [f"  - {d}" for d in skipped]

    msg = "\n".join(lines)
    log(msg)
    send_telegram(msg)


if __name__ == "__main__":
    from backend.task_report import mark_finished
    try:
        main()
        mark_finished("success", 0)
    except Exception:
        mark_finished("failed", 1)
        raise