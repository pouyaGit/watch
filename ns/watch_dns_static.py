#!/usr/bin/env python3
"""
watch_dns_static.py -- static wordlist DNS bruteforce

Reuses the exact wordlist strategy from static.sh (assetnote lists + crunch
1-4 chars, cached after first download) and puredns with the same tuned
flags. Only runs on domains marked feasible=True by watch_dns_precheck.py.

Resumable: --max-minutes stops cleanly, next run picks up the
least-recently-run domain first (DnsBruteStatus.last_static_run).

Usage:
  python3 ns/watch_dns_static.py --max-minutes 300
  python3 watch_dns_static.py --filter dell.com --max-minutes 20
"""

import sys
import os
import argparse
import subprocess
import time
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import upsert_subdomain, upsert_lives, upsert_http, mark_static_run, get_feasible_domains_ordered
from utils.common import detect_cdn, normalize_ips
from wildcard_detector import WildcardDetector
from dns_brute_common import (
    log, send_telegram, run_puredns, run_httpx_quick, WORKDIR,
    estimate_minutes, count_lines
)

START_TIME = time.time()
MERGED_WORDLIST = WORKDIR / "static-merged.txt"


def elapsed_minutes():
    return (time.time() - START_TIME) / 60


def ensure_static_wordlist():
    """Download + merge once, cache like dynamic.sh already does."""
    if MERGED_WORDLIST.exists():
        log(f"Using cached static wordlist: {MERGED_WORDLIST}")
        return

    log("Downloading assetnote wordlists...")
    best = WORKDIR / "best-dns-wordlist.txt"
    two_m = WORKDIR / "2m-subdomains.txt"
    subprocess.run(["curl", "-fsSL", "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt", "-o", str(best)])
    subprocess.run(["curl", "-fsSL", "https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt", "-o", str(two_m)])

    crunch_out = WORKDIR / "4-lower.txt"
    if not crunch_out.exists():
        subprocess.run(f'crunch 1 4 abcdefghijklmnopqrstuvwxyz1234567890 > "{crunch_out}"', shell=True)

    subprocess.run(
        f'cat "{best}" "{two_m}" "{crunch_out}" | sort -u > "{MERGED_WORDLIST}"',
        shell=True
    )
    log(f"Static wordlist ready: {MERGED_WORDLIST}")


def resolve_ip_and_store(program_name, domain, new_names):
    """dnsx + WildcardDetector for IP/CDN, store to LiveSubdomains, then quick httpx."""
    import json

    if not new_names:
        return []

    detector = WildcardDetector(domain)
    tmp = WORKDIR / f"resolve_{domain}_{int(time.time())}.txt"
    tmp.write_text("\n".join(new_names))

    cmd = (
        f'dnsx -l "{tmp}" -silent -a -resp -json -t 10 -rl 30 '
        "-r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222"
    )
    proc = subprocess.run(["zsh", "-c", cmd], capture_output=True, text=True)
    tmp.unlink(missing_ok=True)

    confirmed = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = obj.get("host") or obj.get("hostname")
        ips = normalize_ips(obj.get("a"))
        ips_set = set(ips)

        if detector.is_wildcard(host, ips_set, preserve_private=True):
            continue

        if host:
            upsert_lives({"subdomain": host, "domain": domain, "ips": ips, "cdn": detect_cdn(ips)})
            confirmed.append(host)

    return confirmed


def process_domain(program_name, domain):
    log(f"--- Static bruteforce: {domain} ---")
    ensure_static_wordlist()

    candidates_file = WORKDIR / f"{domain}.static.txt"
    subprocess.run(
        f'awk -v d="{domain}" \'{{print $0"."d}}\' "{MERGED_WORDLIST}" > "{candidates_file}"',
        shell=True
    )

    candidate_count = count_lines(candidates_file)
    eta = estimate_minutes(candidate_count)
    send_telegram(
        f"Now bruteforcing {program_name} ({domain}) [staticBF]\n"
        f"Candidates: {candidate_count:,} | ETA: ~{eta} min"
    )

    resolved_file = WORKDIR / f"{domain}.static.resolved.txt"
    resolved_names = run_puredns(candidates_file, resolved_file)
    log(f"{domain}: puredns resolved {len(resolved_names)} names")

    from database.db import Subdomains
    existing = {s.subdomain for s in Subdomains.objects(scope=domain).only("subdomain")}
    new_names = [n for n in resolved_names if n not in existing]
    log(f"{domain}: {len(new_names)} genuinely new subdomains")

    for name in new_names:
        upsert_subdomain(program_name, name, "staticBF")

    confirmed_live = resolve_ip_and_store(program_name, domain, new_names)
    mark_static_run(domain)

    result_lines = [
        f"Result -- {program_name} ({domain}) [staticBF]",
        f"Tested: {candidate_count:,} | Resolved: {len(resolved_names):,} | "
        f"New: {len(new_names)} | Confirmed live (post-wildcard-filter): {len(confirmed_live)}",
    ]

    if not confirmed_live:
        send_telegram("\n".join(result_lines))
        return 0

    httpx_results = run_httpx_quick(confirmed_live)
    for r in httpx_results:
        upsert_http({
            "subdomain": r.get("host") or r.get("input"),
            "scope": domain,
            "ips": r.get("a", []),
            "tech": r.get("tech", []),
            "title": r.get("title"),
            "status_code": r.get("status_code"),
            "headers": r.get("header", {}),
            "url": r.get("url"),
            "final_url": r.get("final_url", r.get("url")),
            "favicon": r.get("favicon_md5") or r.get("favicon"),
        })
        result_lines.append(f"  - {r.get('url')} [{r.get('status_code')}] {r.get('title', '')}")

    send_telegram("\n".join(result_lines))
    return len(confirmed_live)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filter", default=None)
    parser.add_argument("--max-minutes", type=float, default=None)
    args = parser.parse_args()

    domains = get_feasible_domains_ordered("last_static_run")
    if args.filter:
        domains = [(p, d) for p, d in domains if args.filter.lower() in d.lower()]

    log(f"=== Static DNS Bruteforce | {len(domains)} feasible domains | "
        f"max_minutes={args.max_minutes or 'unlimited'} ===")

    if domains:
        domain_list = "\n".join(f"  - {p} -> {d}" for p, d in domains)
        send_telegram(
            f"Starting staticBF run\n"
            f"Time budget: {args.max_minutes or 'unlimited'} min\n"
            f"Queued domains ({len(domains)}):\n{domain_list}"
        )
    else:
        send_telegram("staticBF run: no feasible domains queued (run watch_dns_precheck.py first)")
        return

    total_new = 0
    processed = 0
    for program_name, domain in domains:
        if args.max_minutes and elapsed_minutes() >= args.max_minutes:
            log(f"Time budget hit after {processed} domains -- rest next run")
            break
        total_new += process_domain(program_name, domain)
        processed += 1

    remaining = len(domains) - processed
    summary = (
        f"staticBF run finished\n"
        f"Domains processed: {processed}/{len(domains)}\n"
        f"New live subdomains: {total_new}\n"
        f"Elapsed: {elapsed_minutes():.1f} min"
    )
    if remaining:
        summary += f"\n{remaining} domains left for next scheduled run"

    log(summary)
    send_telegram(summary)


if __name__ == "__main__":
    main()