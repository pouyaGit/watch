#!/usr/bin/env python3
"""
watch_dns_dynamic.py -- dynamic (pattern-based) DNS bruteforce

Uses AlterX (ProjectDiscovery -- faster than dnsgen/altdns, same tool
family as dnsx/httpx already in use) to generate permutations from
already-known subdomains, resolves with puredns, then filters wildcards
with the same multi-level WildcardDetector used by watch_ns.py and
watch_dns_static.py (cascading per-level checks: *.sub.domain, *.domain,
etc.) -- NOT the single-level TTL+HTTP-hash check this used to have.

That single-level check was swapped out after it produced confirmed false
positives: a nested wildcard on *.ext-apply.qa.indeed.net (a level below
the domain root) wasn't caught by a root-only test, so a completely fake
subdomain resolved and returned the same 403 as the "discovered" ones.

NOTE: verify AlterX's exact flags with `alterx -h` on your server before
trusting this blindly -- CLI flags can differ between versions, same as we
found with x8 and fallparams earlier.

Resumable: --max-minutes stops cleanly, next run picks up the
least-recently-run domain first (DnsBruteStatus.last_dynamic_run).

Usage:
  python3 watch_dns_dynamic.py --max-minutes 180
  python3 watch_dns_dynamic.py --filter dell.com --max-minutes 20
"""

import sys
import os
import argparse
import subprocess
import time
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import Subdomains, upsert_subdomain, upsert_lives, upsert_http, mark_dynamic_run, get_feasible_domains_ordered
from utils.common import detect_cdn, normalize_ips
from wildcard_detector import WildcardDetector
from dns_brute_common import (
    log, send_telegram, run_puredns, run_httpx_quick, WORKDIR,
    estimate_minutes, count_lines
)

START_TIME = time.time()


def elapsed_minutes():
    return (time.time() - START_TIME) / 60


def run_alterx(known_subs_file, out_file):
    if subprocess.call(["which", "alterx"], stdout=subprocess.DEVNULL) != 0:
        log("alterx not found")
        return []
    cmd = f'alterx -l "{known_subs_file}" -o "{out_file}"'
    log(f"$ {cmd}")
    try:
        subprocess.run(cmd, shell=True, timeout=1800)
    except subprocess.TimeoutExpired:
        log(f"alterx timeout on {known_subs_file}")
    if not out_file.exists():
        return []
    return [l.strip() for l in out_file.read_text(errors="ignore").splitlines() if l.strip()]


def resolve_ip_and_store(program_name, domain, new_names):
    """dnsx for IP, then multi-level WildcardDetector (same one watch_ns.py
    and watch_dns_static.py use), then store."""
    import json

    if not new_names:
        return []

    detector = WildcardDetector(domain)
    tmp = WORKDIR / f"dyn_resolve_{domain}_{int(time.time())}.txt"
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
        if not host or not ips:
            continue

        if detector.is_wildcard(host, ips_set, preserve_private=True):
            log(f"  filtered as wildcard: {host}")
            continue

        upsert_lives({"subdomain": host, "domain": domain, "ips": ips, "cdn": detect_cdn(ips)})
        confirmed.append(host)

    return confirmed


def process_domain(program_name, domain):
    log(f"--- Dynamic bruteforce: {domain} ---")

    known = [s.subdomain for s in Subdomains.objects(scope=domain).only("subdomain")]
    if not known:
        log(f"{domain}: no known subdomains yet, skipping (need enum first)")
        return 0

    known_file = WORKDIR / f"{domain}.known.txt"
    known_file.write_text("\n".join(known))

    alterx_out = WORKDIR / f"{domain}.alterx.txt"
    candidates = run_alterx(known_file, alterx_out)
    log(f"{domain}: alterx generated {len(candidates)} candidates")
    if not candidates:
        mark_dynamic_run(domain)
        return 0

    candidates_file = WORKDIR / f"{domain}.dynamic.candidates.txt"
    candidates_file.write_text("\n".join(candidates))

    candidate_count = len(candidates)
    eta = estimate_minutes(candidate_count)
    send_telegram(
        f"Now bruteforcing {program_name} ({domain}) [dynamicBF]\n"
        f"Candidates: {candidate_count:,} | ETA: ~{eta} min"
    )

    resolved_file = WORKDIR / f"{domain}.dynamic.resolved.txt"
    resolved_names = run_puredns(candidates_file, resolved_file)
    log(f"{domain}: puredns resolved {len(resolved_names)} names")

    # clean up temp files -- same disk-fill risk as the static script
    for f in (known_file, alterx_out, candidates_file, resolved_file):
        try:
            f.unlink(missing_ok=True)
        except Exception as e:
            log(f"Could not remove {f}: {e}")

    existing = set(known)
    new_names = [n for n in resolved_names if n not in existing]
    log(f"{domain}: {len(new_names)} genuinely new subdomains")

    if not new_names:
        mark_dynamic_run(domain)
        send_telegram(
            f"Result -- {program_name} ({domain}) [dynamicBF]\n"
            f"Tested: {candidate_count:,} | Resolved: {len(resolved_names):,} | New: 0"
        )
        return 0

    for name in new_names:
        upsert_subdomain(program_name, name, "dynamicBF")

    confirmed_live = resolve_ip_and_store(program_name, domain, new_names)
    mark_dynamic_run(domain)

    result_lines = [
        f"Result -- {program_name} ({domain}) [dynamicBF]",
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

    domains = get_feasible_domains_ordered("last_dynamic_run")
    if args.filter:
        domains = [(p, d) for p, d in domains if args.filter.lower() in d.lower()]

    log(f"=== Dynamic DNS Bruteforce | {len(domains)} feasible domains | "
        f"max_minutes={args.max_minutes or 'unlimited'} ===")

    if domains:
        domain_list = "\n".join(f"  - {p} -> {d}" for p, d in domains)
        send_telegram(
            f"Starting dynamicBF run\n"
            f"Time budget: {args.max_minutes or 'unlimited'} min\n"
            f"Queued domains ({len(domains)}):\n{domain_list}"
        )
    else:
        send_telegram("dynamicBF run: no feasible domains queued (run watch_dns_precheck.py first)")
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
        f"dynamicBF run finished\n"
        f"Domains processed: {processed}/{len(domains)}\n"
        f"New live subdomains: {total_new}\n"
        f"Elapsed: {elapsed_minutes():.1f} min"
    )
    if remaining:
        summary += f"\n{remaining} domains left for next scheduled run"

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