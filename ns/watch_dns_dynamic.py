#!/usr/bin/env python3
"""
watch_dns_dynamic.py -- dynamic (pattern-based) DNS bruteforce

Uses AlterX (ProjectDiscovery -- faster than dnsgen/altdns, same tool
family as dnsx/httpx already in use) to generate permutations from
already-known subdomains, resolves with puredns, then applies an extra
TTL + HTTP-body-hash wildcard check (ported from dynamic_dns_bruteforce.sh)
on top of puredns' own filtering, per the chosen approach.

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
from dns_brute_common import (
    log, send_telegram, run_puredns, run_httpx_quick, WORKDIR,
    collect_wildcard_signature, is_wildcard_match
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


def resolve_ip_with_ttl_hash_check(program_name, domain, new_names, signature):
    """dnsx for IP, then TTL+HTTP-hash wildcard cascade, then store."""
    import json

    if not new_names:
        return []

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
        if not host or not ips:
            continue

        if signature["ips"] and is_wildcard_match(host, ips[0], signature):
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

    resolved_file = WORKDIR / f"{domain}.dynamic.resolved.txt"
    resolved_names = run_puredns(candidates_file, resolved_file)
    log(f"{domain}: puredns resolved {len(resolved_names)} names")

    existing = set(known)
    new_names = [n for n in resolved_names if n not in existing]
    log(f"{domain}: {len(new_names)} genuinely new subdomains")

    if not new_names:
        mark_dynamic_run(domain)
        return 0

    log(f"{domain}: collecting wildcard signature for extra TTL+HTTP-hash check...")
    signature = collect_wildcard_signature(domain)

    for name in new_names:
        upsert_subdomain(program_name, name, "dynamicBF")

    confirmed_live = resolve_ip_with_ttl_hash_check(program_name, domain, new_names, signature)
    mark_dynamic_run(domain)

    if not confirmed_live:
        return 0

    httpx_results = run_httpx_quick(confirmed_live)
    lines = [f"NEW subdomains via dynamicBF -- {program_name} ({domain}): {len(confirmed_live)}"]
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
        lines.append(f"  - {r.get('url')} [{r.get('status_code')}] {r.get('title', '')}")

    send_telegram("\n".join(lines))
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

    total_new = 0
    processed = 0
    for program_name, domain in domains:
        if args.max_minutes and elapsed_minutes() >= args.max_minutes:
            log(f"Time budget hit after {processed} domains -- rest next run")
            break
        total_new += process_domain(program_name, domain)
        processed += 1

    log(f"=== Done | domains processed: {processed}/{len(domains)} | new live subdomains: {total_new} ===")


if __name__ == "__main__":
    main()