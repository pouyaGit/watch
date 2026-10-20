#!/usr/bin/env python3
"""watch_certspotter.py -- keyless subdomain enumeration (replaces abuseipdb).

The old watch_abuseipdb.py scraped abuseipdb.com/whois, which requires a
logged-in session cookie (the code shipped the placeholder "YOUR-SESSION", so
it always 403'd -- it never worked). There is no keyless way to read that page.

This module gets the same kind of data from two reliable, keyless sources and
needs no API key and no cookie:
  - certspotter CT logs  (provider tag: certspotter) -- confirmed working
  - AlienVault OTX passive DNS (provider tag: otx)   -- best-effort, skipped on
    rate-limit/error so one source being down never zeroes the other.

Both are fetched with retry/backoff on timeouts and 429/5xx.
"""
import sys, os, time, random, requests
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import *
from utils.common import colors, current_time

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
RETRYABLE = {429, 500, 502, 503, 504}


def _get_json(url, label, timeout=25, attempts=4):
    """GET JSON with backoff on transient failures. Returns parsed JSON or None
    (None = source unavailable; caller treats it as 0 results from that source,
    never as an error that aborts the other source)."""
    for i in range(1, attempts + 1):
        try:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout)
        except (requests.Timeout, requests.ConnectionError) as exc:
            if i == attempts:
                print(f"[{current_time()}] {label} network error after {i} attempts: {exc}")
                return None
            time.sleep(min(20, 3 * i) + random.uniform(0, 2))
            continue
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                print(f"[{current_time()}] {label} returned non-JSON")
                return None
        if r.status_code in RETRYABLE and i < attempts:
            print(f"[{current_time()}] {label} HTTP {r.status_code} (attempt {i}) — retrying")
            time.sleep(min(20, 3 * i) + random.uniform(0, 2))
            continue
        print(f"[{current_time()}] {label} HTTP {r.status_code}")
        return None
    return None


def _clean(name, domain_lower):
    name = (name or "").strip().lower().lstrip("*.").rstrip(".")
    if name and name != domain_lower and name.endswith("." + domain_lower):
        return name
    return None


def certspotter(domain):
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           f"&include_subdomains=true&expand=dns_names")
    data = _get_json(url, "certspotter") or []
    dl = domain.lower()
    subs = set()
    for entry in data:
        for n in entry.get("dns_names", []):
            c = _clean(n, dl)
            if c:
                subs.add(c)
    print(f"[+] Found {len(subs)} subdomains from certspotter for {domain}")
    return subs


def otx(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    data = _get_json(url, "otx")
    dl = domain.lower()
    subs = set()
    for entry in (data or {}).get("passive_dns", []) or []:
        c = _clean(entry.get("hostname"), dl)
        if c:
            subs.add(c)
    print(f"[+] Found {len(subs)} subdomains from OTX passive DNS for {domain}")
    return subs


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else False
    if domain is False:
        print("Usage: watch_certspotter domain")
        sys.exit(1)

    program = Programs.objects(scopes=domain).first()
    if not program:
        print(f"[{current_time()}] scope for '{domain}' does not exist in watchtower")
        sys.exit(0)

    print(f"[{current_time()}] running certspotter/OTX module for '{domain}'")
    for sub in certspotter(domain):
        upsert_subdomain(program.program_name, sub, "certspotter")
    for sub in otx(domain):
        upsert_subdomain(program.program_name, sub, "otx")
