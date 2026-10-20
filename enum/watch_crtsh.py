#!/usr/bin/env python3
import sys, os, psycopg2, re, requests, random, time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'database')))
from database.db import *
from utils.common import run_command_in_zsh, colors, current_time

def crtsh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    }

    # crt.sh is frequently overloaded (502/503/504) and rate-limits (429); a
    # single attempt returns 0 far too often (observed 502 then 429 back to
    # back). Retry with growing backoff on every transient failure -- timeouts,
    # connection errors and 429/5xx -- so a busy crt.sh degrades to "slower",
    # not "no data". A genuine non-retryable status still returns [].
    RETRYABLE = {429, 500, 502, 503, 504}
    MAX_ATTEMPTS = 5
    r = None
    try:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            if attempt == 1:
                time.sleep(random.uniform(1.5, 3.0))  # gentle initial jitter
            try:
                r = requests.get(url, headers=headers, timeout=30)
            except (requests.Timeout, requests.ConnectionError) as exc:
                if attempt == MAX_ATTEMPTS:
                    print(f"[{current_time()}] crt.sh network error after {attempt} attempts: {exc}")
                    return []
                wait = min(30, 3 * attempt) + random.uniform(0, 2)
                print(f"[{current_time()}] crt.sh {type(exc).__name__} (attempt {attempt}) — retry in {wait:.0f}s")
                time.sleep(wait)
                continue

            if r.status_code == 200:
                break
            if r.status_code in RETRYABLE and attempt < MAX_ATTEMPTS:
                wait = min(30, 3 * attempt) + random.uniform(0, 2)
                print(f"[{current_time()}] crt.sh HTTP {r.status_code} (attempt {attempt}) — retry in {wait:.0f}s")
                time.sleep(wait)
                continue
            print(f"[{current_time()}] crt.sh HTTP Error: {r.status_code} (attempt {attempt})")
            return []

        if r is None or r.status_code != 200:
            return []

        data = r.json()

        subdomains = set()
        domain_lower = domain.lower()

        for entry in data:
            name_value = entry.get("name_value", "")
            # این خط خیلی مهمه!
            names = [n.strip().lower() for n in name_value.split("\n") if n.strip()]
            
            for name in names:
                if name.startswith("*."):
                    name = name[2:]

                if name == domain_lower:
                    continue

                if name.endswith("." + domain_lower):  # بهتره از . + استفاده کنیم
                    subdomains.add(name)

        print(f"[+] Found {len(subdomains)} subdomains from crt.sh for {domain}")
        return sorted(subdomains)

    except Exception as e:
        print(f"[{current_time()}] Error: {e}")
        return []

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else 1
    
    if domain is False:
        print(f"Usage: watch_crtsh domain")
        sys.exit()

    program = Programs.objects(scopes=domain).first()

    if program:
        print(f"[{current_time()}] running Crtsh module for '{domain}'")
        subs = crtsh(domain)
        # todo: save in file

        # save in watchtower database
        for sub in subs:
            upsert_subdomain(program.program_name, sub, "crtsh")
    else:
        print(f"[{current_time()}] scope for '{domain}' does not exist in watchtower")