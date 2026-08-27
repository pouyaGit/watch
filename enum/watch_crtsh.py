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

    try:
        # تأخیر تصادفی برای جلوگیری از بلاک شدن
        time.sleep(random.uniform(1.5, 3.0))

        r = requests.get(url, headers=headers, timeout=20)

        if r.status_code == 429:
            print(f"[{current_time()}] Got 429 — retrying...")
            # یک بار دیگه با تأخیر امتحان می‌کنیم
            time.sleep(random.uniform(3, 5))
            r = requests.get(url, headers=headers, timeout=20)

        if r.status_code != 200:
            print(f"[{current_time()}] HTTP Error: {r.status_code}")
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