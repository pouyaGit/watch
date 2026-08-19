#!/usr/bin/env python3
import os, sys, re
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import *
from utils.common import run_command_in_zsh, colors, current_time

def findomain(domain):
    # -q = quiet mode (فقط ساب‌دامین‌ها رو چاپ می‌کنه)
    command = f"findomain -t {domain} -q"
    print(f"{colors.GRAY}Executing command: {command}{colors.RESET}")
    res = run_command_in_zsh(command)
    
    res_num = len(res) if res else 0
    print(f"{colors.GRAY}done for {domain}, results: {res_num}{colors.RESET}")
    
    return res if res else []

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else False

    if domain is False:
        print(f"Usage: watch_findomain domain")
        sys.exit(1)

    program = Programs.objects(scopes=domain).first()

    if program:
        print(f"[{current_time()}] Running Findomain module for '{domain}'")
        subs = findomain(domain)

        for sub in subs:
            sub = sub.strip().lower()
            if not sub:
                continue
            # فقط ساب‌دامین‌هایی که واقعاً متعلق به دامنه هستن
            if re.search(r'\.' + re.escape(domain) + r'$', sub, re.IGNORECASE) or sub == domain:
                upsert_subdomain(program.program_name, sub, "findomain")
    else:
        print(f"[{current_time()}] scope for '{domain}' does not exist in watchtower")