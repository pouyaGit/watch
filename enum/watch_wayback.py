#!/usr/bin/env python3
import sys, os, re

# Add parent directory to sys.path for module imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database.db import *
from utils.common import run_command_in_zsh, colors, current_time

def wayback_scan(domain):
    # Build command: waybackurls -> unfurl domains -> sort unique
    command = f"waybackurls {domain} | unfurl domains | sort -u"
    print(f"{colors.GRAY}Executing commands: {command}{colors.RESET}")
    res = run_command_in_zsh(command)

    res_num = len(res) if res else 0
    print(f"{colors.GRAY}done for {domain}, results: {res_num}{colors.RESET}")

    return res

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else False

    if domain is False:
        print(f"Usage: watch_wayback domain")
        sys.exit()

    program = Programs.objects(scopes=domain).first()

    if program:
        print(f"[{current_time()}] running waybackurls module for '{domain}'")
        subs = wayback_scan(domain)

        for sub in subs:
            if sub == domain:
                continue
            if re.search(r'^\S+\.' + re.escape(domain), sub, re.IGNORECASE):
                upsert_subdomain(program.program_name, sub, "waybackurls")
    else:
        print(f"[{current_time()}] scope for '{domain}' does not exist in watch-tower")

#todo
 
# command:
# waybackurls icollab.info | unfurl domains | sort -u