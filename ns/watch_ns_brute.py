#!/usr/bin/env python3
import sys, re, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.services import upsert_subdomain, upsert_lives
from database.selectors import get_program_by_scope

from tools import ns_brute

from utils import current_time


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else False

    if not domain:
        print(f"Usage: watch_ns_brute domain")
        sys.exit()

    program = get_program_by_scope(domain)

    if program:
        print(f"[{current_time()}] running ns_brute module for '{domain}'")
        subs = ns_brute(domain)
        for sub in subs:
            if re.search(r"\.\s*" + re.escape(domain), sub, re.IGNORECASE):
                upsert_subdomain(program.program_name, sub, "ns_brute")
                upsert_lives(domain=domain, subdomain=sub, ips=[], cdn="")
    else:
        print(f"[{current_time()}] scope for '{domain}' does not exist in watchtower")
