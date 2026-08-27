#!/usr/bin/env python3
import sys
import os
import json
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import *
from utils.common import (
    colors, current_time, run_command_in_zsh_common,
    create_temp_file, normalize_ips, detect_cdn
)
from wildcard_detector import WildcardDetector


# ---------- Main Resolver ----------
def dnsx(subdomains_array, domain):
    """Run dnsx on list, filter wildcard by IPs, and save live subdomains."""
    if not subdomains_array:
        return False

    temp_file_path = create_temp_file(subdomains_array)

    try:
        detector = WildcardDetector(domain)

        command = (
            f"dnsx -l {temp_file_path} -silent "
            "-a -resp -json -t 10 -rl 30 "
            "-r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222"
        )

        print(f"{colors.GRAY}[{current_time()}] Executing dnsx: {command}{colors.RESET}")
        results = run_command_in_zsh_common(command)

        in_count = len(subdomains_array)
        out_count = 0
        filtered = 0
        stored = 0

        for result in results:
            out_count += 1
            try:
                obj = json.loads(result)
            except Exception:
                continue

            host = obj.get("host") or obj.get("hostname")
            ips = normalize_ips(obj.get("a"))
            ips_set = set(ips)

            if detector.is_wildcard(host, ips_set, preserve_private=True):
                filtered += 1
                continue

            if host:
                upsert_lives({
                    "subdomain": host,
                    "domain": domain,
                    "ips": ips,
                    "cdn": detect_cdn(ips)
                })
                stored += 1

        print(
            f"{colors.GREEN}[{current_time()}] domain={domain} "
            f"in={in_count} dnsx_out={out_count} "
            f"wildcard_filtered={filtered} stored={stored}{colors.RESET}"
        )

        return True

    finally:
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    obj_subs = Subdomains.objects(scope=domain)

    if obj_subs:
        print(f"[{current_time()}] Running Dnsx for '{domain}'")
        dnsx([obj_sub.subdomain for obj_sub in obj_subs], domain)
    else:
        print(f"[{current_time()}] No subdomains for '{domain}'")
