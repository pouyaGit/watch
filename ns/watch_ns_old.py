#!/usr/bin/env python3
import sys
import os
import json
import tempfile
from datetime import datetime
import subprocess
import random
import string
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import *


def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- Utils ----------
class colors:
    GRAY = "\033[90m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"


def run_command_in_zsh(command):
    try:
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[{current_time()}] Error: {result.stderr.strip()}")
            return []
        return result.stdout.splitlines()
    except Exception as e:
        print(f"[{current_time()}] Exception: {e}")
        return []


def create_temp_file(subdomains_array):
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as temp_file:
        for sub in subdomains_array:
            temp_file.write(f"{sub}\n")
        return temp_file.name

def normalize_ips(value):
    """Normalize dnsx 'a' field into a list of IP strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [ip for ip in value if ip]
    if isinstance(value, str):
        # sometimes a can be a single ip string
        return [value] if value else []
    return []


def random_label(length=10):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


# ---------- Wildcard Detection ----------
def get_wildcard_ips(domain):
    """
    Resolve a random non-existing subdomain to detect wildcard IPs.
    Returns a set of IPs (may be empty).
    """
    rnd = f"{random_label(12)}.{domain}"
    temp_file_path = create_temp_file([rnd])

    try:
        command = (
            f"dnsx -l {temp_file_path} -silent "
            "-a -resp -json -t 10 -rl 30 "
            "-r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222"
        )
        print(f"{colors.GRAY}[{current_time()}] wildcard probe: {command}{colors.RESET}")
        results = run_command_in_zsh(command)

        wildcard_ips = set()
        for result in results:
            try:
                obj = json.loads(result)
            except Exception:
                continue
            ips = normalize_ips(obj.get("a"))
            for ip in ips:
                wildcard_ips.add(ip)

        if wildcard_ips:
            print(f"{colors.YELLOW}[{current_time()}] wildcard IPs for {domain}: {', '.join(sorted(wildcard_ips))}{colors.RESET}")
        else:
            print(f"{colors.GREEN}[{current_time()}] no wildcard IPs detected for {domain}{colors.RESET}")

        return wildcard_ips

    finally:
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

# ---------- Main Resolver ----------
def dnsx(subdomains_array, domain):
    """Run dnsx on list, filter wildcard by IPs, and save live subdomains."""
    if not subdomains_array:
        return False

    temp_file_path = create_temp_file(subdomains_array)

    try:
        # detect wildcard IPs once per domain
        wildcard_ips = get_wildcard_ips(domain)

        command = (
            f"dnsx -l {temp_file_path} -silent "
            "-a -resp -json -t 10 -rl 30 "
            "-r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222"
        )

        print(f"{colors.GRAY}[{current_time()}] Executing dnsx: {command}{colors.RESET}")
        results = run_command_in_zsh(command)

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

            # if wildcard IPs exist and all ips are within wildcard -> skip
            if wildcard_ips and ips and set(ips).issubset(wildcard_ips):
                filtered += 1
                continue

            # if no IPs, still save? (optional)
            if host:
                upsert_lives({
                    "subdomain": host,
                    "domain": domain,
                    "ips": ips,
                    "cdn": ""
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
