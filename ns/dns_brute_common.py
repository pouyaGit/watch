#!/usr/bin/env python3
"""
dns_brute_common.py -- shared helpers for watch_dns_static.py and watch_dns_dynamic.py
"""

import subprocess
import hashlib
import requests
import sys
import os
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config

RESOLVERS = "/opt/watch/resolvers.txt"
WORKDIR = Path("/opt/watch/dns-bruteforce/work")
WORKDIR.mkdir(parents=True, exist_ok=True)

HTTPX_BIN = config().get("HTTPX_BIN", "/usr/local/bin/httpx")


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def send_telegram(text):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        log("Telegram not configured")
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": text[:4000]},
            timeout=30
        )
    except Exception as e:
        log(f"Telegram error: {e}")


# ====================== ETA estimation ======================
# Based on the throughput already benchmarked in static.sh for these exact
# puredns settings: ~30M records/hour at -t 100 --wildcard-tests 1
# --rate-limit-trusted 1000 --wildcard-batch 100000
PUREDNS_RECORDS_PER_MINUTE = 30_000_000 / 60


def estimate_minutes(candidate_count):
    return max(1, round(candidate_count / PUREDNS_RECORDS_PER_MINUTE))


def count_lines(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


# ====================== Resolution (puredns, same tuning as static.sh) ======================
def run_puredns(candidates_file, out_file, threads=100, wildcard_tests=1, rate_limit_trusted=1000, wildcard_batch=100000):
    """
    Resolve a candidate list with puredns. Returns the list of names that
    survived puredns' own internal wildcard filtering.
    Flags match the ones already benchmarked in static.sh for large lists.
    """
    if not os.path.exists(RESOLVERS):
        log(f"Resolvers file not found: {RESOLVERS}")
        return []

    cmd = (
        f'puredns resolve "{candidates_file}" -r "{RESOLVERS}" '
        f'-t {threads} --wildcard-tests {wildcard_tests} '
        f'--rate-limit-trusted {rate_limit_trusted} --wildcard-batch {wildcard_batch} '
        f'> "{out_file}"'
    )
    log(f"$ {cmd}")
    try:
        subprocess.run(cmd, shell=True, timeout=21600)  # 6h safety ceiling
    except subprocess.TimeoutExpired:
        log(f"puredns timeout on {candidates_file}")

    if not os.path.exists(out_file):
        return []
    return [l.strip() for l in Path(out_file).read_text(errors="ignore").splitlines() if l.strip()]


# ====================== Quick httpx pass on a small subset ======================
def run_httpx_quick(subdomains):
    """
    Run httpx on a small list of newly-confirmed subdomains, same flags as
    the main http pipeline, and return parsed JSON results.
    """
    import json
    import tempfile

    if not subdomains:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        tmp_path = f.name

    results = []
    try:
        cmd = (
            f"{HTTPX_BIN} -l {tmp_path} "
            "-silent -json -favicon -fhr -tech-detect -irh -include-chain "
            "-timeout 4 -retries 1 -threads 15 -rate-limit 15 "
            "-ports 443 -random-agent"
        )
        proc = subprocess.run(["zsh", "-c", cmd], capture_output=True, text=True, timeout=300)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except Exception as e:
        log(f"httpx error: {e}")
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    return results


# ====================== TTL + HTTP body-hash wildcard check ======================
# Ported from dynamic_dns_bruteforce.sh -- used only by watch_dns_dynamic.py as an
# extra safety net on top of puredns' own filtering, per the chosen approach.

def _dig_a_with_ttl(fqdn, timeout=3):
    """Returns list of (ip, ttl) tuples for the A record."""
    try:
        out = subprocess.run(
            ["dig", "+noall", "+answer", f"+time={timeout}", "+tries=1", "A", fqdn],
            capture_output=True, text=True, timeout=timeout + 2
        ).stdout
    except Exception:
        return []
    pairs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "A":
            ttl, ip = parts[1], parts[4]
            pairs.append((ip, ttl))
    return pairs


def _http_body_hash(fqdn, timeout=3):
    for proto in ("http", "https"):
        try:
            r = requests.get(f"{proto}://{fqdn}", timeout=timeout, verify=False)
            if r.text:
                return hashlib.md5(r.text.encode(errors="ignore")).hexdigest()
        except Exception:
            continue
    return None


def collect_wildcard_signature(domain, test_count=5):
    """Step used once per domain: probe random nonexistent subdomains and
    collect (ip, ttl, http_hash) wildcard signatures."""
    import random
    import string

    ips, ttl_pairs, hashes = set(), set(), set()

    for _ in range(test_count):
        rand_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        test_fqdn = f"{rand_label}.{domain}"
        for ip, ttl in _dig_a_with_ttl(test_fqdn):
            ips.add(ip)
            ttl_pairs.add((ip, ttl))
            h = _http_body_hash(test_fqdn)
            if h:
                hashes.add(h)

    return {"ips": ips, "ttl_pairs": ttl_pairs, "hashes": hashes}


def is_wildcard_match(fqdn, ip, signature):
    """
    Returns True if this specific result should be filtered as wildcard,
    using the TTL-then-HTTP-hash cascade from dynamic_dns_bruteforce.sh:
    - IP not in the wildcard IP set -> not a wildcard match, keep it
    - IP matches but TTL differs -> rescued, keep it
    - IP+TTL both match but HTTP body differs -> rescued, keep it
    - IP+TTL+HTTP body all match -> confirmed wildcard, filter it
    """
    if ip not in signature["ips"]:
        return False

    pairs = _dig_a_with_ttl(fqdn)
    current_ttl = pairs[0][1] if pairs else None
    if current_ttl is None or (ip, current_ttl) not in signature["ttl_pairs"]:
        return False  # TTL mismatch -> rescued

    if not signature["hashes"]:
        return True  # no HTTP signature to compare against, conservative filter

    current_hash = _http_body_hash(fqdn)
    if current_hash and current_hash in signature["hashes"]:
        return True  # confirmed wildcard

    return False  # HTTP mismatch -> rescued