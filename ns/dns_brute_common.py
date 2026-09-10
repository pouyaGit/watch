#!/usr/bin/env python3
"""
dns_brute_common.py -- shared helpers for watch_dns_static.py and watch_dns_dynamic.py
"""

import subprocess
import hashlib
import re
import requests
import sys
import os
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config
from utils.common import ToolError, require_tool, require_tools, tool_env

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


# ====================== Dynamic (alterx) safety ======================
class ToolTimeout(ToolError):
    """A required external tool exceeded its time budget.

    Distinct from a generic ToolError so the dynamic pipeline can report a
    TIMEOUT outcome (with partial output discarded) separately from a hard
    failure, and never mistake it for a legitimate "0 candidates" result.
    """


# alterx's shipped permutation config (permutation_v0.1.0.yaml) expands each
# input line into at most this many permutations: six {{word}} patterns
# (6 x 111 words) + {{number}} (24) + {{region}} (6). This is a property of the
# shipped pattern/payload set, not a value invented here.
ALTERX_MAX_PERMUTATIONS_PER_INPUT = 696

# Estimated bytes per generated FQDN (observed key length + storage overhead),
# used only to reason about alterx's own dedupe backend choice.
ALTERX_EST_KEY_BYTES = 72

# projectdiscovery/utils/dedupe switches from an in-memory map to a disk-backed
# LevelDB/hybrid map above this many estimated bytes. Staying below it keeps
# generation in the fast, bounded regime instead of the disk-bound one that
# caused the 30-minute timeout on large known lists.
ALTERX_IN_MEMORY_DEDUPE_BYTES = 100 * 1024 * 1024


def _derived_dynamic_max_input_lines():
    # 100 MiB / (696 permutations/line * 72 B/key) ~= 2092, floored to the
    # nearest 100 so the ceiling stays stable against cosmetic changes.
    raw = ALTERX_IN_MEMORY_DEDUPE_BYTES // (
        ALTERX_MAX_PERMUTATIONS_PER_INPUT * ALTERX_EST_KEY_BYTES
    )
    return max(100, (raw // 100) * 100)


def _env_positive_int(name, default):
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


# Per-domain ceiling on the number of known subdomains fed to alterx. The
# default is derived from alterx's own in-memory dedupe threshold (never an
# arbitrary large constant); override with WATCH_DYNAMIC_MAX_INPUT_LINES to
# tune without a code change.
DYNAMIC_MAX_INPUT_LINES = _env_positive_int(
    "WATCH_DYNAMIC_MAX_INPUT_LINES", _derived_dynamic_max_input_lines()
)
DYNAMIC_MAX_CANDIDATES = DYNAMIC_MAX_INPUT_LINES * ALTERX_MAX_PERMUTATIONS_PER_INPUT

_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")


def is_valid_hostname(name):
    """Conservative hostname validation for DNS inputs and candidates.

    Rejects empty/whitespace names, wildcards, URLs, and labels with invalid
    characters, while accepting the underscore-bearing names DNS tooling emits.
    """
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    if any(not label for label in labels):
        return False
    return all(_LABEL_RE.match(label) for label in labels)


def bounded_deterministic_sample(sorted_items, limit):
    """Return all items when len <= limit, else an evenly-spaced deterministic
    sample (first and last included) preserving sorted order."""
    n = len(sorted_items)
    if limit <= 0 or n <= limit:
        return list(sorted_items)
    step = n / limit
    return [sorted_items[int(i * step)] for i in range(limit)]


def stream_valid_candidates(src_path, dst_path, max_candidates):
    """Stream src -> dst line by line, dropping empty/invalid/duplicate lines and
    stopping at max_candidates. Never buffers the whole file. Returns the number
    of candidates written (deterministic: preserves source order)."""
    seen = set()
    count = 0
    with open(src_path, "r", errors="ignore") as fin, open(dst_path, "w") as fout:
        for raw in fin:
            name = raw.strip()
            if not name or not is_valid_hostname(name):
                continue
            if name in seen:
                continue
            seen.add(name)
            fout.write(name + "\n")
            count += 1
            if count >= max_candidates:
                break
    return count


# ====================== Resolution (puredns, same tuning as static.sh) ======================
def run_puredns(candidates_file, out_file, threads=100, wildcard_tests=1, rate_limit_trusted=1000, wildcard_batch=100000):
    """
    Resolve a candidate list with puredns. Returns the list of names that
    survived puredns' own internal wildcard filtering.
    Flags match the ones already benchmarked in static.sh for large lists.

    Fail-fast contract (a missing/failing puredns must NEVER look like
    "0 resolved names"):
      - resolvers file missing  -> ToolError
      - puredns binary missing  -> ToolError naming the exact command
      - execution failure       -> ToolError
      - timeout                 -> ToolError (partial output is untrustworthy)
      - non-zero exit           -> ToolError (even exit 127 / "not found")
    Only a zero-exit run whose output file contains no names is a legitimate
    empty result (returns []).
    """
    if not os.path.exists(RESOLVERS):
        raise ToolError(
            f"puredns resolvers file not found: {RESOLVERS} "
            f"(cannot bruteforce without resolvers)"
        )

    puredns_bin = require_tool("puredns")

    argv = [
        puredns_bin, "resolve", str(candidates_file),
        "-r", RESOLVERS,
        "-t", str(threads),
        "--wildcard-tests", str(wildcard_tests),
        "--rate-limit-trusted", str(rate_limit_trusted),
        "--wildcard-batch", str(wildcard_batch),
    ]
    log(f"$ {' '.join(argv)} > {out_file}")
    try:
        with open(out_file, "w", errors="ignore") as fh:
            proc = subprocess.run(
                argv,
                stdout=fh,
                stderr=subprocess.PIPE,
                text=True,
                timeout=21600,  # 6h safety ceiling
                env=tool_env(),
            )
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeout(
            f"puredns resolve timed out on {candidates_file} "
            f"(partial output discarded, not treated as 0 names)"
        ) from exc
    except OSError as exc:
        raise ToolError(f"puredns execution failed: {exc}") from exc

    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()
        tail = tail[-1][:300] if tail else "no stderr"
        raise ToolError(
            f"puredns resolve failed on {candidates_file} "
            f"(exit {proc.returncode}): {tail}"
        )

    if not os.path.exists(out_file):
        raise ToolError(
            f"puredns exited 0 on {candidates_file} but produced no output file: {out_file}"
        )
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
        # Best-effort enrichment (a failed httpx pass must not invalidate the
        # DNS discovery already stored); the canonical tool PATH is still
        # passed so httpx resolves under the systemd environment.
        proc = subprocess.run(["zsh", "-c", cmd], capture_output=True, text=True, timeout=300, env=tool_env())
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