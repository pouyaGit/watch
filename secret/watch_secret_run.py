#!/usr/bin/env python3
"""
watch_secret_run.py -- opt-in JS secret scanner for the heavy worker.

Picks in-scope .js URLs from Urls (never-scanned first, then oldest scan), downloads
each one with a byte cap and no redirect following, and checks the body against a
small set of high-signal regexes. Matches are stored redacted only; the full value
never reaches Mongo, logs or Telegram.

Scope is enforced before any request: out-of-scope or ooscope URLs are marked as
scanned without being fetched.

Usage:
  python3 secret/watch_secret_run.py --max-minutes 20

Env knobs:
  SECRET_BATCH          JS URLs considered per run (default 300)
  SECRET_MAX_BYTES      body read cap per file (default 2000000)
  SECRET_DELAY_MS       pause between fetches (default 200)
  SECRET_RESCAN_DAYS    rescan a JS URL after this many days (default 30)
  SECRET_TIMEOUT        per-request timeout seconds (default 10)
"""
import argparse
import os
import re
import sys
import time
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import requests  # noqa: E402
from mongoengine import Q  # noqa: E402

from database.db import Urls, upsert_finding  # noqa: E402
from utils.recon import (  # noqa: E402
    Deadline, alert, env_int, host_of, in_scope, log, meets_floor, scope_index,
)

JS_URL_REGEX = r"(?i)\.js(\?|#|$)"
MAX_MATCHES_PER_FILE = 20

# (rule name, severity, compiled pattern). A group, when present, is the secret value.
RULES = [
    ("aws_access_key", "high", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("slack_token", "high", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")),
    ("stripe_live_key", "high", re.compile(r"\b(sk_live_[0-9A-Za-z]{24,})\b")),
    ("google_api_key", "medium", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("private_key_block", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", "medium", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
    ("generic_secret_assignment", "medium", re.compile(
        r"(?i)(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|passwd|password)"
        r"[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-/+=]{20,})[\"']")),
]


def redact(value):
    if len(value) <= 10:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 6, 12) + value[-2:]


def scan_text(text):
    hits = []
    for name, severity, pattern in RULES:
        for m in pattern.finditer(text):
            value = m.group(1) if m.re.groups else m.group(0)
            hits.append((name, severity, redact(value)))
            if len(hits) >= MAX_MATCHES_PER_FILE:
                return hits
    return hits


def fetch(url, max_bytes, timeout_s):
    with requests.get(
        url, timeout=timeout_s, stream=True, allow_redirects=False,
        headers={"User-Agent": "watch-secret/1.0"},
    ) as resp:
        if resp.status_code != 200:
            return None
        buf = bytearray()
        for chunk in resp.iter_content(65536):
            buf += chunk
            if len(buf) >= max_bytes:
                break
        return bytes(buf[:max_bytes]).decode("utf-8", errors="replace")


def _scope_for(host, scopes):
    return next((s for s in scopes if host == s.lower() or host.endswith("." + s.lower())), "")


def run(deadline, index, cutoff):
    size = env_int("SECRET_BATCH", 300)
    max_bytes = env_int("SECRET_MAX_BYTES", 2_000_000)
    timeout_s = env_int("SECRET_TIMEOUT", 10)
    delay_s = env_int("SECRET_DELAY_MS", 200) / 1000

    docs = list(
        Urls.objects(url__regex=JS_URL_REGEX)
        .filter(Q(secret_scanned_at=None) | Q(secret_scanned_at__lt=cutoff))
        .order_by("secret_scanned_at")
        .limit(size)
    )
    log(f"--- Secret pass: {len(docs)} JS URLs selected")

    scanned = fetched = findings = 0
    for doc in docs:
        if deadline.expired():
            break
        host = host_of(doc.url)
        scopes, ooscopes = index.get(doc.program_name, ([], []))
        if not in_scope(host, scopes, ooscopes):
            Urls.objects(id=doc.id).update(set__secret_scanned_at=datetime.now())
            continue

        scope = _scope_for(host, scopes)
        log(f"--- Secret scan: {doc.url}")
        try:
            text = fetch(doc.url, max_bytes, timeout_s)
        except requests.RequestException:
            text = None
        fetched += text is not None
        for name, severity, redacted in scan_text(text or ""):
            is_new = upsert_finding({
                "program_name": doc.program_name,
                "scope": scope,
                "target": doc.url,
                "source": "secret",
                "name": name,
                "severity": severity,
                "matched": redacted,
                "extra": {"rule": name},
            })
            if is_new:
                findings += 1
                if meets_floor(severity):
                    alert(f"[secret] {severity.upper()} · {name} · {doc.url} · {redacted}")

        Urls.objects(id=doc.id).update(set__secret_scanned_at=datetime.now())
        scanned += 1
        time.sleep(delay_s)

    log(f"=== Secret pass: {scanned} processed, {fetched} fetched, {findings} new findings ===")
    return scanned


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-minutes", type=float, default=None)
    args = parser.parse_args()

    deadline = Deadline(args.max_minutes)
    index = scope_index()
    cutoff = datetime.now() - timedelta(days=env_int("SECRET_RESCAN_DAYS", 30))
    run(deadline, index, cutoff)


if __name__ == "__main__":
    main()
