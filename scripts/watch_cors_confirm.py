"""Re-check the cors-credentialed-reflection-custom findings and TRIAGE them by
exploitability, so a large batch collapses to the few worth a manual look.

The nuclei template fires on the exploitable *shape*: server echoes our canary
Origin in Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials:
true. That shape is necessary but not sufficient for impact -- the real bug only
matters when the endpoint serves PER-SESSION / authenticated data, because an
attacker page can only steal what the victim's browser is allowed to read.

For each open finding this script, with a realistic browser UA (so Akamai/WAF
403s don't masquerade as "fixed"):

  1. Reproduce: GET with Origin: <canary>  -> is the canary reflected AND
     Access-Control-Allow-Credentials: true still present?
  2. Arbitrary-origin control: GET with a second, unrelated Origin -> reflected
     too? (proves it echoes ANY origin, not a coincidental allow-list match)
  3. Session/auth signal: does the response look like it carries per-session
     data? (Set-Cookie, Vary: Cookie, ACA-Headers: authorization/cookie,
     401/403 auth-gate). These are what separate a real high from CORS noise.

Tiers:
  A-sensitive     reproduced + a session/auth signal   -> MANUAL PRIORITY
  B-public        reproduced, no session signal        -> real misconfig, low impact
  C-not-reproduced reflection/creds gone               -> likely false positive now
  blocked         WAF/5xx with no CORS headers         -> recheck inconclusive
  unreachable     connection failed                    -> recheck inconclusive

Read-only by default (just probes + writes a report). Pass --write to persist
verdicts back onto the Finding docs (extra + status). Nothing here sends an
exploit: it only sets Origin headers, exactly like the scanner did.

Usage:
  python3 scripts/watch_cors_confirm.py                 # probe all, report only
  python3 scripts/watch_cors_confirm.py --program indeed --limit 20
  python3 scripts/watch_cors_confirm.py --write         # also update findings
"""
import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings()
sys.path.insert(0, "/opt/watch")
from database.db import Finding  # noqa: E402

FINDING_NAME = "cors-credentialed-reflection-custom"

# Must match the template's canary exactly so a reproduction is apples-to-apples.
CANARY_ORIGIN = "https://evil-canary-0x1337.attacker.tld"
# A second, structurally different origin. If THIS is reflected too, the server
# echoes literally any origin (not an allow-list that happens to include ours).
CONTROL_ORIGIN = "https://cors-probe-9z8y7x.example.net"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

OUT_DIR = "/opt/watch/logs/cors"
WAF_STATUS = {403, 406, 429, 405, 503}


def probe(url, origin):
    """Single GET with an Origin header; return the CORS-relevant response bits."""
    try:
        r = requests.get(
            url, headers={"User-Agent": UA, "Origin": origin},
            allow_redirects=False, timeout=15, verify=False,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "err": type(exc).__name__}
    h = r.headers
    return {
        "ok": True,
        "status": r.status_code,
        "acao": (h.get("Access-Control-Allow-Origin") or "").strip(),
        "acac": (h.get("Access-Control-Allow-Credentials") or "").strip(),
        "set_cookie": "Set-Cookie" in h,
        "vary": (h.get("Vary") or "").strip(),
        "acah": (h.get("Access-Control-Allow-Headers") or "").strip(),
        "acem": (h.get("Access-Control-Expose-Headers") or "").strip(),
        "ctype": (h.get("Content-Type") or "").strip(),
    }


def classify(url):
    canary = probe(url, CANARY_ORIGIN)
    if not canary.get("ok"):
        return url, "unreachable", canary, {}, {}

    reflects = canary["acao"].lower() == CANARY_ORIGIN.lower()
    creds = canary["acac"].lower() == "true"
    reproduced = reflects and creds

    if not reproduced:
        # Distinguish "genuinely fixed" from "WAF/5xx hid the answer".
        if not canary["acao"] and canary["status"] in WAF_STATUS:
            return url, "blocked", canary, {}, {}
        return url, "C-not-reproduced", canary, {}, {}

    control = probe(url, CONTROL_ORIGIN)
    arbitrary = control.get("ok") and control["acao"].lower() == CONTROL_ORIGIN.lower()

    # Signals that the response is session/auth-scoped (-> worth stealing).
    signals = []
    if canary["set_cookie"]:
        signals.append("set-cookie")
    if "cookie" in canary["vary"].lower():
        signals.append("vary:cookie")
    acah_l = canary["acah"].lower()
    if "authorization" in acah_l:
        signals.append("aca-headers:authorization")
    if "cookie" in acah_l:
        signals.append("aca-headers:cookie")
    if canary["status"] in (401, 403):
        signals.append(f"auth-gated:{canary['status']}")

    tier = "A-sensitive" if signals else "B-public"
    meta = {"arbitrary_origin": bool(arbitrary), "signals": signals}
    return url, tier, canary, control, meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--program", help="only findings for this program")
    ap.add_argument("--limit", type=int, help="cap how many to re-check (testing)")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--write", action="store_true",
                    help="persist verdicts to the Finding docs (status + extra)")
    args = ap.parse_args()

    q = {"name": FINDING_NAME, "status": "open"}
    if args.program:
        q["program_name"] = args.program
    rows = list(Finding.objects(**q))
    if args.limit:
        rows = rows[:args.limit]
    print(f"[*] {len(rows)} open {FINDING_NAME} finding(s) to re-check "
          f"(write={'on' if args.write else 'OFF (report only)'})", flush=True)

    url_of = {f: (f.matched or f.target) for f in rows}
    buckets = {k: [] for k in
               ("A-sensitive", "B-public", "C-not-reproduced", "blocked", "unreachable")}
    results = {}

    def work(f):
        return f, classify(url_of[f])

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for i, (f, (url, tier, canary, control, meta)) in enumerate(ex.map(work, rows), 1):
            buckets[tier].append(f)
            results[f] = (url, tier, canary, control, meta)
            if tier == "A-sensitive":
                print(f"[A] {f.program_name} {url[:70]}  signals={','.join(meta['signals'])}")
            if i % 25 == 0:
                print(f"  [{i}/{len(rows)}] A={len(buckets['A-sensitive'])} "
                      f"B={len(buckets['B-public'])} C={len(buckets['C-not-reproduced'])}",
                      flush=True)

    print("\n=== summary ===")
    for k in ("A-sensitive", "B-public", "C-not-reproduced", "blocked", "unreachable"):
        print(f"  {k:16} {len(buckets[k])}")
    print("\nA-sensitive (check these by hand first):")
    for f in buckets["A-sensitive"]:
        url, _, canary, _, meta = results[f]
        print(f"  {url}  [{','.join(meta['signals'])}]  status={canary['status']}")

    # ---- report file ----
    os.makedirs(OUT_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(OUT_DIR, f"cors_confirm_{stamp}.json")
    report = {"counts": {k: len(v) for k, v in buckets.items()}, "tiers": {}}
    for k, fs in buckets.items():
        report["tiers"][k] = [{
            "program": f.program_name, "url": results[f][0],
            "status": results[f][2].get("status"),
            "acao": results[f][2].get("acao"), "acac": results[f][2].get("acac"),
            "arbitrary_origin": results[f][4].get("arbitrary_origin"),
            "signals": results[f][4].get("signals", []),
        } for f in fs]
    json.dump(report, open(out, "w"), indent=1)
    print(f"\nwrote {out}")

    # ---- optional persistence ----
    if not args.write:
        print("(report only — rerun with --write to update finding statuses)")
        return

    verdict = {
        "A-sensitive": ("open", "reproduced; session/auth signal present — MANUAL PRIORITY"),
        "B-public": ("triaged", "reproduced but no session/auth signal — likely low impact"),
        "C-not-reproduced": ("false_positive", "CORS reflection/credentials no longer present"),
        "blocked": ("open", "recheck inconclusive (WAF/5xx hid CORS headers)"),
        "unreachable": ("open", "recheck inconclusive (host unreachable)"),
    }
    changed = 0
    for tier, fs in buckets.items():
        status, note = verdict[tier]
        for f in fs:
            url, _, canary, control, meta = results[f]
            extra = f.extra if isinstance(f.extra, dict) else {}
            extra.update({
                "cors_recheck": note,
                "recheck_at": stamp,
                "live_acao": canary.get("acao"),
                "live_acac": canary.get("acac"),
                "live_status": canary.get("status"),
                "arbitrary_origin": meta.get("arbitrary_origin"),
                "session_signals": meta.get("signals", []),
            })
            f.extra, f.status = extra, status
            f.save()
            changed += 1
    print(f"[+] updated {changed} finding(s)")


if __name__ == "__main__":
    main()
