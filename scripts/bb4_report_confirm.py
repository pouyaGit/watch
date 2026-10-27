#!/usr/bin/env python3
"""bb4_report_confirm.py -- build the confirmation report.

Reads logs/bb4/confirm/classified.jsonl (baseline vs canary google.com) and
writes /opt/watch/reports/redirect-confirmation-<date>.md.

Sections:
  1. Result: how many of the N candidates actually redirected to google.com.
  2. Validation-rejected endpoints: the parameter IS consumed and the value was
     refused -> where a redirect_uri/ReturnUrl bypass is still worth trying.
  3. Behaviour-changed endpoints (IdP fell back to its own error page).
  4. Unreachable endpoints (dead hosts / TLS / connection refused).
"""
import collections
import json
import os
import time
from urllib.parse import urlsplit

ROOT = "/opt/watch"
SRC = os.path.join(ROOT, "logs", "bb4", "confirm", "classified.jsonl")
OUT = os.path.join(ROOT, "reports",
                   f"redirect-confirmation-{time.strftime('%Y%m%d')}.md")
CANARY = "https://google.com"


def host(loc):
    if not loc:
        return ""
    loc = loc.strip()
    if not loc.startswith(("http://", "https://", "//")):
        return ""
    try:
        return (urlsplit(loc if not loc.startswith("//") else "https:" + loc).hostname or "").lower()
    except ValueError:
        return ""


def main():
    rows = [json.loads(l) for l in open(SRC)]
    n = len(rows)
    by_cls = collections.Counter(r["cls"] for r in rows)
    changed = [r for r in rows if r["cls"] == "redirect-changed-host"]
    rejected = [r for r in rows if r["cls"] == "validated-rejected"]
    expired = [r for r in rows if r["cls"] == "accepted-after-original-expired"]
    dead = [r for r in rows if r["cls"] == "unreachable"]
    # genuine open redirect = canary landed on google.com while baseline did not
    real = [r for r in rows if host(r["canary"]["location"]) == "google.com"
            and host(r["baseline"]["location"]) != "google.com"
            and r["canary"]["status"] in (301, 302, 303, 307, 308)]

    L = []
    L.append("# Open-redirect confirmation — redirect param set to "
             f"`{CANARY}`")
    L.append("")
    L.append(f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S %z')}")
    L.append(f"- Candidates tested: **{n}** endpoints (from "
             "redirect-params-4platforms-20261026.md)")
    L.append(f"- Method: original archived URL re-requested with every "
             f"redirect-style parameter rewritten to `{CANARY}`, one GET, "
             "no follow, 15s timeout, then compared against the untouched "
             "baseline response")
    L.append("- Exact-host match on `Location` (a `*.google.com` subdomain does "
             "not count — only `google.com` itself)")
    L.append("")
    L.append(f"## Result: {len(real)} confirmed open redirect(s)")
    L.append("")
    if real:
        for r in real:
            L.append(f"- {r['platform']} / {r['program']}: {r['endpoint']}")
            L.append(f"  - {r['canary']['status']} Location: "
                     f"`{r['canary']['location']}`")
    else:
        L.append("**No endpoint redirected to the supplied canary host.** "
                 "Every candidate either ignored the parameter, validated and "
                 "refused the value, or did not redirect at all. Nothing here "
                 "is reportable as an open redirect yet.")
    L.append("")
    L.append("### Breakdown")
    L.append("")
    for k, label in (("unreachable", "unreachable (dead host / TLS / refused)"),
                     ("no-redirect-both", "no redirect with either value"),
                     ("redirect-same", "redirects, unchanged by our value"),
                     ("blocked", "blocked at the edge (403/404/406/429 — "
                                 "WAF or bot filter, not a verdict on the param)"),
                     ("validated-rejected",
                      "param consumed, value refused (4xx)"),
                     ("redirect-changed-host", "param consumed, IdP error page"),
                     ("accepted-after-original-expired",
                      "archived value expired, ours accepted"),
                     ("other", "other / inconclusive")):
        if by_cls.get(k):
            L.append(f"- {by_cls[k]:5d}  {label}")
    L.append("")
    blocked = [r for r in rows if r["cls"] == "blocked"]
    if blocked:
        L.append(f"Note: {len(blocked)} endpoints answered with the same 4xx to "
                 "both the untouched URL and the canary URL (mostly 403/406/429 "
                 "from an edge WAF or bot filter, 404 for dead paths). Those "
                 "were **not** validated as safe — they are blocked from this "
                 "IP without a browser session, and are simply untested.")
        L.append("")

    def section(title, items, note):
        L.append(f"## {title} ({len(items)})")
        L.append("")
        if note:
            L.append(note)
            L.append("")
        grp = collections.OrderedDict()
        for r in items:
            grp.setdefault((r["platform"], r["program"]), []).append(r)
        for (plat, prog), rs in sorted(grp.items(), key=lambda kv: -len(kv[1])):
            L.append(f"### {plat} / {prog} — {len(rs)}")
            if rs[0].get("program_url"):
                L.append(f"program: {rs[0]['program_url']}")
            L.append("")
            for r in rs:
                b, c = r["baseline"], r["canary"]
                L.append(r["endpoint"])
                L.append(f"  baseline: {b['status']} -> "
                         f"{host(b['location']) or '(none)'}")
                L.append(f"  canary  : {c['status']} -> "
                         f"{host(c['location']) or '(none)'}")
            L.append("")

    section("Where the parameter is consumed but the value was refused",
            rejected,
            "These endpoints read the redirect parameter and rejected our "
            "external host with a 4xx. That is the correct behaviour and also "
            "the exact place a `redirect_uri` whitelist bypass (subdomain, "
            "`@`, backslash, `%2f%2f`, path traversal, open redirect on an "
            "allowed host) would be attempted — one program at a time, inside "
            "its scope.")
    section("Where the parameter changed the response without redirecting "
            "to us", changed,
            "The identity provider fell back to its own error page instead of "
            "honouring the external URI. Not a redirect; listed because it "
            "proves the value is parsed.")
    section("Archived value no longer valid, ours accepted", expired, "")
    if dead:
        L.append(f"## Unreachable ({len(dead)})")
        L.append("")
        L.append("These could not be tested (host dead, connection refused or "
                 "TLS failure) — they remain untested, not clean.")
        L.append("")
        c = collections.Counter((r["platform"], r["program"]) for r in dead)
        for (plat, prog), k in c.most_common():
            L.append(f"- {k:4d}  {plat} / {prog}")
        L.append("")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as fh:
        fh.write("\n".join(L) + "\n")
    print(OUT)
    print(f"{n} tested, {len(real)} real redirects, "
          f"{len(rejected)} refused, {len(changed)} error-page, "
          f"{len(dead)} unreachable")


if __name__ == "__main__":
    main()
