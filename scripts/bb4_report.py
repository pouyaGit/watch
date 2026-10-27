#!/usr/bin/env python3
"""bb4_report.py -- build the deliverable report from bb4 harvested hits.

Grouping: platform -> program -> one finding per line (full URL incl. parameter).
Only bounty:true programs are in the seed, so every line is a paid program.

Usage:
  ./.venv/bin/python scripts/bb4_report.py            # writes newest report
  ./.venv/bin/python scripts/bb4_report.py --out /opt/watch/reports/foo.md
"""
import argparse
import glob
import json
import os
import re
import time
from collections import OrderedDict
from urllib.parse import urlsplit

ROOT = "/opt/watch"
HITDIR = os.path.join(ROOT, "logs", "bb4", "hits")
REPDIR = os.path.join(ROOT, "reports")
PROGRAMS = os.path.join(ROOT, "logs", "bb4_programs.json")
PLAT_ORDER = ["hackerone", "bugcrowd", "yeswehack", "intigriti"]
PLAT_LABEL = {"hackerone": "HackerOne", "bugcrowd": "Bugcrowd",
              "yeswehack": "YesWeHack", "intigriti": "Intigriti"}

# A redirect param is worth a line when its value actually points somewhere.
DROP_VALUES = {"", "null", "none", "undefined", "1", "0", "true", "false", "-",
               "en", "us", "en-us", "home", "index"}
# names that pass the wordlist but never carry a destination
NOISE_PARAMS = {"page", "path", "file", "data", "val", "image_url", "imageurl",
                "feed", "prompt_url", "reference"}


def looks_like_destination(value):
    v = value.strip()
    if not v or v.lower() in DROP_VALUES:
        return False
    low = v.lower()
    if low.startswith(("http://", "https://", "//", "/", "%2f", "%2f%2f",
                       "%5c", "\\\\", "\\/", "./", "../")):
        return True
    if "%2f" in low or "/" in v or "\\" in v:
        return True
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$|\?)", low):
        return True
    return False



def collect():
    progs = json.load(open(PROGRAMS))
    dom2prog = {}
    for p in progs:
        for d in p["domains"]:
            dom2prog.setdefault(d, []).append((p["platform"], p["program"]))
    meta = {(p["platform"], p["program"]): p for p in progs}

    best = {}          # (platform, program, host, path, param-set) -> url
    for f in sorted(glob.glob(os.path.join(HITDIR, "*.jsonl"))):
        if "/archive/" in f:
            continue
        with open(f) as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    h = json.loads(ln)
                except Exception:
                    continue
                url = h.get("url") or ""
                params = h.get("params") or {}
                keep = {k: v for k, v in params.items()
                        if k.lower() not in NOISE_PARAMS
                        and looks_like_destination(v)}
                if not keep:
                    continue
                try:
                    sp = urlsplit(url)
                except ValueError:
                    continue
                if not sp.hostname:
                    continue
                # prefer https form of the same path
                https_url = url
                if sp.scheme != "https":
                    https_url = "https://" + sp.netloc + (sp.path or "") + \
                                (("?" + sp.query) if sp.query else "")
                for plat, prog in (h.get("programs") or dom2prog.get(h["domain"], [])):
                    key = (plat, prog, sp.hostname.lower(),
                           (sp.path or "/").lower(), tuple(sorted(keep)))
                    prev = best.get(key)
                    cand = (0 if https_url.startswith("https://") else 1,
                            len(https_url))
                    if prev is None or cand < prev[0]:
                        best[key] = (cand, https_url)
    return {k: v[1] for k, v in best.items()}, meta, progs


def build(out_path):
    best, meta, progs = collect()
    grouped = OrderedDict()
    for (plat, prog, host, path, ps) in best:
        grouped.setdefault((plat, prog), set()).add(best[(plat, prog, host, path, ps)])

    total = sum(len(v) for v in grouped.values())
    per_plat = {p: len([k for k in grouped if k[0] == p]) for p in PLAT_ORDER}
    seed = {p: len([x for x in progs if x["platform"] == p]) for p in PLAT_ORDER}
    lines = [
        "# Redirect-parameter findings — paid programs on 4 platforms",
        "",
        f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S %z')}",
        "- Scope: `bounty: true` programs only, from "
        "projectdiscovery/public-bugbounty-programs (`dist/data.json`)",
        "- Platforms (programs with >=1 finding / paid programs in seed): "
        + ", ".join(f"{PLAT_LABEL[p]} {per_plat[p]}/{seed[p]}" for p in PLAT_ORDER),
        "- Method: passive archive harvest (Wayback CDX, urlscan.io, OTX, "
        "arquivo.pt) over 1,141 in-scope root domains -> auth-flow paths "
        "carrying a redirect-style parameter (name list: "
        "`wordlists/redirect-params.txt`, 177 names)",
        f"- Findings: **{total}** endpoints in **{len(grouped)}** programs",
        "- Each line is one endpoint; the full URL keeps the redirect parameter "
        "and its value. Nothing here is confirmed exploitable yet — this is the "
        "candidate list for per-program open-redirect / OAuth `redirect_uri` "
        "confirmation.",
        "",
    ]
    for plat in PLAT_ORDER + [p for p in {k[0] for k in grouped}
                             if p not in PLAT_ORDER]:
        sub = {k: v for k, v in grouped.items() if k[0] == plat}
        if not sub:
            continue
        n = sum(len(v) for v in sub.values())
        lines.append(f"## {PLAT_LABEL.get(plat, plat)} ({len(sub)} programs, {n} findings)")
        lines.append("")
        for (p_plat, prog), urls in sorted(sub.items(), key=lambda kv: kv[0][1].lower()):
            m = meta.get((p_plat, prog), {})
            lines.append(f"### {prog} — {len(urls)}")
            if m.get("url"):
                lines.append(f"program: {m['url']}")
            lines.append("")
            for u in sorted(urls):
                lines.append(u)
            lines.append("")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return out_path, total, len(grouped)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(
        REPDIR, f"redirect-params-4platforms-{time.strftime('%Y%m%d_%H%M')}.md"))
    a = ap.parse_args()
    p, t, g = build(a.out)
    print(f"{p}\n{t} findings in {g} programs")
