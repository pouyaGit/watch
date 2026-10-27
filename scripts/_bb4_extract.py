#!/usr/bin/env python3
"""Extract bounty:true programs for the 4 public platforms from the
projectdiscovery/public-bugbounty-programs dataset."""
import json
import re

SRC = "/tmp/pdbounty.json"
OUT = "/opt/watch/logs/bb4_programs.json"
PLAT = {"hackerone.com": "hackerone", "bugcrowd.com": "bugcrowd",
        "yeswehack.com": "yeswehack", "app.intigriti.com": "intigriti"}

data = json.load(open(SRC))["programs"]
rows = []
for p in data:
    if not p.get("bounty"):
        continue
    m = re.match(r"https?://([^/]+)", p.get("url") or "")
    host = m.group(1).lower() if m else ""
    plat = PLAT.get(host)
    if not plat:
        continue
    doms = sorted({x.strip().lstrip("*.").lower()
                   for x in (p.get("domains") or []) if x.strip()})
    rows.append({"platform": plat, "program": p["name"],
                 "url": p["url"], "domains": doms})

print("programs", len(rows))
for k in ("hackerone", "bugcrowd", "yeswehack", "intigriti"):
    s = [o for o in rows if o["platform"] == k]
    print(k, len(s), "with domains", sum(1 for o in s if o["domains"]),
          "roots", sum(len(o["domains"]) for o in s))
json.dump(rows, open(OUT, "w"), indent=1)
print("wrote", OUT)
