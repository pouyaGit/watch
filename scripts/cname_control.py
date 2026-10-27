"""Control for the 2,906 non-resolving *.indeed.tech CNAME targets.

Per hunt-subdomain: a non-answering target proves nothing until a name you KNOW
is live in the SAME namespace resolves from the same vantage. Pull real
indeed.tech names from certificate transparency (never invent them), resolve
them, and compare.
"""
import json
import re
import subprocess
import urllib.request

R = "/root/go/bin/dnsx"

print("== pulling real indeed.tech names from crt.sh (CT)")
url = "https://crt.sh/?q=%25.indeed.tech&output=json"
try:
    raw = urllib.request.urlopen(url, timeout=90).read().decode("utf-8", "ignore")
    data = json.loads(raw)
    names = set()
    for row in data:
        for n in (row.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith("indeed.tech") and n not in ("indeed.tech",):
                names.add(n)
    print(f"  crt.sh rows={len(data)} distinct names={len(names)}")
except Exception as e:
    print("  crt.sh failed:", e)
    names = set()

# fall back to names already in our own CNAME corpus that DO resolve
d = json.load(open("/opt/watch/logs/bb4/cname_sweep.json"))
alive_in_ns = sorted({r["cname"] for r in d["rows"]
                      if r["cname"].endswith(".indeed.tech")
                      and r["target_resolves"]})
print(f"  CNAME targets in the same namespace that DID resolve: {len(alive_in_ns)}")

sample = sorted(names)[:400] + alive_in_ns
p = subprocess.run([R, "-silent", "-nc", "-a", "-t", "100"],
                   input="\n".join(sample), capture_output=True, text=True,
                   timeout=600)
resolved = {ln.split()[0] for ln in p.stdout.splitlines() if ln.strip()}
print(f"\n== resolved {len(resolved)}/{len(sample)} sample names in indeed.tech")

ns_total = {r["cname"] for r in d["rows"] if r["cname"].endswith(".indeed.tech")}
ns_alive = {r["cname"] for r in d["rows"]
            if r["cname"].endswith(".indeed.tech") and r["target_resolves"]}
print(f"== our corpus: {len(ns_total)} distinct *.indeed.tech targets, "
      f"{len(ns_alive)} resolve")
print(f"   -> the namespace DOES resolve for some names"
      if ns_alive else "   -> namespace never resolves from here")
for n in sorted(ns_alive)[:8]:
    print("   resolves:", n)
