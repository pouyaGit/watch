"""Verify the cloudapp.azure.com candidates: is the target actually released,
and is the host currently serving an Azure error (i.e. unclaimed VM)?"""
import json
import subprocess

d = json.load(open('/opt/watch/logs/bb4/cname_sweep.json'))
az = [r for r in d['rows'] if r['cname'].endswith('cloudapp.azure.com')]
print(f"{len(az)} cloudapp.azure.com CNAME records\n")

for r in az:
    print("=" * 100)
    print(f"host   : {r['host']}")
    print(f"cname  : {r['cname']}   resolves={r['target_resolves']}")
    # CNAME chain + A of the target + the host itself
    for q in ("CNAME", "A"):
        p = subprocess.run(["dig", "+short", r['host'], q], capture_output=True,
                           text=True, timeout=30)
        print(f"  {q:6} {r['host']}: {p.stdout.strip().replace(chr(10), ' ')[:120]}")
    p = subprocess.run(["dig", "+short", r['cname'], "A"], capture_output=True,
                       text=True, timeout=30)
    out = p.stdout.strip()
    print(f"  target A: {out or '(NXDOMAIN/NODATA)'}")
