import json
import sys

import requests
import urllib3

urllib3.disable_warnings()
H = {"Content-Type": "application/json", "Accept": "application/json",
     "User-Agent": "Mozilla/5.0 Chrome/126.0"}

Q = {"query": "query{__schema{queryType{fields{name args{name type{name kind ofType{name}}} type{name kind ofType{name}}}} mutationType{fields{name}}}}"}

for t in sys.argv[1:]:
    print("=" * 90)
    print(t)
    try:
        r = requests.post(t, json=Q, headers=H, timeout=30, verify=False)
        d = r.json()
    except Exception as e:
        print("  ERR", e)
        continue
    s = (d.get("data") or {}).get("__schema") or {}
    q = (s.get("queryType") or {}).get("fields") or []
    m = (s.get("mutationType") or {}).get("fields") or []
    print(f"  queries={len(q)} mutations={len(m)}")
    print("  QUERIES:", ", ".join(x["name"] for x in q)[:1200])
    if m:
        print("  MUTATIONS:", ", ".join(x["name"] for x in m)[:800])
