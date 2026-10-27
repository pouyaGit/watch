import json
import urllib3
import requests

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0",
      "Content-Type": "application/json",
      "Accept": "application/json"}

Q = {"query": "query{__schema{queryType{name} mutationType{name} types{name kind}}}"}

targets = [
    "https://vercara.digicert.com/api/graphql",
    "https://knowledge.digicert.com/api/graphql",
    "https://constellix.digicert.com/api/graphql",
    "https://cart.digicert.com/graphql",
    "https://mcprod.digicert.com/graphql",
    "https://compliance.indeed.com/graphql",
    "https://cocos-api.indeed.com/graphql",
    "https://reportcontent.indeed.com/graphql",
]

for t in targets:
    print("=" * 100)
    print(t)
    for method in ("POST", "GET"):
        try:
            if method == "POST":
                r = requests.post(t, json=Q, headers=UA, timeout=25, verify=False,
                                  allow_redirects=False)
            else:
                r = requests.get(t, params={"query": Q["query"]}, headers=UA,
                                 timeout=25, verify=False, allow_redirects=False)
        except Exception as e:
            print(f"  {method}: ERR {type(e).__name__} {str(e)[:80]}")
            continue
        ct = r.headers.get("content-type", "")
        body = r.text[:400].replace("\n", " ")
        print(f"  {method}: {r.status_code} ct={ct[:40]}")
        print(f"       {body}")
        if r.status_code == 200 and "json" in ct:
            try:
                d = r.json()
                if isinstance(d, dict):
                    print("       keys:", list(d.keys()))
                    if d.get("errors"):
                        print("       ERRORS:", str(d["errors"])[:200])
                    if d.get("data") and d["data"].get("__schema"):
                        qt = d["data"]["__schema"].get("queryType")
                        nt = len(d["data"]["__schema"].get("types") or [])
                        print(f"       *** INTROSPECTION OK queryType={qt} types={nt}")
            except Exception as e:
                print("       json parse fail:", e)
