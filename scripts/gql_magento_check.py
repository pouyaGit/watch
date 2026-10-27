import json

import requests
import urllib3

urllib3.disable_warnings()
H = {"Content-Type": "application/json", "Accept": "application/json",
     "User-Agent": "Mozilla/5.0 Chrome/126.0"}

# Magento: does an anonymous caller get customer data? (expected: auth error)
queries = {
    "customer-unauth": "{customer{email firstname lastname}}",
    "customerCart-unauth": "{customerCart{id email}}",
    "storeConfig": "{storeConfig{base_url base_currency_code}}",
    "orders-filter": "{customerOrders{items{number}}}",
}

for t in ("https://cart.digicert.com/graphql",
          "https://vercara.digicert.com/api/graphql"):
    print("=" * 90)
    print(t)
    for name, q in queries.items():
        try:
            r = requests.post(t, json={"query": q}, headers=H, timeout=25,
                              verify=False)
            body = r.text[:300].replace("\n", " ")
            print(f"  {name:22} {r.status_code} {body}")
        except Exception as e:
            print(f"  {name:22} ERR {type(e).__name__}")
