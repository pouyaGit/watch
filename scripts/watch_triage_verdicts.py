"""Record verification verdicts in the Watch Finding collection (status only,
never delete)."""
import sys

sys.path.insert(0, "/opt/watch")
from database.db import Finding  # noqa: E402

UPDATES = [
    # Dell takeover: asuid TXT present -> domain bound to a live subscription,
    # not claimable. Confirmed FP per HUNT_GUIDE 5a.
    ({"program_name": "dell", "source": "takeover"},
     "false_positive",
     "asuid TXT asuid.selectortool.dell.com present (domain bound to an existing "
     "Azure subscription); A-record only, no dangling CNAME -> not claimable"),

    # GraphQL: introspection is default behaviour for the framework and authz
    # holds; no data exposure demonstrated.
    ({"program_name": "digicert", "source": "nuclei"},
     "false_positive",
     "re-verified: Magento 2 storefront GraphQL. Introspection unauth = framework "
     "default. customer/customerCart/customerOrders all return graphql-authorization "
     "errors unauthenticated; storeConfig shows only public base_url + currency"),

    ({"program_name": "indeed", "source": "nuclei"},
     "false_positive",
     "re-verified: introspection unauth on cocos-api/reportcontent/compliance. "
     "Exposed surface is question/survey + content-report only; no PII query "
     "reachable unauthenticated, mutations require service auth"),

    # Google API key resolves to a live project but every tested API is disabled.
    ({"program_name": "indeed", "source": "secret"},
     "false_positive",
     "AIza key valid for project 655407646403 but YouTube Data / Custom Search / "
     "Translation / Geocode / StaticMap / Timezone all return 'not activated'. "
     "No billable or unrestricted capability demonstrated"),
]

for query, status, note in UPDATES:
    rows = Finding.objects(**query)
    n = rows.count()
    if not n:
        print("  no rows for", query)
        continue
    for doc in rows:
        ex = doc.extra if isinstance(doc.extra, dict) else {}
        ex["verified"] = note
        doc.extra = ex
        doc.status = status
        doc.save()
    print(f"  {n} row(s) -> {status}: {query}")

print("\n== remaining open, by source")
from collections import Counter  # noqa: E402
c = Counter((f.program_name, f.source) for f in Finding.objects(status="open"))
for k, v in sorted(c.items()):
    print(f"  {v:4d}  {k[0]:10} {k[1]}")
