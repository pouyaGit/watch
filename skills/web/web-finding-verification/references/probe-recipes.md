# Probe recipes — disproving a candidate

Concrete commands for the verification steps in SKILL.md §2–§4. All are read-only and
non-destructive; run them before writing any finding.

## Is the endpoint session-gated? (§1–§2)

Send the request with no credentials and read the BODY, not the status.

```bash
curl -sS -X POST 'https://host/api/thing/downloadfile' \
  -H 'Content-Type: application/json' \
  -d '{"id":"1"}' -w '\nHTTP:%{http_code}\n' | head -40
```

Look for a denial envelope in a 200 response:

```bash
grep -oiE 'invalid (user )?session|unauthor|expired|please refresh|not logged in'
```

If the envelope is identical for every object reference (`id=1`, `id=2`, a nonsense
value), the check runs before the data layer. Classify the whole endpoint family as
session-gated and stop swapping identifiers.

**Mass-IDOR loops must gate on the envelope, not the code:**

```python
body = r.text.lower()
if r.status_code == 200 and not any(k in body for k in
        ("invalid user session", "unauthor", "expired", "please refresh")):
    hits.append(obj_id)          # a real 200 — verify the field is populated too
```

## Differential SSRF test (§3)

Three inputs, same request. An SSRF answers differently per destination; a logic bug
does not.

```bash
for t in 'http://<your-listener>/x' 'http://10.255.255.1:9/' 'http://127.0.0.1:1/' 'not a url' ''; do
  printf '%-28s ' "$t"
  curl -sS -o /dev/null -w 'code=%{http_code} time=%{time_total}\n' \
    --max-time 25 -X POST 'https://host/api/thing/remotefilecheck' \
    -H 'Content-Type: application/json' -d "{\"fileName\":\"$t\"}"
done
```

Reading the result:

- **Time varies by destination, or your listener logs a hit** → real fetch. Escalate.
- **Every row identical (all hang at 25s, or all return the same constant)** → no fetch
  is happening. Not SSRF. If it hangs unboundedly on any input, report it as resource
  exhaustion instead.

Run each input twice: a one-off hang can be a slow host, a repeatable one is the
behaviour. Include the no-input and malformed cases — a constant `true`/`ok` for an
empty parameter is the tell that the parameter is ignored entirely.

## GraphQL: auth inconsistency vs exposure (§4)

```bash
# 1. Does it answer at all without credentials?
curl -sS -X POST 'https://host/api/now/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ __typename }"}'

# 2. Is introspection open?
curl -sS -X POST 'https://host/api/now/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}'

# 3. Named type probe
curl -sS -X POST 'https://host/api/now/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ __type(name: \"QueryType\") { fields { name } } }"}'

# 4. Compare against sibling endpoints that should require auth
for p in /api/now/table/sys_user /api/now/v1/graphql /api/now/batch /api/now/graphql; do
  printf '%-28s ' "$p"
  curl -sS -o /dev/null -w '%{http_code}\n' "https://host$p"
done
```

Decision table:

| Observation | Verdict |
|---|---|
| 200 unauth, `__typename` resolves, introspection disabled, guessed fields `undefined` | **Auth inconsistency (Low)** — no data exposed. State that explicitly. |
| 200 unauth, introspection open | Schema disclosure. Enumerate; still not data exposure until a record returns. |
| 200 unauth and a real record returns | Data exposure. Escalate and capture the exact response. |
| All siblings 401 including this one | No finding. |

Table/type names surfaced by validation errors are a side effect of the parser naming
what it could not resolve — record them as schema disclosure, never as data.

## Closing the negative pass (§5)

Before writing "0 findings", reconcile the counts so the sweep is auditable:

```bash
wc -l < urls.txt                      # surface attempted
python3 - <<'PY'
import json
d = json.load(open('results.json'))
print('sent', d['sent'], 'reflected', d['reflected'], 'raw', d['raw'])
PY
```

Quote `sent` and `reflected` together. A reflected count of 0 beside a sent count in the
thousands is the evidence; the number alone is not.
