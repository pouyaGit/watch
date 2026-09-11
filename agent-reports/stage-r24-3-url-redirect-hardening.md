# Stage R24.3 — URL / Redirect Hardening

Status: **PASS**.

This stage implements deterministic DNS pre-resolution, manual
redirect handling with per-hop validation, and complete
`redirect_chain`/`final_url` provenance on top of the R24.2 HTTP seam.
No R23 behavior, scheduler, systemd, database, 5B–5J, Nuclei, browser,
verifier, finding, or alert code was touched. `WATCH_RESEARCH_DISCOVERY`
remains off.

---

## 1. Status

**PASS** — all 265 unit tests across the R23 (92), R24.1 (43),
R24.2 (50), and R24.3 (80) suites pass; the new R24.3 code is
isolated under `ai/research_agent/netguard.py` plus a thin additive
seam in `BoundedHTTPClient`; the existing R24.2 `request(...)` method
is byte-for-byte unchanged.

A small controlled live DNS smoke test (single `example.com`
resolution against the system resolver + literal-host rejection
probes) was run as the only real-network action. No HTTP fetches
were issued against any external service.

---

## 2. Files changed

All changes are additive. No R23, R24.1, R24.2 module or any other
tracked file was modified except for a single additive method on
`BoundedHTTPClient`. The pre-existing working-tree modifications to
unrelated tracked files were present *before* this task and were not
touched.

| File | Kind | Purpose |
|---|---|---|
| `ai/research_agent/netguard.py` | new | DNS pre-resolution, URL/port/credential guards, manual redirect walker, redirect-loop detector, `RedirectResult` dataclass |
| `tests/test_research_agent_r24_3.py` | new | Focused R24.3 test suite (80 tests) |
| `ai/research_agent/provider_base.py` | additive | One new method `BoundedHTTPClient.request_via_netguard(...)` that defers to `netguard.safe_fetch_with_redirects`. The existing `request(...)` method is preserved byte-for-byte. |

`git diff --check` is clean.

---

## 3. DNS controls

`netguard.resolve_public_ips(host, *, resolver=None)` is the
single DNS entry point.

- Resolves **A + AAAA** records via an injectable resolver
  (default: `socket.getaddrinfo` filtered to A/AAAA only).
- **Fail closed** on `socket.gaierror`, `socket.timeout`, empty
  result, and any other resolver exception.
- **Rejects** any hostname whose resolved-or-literal IP falls in:
  - loopback (`127.0.0.0/8`, `::1`)
  - private (RFC1918, IPv6 ULA `fc00::/7`)
  - link-local (`169.254.0.0/16`, `fe80::/10`)
  - multicast
  - reserved (covers `2001:db8::/32`, etc.)
  - unspecified (`0.0.0.0`, `::`)
  - cloud metadata IPs (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`)
- Belt-and-braces: hostname-suffix checks (`*.local`, `*.internal`,
  `*.localhost`) and a hostname blacklist (`metadata.google.internal`,
  `instance-data`, etc.) also reject before resolution.
- Any single non-public address in the resolved set causes the
  **entire host** to be rejected (no "one public address saves the
  host" loophole).
- Resolved IPs are never exposed as research evidence; they are used
  only for validation.

Confirmed against the live system resolver: `example.com` resolves
to public IPv4 + IPv6 (`188.114.98.0`, `2a06:98c1:3122::`, …); literals
`127.0.0.1` and `169.254.169.254` are rejected without any DNS
request.

---

## 4. Redirect controls

`netguard.safe_fetch_with_redirects(url, *, transport, resolver, …)`
is the manual-redirect walker.

- Single GET per hop; the underlying transport is injected (no live
  HTTP in tests).
- `MAX_REDIRECTS = 3`; the 4th redirect is a hard stop
  (`reason="redirect_loop"`, `error="redirect_limit"`).
- Every `Location` is resolved via `urllib.parse.urljoin` against
  the current URL (RFC 3986); relative `Location` is supported.
- Every hop is re-validated by `netguard.validate_hop`, which:
  - calls `netguard.resolve_public_ips` for the hop host;
  - calls `netguard.validate_url` (full SSRF guard);
  - plus hop-specific rules (HTTPS→HTTP downgrade, port change,
    embedded credentials).
- Redirect-loop detection: a `seen` set tracks every URL already
  fetched; an `A → B → A` cycle trips `reason="redirect_loop"`.
- `redirect_chain: list[str]` lists every URL actually fetched in
  order (initial URL + each accepted hop).
- `final_url: str` is the last URL actually fetched (empty when no
  fetcher completed; never the value of a `Location` header that
  was rejected).
- `discovered_url` is preserved unchanged by the walker; the
  `RedirectResult` exposes it as the first field.

The walker is fail-soft: every failure (private hop host, loopback
hop, embedded credentials, scheme downgrade, port change,
redirect-limit, transport exception, DNS failure) yields a
`RedirectResult` with `error` set and the body empty.

---

## 5. Port / scheme / credential controls

`validate_url` and `validate_hop` enforce, on both the initial URL
and every redirect hop:

- **Schemes**: only `http` and `https` are accepted. `file://`,
  `data:`, `ftp://`, etc. are rejected.
- **Default-port rule**:
  - `https` → 443
  - `http` → 80
  - any explicit port that is not the scheme default is rejected
    (initial fetch and every redirect hop).
- **Embedded credentials**: any URL containing `user[:pass]@host`
  is rejected (initial fetch and every redirect hop).
- **HTTPS → HTTP downgrade**: rejected on every redirect hop.
- **HTTP → HTTPS upgrade**: allowed (security improvement).
- **Host guards**: `localhost`, `*.local`, `*.internal`,
  `metadata.google.internal`, `instance-data`,
  `kubernetes.default`, `0.0.0.0`, `::`, plus all private /
  loopback / link-local / metadata IP literals.
- **Program/asset host**: any URL whose host matches a supplied
  `program=` token is rejected (via the R23
  `_host_matches_program` semantics).
- **Allowlist**: when the caller supplies an `allowed_hosts=` set,
  hosts outside it are rejected.

---

## 6. Provenance

`RedirectResult` carries:

- `discovered_url` — preserved unchanged from the caller.
- `url` — the initial URL after R24.3 URL guard (may equal
  `discovered_url`).
- `redirect_chain` — every URL actually fetched, in order.
- `final_url` — the last validated URL that was fetched.
- `status`, `body`, `content_type` — the final fetched metadata.
- `hops` — number of accepted redirect hops.
- `error`, `reason` — populated on fail-soft failures
  (`reason` is a short machine-readable tag: `private_ip`,
  `host`, `port`, `scheme`, `scheme_downgrade`,
  `embedded_credentials`, `program_host`, `allowlist`,
  `redirect_loop`, `transport`, `invalid_url`).

The HTTP seam
(`BoundedHTTPClient.request_via_netguard`) maps `RedirectResult`
onto the existing `ProviderResponse` shape so downstream R24.2 code
keeps working unchanged. The full redirect chain is recorded on
`content_type` (prefixed with `chain=`) so it is testable without
extending `ProviderResponse`. The trusted content hash (used by
later R24.5 evidence integration) is computed from `result.body` —
i.e. from the **final fetched body**, not from a redirect Location
header or the initial URL.

---

## 7. Bounds

- `MAX_REDIRECTS = 3` (constant exported by `netguard`).
- Per-call `timeout` (default 10 s) and `max_bytes` (default 1 MB,
  fully honoured) propagated to the injected transport.
- A single hop is one HTTP request; the walker never fans out and
  never recursively follows links discovered in a fetched page.
- No shell, no `subprocess`, no `eval`/`exec`, no streaming. All
  body bytes are read into memory up to `max_bytes` and truncated
  beyond.

---

## 8. Tests and verification

### Commands and results

```
python3 -m unittest tests.test_research_agent             → 92 OK (R23 unchanged)
python3 -m unittest tests.test_research_agent_r24_1       → 43 OK (R24.1 unchanged)
python3 -m unittest tests.test_research_agent_r24_2       → 50 OK (R24.2 unchanged)
python3 -m unittest tests.test_research_agent_r24_3       → 80 OK (R24.3 new)
python3 -m unittest tests.test_research_agent tests.test_research_agent_r24_1 tests.test_research_agent_r24_2 tests.test_research_agent_r24_3
                                                         → 265 OK
git diff --check                                         → clean
```

### R24.3 test coverage (`tests/test_research_agent_r24_3.py`, 80 tests)

- **DNS guards** (15 tests): public IPv4 accepted, loopback / 127 /
  RFC1918 (10/192/172) / link-local / `169.254.169.254` /
  `metadata.google.internal` / IPv6 `::1` / IPv6 ULA `fd00::/7` /
  IPv6 link-local `fe80::/10` / IPv6 reserved `2001:db8::/32` /
  mixed-resolution rejection / DNS exception fail-closed /
  empty-resolver fail-closed / `*.internal` suffix rejected.
- **URL guards** (15 tests): default ports ok, non-default
  `https:8443` / `http:81` rejected, embedded user rejected,
  embedded user:password rejected, `file://` / `data:` / `ftp://`
  rejected, localhost / metadata hostname / `169.254.169.254` / IP
  literal rejection, program-host (full match and label match),
  allowlist enforce / exact / subdomain match, empty URL rejected,
  no-host URL rejected.
- **Hop guard** (9 tests): HTTPS→HTTP downgrade rejected,
  HTTP→HTTPS upgrade allowed, relative `Location` resolved,
  `..` resolved, hop with embedded credentials rejected, hop with
  non-default port rejected, hop with program host rejected,
  allowlist enforced on hop, empty `Location` rejected.
- **Redirect walker** (12 tests): initial 2xx short-circuits,
  single redirect produces full chain + correct `final_url`,
  3-hop sequence ok, 4th hop hard stop (`MAX_REDIRECTS = 3`),
  constant value, redirect to private IP rejected with
  `reason="private_ip"`, redirect to localhost rejected,
  redirect to metadata rejected, redirect to non-default port
  rejected with `reason="port"`, redirect with embedded
  credentials rejected with `reason="embedded_credentials"`,
  scheme downgrade rejected with `reason="scheme_downgrade"`,
  redirect loop detected, relative `Location` resolved,
  program-host hop rejected.
- **Fail-soft** (5 tests): DNS failure / DNS exception fail-closed
  with no transport call, transport exception fail-soft with no
  HTTP call, no-transport fail-soft, initial-URL DNS rejection
  yields empty body and empty chain, transport returns `None`
  fail-soft.
- **Bounds** (3 tests): final body truncated at `max_bytes`,
  timeout propagates to transport, no recursive crawling.
- **HTTP seam** (5 tests): seam returns `ProviderResponse` on
  success, returns `None` and sets `last_error` on DNS failure,
  follows redirect with chain encoded in `content_type`, rejects
  HTTPS→HTTP downgrade, allowlist enforced.
- **Safety** (3 tests): no target resolution path (transport
  never called for a target host), `RedirectResult` carries no
  `production_finding` field, target host never appended to chain.
- **Import boundary** (3 tests): `netguard.py` has no forbidden
  imports (no 5B–5J, no browser, no `subprocess`/`requests`/
  `httpx`/`urllib.request`), no `eval(`/`exec(`/os.system(`
  tokens in `netguard.py`, the seam's import statement is the
  single `from ai.research_agent.netguard` line.
- **Regression** (3 tests): R24.2 seam still works
  (`BoundedHTTPClient.request`, `get_json`, `get_text` +
  R24.3 `request_via_netguard` all present), R24.1 enums intact
  (SourceCategory, TrustTier, Lifecycle, SearchProvider values),
  R24.2 registry returns 7 providers.

All transport is mocked via a fake callable injected into
`BoundedHTTPClient`. The test suite never touches the live network
for HTTP and only the **single controlled live DNS smoke test**
above used the system resolver.

---

## 9. Live network smoke test

A single tiny controlled smoke test was performed against the system
DNS resolver (no HTTP, no Nuclei, no browser, no target interaction):

- `resolve_public_ips("example.com")` returned 4 public IPs (IPv4 +
  IPv6).
- `resolve_public_ips("127.0.0.1")` returned `[]`.
- `resolve_public_ips("169.254.169.254")` returned `[]`.
- `validate_url("https://user:pass@example.com/")` raised
  `NetGuardError("url contains embedded credentials")`.
- `validate_url("https://localhost/")` raised
  `NetGuardError("blocked host: localhost")`.

All other tests are mocked. No broader live research run was
performed, and no live HTTP request was issued.

---

## 10. Explicit confirmations

- **R23 unchanged.** `ai/research_agent/{agent,scheduler,storage,
  sources,prompts}.py`, `ai/schemas/research_agent.py`, and the
  entire R23 test suite (92 tests) pass byte-for-byte as before.
- **R24.1 unchanged.** The R24.1 contract files were not modified;
  the 43-test R24.1 suite passes unmodified.
- **R24.2 behavior preserved.** The R24.2 `BoundedHTTPClient.request
  (...)` method is **byte-for-byte unchanged**; only one additive
  method (`request_via_netguard`) was added. The 50-test R24.2
  suite passes unmodified.
- **No scheduler / systemd / timer changes.** `WATCH_RESEARCH_
  DISCOVERY` is not wired anywhere in R24.3. No systemd unit, timer,
  or `*.sh` script was modified.
- **No database change.** `database/db.py` was not touched.
- **No target interaction.** No provider is given a target URL / host
  / IP; no transport call is directed at a program/asset host; the
  SSRF guard rejects any such attempt; the DNS-resolved IP is
  validated as public before any transport call and never exposed
  as research evidence.
- **No 5B–5J coupling.** `netguard.py` imports only stdlib
  (`ipaddress`, `socket`, `urllib.parse`, `dataclasses`, `typing`,
  `re`) plus the R24.2 types. The seam in `provider_base.py`
  imports only `ai.research_agent.netguard`. Static-import scan
  enforces this.
- **No findings / alerts.** No finding/alert writer is invoked; no
  `RedirectResult` carries a `production_finding` field (the
  producer class doesn't define it; the test asserts that).

---

## 11. Known limitations deferred to R24.4+

- **R24.4 — Source Ranking & Dedup.** Deterministic scoring
  (`TIER_BASE` + category/signal bonuses + penalties) and the
  canonical-URL / content-hash dedup ledger. R24.3 supplies the
  `redirect_chain` / `final_url` provenance R24.4 will fold into
  the canonicalization key.
- **R24.5 — Evidence Integration.** Lifecycle transitions
  (`DISCOVERED_SOURCE → FETCHED_SOURCE → RELEVANT_SOURCE →
  EVIDENCE`), grounded evidence mapping onto `sources[]` /
  `evidence[]`, additive result `discovery` block. The trusted
  content hash will be computed from the final fetched body
  surfaced by `RedirectResult.body`.
- **R24.6 — LLM Research Loop.** Bounded two-round
  discover→rank→validate→fetch→extract→analyze→gap loop; gap-
  directed queries; LLM is never authoritative; verdict language
  is scrubbed.
- **R24.8 — Scheduler Integration.** Wire
  `WATCH_RESEARCH_DISCOVERY` through the existing
  `SchedulerConfig`/agent construction; no new timer, no systemd
  edit; flag-off = R23 behaviour.

---

## 12. Next-stage recommendation

**R24.4 — Source Ranking & Dedup (`ai/research_agent/ranking.py`
and `ai/research_agent/dedup.py`).**

Implement:

1. **Ranking** — deterministic scoring from R24.1
   `SourceCategory` / `TrustTier` + a category bonus table + a
   deterministic signal-bonus table (CVE id / product / component /
   CWE / version / canonical-path) + a penalty table (known
   aggregator / Tier 4 without corroboration). Clamp to `[0, 200]`
   and store `source_quality = round(score / 200, 2)`. Ordering:
   `score` desc → tier rank asc → `canonical_url` asc →
   `source_id` asc.

2. **Dedup ledger** — two-level, deterministic:

   - Pre-fetch URL canonicalization (extend
     `ai/researcher.reference_cache.canonicalize_reference_url` for
     R24 keys: trim, drop fragment, drop only tracking params
     (`utm_*`, `gclid`, `fbclid`), lowercase scheme/host, strip
     default ports, deterministic GitHub `blob/raw → raw.github
     usercontent.com` mapping, include `final_url` once known).
   - Post-fetch content hashing (`sha256(normalize_text(body)
     [:MAX_DOC_CHARS])` via `ai.collectors.body_extraction
     .sha256_text`). Identical bodies from different URLs collapse
     into one source: highest-tier / highest-quality URL becomes
     canonical; the others are recorded as `aliases` /
     `discovered_via`.

3. **Evidence eligibility gate** — `content_hash` present,
   `source_quality ≥ EVIDENCE_FLOOR = 0.45`, tier in
   `TRUSTED`/`SEMI_TRUSTED` (or `DISCOVERY_ONLY` detection rule
   with an explicit advisory reference). Below-floor sources
   remain `RELEVANT_SOURCE` / `UNKNOWN`. `GENERIC` sources can
   never be evidence on their own.

R24.4 must reuse the R24.3 `redirect_chain` / `final_url`
provenance and must not re-resolve DNS or re-fetch.

---

## Agent / Model
- Model: claude-sonnet-4-20250514 (Cline)
- Stage: R24.3
- Role: URL / Redirect Hardening
