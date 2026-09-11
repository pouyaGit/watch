# Stage R24.2 — Search Providers

Status: **PASS**.

This stage implements the provider abstraction and seven deterministic
public-source discovery providers on top of the R24.1 contract. It is
provider-implementation only; no R23 behavior, scheduler, systemd,
database, 5B–5J, redirect hardening, ranking, evidence integration, or
LLM research loop is touched.

---

## 1. Status

**PASS** — all 185 unit tests across the R23, R24.1, and R24.2 suites
pass; the implementation is gated by an isolated transport, does not
touch the live network, and preserves every R24.1 invariant.

---

## 2. Files changed

All changes are additive. Three new files were created; one R24.1 file
(`ai/research_agent/discovery_contract.py`) was extended with a single
additive enum member (`SearchProvider.GENERIC_SEARCH = "generic_search"`)
because the R24 scope lists seven provider identifiers but the R24.1
contract enum stub only carried six. No R23, R24.1 module, or any other
tracked file was modified otherwise. The pre-existing working-tree
modifications to unrelated tracked files (backend, web templates,
`tests/test_research_ui.py`, etc.) were present *before* this task and
were not touched.

| File | Kind | Purpose |
|---|---|---|
| `ai/research_agent/provider_base.py` | new | Provider protocol, bounded HTTP client, host classification helpers, registry |
| `ai/research_agent/providers.py` | new | Seven concrete provider classes + `build_providers` factory |
| `tests/test_research_agent_r24_2.py` | new | Focused R24.2 test suite (50 tests) |
| `ai/research_agent/discovery_contract.py` | extended | Added `SearchProvider.GENERIC_SEARCH` to complete the closed set |

`git diff --check` is clean.

---

## 3. Provider architecture

### Protocol and base (`provider_base.py`)

- `SearchProviderProtocol` — `discover(query: DiscoveryQuery) -> list[DiscoveredSource]`.
- `BoundedHTTPClient` — injectable transport (`ProviderTransport` callable);
  no caller-supplied headers/cookies/credentials; only a fixed neutral
  `User-Agent` is ever sent. Finite `timeout` (default 10 s) and
  `max_bytes` (default 1 MB, fully honoured). Pre-fetch SSRF guard via
  the existing R23 `validate_source_url`. Host allowlist defense in
  depth. Private / loopback / link-local / multicast / unspecified IP
  literals rejected. Fail-soft: every exception becomes `None`.
- `ProviderResponse` — frozen dataclass (`url, status, body,
  content_type, final_url`); `202 Accepted` is treated as a non-content
  miss so Wordfence/WPScan fail soft on `202` per the R24 scope.
- `make_discovered_source(...)` — single builder enforcing
  `production_finding=False` and applying the R23
  `validate_source_url`. Records `discovered_url` and `final_url`
  separately so R24.3 can attach redirect-chain provenance later.
- `_assert_provider_input_safe(query)` — structural guard: rejects any
  query with a forbidden field (`target_url`, `program`, `asset`,
  `headers`, `cookies`, `credentials`, `endpoint`, `response`,
  `target_host`, `target_ip`, `target`, `url`) or any DNS-style host in
  `inputs_used`. This is a defense-in-depth check on top of the R24.1
  `QueryBuilder` token-level invariant.
- `classify_*_host(host)` helpers and `classify_host(host)` —
  deterministic host → `(SourceCategory, TrustTier)` mapping using the
  R24.1 enum vocabulary.
- `ProviderRegistry` — closed map of provider id → provider. Rejects any
  id not in the R24.1 `SearchProvider` enum; enforces bounded result
  count (`MAX_PROVIDER_RESULTS_PER_QUERY = 10`); force-overrides
  `discovery_provider`/`discovery_query`/`discovery_template_id` so a
  provider cannot relabel provenance; converts any provider exception
  to a `[]` result.
- `build_default_registry(http_client, forbidden_tokens)` — wires
  `providers.build_providers`.

### Concrete providers (`providers.py`)

| Class | Provider id | URL strategy | Category / Tier |
|---|---|---|---|
| `NVDProvider` | `nvd` | NVD REST, MITRE, cve.org | `nvd_cve` / `TRUSTED` |
| `GitHubSearchProvider` | `github_search` | public `/advisories` and `/search/repositories` (no auth) | `github_advisory` / `SEMI_TRUSTED`; `github_repo` / `DISCOVERY_ONLY` |
| `VendorAdvisoryProvider` | `vendor_advisory` | fixed canonical vendor search endpoints (MSRC, Oracle, Red Hat, Adobe, Apache, WordPress.org, Drupal, nginx, Node.js, PHP, Python, cve.org) | `vendor_advisory` / `TRUSTED` |
| `WordfenceProvider` | `wordfence` | `www.wordfence.com/threat-intel/vulnerabilities` | `wordfence` / `SEMI_TRUSTED` |
| `WPScanProvider` | `wpscan` | `wpscan.com/vulnerabilities` | `wpscan` / `SEMI_TRUSTED` |
| `DetectionRuleProvider` | `detection_rule` | public Nuclei-templates / Sigma / YARA indices on github.com (metadata only) | `detection_rule` / `DISCOVERY_ONLY` |
| `GenericSearchProvider` | `generic_search` | `www.google.com/search` | `generic_search` / `GENERIC` |

Each provider conforms to `SearchProviderProtocol`, takes only a
`DiscoveryQuery` as input, and never accepts a target URL/host/IP,
program, asset, endpoint, response, credentials, cookies, or headers.
All provider URLs are fixed canonical public endpoints — no caller-
supplied URL ever reaches the transport.

---

## 4. Endpoint / source strategy

- NVD — three fixed public URLs (NVD REST, MITRE, cve.org) keyed by
  the CVE id extracted from the query text.
- GitHub — public `/advisories` (list) and `/search/repositories`
  (metadata); no auth header; advisory results carry `ghsa_id` and
  `html_url` only; bodies are never inspected.
- Vendor advisory — each canonical vendor host has one fixed search
  template; the provider picks one per query in deterministic order,
  URL-encoding the (already sanitized) query text.
- Wordfence / WPScan — single canonical public index URL each; no
  parameterised search call; classification is purely host-based.
- Detection rule — three fixed public indices (nuclei-templates,
  Sigma, YARA-rules) on github.com; metadata only; **no Nuclei
  execution**, no template download, no body parsing.
- Generic search — fixed `https://www.google.com/search?q=...`; one
  result per query (the deterministic query URL itself); no link
  following.

No recursive crawling, no link following, no authenticated requests,
no arbitrary caller-supplied URLs.

---

## 5. Safety controls

1. **No forbidden input fields.** `_assert_provider_input_safe` rejects
   queries carrying `target_url`, `program`, `asset`, `endpoint`,
   `response`, `credentials`, `cookies`, `headers`, `target_host`,
   `target_ip`, `target`, `url`, or any DNS-style host in
   `inputs_used`. The R24.1 `QueryBuilder` enforces the token-level
   invariant on top of this.
2. **No target in requests.** All transport URLs are fixed canonical
   endpoints chosen by the provider; the test suite asserts that no
   transport call ever targets `dell`, `localhost`, `127.0.0.1`, or
   `192.168.*`.
3. **Bounded.** `MAX_PROVIDER_RESULTS_PER_QUERY = 10`; configurable
   per-call `timeout` (default 10 s) and `max_bytes` (default 1 MB,
   fully honoured, 1-byte floor).
4. **Fail-soft.** Any HTTP error / non-2xx (including 202, 403, 404) /
   transport exception → `[]`. A single provider failure never aborts
   a research run.
5. **No redirect-hop validation.** Redirect chains and DNS
   pre-resolution are deferred to R24.3 and are explicitly out of scope
   here. The transport records `final_url` from its own redirect
   handling but R24.2 does not validate the hop chain.
6. **No credentials / cookies / authenticated GitHub.** The HTTP client
   accepts no caller headers; the test suite asserts the only header
   sent is the fixed neutral `User-Agent` and that no `Authorization`
   or `Cookie` header is ever emitted.
7. **No subprocess / eval / exec / shell.** A static-source scan in the
   test suite asserts no `subprocess`, `eval(`, `exec(`, or
   `os.system(` token appears in `provider_base.py` or `providers.py`.
8. **No 5B–5J imports.** A static-import scan asserts no
   `ai.execution` / `ai.verification` / `ai.finding` / `ai.resolver` /
   `ai.authorizer` / `ai.persistence` / `nuclei_runner` / `selenium` /
   `playwright` / `pyppeteer` / `requests` / `urllib.request` import.
9. **`production_finding = False` always.** Enforced by the
   `make_discovered_source` helper and asserted by the test suite for
   every provider.
10. **Generic results stay GENERIC.** `GenericSearchProvider` always
    emits `category=generic_search`, `tier=GENERIC`; no other code path
    can relabel a generic result.

---

## 6. Bounds (R24 scope §7)

- `MAX_PROVIDER_RESULTS_PER_QUERY = 10` (R24 scope `Results per query = 10`).
- R24.2 does not introduce the loop / round / wall-budget wiring; the
  provider layer honours per-call bounds and is ready to be plugged
  into the R24.6 loop with the larger R24 limits (12 queries/plan,
  40 queries/run, 40 sources/plan) applied at the call site.
- No recursive discovery, no unbounded pagination, no streaming,
  no shell execution.

---

## 7. Tests and verification

### Commands and results

```
python3 -m unittest tests.test_research_agent             → 92 OK (R23 unchanged)
python3 -m unittest tests.test_research_agent_r24_1       → 43 OK (R24.1 unchanged)
python3 -m unittest tests.test_research_agent_r24_2       → 50 OK (R24.2 new)
python3 -m unittest tests.test_research_agent tests.test_research_agent_r24_1 tests.test_research_agent_r24_2
                                                         → 185 OK
git diff --check                                         → clean
```

All tests pass; no unrelated pre-existing failures were touched.

### R24.2 test coverage (`tests/test_research_agent_r24_2.py`, 50 tests)

- Provider registry contains exactly the seven allowed provider ids
  (matches the `SearchProvider` enum); no additional identifiers are
  introduced.
- Unknown provider id → `[]` (fail-soft).
- Each provider accepts a `DiscoveryQuery` and preserves provenance
  (`query_id`, `template_id`, `provider`, `query`).
- Category/tier classification for every provider.
- Bounded result count (50-item payload → ≤ 10).
- Response body truncated at `max_bytes` (50 KB body / 64-byte cap →
  ≤ 64 bytes).
- Provider timeout propagates to transport.
- Transport failure / non-2xx / 403 / 404 / 202 → empty result; the
  run never aborts.
- Provider exception → empty result.
- Non-CVE NVD query → empty result.
- Forbidden program token in URL → client rejects.
- DNS-style host in `inputs_used` → `_assert_provider_input_safe`
  raises `ForbiddenInputError`; registry `discover()` returns `[]`.
- No target/program host appears in transport calls.
- DetectionRuleProvider has no `nuclei_runner` / 5B–5J / `subprocess` /
  `eval(` / `exec(` / `os.system(` static-import or string token.
- GenericSearchProvider stays `GENERIC_SEARCH` / `GENERIC`.
- GitHubSearchProvider sends only the fixed neutral `User-Agent` (no
  `Authorization`, `Cookie`, `X-GitHub-Token`, etc.).
- No `follow_links` / `recursive` / `crawl` code paths (docstrings
  excluded).
- `production_finding` always False across every provider.
- Static import-boundary scan: no forbidden modules imported.
- HTTP client rejects `localhost`, RFC1918 IPs (`192.168.1.1`),
  metadata IP (`169.254.169.254`), `file://`, and hosts outside the
  per-provider allowlist.
- `DiscoveredSource.to_r23()` still produces a valid R23
  `ResearchAgentSource` (regression check).
- All transport is mocked via a fake callable injected into
  `BoundedHTTPClient`; the test suite never touches the live network.

---

## 8. Live network smoke test

**Not performed.** R24.2 explicitly does not run a broad real research
run. The implementation is transport-injected; tests use a fake
`ProviderTransport`. The single network-eligible path is the
`BoundedHTTPClient.request` method, which has been verified offline
against:

- localhost / RFC1918 / metadata-IP rejection;
- off-allowlist host rejection;
- finite timeout and body-size cap enforcement;
- fail-soft on transport failure.

The default transport is `None`, so calling any provider with the
default client returns `[]` — the run is fully offline.

---

## 9. Explicit confirmations

- **R23 unchanged.** `ai/research_agent/{agent,scheduler,storage,sources,prompts}.py`,
  `ai/schemas/research_agent.py`, and the entire R23 test suite
  (92 tests) pass byte-for-byte as before.
- **R24.1 unchanged in behaviour.** The R24.1 contract files were
  preserved; the only edit was an additive enum member
  (`SearchProvider.GENERIC_SEARCH`) that completes the closed
  identifier set required by the R24 scope. The 43-test R24.1 suite
  passes unmodified.
- **No scheduler / systemd / timer changes.** `WATCH_RESEARCH_DISCOVERY`
  is not wired anywhere in R24.2. No systemd unit, timer, or `*.sh`
  script was modified.
- **No database change.** `database/db.py` was not touched.
- **No target interaction.** No provider is given a target URL/host/IP;
  no transport call is directed at a program/asset host; the SSRF
  guard rejects any such attempt.
- **No 5B–5J coupling.** The new modules import only stdlib + pydantic +
  the R24.1 contract + the R23 neutral URL validator + the new
  internal modules. Static-import scan enforces this.
- **No findings / alerts.** No finding/alert writer is invoked; every
  emitted `DiscoveredSource` carries `production_finding=False` and
  `status=STORED_ONLY`.

---

## 10. Known limitations deferred to R24.3+

- **R24.3 — URL / Redirect Hardening.** Manual redirect handling,
  hop-by-hop SSRF guard, DNS pre-resolution, scheme-downgrade
  rejection, port-change rejection, embedded-credentials rejection,
  program-host rejection at every hop, `MAX_REDIRECTS = 3`, and full
  redirect-chain provenance on `redirect_chain` / `final_url`.
- **R24.4 — Source Ranking & Dedup.** Deterministic ranking
  (`TIER_BASE` + category/signal bonuses + penalties) and the
  canonical-URL / content-hash dedup ledger.
- **R24.5 — Evidence Integration.** Lifecycle transitions
  (`DISCOVERED_SOURCE → FETCHED_SOURCE → RELEVANT_SOURCE → EVIDENCE`),
  grounded evidence mapping onto `sources[]` / `evidence[]`, additive
  result `discovery` block.
- **R24.6 — LLM Research Loop.** Bounded two-round
  discover→rank→validate→fetch→extract→analyze→gap loop; gap-directed
  queries; LLM is never authoritative; verdict language is scrubbed.
- **R24.8 — Scheduler Integration.** Wire
  `WATCH_RESEARCH_DISCOVERY` through the existing
  `SchedulerConfig`/agent construction; no new timer, no systemd edit;
  flag-off = R23 behaviour.

---

## 11. Next-stage recommendation

**R24.3 — URL / Redirect Hardening (`ai/research_agent/netguard.py`).**
Implement:

1. A pre-fetch DNS-resolution check that rejects any host whose
   resolved A/AAAA record is private/loopback/link-local/reserved/
   metadata.
2. Manual redirect handling (`follow_redirects=False`) with a
   hop-by-hop validator that re-runs the full SSRF guard at every
   hop, rejects scheme downgrades, port changes, URL-embedded
   credentials, and program/asset hosts.
3. `MAX_REDIRECTS = 3` (4th redirect is a hard stop → source is
   `REJECTED`/`REDIRECT_LIMIT`).
4. Full hop chain recorded in provenance (`redirect_chain[]`,
   `final_url`); the trusted content hash is always computed over the
   final fetched body.
5. R24.2's `BoundedHTTPClient` is the natural seam: a future PR can
   either replace it with a redirect-aware variant or wrap its
   `request` method with a manual `Location` validator.

R24.3 must remain independent of the R24.2 import boundary and must
not import any 5B–5J module.

---

## Agent / Model
- Model: claude-sonnet-4-20250514 (Cline)
- Stage: R24.2
- Role: Search Providers
