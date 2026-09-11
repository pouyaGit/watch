# Stage R24.1 — Source Discovery Contract

Status: **CONTRACT ONLY.** No network, no provider calls, no URL fetches, no
discovery execution, no systemd/scheduler change, no LLM, no Nuclei, no PoC, no
browser automation, no 5B–5J, no `database/db.py`, and no Git operations
(no commit/push). R23 behavior is byte-for-byte unchanged.

---

## 1. Files changed

All changes are **additive** — only new files were created; no existing tracked
file was modified.

| File | Kind | Purpose |
|---|---|---|
| `ai/research_agent/discovery_contract.py` | new | Deterministic contract/data model: enums, `DiscoveryQuery`, `DiscoveredSource`, forbidden-input invariant, deterministic ids |
| `ai/research_agent/queries.py` | new | Deterministic query-builder primitives: sanitization, `CVEResearchMetadata`, fixed template IDs, `QueryBuilder` |
| `tests/test_research_agent_r24_1.py` | new | Focused R24.1 test suite (43 tests) |

No changes were made to `ai/schemas/research_agent.py`, `sources.py`, `agent.py`,
`scheduler.py`, `storage.py`, any backend, `database/db.py`, or any tracked
test. The pre-existing working-tree modifications to unrelated tracked files
(`tests/test_research_ui.py`, `tests/test_research_navigation.py`,
`tests/test_xss_llm_dashboard.py`, backend/web templates) were present *before*
this task and were not touched.

---

## 2. Contracts implemented

### `discovery_contract.py`

- **`SourceCategory`** (str enum) — exact values:
  `nvd_cve, vendor_advisory, wordfence, wpscan, github_advisory, github_repo,
  detection_rule, exploit_reference, writeup, security_blog, generic_search`.
- **`TrustTier`** (str enum) — exact values:
  `TRUSTED, SEMI_TRUSTED, DISCOVERY_ONLY, GENERIC`.
- **`Lifecycle`** (str enum) — exact values:
  `DISCOVERED_SOURCE, FETCHED_SOURCE, RELEVANT_SOURCE, EVIDENCE, UNKNOWN,
  INFERENCE`.
- **`SearchProvider`** (str enum) — closed provider identifiers for future
  R24.2 (`nvd, github_search, vendor_advisory, wordfence, wpscan,
  detection_rule, generic_search`).
- **`DiscoveryQuery`** (pydantic) — deterministic provenance:
  `query_id, template_id, provider, query, inputs_used`. **No**
  target/program/asset input fields. `production_finding` forced `False`;
  provider-syntax-altering quotes rejected.
- **`DiscoveredSource`** (pydantic) — all R24 additive fields (`source_id`,
  `lifecycle`, `category`, `tier`, `source_quality`, `discovery_provider`,
  `discovery_query`, `discovery_template_id`, `discovered_url`, `final_url`,
  `redirect_chain`, `aliases`, `extraction_method`) **plus** the minimum
  identity/status fields required by R23 serialization (`url`, `source_type`,
  `status`, `title`, `content_hash`, `char_count`, `note`). Provides
  `to_r23()` to map onto the existing R23 `ResearchAgentSource` unchanged.
- **Forbidden-input invariant** — `ForbiddenInputError`,
  `contains_forbidden_token`, `assert_no_forbidden_input` (whole-token,
  word-boundary, case-insensitive; host labels expanded except generic TLDs and
  all-numeric IP octets).
- **Deterministic ids** — `query_id_for(...)` and `discovered_source_id(url)`
  (SHA-256 over canonicalized provenance; prefixes `q-` / `ds-` distinct from
  R23 `src-`).

### `queries.py`

- `sanitize_query(...)` — control characters removed, quotes/backslash removed,
  whitespace collapsed, bounded to `MAX_QUERY_CHARS = 200`.
- `normalize_cve_id(...)` — deterministic `CVE-\d{4,}-\d+` normalization.
- **`CVEResearchMetadata`** (frozen dataclass) — accepts **only** allowed CVE
  research metadata: `cve_id, product, component, parameter, version, cwe,
  vulnerability_type, existing_references`. Forbidden fields (program, target,
  asset, target URL/host/IP, endpoint, response, credentials, cookies, headers)
  have no representation, so they are rejected structurally (TypeError).
- **Fixed template IDs** (12) matching R24 scope §3.2, in deterministic order.
- **`QueryBuilder`** — deterministic, total function of the metadata: no clock,
  no randomness, no timestamps, no model-generated queries. Emits queries in the
  fixed template order with deduplicated/sorted `inputs_used`.

---

## 3. Invariants

1. **Forbidden-input invariant** — a rendered query or supplied input containing
   any supplied program/asset host/token raises `ForbiddenInputError`
   (fail-closed); the program name is only ever an exclusion filter, never a
   query term.
2. **Structural input boundary** — `CVEResearchMetadata` cannot carry
   program/target/asset/credentials/headers fields at all.
3. **Determinism** — query construction is a total function of inputs; ids and
   ordering are stable; no randomness, clock, timestamps, or model.
4. **Bounded output** — every query ≤ 200 chars; every input value ≤ 64 chars.
5. **Schema safety** — `production_finding` forced `False`; statuses must be in
   the R23 `SOURCE_STATES` vocabulary; VULNERABLE / VERIFIED / EXPLOITED /
   FINDING are never affirmative result states.

---

## 4. Backward compatibility

- No existing R23 schema was changed; no R23 result file, service, or timer was
  touched.
- `DiscoveredSource.to_r23()` returns a valid R23 `ResearchAgentSource` carrying
  only the R23-compatible subset (identity/status preserved), so R24 lifecycle
  can later be mapped onto R23 `sources[]` without altering R23 behavior.
- `status` is constrained to the exact R23 `SOURCE_STATES` set; defaults mirror
  R23 (`STORED_ONLY`).
- The existing `python3 -m unittest tests.test_research_agent` suite still
  passes (92 tests).

---

## 5. Tests

New suite `tests/test_research_agent_r24_1.py` (43 tests) covers:

- exact enum values
- deterministic query IDs
- deterministic query ordering / unique ids
- query sanitization (control chars, whitespace collapse, quotes removed,
  200-char bound, empty/None)
- allowed CVE metadata inputs + structural rejection of program/target/headers
- forbidden-input invariant (whole-word token, host labels sans TLD, exact IP,
  builder rejection, target-host leakage prevention)
- duplicate-input normalization (reference dedup, sorted inputs)
- empty/invalid metadata handling (empty → no queries, invalid CVE skipped)
- schema serialization (both models round-trip JSON)
- production_finding safety (forced False, forbidden state absence)
- import boundary (static scan: no `ai.execution`/`verification`/`finding`/
  `resolver`/`authorizer`/`persistence`/`nuclei_runner`/browser/`subprocess`/
  `requests`/`httpx`/`socket`/`urllib`; only allowed imports; no `eval(`/`exec(`)
- compatibility with existing R23 structures (`to_r23`, R23 status vocabulary)

Commands (all pass):

```
python3 -m unittest tests.test_research_agent            # 92 OK (unchanged)
python3 -m unittest tests.test_research_agent_r24_1      # 43 OK (new)
python3 -m unittest tests.test_research_agent tests.test_research_agent_r24_1  # 135 OK
git diff --check                                          # clean
```

No unrelated failing tests were modified.

---

## 6. Security review

- **No target discovery / no HTTP / no DNS / no redirects** — contract only;
  those are deferred to R24.3.
- **No unbounded expansion** — fixed template count, bounded values/length,
  deterministic ordering.
- **No secret handling** — credentials/cookies/headers are structurally
  excluded and never logged or embedded.
- **No code execution** — no `subprocess`/`eval`/`exec` on any content.
- **No 5B–5J coupling** — modules import only stdlib + pydantic + the neutral R23
  schema constants + deterministic canonicalization/hash helpers.
- **Fail-closed** — forbidden-token presence rejects the query rather than
  silently permitting it.

---

## 7. Explicit confirmation: NO NETWORK

This stage performs **no** network request of any kind. The new modules define
data structures and string transformation only. They import no HTTP/DNS/socket
client and issue no I/O at import, build, or test time. All tests run offline.

## 8. Explicit confirmation: R23 timer untouched

`watch-research.service` and `watch-research.timer` were **not** modified, and no
new timer/unit was created. The R23 `SchedulerConfig` defaults and scheduler
behavior are unchanged (existing scheduler tests still pass).
`WATCH_RESEARCH_DISCOVERY` is not wired anywhere; discovery is not enabled.

---

## 9. Remaining limitations (out of scope → later stages)

- No search providers / provider protocol instantiation (R24.2).
- No HTTP client, DNS resolution, or redirect-hop guard (R24.3).
- No ranking score or `source_quality` computation; it is a stored field only
  (R24.4).
- No canonical-URL/content-hash dedup ledger and no lifecycle transitions
  (R24.4/R24.5).
- No evidence mapping or `ResearchAgentSource`/`Result` schema additions — the
  R24.1 contract only declares the `DiscoveredSource` model and an explicit
  `to_r23()` bridge; schema field additions land in R24.5 additively.
- No model-generated query support (R24.6); `QueryBuilder` is strictly
  deterministic.
- `SourceCategory`/`TrustTier` are closed enums for later host-allowlist
  classification (`classify_source` reuse lands in R24.4).

---

## Agent / Model
- Model: claude-sonnet-4-20250514 (Cline)
- Stage: R24.1
- Role: Source Discovery Contract