# Stage R24.6 — LLM Research Loop

**Status: PASS.**

Implemented the bounded, evidence-grounded R24 research loop. This is the first
stage that allows the LLM into the R24 discovery pipeline, under a strict
public-research-only boundary. R23 behavior is unchanged, R24.1–R24.5 are
untouched, `WATCH_RESEARCH_DISCOVERY` remains unset/off, and no scheduler,
systemd, timer, database, target, or 5B–5J surface was modified.

---

## 1. Files changed (all new additions)

| File | Change |
|---|---|
| `ai/research_agent/llm_research.py` | **New.** Sanitized LLM context, prompt builder, strict output contract, attribution/grounding validation, verdict sanitization, query-suggestion safety/mapping. |
| `ai/research_agent/llm_loop.py` | **New.** Bounded round-1/round-2 orchestration, budget tracker, loop result models, fail-soft handling. |
| `ai/research_agent/storage.py` | **Additive only** (+127/−0): `research_loop_path`, `store_research_loop`, `load_research_loop`. No existing function altered. |
| `tests/test_research_agent_r24_6.py` | **New.** 49 offline tests. |
| `agent-reports/stage-r24-6-llm-research-loop.md` | This report. |

`git diff --check` → clean (rc=0). `ai/research_agent/storage.py` diff:
`1 file changed, 127 insertions(+)`.

---

## 2. Architecture

```
R22 plan + CVEResearchMetadata
  └─ QueryBuilder (R24.1) ──────────────► deterministic DiscoveryQuery[]
       └─ ProviderRegistry (R24.2) ─────► DiscoveredSource[]        (fail-soft)
            └─ rank_sources (R24.4) ────► source_quality assigned
                 └─ dedup_discovered_sources (R24.4) ──► canonical sources
                      └─ injected fetcher ──► materialized content + trusted hash
                           └─ integrate_discovery (R24.5) ──► DiscoveryBlock
                                └─ build_llm_context ──► ResearchLLMContext (public only)
                                     └─ LLM analysis (existing provider)
                                          └─ validate_and_sanitize_analysis
                                               └─ gap detection
                                                    └─ ONE bounded round 2
                                                         └─ LLMResearchLoopResult
```

`run_llm_research_loop(plan, metadata, registry, fetcher, llm, ...)` receives
every external dependency by injection. This module performs no network itself;
tests use fake registry/fetcher/LLM.

---

## 3. LLM context boundary

`ResearchLLMContext` (and `ResearchContextSource` / `ResearchContextEvidence`)
structurally contain only: CVE id, product, component, parameter, version, CWE,
vulnerability type, existing public references, deterministic unknowns, public
source metadata (id, canonical URL, title, category, tier, quality, hash,
provider/query/template), bounded source content, and grounded evidence.

- `FORBIDDEN_CONTEXT_FIELDS` = `{program, target, asset, target_url, target_host,
  target_ip, endpoint, response, credentials, cookies, headers, authorization,
  cookie, credential}`; asserted disjoint from all context model fields.
- Program/asset tokens are used **only** as an exclusion filter:
  `build_llm_context` drops any source/evidence whose text contains a forbidden
  token (counted in `excluded_forbidden`) — it never enters the prompt.
- `assert_context_safe(context, forbidden_tokens)` raises if a forbidden field
  or token is present.
- `public_research_only=True` and `production_finding=False` are enforced.

---

## 4. Output schema

Strict Pydantic models: `LLMAnalysis` (summary, supported_claims, inferences,
unknowns, contradictions, gaps, suggested_queries), `LLMSupportedClaim`
(claim, evidence_ids, source_ids, confidence, quote), `LLMInference`,
`LLMContradiction`. Missing fields default; malformed/non-object JSON raises
(`parse_llm_analysis` via the existing `parse_llm_json`) and is never treated as
success. Extra keys (e.g. fabricated `content_hash`, `source_url`) are ignored.

---

## 5. Attribution rules

`validate_and_sanitize_analysis` drops or downgrades:

- unknown `evidence_id`/`source_id` → drop (recorded);
- no attribution at all → downgrade to UNKNOWN;
- invented URL not present in the supplied context → drop;
- claim not grounded in the referenced supplied text (normalized substring or
  significant-token overlap) → downgrade to UNKNOWN;
- duplicate claims deduplicated.

Inferences with unknown attribution are dropped; contradictions with unknown
source ids are dropped (valid contradictions preserve both source ids). LLM
output never becomes evidence and never changes a source's lifecycle.

---

## 6. Verdict sanitization

`find_forbidden_terms` (VULNERABLE / VERIFIED / EXPLOITED / FINDING) is applied
to every claim, inference, contradiction, summary, gap and suggestion.
Offending items are dropped; a verdict-bearing summary is cleared. The result
stays explicitly `public_research_only`; the prompt forbids target-verdict
language. Trust tier/category are deterministic provider properties and are
never derived from LLM output.

---

## 7. Round-1 flow

Build the fixed template queries (R24.1) → discover via the registry (R24.2,
fail-soft) → rank (R24.4) → dedup (R24.4) → fetch/materialize top sources via
the injected fetcher (R24.3 hardening is the fetcher's responsibility; the loop
attaches `final_url`/`redirect_chain` and trusted hash via `with_content_hash`)
→ integrate evidence (R24.5) → build sanitized context → one LLM analysis call →
gap detection. Round 1 uses at most `max_queries_per_plan − round2_reserve`
queries.

## 8. Round-2 flow

Runs only when round-1 gaps exist, `max_rounds ≥ 2`, and query/discovery budgets
remain. Queries are built by `_round2_queries`: model `suggested_queries` are
first validated (`is_safe_suggested_query`) and mapped to an **approved R24.1
template** (`map_suggestion_to_discovery_query`); the model never supplies a
provider, URL, or free-form query. If no safe suggestion selects a new template,
remaining unused templates are used in fixed order. Round 2 repeats
discover→rank→dedup→fetch→integrate→analysis under the remaining budget. A
round-2 failure leaves the round-1 result intact.

## 9. Query safety

`is_safe_suggested_query` rejects (never silently sanitizes) any suggestion
containing a forbidden program/asset token, URL (`://`), host-like token, IP
literal, endpoint/path (`/`, `?`, `:`), credentials marker (`@`), or the words
target/program/asset/endpoint/response/credential/cookie/header/authorization.
Accepted suggestions only select among the fixed `QueryBuilder` templates, and
all rendered queries pass the R24.1 `assert_no_forbidden_input` invariant.

## 10. Source trust rules

Trust tier and category come from the R24.2 provider classification and are
never modified by the LLM or the loop. Tests confirm a GENERIC source stays
GENERIC and a DISCOVERY_ONLY detection rule stays DISCOVERY_ONLY (and produces
no evidence) unless the existing R24.4 eligibility condition (explicit
authoritative advisory reference) is satisfied. The LLM analysis model has no
field capable of redefining trust.

## 11. Evidence integration

Evidence is produced only by R24.5 `integrate_discovery`, from fetched,
hash-verified sources; the LLM analysis is stored separately and is never
evidence. If attribution fails, the item becomes UNKNOWN and no evidence is
created and no lifecycle upgraded.

## 12. Failure handling (all fail-soft)

| Failure | Behavior |
|---|---|
| Provider failure | other providers continue; recorded in `provider_failures` |
| DNS/URL failure | source rejected (R24.3 fetcher); non-evidence |
| Fetch failure | source marked `FAILED`; no evidence |
| LLM timeout/error | `llm_status="failed"`, key-free `llm_error`, deterministic evidence preserved |
| LLM malformed JSON | `llm_status="failed"`; evidence preserved |
| LLM hallucinated source/evidence id | dropped |
| LLM invented evidence/URL/hash | dropped/ignored |
| LLM forbidden target content | affected item rejected; summary cleared |
| Second-round failure | round-1 result preserved |
| No evidence at all | `RESEARCH_PARTIAL`/`RESEARCH_BLOCKED`, never fabricated success |

## 13. Resource bounds (`LoopBudgets`, all enforced)

`max_rounds=2`, `max_queries_per_plan=12`, `max_queries_per_run=40`,
`max_discovered=40`, `max_fetched_per_plan=12`, `max_fetched_per_run=40`,
`max_bytes_per_source=2_000_000`, `max_bytes_per_run=8_000_000`,
`max_llm_calls_per_plan=2`, `max_llm_calls_per_run=3`. A shared `BudgetTracker`
accounts run-level usage across plans.

## 14. Storage

Additive, atomic, idempotent `ai_data/research/agent/<plan>.r24-loop-1.loop.json`
holding rounds (number, queries, provider failures, counts, `DiscoveryBlock`),
LLM analysis, gaps, unknowns, inferences, provider failures, status and
budgets. Model id and rule versions are persisted; **no API keys are ever
persisted** (tested). R23 results and R24.5 discovery blocks are untouched.

---

## 15. Exact test results

| Suite | Result |
|---|---|
| `tests.test_research_agent` | **92 OK** |
| `tests.test_research_agent_r24_1` | **43 OK** |
| `tests.test_research_agent_r24_2` | **50 OK** |
| `tests.test_research_agent_r24_3` | **80 OK** |
| `tests.test_research_agent_r24_4` | **71 OK** |
| `tests.test_research_agent_r24_5` | **38 OK** |
| `tests.test_research_agent_r24_6` | **49 OK** |

Combined:

```
python3 -m unittest \
  tests.test_research_agent tests.test_research_agent_r24_1 \
  tests.test_research_agent_r24_2 tests.test_research_agent_r24_3 \
  tests.test_research_agent_r24_4 tests.test_research_agent_r24_5 \
  tests.test_research_agent_r24_6
→ Ran 423 tests ... OK
```

`git diff --check` → clean.

New R24.6 coverage: LLM context allowed/forbidden fields and token exclusion;
output validation (valid, malformed, missing, invented source/evidence/URL/hash,
unsupported downgrade, attribution); verdict sanitization (VULNERABLE / VERIFIED
/ EXPLOITED / FINDING / target verdict); trust immutability; LLM cannot create
evidence; round-1, gaps-only round-2, max-2-rounds, round-2 failure preserves
round-1; provider/fetch/LLM fail-soft; query/discovered/byte limits; forbidden
suggestion rejected; provenance; detection-rule trust; storage + no-secret; static
import/exec/network boundary; R23 + R24.1–R24.5 compatibility.

---

## 16. Network status

**ZERO live network in R24.6 and in the test suite.** All providers, transport/
DNS, fetcher and LLM are injected fakes; no API keys are present in tests. A
runtime test patches `socket.socket` to raise during a loop run. No broad real
research run was performed (a real smoke test was optional and not required).

## 17. R23 / R24.1–R24.5 compatibility

No R23 or R24.1–R24.5 file was edited except the purely additive storage
functions. All prior suites pass unchanged (counts above). R24.6 imports and
reuses their contracts without duplicating ranking, canonicalization, dedup or
evidence eligibility.

## 18. Scheduler / systemd status

`watch-research.service` and `watch-research.timer` were not touched; no
scheduler default changed; `WATCH_RESEARCH_DISCOVERY` remains unset (off); R24.6
is not wired into `ResearchAgent`/scheduler (deferred to R24.8).

## 19. Target-interaction status

**None.** No target/program/asset was contacted. Program name is used only as an
exclusion filter and is filtered out of the LLM context. No target URLs/hosts/
IPs/endpoints/responses/credentials/cookies/headers reach the LLM.

## 20. 5B–5J status

**Not touched.** No verifier, finding, alert, execution, resolver, authorizer,
persistence, Nuclei, PoC, or browser surface is imported or invoked; static
import-boundary tests assert this for the new modules.

---

## 21. Known limitations

- **Not wired into the scheduler/R23 agent** — R24.6 exposes the loop API; wiring
  under the (off) discovery flag is R24.8.
- **Claim grounding is structural** (substring/token overlap), not semantic
  verification; paraphrase-heavy claims may be conservatively downgraded.
- **Contradiction resolution is preserved, not adjudicated** (by design; the LLM
  never wins).
- **The default fetcher is injected**; R24.6 does not itself construct an HTTP
  transport, so a real deployment must wire the R24.3 `netguard`-backed fetcher.
- **Budget split**: round 1 reserves `round2_reserve` query slots so a second
  round can run without exceeding the per-plan cap.

## 22. Next-stage recommendation

Proceed to **R24.7 — Controlled Real Research** (tiny, bounded, target-isolated
smoke over public sources using the R24.3 fetcher and the existing OpenRouter
provider), then **R24.8 — Scheduler Integration** to wire
`WATCH_RESEARCH_DISCOVERY` through the existing R23 scheduler/timer (no second
timer). Keep defaults off until R24.7 validates, and keep production_finding
False throughout.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R24.6
- Role: LLM Research Loop
