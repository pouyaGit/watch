# WATCH-AI-AGENT-INTELLIGENCE-V1 — Discovery & Delivery Report

Epic: add REAL LLM intelligence to the deployed AI Agent Runtime v1,
free-only (OpenRouter `openrouter/free`), XSS specialist first.

## Phase 0 — verified current architecture (as deployed at `1b17cf2`)

| Component | Verified state | Disposition |
|---|---|---|
| `backend/research_agents/runtime.py` | `AgentWorker` phases: claim → authz → knowledge → observations → deterministic analysis → optional LLM → evidence rows → case gate → result → activity; `RuntimeConfig` carries `llm_provider_kind/llm_model/llm_timeout` | extended in place (no parallel subsystem) |
| `runtime_store.py` | flock-atomic queue/leases/audit JSONL/evidence/cases/knowledge/activity | unchanged |
| `capabilities.py` | 8 specialist definitions incl. `evidence_requirements` + `output_schema` | unchanged |
| `cli.py` | bounded `run --max-jobs/--llm/--model`, `status`, `enqueue`, `cancel` | unchanged (env-driven free mode) |
| `ai.providers.select_provider` | explicit-kind fail-closed factory; `OpenRouterProvider` = `RealAdvisoryProvider` (base `https://openrouter.ai/api/v1`, key env-only, explicit timeout, bounded retries, strict JSON response validation, telemetry envelope `{response, error, telemetry, _exception}`) | reused as the ONLY provider path |
| `llm_reliability.call_llm` | string-in/string-out helper for simple providers | not used by the runtime anymore: the real provider speaks the R45/R51 advisory request/response contract via `complete(request)`; `call_llm` would feed it a raw string (would classify non-envelope output as malformed) |
| Existing OpenRouter support | R51 `export_real_llm_advisory` proves the real contract end-to-end | used as the reference pattern |
| Configuration/secrets | `/opt/watch/.env` defines `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`, `OPENROUTER_MAX_TOKENS`; agent env itself carries no key | key read only inside provider via env; never passed through runtime code, never persisted |
| Structured output | `parse_advisory_content` = strict project contract `{summary, insights[{insight_code,text}], recommendations[{recommendation_code,text}]}` (≤8 items, exact keys, bounded text, no URLs) | this IS the project's structured-output convention (Epic allows schema adaptation) |
| XSS e2e path | job → capability `xss-agent` → `ReadStoreObservations` (Urls/Endpoints/Http params+headers, bounded 50) → knowledge loader (`list_kb`) → analysis → gate | extended with the LLM stage between observations and gate |

### Critical Phase-0 findings
1. **The old raw-prompt path could not work against the real provider**
   (`call_llm` + JSON-string schema ≠ advisory contract). Replaced with the
   real `provider.complete(request)` envelope path.
2. **The R51 allowlist forbids URLs/credential-shaped content outbound**
   (`SENSITIVE_RULES` → `ProviderContextRejected`). Observation context is
   therefore carried as URL-free structural facts (internal ref, parameter
   names, status) — proven by a test running the REAL
   `sanitize_provider_context`.
3. **`/opt/watch/.env` sets `OPENROUTER_MODEL` to a different free-model
   id** (`nvidia/…:free`). Free-only guard rejects any env model ≠
   `openrouter/free` — the first real job must source the key and pin
   `OPENROUTER_MODEL=openrouter/free`.

## Phase 1 — free-only provider & guard (`llm_guard.py`)
- Allowed path is exactly `OPENROUTER` + `openrouter/free`; base URL must
  be `https://openrouter.ai…` when set; key must exist (presence only).
- `WATCH_AGENT_LLM_MODE`: `free` (default) or `off`; any other value fails
  closed. Paid/unknown model, wrong provider, env-model injection,
  missing key → `FreeOnlyViolation` → `AnalysisUnavailable(free_only:…)`
  → existing retry policy → `FAILED/TERMINAL_FAILED`. **No fallback branch
  exists anywhere.**
- `llm_indicator()` = safe config projection (`LLM: OpenRouter Free ·
  Model: openrouter/free · key configured/missing`) — never the key.

## Phase 2 — free router, resolved-model honesty
- Requested model always `openrouter/free` (explicit `model=` kwarg to
  `select_provider`; env cannot override the guard).
- Persisted: requested model, `resolved_model` (from provider telemetry
  when exposed, else literal `not_exposed_by_contract` — never invented),
  provider label, request id (when exposed), latency `analysis_ms`,
  usage (when exposed, else `null`), prompt version, free-only rule id.
- Never persisted: key, Authorization header, request payloads.

## Phase 3 — structured analysis schema (validated, input-only)
`structured` persisted on `ResearchResult` with at minimum:
`hypothesis, vulnerability_class, observations_considered,
evidence_required, evidence_present, confidence, blockers,
reasoning_summary, recommended_next_observation, verdict` (+ raw
`llm_insights/llm_recommendations`, resolved model, usage, latency).
- Response validation mirrors the R45 validator + strict item shapes;
  any violation → `schema_failure` → retry policy, never a degraded guess.
- `confidence` inside structured = deterministic gate value; `verdict`
  vocabulary is ours (`evidence_sufficient_for_review |
  needs_more_observation | insufficient_evidence`) — no LLM-issued
  "confirmed" verdict can exist.

## Phase 4/5 — bounded authorized context + knowledge
- `_advisory_request`: mission, specialization, structural observation
  facts (≤4), knowledge excerpts (≤3 × ≤400 chars, only docs the loader
  actually read), deterministic evidence candidates, all through the
  REAL allowlist; explicit `context_max_chars` budget (default 4000 =
  provider ceiling) → `context_too_large` fail-closed.
- Knowledge loader now carries each document's bounded `summary`
  excerpt; `knowledge_used` rows are recorded only for documents loaded.

## Phase 6/7 — XSS first, prompt versioning
- Only the `xss-agent` path is exercised end-to-end; other specialists
  share the same capability/provider abstraction untouched.
- Prompt identity: instruction carries agent identity, mission,
  advisory-only rules, evidence-gate rule, output contract, and
  `xss-agent-analysis-v1`; `prompt_version` persisted on every LLM
  analysis (result + activity + SOC).

## Phase 8/14 — failure handling (auditable kinds)
`free_only, context_too_large, provider_configuration, llm_timeout,
llm_rate_limit, llm_auth, llm_empty_response, llm_context_rejected,
llm_schema_failure, llm_provider_unavailable, llm_provider_error` — each
raises `AnalysisUnavailable` → job fails → retry per existing policy →
terminal; `llm_analysis_failed` + `job_failed` activity rows and audit
entries record the reason; no result is ever written; deterministic
output is never relabeled as an LLM result.

## Phase 9 — cost guard tests
Paid model / other-free-model id / wrong provider / missing key /
env-model injection / mode off / invalid mode all rejected with the
provider **never constructed** (call count 0); accepted configs always
resolve to exactly `openrouter/free`; logs/state/result scans contain no
key material; indicator shows label+model+key-configured boolean only.

## Phase 10 — resource control
Concurrency 1, one bounded job, provider called with
`max_retries=0, retry_backoff_seconds=0` (single HTTP attempt per job
attempt; retry loop is the job-level policy only), bounded context,
bounded output (provider `max_tokens` bound), strict timeout, no
persistent worker; wall/CPU/RSS/latency/usage captured per run.

## Phase 11 — SOC exposure
- Runtime banner (index + detail): `LLM: OpenRouter Free · model
  openrouter/free · key configured/missing` (+ failure reason when the
  guard blocks).
- Agent Detail new "Agent research runtime" section: last analysis
  (prompt version, provider, requested/resolved model, latency,
  confidence, verdict, hypothesis, reasoning, usage), research jobs,
  knowledge actually used, case/evidence counts.
- Activity distinguishes: `observations_loaded`,
  `llm_analysis_started/completed/failed`, `evidence_gate_evaluated`,
  `analysis_completed`, `job_completed/failed` (+ queued/claimed/running).

## Phase 12 — case/evidence safety
LLM merges reasoning text only: `confidence`, `blockers`,
`evidence_candidates` stay deterministic; the gate reads deterministic
values; tests prove an LLM hypothesis cannot create or upgrade a case.

## Honest deviations
- Resolved-model/request-id/usage are recorded only if the provider
  contract exposes them; otherwise explicit `not_exposed_by_contract` /
  `null` (R51 telemetry exposes attempts/chars, not token usage).
- `llm_reliability.call_llm` remains for R-series callers but the
  runtime uses `complete()` directly because the real provider's
  contract is envelope-based (Phase-0 finding #1).
- `backend/routers/research_agents.py` still ships unmounted.

## First real LLM job — attempt 1 and the contract defect (recorded)

Job `job-xss-c70608036a` (XSS, `xss-agent`, program dell,
`www.dell.com`, scope `watch:scope:dell/www.dell.com`, production,
priority 70, timeout 120) ran bounded with `--max-jobs 1 --llm OPENROUTER`,
key sourced from `/opt/watch/.env` with `OPENROUTER_MODEL` pinned to
`openrouter/free` (the `.env` default `nvidia/…:free` is rejected by the
guard). Wall 47.8 s, CPU 1.3 s, peak RSS ~65 MB, exit 0.

What worked: claim → authz → 50 observations → 5 real knowledge documents
read → `llm_analysis_started (OpenRouter openrouter/free
xss-agent-analysis-v1)` → failure path fail-closed: no evidence, no case,
no result, `llm_analysis_failed` + `job_failed` audit + automatic retry
requeue (attempt 1/3, no fake output anywhere).

**Concrete runtime defect found:** the attempt's reason was
`llm_provider_error: ` (empty). Diagnosis (no mocks): endpoint reachable
(HTTPS 200 in 0.21 s) and a bounded real `complete()` diagnostic returned
in 14.1 s with the **flat R45 success projection** — `complete()` returns
`{summary, insights, recommendations, …}` directly on success and
**raises** `ProviderCallError` on failure; only `complete_with_status()`
returns the `{response, error, telemetry, _exception}` envelope. The
runtime awaited an envelope from `complete()`, so a successful LLM answer
was misclassified as a provider failure with an empty reason.

**Fix (commit `7ebf28e`):** use `complete_with_status()` when available
(telemetry: attempts/response_chars), normalize all three real outcome
shapes (flat projection / envelope / raised exception), classify from
plan fields (`error_category`/`error_code`/`status_code`) and exception
attributes — deterministic mapping to `timeout | rate_limit | auth |
configuration | empty_response | context_rejected | schema_failure |
provider_unavailable | provider_error` — and reasons are never empty
(bare exceptions fall back to the exception class name). Three regression
tests added (flat projection accepted, `complete_with_status` preferred,
non-empty reason); full battery re-run green: 98 + 98 + AEC 2149 +
smoke 95/95.

## Attempts 2–3 and prompt v1.1 (recorded)

- **Attempt 2** (after fix promotion `9d27acd`): full classified reason —
  `llm_schema_failure: provider summary exceeds the bounded size` (the
  free model's `summary` exceeded the R45 400-char bound). Fail-closed,
  audited, auto-retry. Wall 23.0 s, RSS 65 MB.
- **Attempt 3**: `schema_failure: insight_code item shape invalid`
  (model emitted a malformed insight item). Attempts exhausted →
  **TERMINAL_FAILED** (3/3), no result, no case, no fabricated output —
  the Epic's retry/terminal policy proven end-to-end on real traffic.
- The strict R45 validator never repairs content, so the sanctioned lever
  is the versioned prompt (Phase 7): **`xss-agent-analysis-v1.1`** adds
  explicit numeric contract bounds (`summary <=150 chars`, max 6 items,
  exact two-key item shapes, `no other keys`), worst-case length 396/400,
  regression-tested (instruction bounds + version pins). The terminal job
  `job-xss-c70608036a` remains an honest permanent record; a fresh job
  runs the v1.1 success-path validation after promotion.

## v1.2: example-driven prompt after v1.1 attempts (recorded)

- Job `job-xss-113d54a0e0` ran on v1.1: attempt 1
  `llm_schema_failure: provider content is not valid JSON`;
  attempt 2 `schema_failure: insight_code item shape invalid`
  (2/3, auto-retrying, no fabricated output). Across five real
  free-router calls the varying reply defects are: over-long summary,
  malformed items, non-JSON content — the strict R45 validator never
  repairs, and prose-style shape instructions did not lift conformance.
- **`xss-agent-analysis-v1.2`** replaces prose with a complete
  example skeleton (exact `summary`/`insights`/`recommendations`
  objects), `Raw JSON, no markdown, exactly:`, item/length caps —
  worst-case length 389/400, regression-tested (version pins +
  skeleton-token assertions). Attempt 3 of the same job runs on v1.2
  after promotion.

## Root cause of the repeated `shape invalid` failures (recorded)

- After `job-xss-113d54a0e0` attempt 3 also ended
  `schema_failure: insight_code item shape invalid` (TERMINAL, 3/3),
  the message was traced to **our** `_map_advisory_response`
  (`runtime.py`), not the provider validator: the R45 projection items
  legitimately carry 4 keys (`insight_code`/`recommendation_code`,
  `text`, plus projection metadata `source_refs`, `research_only`),
  while the mapper demanded exactly `{code, text}` — so **3 of the 6
  real attempts were false rejections of provider-valid replies**
  (the other 3 were genuine provider rejects: envelope-contract bug,
  `summary` > 400, non-JSON content).
- Fix: the mapper now requires the canonical keys (non-empty code +
  text), tolerates projection metadata, and stores only the canonical
  pair — extraction, never repair (the provider validator remains the
  strict upstream gate). Regression tests: projection-shaped items
  accepted with canonical-only storage and deterministic gate values;
  missing canonical code key still rejected. Battery: 198 OK, AEC
  2149 OK, smoke 95/95.

## Phase 13 — first real LLM job: SUCCESS (`job-xss-b92f12aa7b`)

After promotion `58eef77` (mapper fix live), one fresh production XSS
job ran `--max-jobs 1 --llm OPENROUTER` with key sourced from `.env`
and `OPENROUTER_MODEL` pinned `openrouter/free` and **COMPLETED on
attempt 1**. Verified chain, all from real persisted state:

1. Guard preflight accepted exact free config (key loaded, model
   `openrouter/free`, `WATCH_AGENT_LLM_MODE=free`).
2. Claim → authorization (`watch:scope:dell/www.dell.com`) →
   `observations_loaded: 50 authorized observations`.
3. Knowledge: 5 real KB documents read for this attempt
   (`knowledge_used` 12:48:52 — cve_hub ×2, Yoast, TinyMCE, jQuery).
4. `llm_analysis_started: OpenRouter openrouter/free
   xss-agent-analysis-v1.2` → real response → **schema validation
   PASSED** → `llm_analysis_completed: resolved=openrouter/free
   latency_ms=32873 usage=n/a prompt=xss-agent-analysis-v1.2`.
5. **Evidence gate authoritative:** `evidence_gate_evaluated:
   decision=case reason=evidence_rules_met gate_confidence=high`
   (deterministic confidence; LLM output only merged as reasoning).
6. Research result persisted (`structured-analysis-v1`): hypothesis +
   5 insights (UPPER_SNAKE codes e.g. `OBSERVATION_SET`) + 4
   recommendations + 8 observations considered; verdict
   `evidence_sufficient_for_review`; 4 findings.
7. Case **`case-3c80c0ab076f`** created (production mode, auth
   context, real advisory hypothesis/analysis text) with **6 evidence**
   refs; audit 90 events total (`evidence_recorded` ×6,
   `case_created`, `result_persisted`, `job_completed`).
8. SOC exposure (service layer, exactly what the template renders):
   banner `agent-intelligence-v1-free-only` / OpenRouter Free /
   `key_configured: true` (no key value), `llm_last` =
   job COMPLETED, requested=resolved `openrouter/free`, prompt
   `xss-agent-analysis-v1.2`, latency 32873 ms, usage `{}` (not
   exposed by contract — reported honestly), confidence `high`,
   verdict + real hypothesis/reasoning.
9. **Secret scan:** runtime store (4 files) scanned against the real
   key value and `sk-or-v1-` prefix — **NONE present**; API key never
   persisted, logged, or echoed.
10. Resources: worker exit 0, wall 34.6 s, CPU 1.3 s, peak RSS 65 MB;
    concurrency 1, single bounded run, no persistent worker, no
    systemd change.

Final state: 4 jobs total — 2 COMPLETED (pre-LLM
`job-xss-d554bb5304` + LLM `job-xss-b92f12aa7b`), 2 honest
TERMINAL_FAILED (`job-xss-c70608036a`, `job-xss-113d54a0e0` —
attempts exhausted under real defect conditions, documented above),
queue 0, 2 cases, 12 evidence. The authenticated HTML page itself
cannot be rendered by the agent (Telegram-auth wall); its data source
was invoked directly and every field above comes from it.
