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
