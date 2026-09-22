# WATCH — AI Agent Runtime v1: Phase 0 architecture discovery

Read-only inspection of the existing implementation before any runtime code
is written.  Maps the required chain and marks each component **exists** /
**exists (unpromoted)** / **must be built**.

## The required chain, mapped to real components

```
Agent → Job → Authorization → Observation → Evidence → Research Result →
Case → Knowledge → SOC
```

| Chain step | Real component today | Status |
| --- | --- | --- |
| **Agent** (definition) | `ai/knowledge/specialist_registry.py` (8 specialists, R52-1, identity/priority/context keys) + `backend/research_agents/registry.py` (AgentRegistry with `ready_for` / `analyzer_for`) + `backend/research_agents/agents/*` (xss, idor, ssrf, authz, upload analyzers, 1134 lines) | **exists (partly unpromoted)** |
| **Agent** (runtime state) | none — statuses were identity-derived (`PLANNED`) or defaulted | **must be built** |
| **Job** | `backend/research_agents/models.py` (`ResearchJob`, `JobStatus` NEW→QUEUED→ASSIGNED→RUNNING→WAITING_EVIDENCE→COMPLETED/FAILED, `JOB_STATUS_FLOW` guard) + `orchestrator.py` (candidate→job→assign→analyze, idempotent) + `repository.py` (`ResearchJobStore`: thread-safe, optional JSON artifact, **in-memory in production**) | **exists (unpromoted), must be extended** — no CLAIMED/CANCELLED/EXPIRED/TIMEOUT, no lease/heartbeat/attempt/timeout fields, persistence optional and unauthenticated |
| **Queue** | `ResearchJobStore` ordering by priority + `service.py` counters (`queue/job_count/active_jobs`) + candidate source = Attack Surface priority queue (`repository.load_priority_candidates`, read-only) + AEC `aec/queue/` (observation queue) | **exists (unpromoted)** for agent jobs; **must be extended**: persistent across restart, atomic claim, lease, retry, cancellation, expiry |
| **Authorization** | `aec/authorization_gate.py` (pure ALLOW/REFUSE with closed refusal vocabulary, no I/O), `aec/budget_ledger.py` (cost budgets), AEC authorization model via `backend/routers/aec.py` read-only views, scope = Watch Attack Surface candidates (targets only ever come from Watch's own authorized stores) | **exists** — runtime must *consume* it, never reimplement or bypass |
| **Observation** | `aec/observation_plan.py` (plan draft, MAX_STEPS), AEC-1 EPIC7 **authorized observation runtime** (`aec/execution/`, `aec/observation_plan`, `build_observations_view`), plus read-only Watch data stores (`database/db.py`: Http, Subdomains, Urls, Endpoints, LiveSubdomains) and `ai/research_agent/netguard.py` (the *only* DNS/redirect-allowlist network piece) | **exists** — runtime gets observations through a provider that reads Watch stores / the AEC execution bridge only; **no direct specialist-to-target HTTP** |
| **Evidence** | AEC `build_evidence_view` (execution-simulation backed today), `ai/research_agent/evidence.py` + `case_evidence.py` (R-series real evidence), `aic` redaction (`aec/redaction.py`) | **exists** — runtime records *references* to evidence it consumed/produced |
| **Research Result** | `backend/research_agents/models.py::ResearchResult` (findings + evidence_required + blockers + signals + confidence; **never claims a vulnerability**) + `ai/research_agent/storage.py` (atomic, idempotent result+report persistence) | **exists (unpromoted)** — extend with analysis provenance (provider/model/prompt version/timing) |
| **Case** | AEC case compiler (`aec/case_compiler.py`) + case explorer view (**fixture simulation source** — `_simulation_run()`), real research case store via `ai/research_agent/case_bridge.py` / `case_decision.py` (writes under `ai_data/research`) | **exists split**: AEC views are fixture-backed; real case decisions live in the research-agent case bridge.  Runtime adds its own evidence-gated case records and must label provenance honestly |
| **Knowledge** | `ai/knowledge/store.py::retrieve` (R-series store), `backend/research_data.list_kb` (KB docs, production count 30), specialist context keys (`SPECIALIST_CONTEXT_KEYS`) | **exists** — runtime records a *real* read relationship when it retrieves |
| **SOC** | `backend/routers/soc.py` (8 GET UI routes), `backend/soc/{agents,overview,activity,cases,handoff}.py`, templates; truthful PLANNED statuses + provenance from the previous epics | **exists** — must become runtime-aware (real statuses/queues/jobs/activity) while staying truthful when no runtime/worker exists |
| **Activity** | `backend/soc/activity.py` (timeline from research-loop records + investigation reports + AEC transitions), `backend/research_activity.py` (R83 collector: run records, case records, lock probe) | **exists** — runtime appends its own real events |
| **Audit** | AEC run transitions (consumed by SOC activity), `ai/execution/ledger.py`, promotions `AUDIT.log` | **exists for other surfaces; agent-runtime audit must be built** (JSONL, atomic, no secrets) |

## Reused execution / worker / scheduler architecture

- **Scheduler**: `ai/research_agent/scheduler.py` (R23) — disabled by default,
  explicit window (Asia/Tehran), max wall-clock, max plans, one plan at a
  time, **single-worker `flock`**, runs once and exits.  Records:
  `ai_data/research/agent/runs/<run_id>.json` (50 real records today).
- **Service**: `watch-research.service` — `Type=oneshot`,
  `ExecStart=flock -n /run/watch-research/service.lock python3 -m
  ai.research_cli agent run`, `EnvironmentFile=/opt/watch/.env`,
  `WATCH_RESEARCH_LOCK=/run/watch-research/research.lock`.  **Phase 10 must
  extend this pattern**, not add a new unit (delivery policy forbids new
  `*.service`/`systemd/*` files; the Epic also prefers extension).
- **Other services**: `watch-api` (FastAPI), one-shot task services
  (crawl/dns/param), `watch-ai-report`.  `watch.service` currently failed
  (pre-existing, unrelated).

## LLM provider abstraction (Phase 6 input)

- `ai/providers/provider_registry.py` (R51): **explicit selection only, no
  default provider, fail-closed CONFIGURATION_ERROR**, injectable transport,
  no I/O at selection time.
- Providers: `openrouter_provider.py` (`OPENROUTER_API_KEY` required at call
  time, fail closed), `openai_provider.py` (`OPENAI_API_KEY`), mock provider
  (`ai.knowledge.llm_provider.MockLLMProvider`).
- `ai/providers/context_allowlist.py` (R51): **allowlist-only projection**,
  reject-never-rewrite for credential/cookie/token/payload content, data
  minimization, deterministic reason codes — this is the "minimum authorized
  context" mechanism the Epic demands.
- `ai/providers/advisory_bridge.py` (R51): one bounded provider call →
  R45 validator → structured envelope, **no prompt/credential in output**,
  provider errors become infrastructure errors, never findings.
- `ai/research_agent/llm_loop.py`: budget counters (`can_call_llm`,
  `consume_llm`), `validate_and_sanitize_analysis` — bounded LLM budgets
  already exist.
- DeepSeek: not present as a kind (`R51_REGISTRY_KINDS` = mock/openai/
  openrouter); reachable through OpenRouter models if configured.  No
  DeepSeek-specific integration required for v1.

## Configuration / secrets

`.env` via systemd `EnvironmentFile` + fail-closed env lookups at call time.
Rule for the runtime: never read keys itself, never persist them, never log
them — providers already enforce this.

## Existing test surface that must stay green (regression baseline)

- `tests/test_research_agents.py` (578 lines), `test_agent_orchestrator{,_registry,_safety}.py`
- `tests/test_research_agent*.py` (R24 series + case bridge)
- AEC suites (2149 tests), SOC suites, Recon navigation suites, delivery +
  read-only guards, mounted smoke (95/95 at last run)

## What must be built (summary)

1. **Runtime state + persistence**: promote the store from in-memory to a
   persistent, atomically-locked queue with lease/heartbeat/attempt/timeout
   fields, the full Epic lifecycle (CLAIMED, CANCELLED, EXPIRED, TIMEOUT,
   retry), and no-orphan guarantees.
2. **Worker runtime**: claim → authorize → load definition/knowledge →
   bounded plan → observations via providers → analyze (deterministic or
   LLM through the R51 bridge) → evidence refs → evidence-gated case →
   result → activity → audit → release; survives restart/timeout/duplicate
   claims/partial failure; bounded concurrency; graceful shutdown.
3. **Observation providers**: read-only Watch-store provider + fixture
   provider (tests) — the only two; enforced by an import-boundary test
   (no `requests`/`socket`/`subprocess` in the runtime package).
4. **Capability definitions** for all 8 specialists (mission types, allowed
   observations, evidence requirements, output schema, case conditions,
   unsupported operations).
5. **Runtime observability** (worker alive/dead, queue, leases, heartbeats,
   last success/failure) consumed by the SOC.
6. **SOC runtime integration**: real statuses (PLANNED/READY/IDLE/ACTIVE/
   FAILED per Epic definitions), queue/active/total/last job, agent detail
   jobs/knowledge/history/cases, honest fallbacks when no worker has run.
7. **Operations**: worker CLI with one-shot + bounded loop + SIGTERM,
   deployable under the existing `watch-research` service pattern.
8. **Audit + activity events** for every transition (JSONL, atomic).
9. **Tests**: lifecycle, atomic claim, lease/timeout/retry/cancel/crash,
   authorization refusals, observation boundary, LLM validation/failures/
   secret-leakage, full E2E chain + failure matrix, SOC consistency, and
   every existing regression suite.

## Explicit non-goals (safety)

No arbitrary HTTP from the runtime or an LLM, no shell/code execution from
model output, no exploit execution, no credential operations, no bypass of
`aec/authorization_gate`, no writes outside the runtime's own data
directory + existing case/evidence stores, no new systemd units, no 24/7
high-concurrency loop (bounded, windowed, lock-guarded like R23).
