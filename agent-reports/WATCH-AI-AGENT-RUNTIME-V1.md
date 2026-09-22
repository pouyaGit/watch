# WATCH — AI Agent Runtime v1 (Epic delivery report)

## Architecture discovered
Phase 0 report: `agent-reports/WATCH-AI-AGENT-RUNTIME-V1-DISCOVERY.md`.
Full Agent→Job→Auth→Observation→Evidence→Result→Case→Knowledge→SOC
mapping; every component marked EXISTING vs NEW.

## Components reused (no parallel architecture)
- `backend/research_agents/` models/repository/service/orchestrator —
  extended in place (lifecycle vocabulary + runtime fields + reload).
- AEC authorization model & evidence/case stores: unchanged, consumed
  read-only; the AEC fixture case view stays separate from runtime cases.
- Watch Mongo stores = the entire observation boundary
  (`ReadStoreObservations`, read-only, bounded).
- Knowledge: `backend.research_data.list_kb` — every real read recorded.
- LLM: `ai.providers.provider_registry.select_provider` (fail-closed
  explicit kind) + `ai.research_agent.llm_reliability.call_llm`
  (fail-soft, secret-sanitizing) + bounded minimum-context projection.
- Ops model: extend the existing watch-research one-shot service pattern
  (`flock` + bounded run) — no new systemd unit (policy-banned), no 24/7 loop.

## Components implemented
- `backend/research_agents/capabilities.py` — 8 specialist capability
  definitions (identity, missions, allowed observations, evidence rules,
  output schema, confidence semantics, case conditions, knowledge needs,
  unsupported operations incl. every Epic ban).
- `backend/research_agents/runtime_store.py` — persistent work queue:
  `fcntl.flock` inter-process atomic claim, atomic JSON writes, audit
  JSONL, evidence/cases/knowledge/activity stores, worker heartbeat,
  sweep/recovery, snapshot (Phase 11).
- `backend/research_agents/runtime.py` — worker: claim→lease→verify
  authorization→knowledge→observations→deterministic (+ optional LLM)
  analysis→evidence→evidence-gated case→result→activity→complete, with
  retry/timeout/cancellation/failure policy and honest fixture/production
  `execution_mode` stamping.
- `backend/research_agents/cli.py` — bounded worker CLI
  (`run --max-jobs/--llm/--mode`, `status`, `enqueue`, `cancel`) with
  SIGTERM/SIGINT graceful shutdown.
- SOC integration: `backend/soc/agents.py` (five real states
  PLANNED/READY/IDLE/ACTIVE/FAILED from queue state + worker heartbeat,
  per-agent jobs/knowledge/cases/evidence records), `overview.py`
  (five-way split), `activity.py` (agent-runtime timeline events),
  `cases.py` (runtime cases in index + case detail with responsible
  agent + research chain), templates `home/agents/agent_detail.html`.

## Queue / worker / runtime model
- Queue: JSON state file under `WATCH_AGENT_RUNTIME_DIR`
  (default `ai_data/research/agent/runtime`), flock-serialized; lifecycle
  QUEUED→CLAIMED→RUNNING→COMPLETED + FAILED→QUEUED|TERMINAL_FAILED,
  CLAIMED→EXPIRED, RUNNING→TIMEOUT, QUEUED/CLAIMED→CANCELLED; no orphaned
  jobs (sweep requeues or terminates, audited).
- Worker: single-lease per claim, per-job timeout, heartbeat renewal,
  crash recovery via lease sweep, bounded `--max-jobs` per invocation,
  stop-flag/SIGTERM graceful.
- First real end-to-end path: XSS specialist over authorized Watch
  HTTP/URL rows (read-only store observations) → knowledge → analysis →
  evidence → case (evidence-gated) → SOC. Tests run it fixture-tagged;
  production mode uses the same code with `ReadStoreObservations`.

## Security boundaries (verified by tests, not prose)
- AST bans in `backend/research_agents/*`: no socket/requests/http/urllib/
  subprocess imports; no system/popen/urlopen/eval/exec calls; only env
  key read is `WATCH_AGENT_RUNTIME_DIR`.
- Fail-closed authorization: missing ref, non-watch scope, out-of-scope
  target, missing scope fields → job TERMINAL_FAILED + audited
  `job_rejected`, never a result.
- LLM: provider failure/timeout/malformed JSON → AnalysisUnavailable →
  job fails/retries; LLM cannot upgrade missing evidence to a finding;
  no secret can persist (sanitized errors, no key fields anywhere).

## Operations / resource limits
- Conservative default: max 5 jobs/invocation, 30 s lease, 120 s job
  timeout, observation limit 50 rows, knowledge limit 5 docs, activity
  capped at 500 rows; single worker identity per process; no process
  spawning. Deployment = bounded one-shot invocation under the existing
  service pattern; `status` prints the observability snapshot.

## Tests (exact results)
- NEW `tests/test_agent_runtime_core.py`, `tests/test_agent_runtime_
  security_llm.py`, `tests.test_agent_runtime_e2e_soc` → **68 OK**
- SOC+nav: `test_soc_ux_correction`, `test_soc_ui_stabilization`,
  `test_recon_soc_navigation`, `test_soc_ui_navigation` → **90 OK**
  (combined with runtime modules: **158 OK**)
- `tests.test_research_agents` → **46 OK**; orchestrator trio → **101 OK**
- AEC discover `test_aec*.py` → **2149 OK**
- Mounted smoke → **95/95 PASS**
- Test updates (source moves, contract follows): R52 boundary exception
  documented for SOC layered identity + capabilities comment reworded;
  closed-vocabulary pin extended for the Epic lifecycle; overview split
  + status derivation tests moved to the new runtime source.

## Honest deviations
- `/api/research-agents` HTTP routes stay UNMOUNTED (inert router
  shipped): a new POST surface was not requested by the Epic and adds
  review scope; the queue is driven by the worker CLI/store and read by
  SOC directly. `tests.test_research_agents.TestApi` passes in-worktree
  (the worktree `api.py` mounts it) but the production surface does not
  gain these routes.
- The pre-existing `test_dashboard_navigation` hang and 1 data-dependent
  `test_research_activity_api` failure are unchanged, unrelated baselines.
- AEC plan-level `authorization_gate` object is not wired per-plan yet;
  v1 enforces scope-reference + read-only observation provider + audit.

## Git
- commit: `<filled after commit>` · branch `agent/daily-development`
- push: via `push_safe.sh` · promotion request: generated, STOP at APPROVE
