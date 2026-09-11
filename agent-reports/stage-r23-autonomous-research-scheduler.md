# Stage R23 — Autonomous Research Scheduler

## 1. Scope and safety statement

R23 connects the existing deterministic Research Intelligence pipeline to a
time-bounded autonomous **research** worker. It is autonomous research, never
autonomous exploitation.

The worker may: read/search public security research (NVD, vendor advisories,
GitHub, Wordfence, WPScan, write-ups), inspect CVE references, summarize
evidence, extract affected products/components/parameters/versions, identify
exploitability information, identify/propose research-only Nuclei template
candidates, and produce research reports + optional research-only KB notes.

The worker **MUST NOT** and **does not**: attack targets, scan programs, run
Nuclei against assets, run browser validation, perform active validation,
execute PoCs, call 5B–5J, create production findings, create alerts, mark
anything VERIFIED/VULNERABLE/EXPLOITED, use production credentials, or modify
production asset state.

No Git operations were performed. `database/db.py` was not modified.

## 2. Architecture

```
ResearchExecutionPlan (R22)
        |
        v
ResearchScheduler  (ai/research_agent/scheduler.py — policy, window, lock)
        |
        v
ResearchAgent      (ai/research_agent/agent.py — bounded, fail-soft)
        |
        +--> sources.py    public references (SSRF-validated, bounded)
        +--> prompts.py    bounded research prompt (EVIDENCE/INFERENCE/UNKNOWN)
        +--> (existing) ai.llm.openrouter provider — never a new provider
        |
        v
ResearchAgentResult (ai/schemas/research_agent.py)
        |
        +--> ai_data/research/agent/<plan>.<rule>.json
        +--> ai_data/research/agent/<plan>.<rule>.md   (deterministic report)
        +--> optional KnowledgeStore ingestion (research note; opt-in)
        |
        v
Dashboard (/ui/research/agent, /api/research/agent/*)
```

New package (small, single-purpose modules):

- `ai/research_agent/__init__.py`
- `ai/research_agent/agent.py` — plan → result execution
- `ai/research_agent/scheduler.py` — policy, window, selection, flock, run loop
- `ai/research_agent/sources.py` — validated/bounded public source layer
- `ai/research_agent/prompts.py` — bounded prompt + output contract
- `ai/research_agent/storage.py` — atomic/idempotent result + report + run store
- `ai/schemas/research_agent.py` — result/evidence/source schema
- `backend/research_agent.py` — read-only view layer for dashboard/API

## 3. Scheduler policy

Configuration (conservative, env-driven):

```
WATCH_RESEARCH_ENABLED=false          # disabled by default
WATCH_RESEARCH_WINDOW_START=18:00
WATCH_RESEARCH_WINDOW_END=00:00
WATCH_RESEARCH_MAX_MINUTES=300
WATCH_RESEARCH_MAX_PLANS=5
WATCH_RESEARCH_TIMEZONE=Asia/Tehran
WATCH_RESEARCH_LOCK=/run/watch-research.lock
WATCH_RESEARCH_NETWORK=true           # bounded public fetching (dry-run always off)
WATCH_RESEARCH_LLM=false              # opt-in; needs WATCH_LLM_* / provider config
WATCH_RESEARCH_MAX_SOURCES=12
WATCH_RESEARCH_KB_INGEST=false        # optional research-only KB note
WATCH_RESEARCH_AGENT_DIR=ai_data/research/agent
```

Behaviour:

- disabled by default → a run does nothing.
- outside the configured window → a run does nothing.
- inside the window → select bounded R22 plans, one at a time.
- max runtime enforced (wall clock, monotonic) and max plans enforced.
- deterministic ordering; fail-soft per plan; single worker via lock.
- one shot per invocation (`agent run`), never continuous.

Timezone is explicit (`WATCH_RESEARCH_TIMEZONE` via `zoneinfo.ZoneInfo`); the
business logic never reads the system clock timezone. Windows crossing midnight
(e.g. `18:00 → 00:00`, `22:00 → 06:00`) are supported; `start == end` is a
closed (zero-length) window.

## 4. Plan selection

Input is the existing R22 projection only (`backend.research_execution.build_plans`).
Completed plans are excluded. Priority classes first
(CRITICAL > HIGH > MEDIUM > LOW > INSUFFICIENT_DATA > other), then within a
class by R22 `recommended_start`, relevance score (desc), priority score
(desc), CVE, program, and finally `plan_id` (a stable tiebreak so fully
identical plans are still deterministic regardless of input order). Selection
is capped by `WATCH_RESEARCH_MAX_PLANS`.

The program is research context only. The agent never requests a program URL.

## 5. Locking

A non-blocking `fcntl.flock` exclusive lock prevents two workers running at
once. If the lock is held (or the lock path is unavailable), the run exits
cleanly with `skipped="locked"` and performs no work, no writes. The systemd
unit additionally wraps the process in `flock` on a separate lock path so the
service launch path is also serialized (the two locks do not conflict).

## 6. Source boundaries

- Reuses the existing `ai.collectors.reference.ReferenceCollector` (no second
  generic HTTP client); `httpx` is never imported by the R23 package.
- Every outbound URL is validated before fetching via `validate_source_url`:
  http(s) only; rejects localhost/`*.local`/`*.internal`, loopback, RFC1918
  (10/8, 172.16/12, 192.168/16), link-local, reserved/multicast/unspecified IP
  literals, and cloud metadata hostnames/IPs (`169.254.169.254`,
  `metadata.google.internal`, `instance-data`, …); rejects the program/target
  host (program token compared against DNS labels); rejects caller-supplied
  forbidden hosts.
- Only URLs already associated with the CVE (persisted research references)
  are ever considered; no arbitrary user-supplied URLs.
- Bounded: max sources (`MAX_SOURCES=12`), max bytes
  (`ReferenceCollector.MAX_BYTES=2_000_000`), max chars per document,
  timeout-controlled, per-plan dedupe by canonicalized URL and content hash.
- Fail-soft per source: a rejected/failed/empty source is recorded with a
  status/note; other sources still process.
- Existing stored references are read offline; archive bodies yield a trusted
  content hash. URL-only references are kept as `STORED_ONLY` and can never
  back an evidence claim (no content ⇒ no hash).

## 7. LLM boundary

- Uses the existing `ai.llm.openrouter.OpenRouterProvider` only. No new
  provider was added and no model is hard-coded. `WATCH_LLM_PROVIDER` and
  `WATCH_LLM_MODEL` are honored when set, while the existing
  `OPENROUTER_*` configuration remains authoritative (empty `WATCH_LLM_MODEL`
  falls back to the provider's `OPENROUTER_MODEL`).
- LLM is opt-in (`WATCH_RESEARCH_LLM`, default false). With it disabled the
  agent runs in deterministic/offline mode.
- LLM output is never authoritative. Evidence is accepted only when its
  `source_url` matches a supplied source that has a trusted content hash; the
  hash is copied from the source layer, never from the model. Uncited
  evidence and any evidence/inference containing a forbidden verdict term
  (VULNERABLE/VERIFIED/EXPLOITED/FINDING) are dropped and recorded as unknowns.
- Provider errors/invalid JSON degrade to `RESEARCH_PARTIAL` with an explicit
  unknown; they never crash the run.

## 8. Result and evidence schema

`ResearchAgentResult` carries: `result_id`, `run_id`, `plan_id`, `lead_id`,
`cve_id`, `program`, `started_at`, `completed_at`, `status`, `sources[]`,
`evidence[]`, `inferences[]`, `unknowns[]`, `affected_versions[]`,
`affected_components[]`, `affected_parameters[]`, `exploitability_summary`,
`nuclei_candidates[]`, `recommended_next_step`, `report_path`, `rule_version`,
`production_finding` (forced False).

Statuses: `RESEARCH_COMPLETED`, `RESEARCH_PARTIAL`, `RESEARCH_BLOCKED`,
`RESEARCH_FAILED`. The schema validator rejects VULNERABLE/VERIFIED/EXPLOITED/
FINDING.

Evidence items: `evidence_id`, `source_url`, `source_type`, `claim`,
`confidence` (HIGH/MEDIUM/LOW), `knowledge_ids`, `quote`, `content_hash`.
`content_hash` is required and is computed deterministically by the source
layer as `sha256(normalize_text(content))`; the schema rejects empty hashes and
missing source URLs.

Nuclei candidates are research proposals only; the schema forces
`executed=False` and `target_url=None`.

## 9. Research prompt

`ai/research_agent/prompts.py` builds a size-bounded prompt
(`MAX_PROMPT_CHARS=60_000`, `MAX_PROMPT_DOCS=8`, `MAX_PROMPT_DOC_CHARS=4_000`).
It supplies the CVE/projection context, the R22 plan, the R21 lead, the
supplied documents (only sources with a trusted hash), and URL-only references
separately. It explicitly states: research-only; do not claim the target is
vulnerable; do not invent evidence; do not perform or suggest active
validation; separate EVIDENCE/INFERENCE/UNKNOWN; do not output a content_hash.
Output is parsed with the existing `ai.researcher.researcher.parse_llm_json`
and validated. Output-token bounding remains the existing provider's
`OPENROUTER_MAX_TOKENS` budget.

## 10. Nuclei research (no execution)

The agent may surface an existing persisted `nuclei_candidate` flag/reason and
may accept model-proposed candidates (product, template source, request shape,
matcher logic) as **research candidates**. There is no Nuclei execution, no
target URL, and no template activation. The schema enforces `executed=False`
and `target_url=None`.

## 11. Persistence

`ai_data/research/agent/`:

- `<plan_id>.<rule_version>.json` — one completed result per plan+rule
- `<plan_id>.<rule_version>.md` — deterministic Markdown report
- `runs/<run_id>.json` — one scheduler run record

Writes are atomic (temp file + `os.replace`). Result/report writes are
idempotent: an existing completed file is not overwritten (explicit
`overwrite=True` is the only opt-in). Result files are keyed by plan+rule
version. No secrets, no raw API keys, no arbitrary target responses are stored.
Optional KB ingestion (opt-in) builds a deterministic research note (run-scoped
metadata stripped) and re-ingests idempotently via the existing
`KnowledgeStore`.

## 12. CLI

```
python -m ai.research_cli agent status
python -m ai.research_cli agent run
python -m ai.research_cli agent run --plan r22-...
python -m ai.research_cli agent run --limit 1
python -m ai.research_cli agent report
python -m ai.research_cli agent dry-run
```

`run` supports `--force` (manual override of enabled/window), `--network` /
`--no-network`, and `--json`. `dry-run` builds no agent/provider/fetcher and
performs zero network and zero LLM activity. Observed dry-run output:

```
Research Agent
==============

Enabled: false
Window: 18:00-00:00 Asia/Tehran
Network: enabled
LLM: disabled

Eligible plans:
  #1 CVE-2026-1557 -> dell
  #2 CVE-2026-1557 -> indeed

MODE: dry-run (no network, no LLM, no writes)
```

## 13. systemd design

New files (created, **NOT enabled**; existing `watch.service` untouched):

- `systemd/watch-research.service`
- `systemd/watch-research.timer` (hourly, `Persistent=true`; the service
  enforces the exact window)

Service properties: `Type=oneshot`; `User=pouya_behnia`;
`WorkingDirectory=/opt/watch`; `EnvironmentFile=/opt/watch/.env`; explicit
`PATH`; hard timeout via `TimeoutStartSec=330min`; `KillMode=control-group`;
`RuntimeDirectory=watch-research`; outer `flock` + internal `flock`;
`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`, `ProtectHome=read-only`,
`ProtectKernelTunables`, `ProtectControlGroups`, `RestrictSUIDSGID`,
`LockPersonality`; `MemoryMax=1G`, `CPUQuota=150%`. No root, no Docker socket,
no SSH keys, no credentials beyond the research provider config in `.env`.
`systemd-analyze verify` passes for both units.

## 14. Dashboard and API

- Dashboard card "Research Agent": Enabled, current window, In window, Next
  eligible run, Last run + last status, plans processed, research results,
  eligible plans. Fail-soft (never breaks the recon dashboard).
- `/ui/research/agent` — status, window/bounds, runs, results (read-only).
- `/ui/research/agent/{run_id}` — one run (read-only).
- `GET /api/research/agent/status`, `GET /api/research/agent/runs` (read-only,
  key-gated).
- Sidebar gains "Research Agent" under Research; `agent_url` is defined in all
  four context builders (`pages.py`, `programs.py`, `runs.py`,
  `research_pages.py`) and every link is built with the shared `build_url`
  helper (no query-string concatenation). Route ordering keeps
  `/ui/research/agent*` and `/api/research/agent/*` ahead of the generic
  `/ui/research/{cve}` / `/api/research/{cve}` routes.

## 15. Tests

New suite `tests/test_research_agent.py` — **89 tests, all passing**, covering
every R23 requirement: disabled-by-default, timezone/window handling,
outside-window rejection, max runtime, max plans, deterministic selection,
priority ordering, lock contention, no concurrent workers, source URL
validation, localhost/RFC1918/metadata/program-URL rejection, response-size
bounds, evidence provenance, trusted content hash, LLM-cannot-overwrite-hash,
UNKNOWN handling, no vulnerability vocabulary, no Nuclei execution, no active
validation (schema + prompt + static source scan), idempotent persistence
(results and KB), fail-soft per plan, and dry-run zero network/LLM/writes.

Regression runs (all OK):

```
Ran 354 tests in 36.714s
OK
```

covering `test_research_agent`, `test_research_navigation`,
`test_research_intelligence_ui`, `test_research_workflow`,
`test_research_api`, `test_research_leads`, `test_research_execution`,
`test_dashboard_navigation`, `test_dashboard_logic`, `ai.test_research_cli`,
`ai.test_knowledge_store`, `ai.test_openrouter`.

Pre-existing, unrelated failures (unchanged; not caused by R23):
`test_page_render.test_domains_page_200`,
`test_page_render.test_program_detail_200`,
`test_routers_fixes.test_lookup_matches_program_name` (Mongo unavailable
locally).

`git diff --check`: clean.

## 16. Real corpus test

CVE-2026-1557 → dell (`r22-38d26f10681e9a0f`) and indeed
(`r22-fda96966ea7af4ae`) selected from the real R22 corpus. Offline run
(`--force --no-network`):

```
r22-38d26f10681e9a0f CVE-2026-1557 -> dell   [RESEARCH_PARTIAL] evidence=0 sources=6
r22-fda96966ea7af4ae CVE-2026-1557 -> indeed [RESEARCH_PARTIAL] evidence=0 sources=6
```

A controlled/mock source layer + grounded mock LLM (used by the test suite,
never the live network) verified: plan selected, sources processed, evidence
generated and grounded to a supplied source with a trusted hash, unknowns
preserved, result stored, no source URL is a program host, and
`production_finding=False` with an allowed research status.

No live research was performed against dell.com or any program asset.

## 17. Security review

- SSRF guard rejects localhost, loopback, RFC1918, link-local, metadata
  endpoints, internal suffixes, and program/target hosts before any fetch.
- No arbitrary/user-supplied URLs; only persisted CVE references are considered.
- Bounded count/bytes/time/size; per-source fail-soft.
- LLM is never authoritative; evidence requires a supplied source and a
  source-layer hash; forbidden verdict and uncited claims are dropped.
- No execution surface: static scan confirms no `subprocess`, `socket`,
  `browser`, `ai.execution`, `ai.verification`, `ai.finding`, `ai.resolver`,
  `nuclei_runner`, `ai.authorizer`, `ai.persistence`, or `httpx` imports in the
  R23 package.
- Schema forces no production findings, no executed Nuclei, no target URL.
- Persistence is atomic/idempotent and stores no secrets or raw target data.
- systemd unit is least-privilege, non-root, and not enabled.

## 18. Limitations

- The initial source layer fetches the CVE's persisted reference URLs only; it
  does not implement NVD/Wordfence/WPScan search APIs. Source "types" are
  classified (nvd/vendor/github/wordfence/wpscan/writeup/other) over those
  references.
- Evidence grounding is attributional (source URL + trusted hash), not semantic
  verification of the quote against the document body.
- Without a local reference archive body, URL-only references yield
  `RESEARCH_PARTIAL` and no evidence (honest, deterministic).
- `latest_runs`-style per-operation resilience applies to the agent store; the
  run record is written once per invocation and keyed by a timestamp-based
  run id (runtime metadata, not a decision input).
- The scheduler still loads the full R22 plan list to select from it (local JSON
  reads); selection itself is bounded.
- During testing a collector dedupe-state bug was found and fixed: the shared
  collector retained seen URLs across plans, which zeroed a second plan sharing
  references. State is now scoped per plan collection, and a regression test
  covers it.

## 19. Explicit confirmations

- NO target interaction
- NO active validation
- NO Nuclei execution
- NO production findings
- NO alerts
- NO 5B–5J
- NO Git operations (no commit, no push)
- `database/db.py` not modified

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R23
- Role: Autonomous Research Scheduler
