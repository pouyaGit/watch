# AUTONOMOUS RESEARCH INTELLIGENCE v1

Status: **COMPLETE through Phase 13** — promoted (main `a7a68bc`),
both real production jobs run and verified; this amendment (report-only)
is the closing promotion.
Epic scope: turn the deployed AI Agent Runtime from "execute one bounded
analysis job" into a research-capable intelligence system — persistent
research memory, a gate-authoritative learning loop, a bounded
recommendation engine, relevance-aware knowledge intelligence,
prior-research similarity, bounded cross-job context, a research-aware
output contract (v2), a shared layer integrated for two specialists,
SOC exposure, and append-only research lineage — under the unchanged
free-only LLM rule (`openrouter/free`, no paid fallback).

---

## 1. Executive result

- New shared intelligence package `backend/research_agents/intelligence/`
  (memory, learning, knowledge_intel, similarity, context, recommend,
  lineage) integrated into the existing worker pipeline — no parallel
  subsystem, provider abstraction untouched, Evidence Gate untouched and
  still authoritative.
- Research memory: append-only JSONL `memory.jsonl` beside the runtime
  store, provenance mandatory on every item, five preserved states
  (OBSERVED / INFERRED / RESEARCHED / VERIFIED / REJECTED), VERIFIED only
  from a case-creating gate decision.
- Learning, recommendation, knowledge selection and similarity are all
  deterministic; the LLM contributes reasoning TEXT only (contract
  `structured-research-v2`).
- Second specialist **CVE_RESEARCH** (`cve-research-specialist`) runs the
  same layer end-to-end; all eight specialists inherit the shared code
  path capability-driven.
- 70 new tests green; full battery green except 7 pre-existing baseline
  failures (identical on production `main`, see §16); AEC 2149 OK;
  committed smoke 95/95; runtime E2E smoke OK with the full intelligence
  audit chain.
- **Phase 13 COMPLETE** — two bounded real production-mode jobs, both
  COMPLETED on attempt 1 with the full verified chain:
  **`job-xss-096f2b6161`** (XSS → case `case-8abe5a725d57`, 6 evidence)
  and **`job-cve_research-f118fdf314`** (CVE_RESEARCH → honest gate
  non-claim `insufficient_evidence`, no case). Both resolved model
  `openrouter/free` only; secret scan CLEAN; exact chains in §14.

## 2. Architecture changes

Existing (reused, not replaced): `backend/research_agents` worker +
RuntimeStore (state.json/audit.jsonl), `ai/providers` R45/R51/R52
contracts, `llm_guard` free-only gate, `backend.research_data.list_kb`
knowledge API, SOC routers/templates.

Added/modified:
- `intelligence/memory.py` — memory model + store (Phase 1)
- `intelligence/learning.py` — job → memory extraction (Phase 2)
- `intelligence/recommend.py` — recommendation engine (Phase 3)
- `intelligence/knowledge_intel.py` — relevance selection + usage index
  (Phase 4)
- `intelligence/similarity.py` — prior research similarity (Phase 5)
- `intelligence/context.py` — bounded cross-job context (Phase 6)
- `intelligence/lineage.py` — lineage digest + audit events (Phase 10)
- `runtime.py` — config limits, intelligence phases in `_run_phases`,
  `attach_research_contract` (v2), prompt `*-analysis-v2`, loader upgrade,
  honest degrade catches, activity/audit emission
- `runtime_store.py` — `record_audit_event` (append-only, scrubbed)
- `capabilities.py` — `intelligence_hints` edge field (XSS, CVE)
- SOC: `agents.py` intelligence block, `cases.py` research_intel block,
  `research_pages.py` KB usage, templates `agent_detail/case_detail/kb/
  kb_detail`

Explicitly NOT used (legacy, untouched): `ai/knowledge/**` R31/R43/R44
pure engines (feedback/legacy research flow, no agent inputs),
`ai/evidence` + `ai/finding` legacy finding pipeline, old
`ai/research_agent/llm_reliability.call_llm`, `backend/investigation_engine`.

## 3. Research memory model

Append-only `memory.jsonl` in the runtime dir (env
`WATCH_AGENT_RUNTIME_DIR`, gitignored). Every item: stable id
`mem-<sha256(kind|category|target|subject)[:16]>`, kind (14 fixed kinds
incl. hypothesis, negative_evidence, confirmed_historical_result,
rejected_hypothesis, research_recommendation, parameter_pattern,
evidence_requirement…), state (5 fixed), subject_key, bounded scrubbed
text, category/agent/target/program/confidence, mandatory provenance
{job_id, source, refs, created_at}, created/updated, rule_version,
limitations. `append()` dedups against heads via `should_append`
(legitimate transitions only; no demotion). Readers fold by id (newest
wins); corrupt lines counted, never surfaced. Secrets scrubbed at write
(`sk-or-*`, bearer, api-key patterns).

## 4. Learning loop

`learn(store, job, capability, decision, analysis, observations,
knowledge, case_id)` runs AFTER the gate:
- OBSERVED — parameter/endpoint/behavior patterns from real rows
- RESEARCHED — knowledge docs read (source_reference) + capability
  evidence requirements + class baseline
- INFERRED — LLM/determin hypotheses (advisory, never verified)
- VERIFIED — `confirmed_historical_result` **only** when the gate created
  a case (provenance: evidence_gate + case id)
- REJECTED — gate non-claim ⇒ rejected_hypothesis + negative_evidence
  (blockers, state OBSERVED) — negative research memory survives
Terminal failures append an honest failure memory
(`learn_from_failure`). Dedup: re-running identical inputs appends 0.

## 5. Recommendation engine

Post-gate, deterministic, ≤ `intelligence_recommendation_limit` (6):
gate negative result; missing required evidence types; specialist
signal-hint gaps (`missing_signal_evidence:<hint>` — the Phase 3 example:
reflection evidence requested before XSS claims); similar rejected
hypothesis → consult negative memory; similar verified case →
reference-without-proof; knowledge relevance; XSS parameter-reflection /
CVE technology-correlation edge rules. Every rec: id, type, text ≤300,
reason_codes, provenance{job, source, refs}, limitations. Execution-style
text is refused at generation (`_validate` + BANNED_PATTERNS incl.
payload/exploit/send/shell/URL/credential patterns) — `RecommendationUnsafe`
→ honest drop recorded. Recs also persist to memory
(research_recommendation) for future jobs.

## 6. Knowledge intelligence

`select_knowledge` over the existing `list_kb` API: candidates from
knowledge_requirements + intelligence_hints (bounded MAX_CANDIDATES),
deterministic scoring (+3 specialist topic, +2 class/hint, +≤3 signal
tokens from rows (tech/db_error/params), +2 prior memory reference),
reason codes per doc, bounded `knowledge_limit`, zero-score docs skipped.
All queries failing ⇒ `KnowledgeUnavailable` → loader degrades honestly
(activity `knowledge_selected … unavailable`). Every selected doc is
recorded (`record_knowledge_use` + relevance_score + reasons +
`knowledge_selected` activity + audit). Result v2 shows
knowledge_considered {id,title,why,informed}.

## 7. Prior research intelligence

`find_related` over bounded history (jobs, cases, memory) with structured
signals only: same target/program/category, path shape, parameter overlap,
mission/param token overlap. Row kinds: similar_observation,
similar_hypothesis, similar_verified_case, similar_rejected_hypothesis —
each with reason codes, provenance and the standing limitation
"similarity is a research aid, never proof or evidence about the current
target". Accepts ResearchJob objects or dict rows; failures degrade to
`prior_research_matched … unavailable` + honest error recorded.

## 8. Cross-job context

`assemble` builds allowlist-shaped sections (PRIOR_RESEARCH,
MEMORY_REFERENCE, RECOMMENDATION_REFERENCE, KNOWLEDGE_REFERENCE with
title+excerpt+why, HISTORICAL_JOB) under configuration-driven limits:
intelligence_memory_limit=12, related=5, history_jobs=4,
context_items=24, context_chars=1600 (≤ context_max_chars),
recommendation_limit=6, scan_limit=60. Priority-ordered trim enforces
items AND bytes; stats {items, chars, dropped, counts, limits} audited and
persisted as `context_stats`. R51 caps learning_signals at 8: with intel,
2 observation facts + up to 6 intel sections. The LLM never sees
unrestricted history; oversized payloads still fail closed with
`context_too_large` before any provider call.

## 9. Specialist integrations

Shared layer is capability-driven (category/agent/hints/evidence rules).
Integrated: **XSS** (prompt `xss-agent-analysis-v2`) and
**CVE_RESEARCH** (prompt `cve-research-specialist-analysis-v2`, hints
version/technology/correlation) — same memory, retrieval, recommendations,
prior-research context, evidence semantics and audit model; specialist
logic lives in capability fields + edge rules. Other six specialists
inherit the same pipeline automatically (not yet edge-tested).

## 10. SOC changes

- Agent page: "Research intelligence" — memory state counts, previous
  hypotheses (INFERRED), rejected hypotheses (source/job), research
  recommendations, related cases (labeled not-proof), recent knowledge
  relevance, recent intelligence activity, honest degradation list,
  lineage digest + contract.
- Case page: "Research intelligence" — authoritative gate, recommended
  next observation, evidence missing, hypotheses with preserved states,
  negative evidence, knowledge consulted (why·informed), prior research
  (reasons), memory considered, recommendations (reason codes), context
  stats, lineage digest, degradations.
- Knowledge pages: Agent-uses column + usage/specialists/last-used,
  "Agent research usage" panel with contributing research contexts and
  memory references.
- Activity: memory_retrieved, knowledge_selected, prior_research_matched,
  memory_learned, recommendation_generated rows visible in SOC activity.
- No secrets: payloads key-free (tests assert sentinel absence).

## 11. Audit / provenance

Append-only `audit.jsonl` events (all scrubbed at write):
intelligence_memory_retrieved, intelligence_knowledge_selected,
intelligence_prior_research_matched, intelligence_context_assembled,
intelligence_memory_learned, intelligence_recommendation_generated,
intelligence_lineage_recorded — each with job_id join key, ids, states/
kinds. Result carries `research_lineage` {digest, stages{job, knowledge,
memory, prior, prompt, gate(case/conf/reason), learned, recommendations,
context, errors}, rule_version}: full chain job → authorization →
observations → knowledge → memory → prior research → prompt/model → LLM →
validation → gate → learning → recommendation → result → case.

## 12. Security / safety verification

16 explicit tests (`test_research_intelligence_safety.py`, 17 tests):
LLM cannot create cases (CVE gate holds under LLM pressure), upgrade
confidence (deterministic equality proof), manufacture evidence (obs
refs ⊆ fixture refs), widen scope; AST proofs that the intelligence
package imports no HTTP/shell/code-execution surfaces and calls no
eval/exec/compile (re.compile excepted); recommendations carry no
execution text (banned-marker scan); context limits enforced pre-provider
and via worker config; paid model identifiers rejected; unknown
provider/mode fails closed; malformed intelligence never persists; REJECTED
vs VERIFIED distinguishable; secrets scrubbed from memory AND from audit/
activity payloads. R51/R52 provider contracts untouched.

## 13. Failure / recovery verification

12 conditions (`test_research_intelligence_failure.py`, 14 tests):
openrouter unavailable, timeout, rate limit, malformed, schema failure,
empty response, context limit (all classified, provider never called for
context), knowledge store unavailable, research memory unavailable,
prior-research retrieval failure, persistence (append) failure, partial
learning failure — each: classified/honest reason, degradation recorded in
`intelligence_errors` + activity, job completes deterministically where
safe, NO fake result/memory/recommendation, no paid downgrade. Real
defect found and fixed during tests: `learn_from_failure` NameError
(failure memory never persisted); intelligence stages now degrade on ANY
exception instead of failing the job.

## 14. Real production jobs

Both ran against production state from deployed `main a7a68bc`
(`watch-api` restarted first, openapi 200 / soc 401), one bounded
`--max-jobs 1` run each, key sourced from `.env` (never echoed), model
pinned `openrouter/free`, concurrency 1.

**Job A — `job-xss-096f2b6161` (XSS, production, COMPLETED, attempt 1):**
authorization `watch:scope:dell/www.dell.com` → 50 authorized
observations → memory_retrieved 0 items (first-ever run, honestly empty)
→ knowledge_selected **5 of 7 candidates** with relevance reasons
(specialist_topic/class_match/hint_match stored|dom) →
prior_research_matched **5** real records (cases `case-3c80c0ab076f`,
`case-6ccc0f2569bd` + prior jobs) → context 8 items / 1515 chars
(dropped 4, all limits visible) → **real LLM** `xss-agent-analysis-v2`,
`llm_analysis_completed resolved=openrouter/free latency_ms=3320` →
schema PASSED → **evidence gate authoritative** `case /
evidence_rules_met / high` → learning appended **12 memories across
INFERRED/OBSERVED/RESEARCHED/VERIFIED** → **5 recommendations**
(acquire_evidence ×2, reference_prior_verified, consult_knowledge ×2) →
result persisted (`structured-research-v2`, `intelligence_errors: []`) →
**case `case-8abe5a725d57` + 6 evidence** (3 observation + 3 knowledge)
→ lineage digest `cf1f33c0db1208520b9c34f2` → audit chain complete
(enqueued→…→`intelligence_lineage_recorded`→`job_completed`).

**Job B — `job-cve_research-f118fdf314` (CVE_RESEARCH, production,
COMPLETED, attempt 1):** scope `watch:scope:dell/www.dell.com` → 50
observations → memory_retrieved 0 (no CVE-category memory existed yet —
category-scoped retrieval, honest) → knowledge_selected **5 of 11**
(CVE topics + version/technology/correlation hints) →
prior_research_matched **5** including **Job A's job id and case
`case-8abe5a725d57`** (cross-job context proven on real data) → context
9 items / 1589 chars → **real LLM** `cve-research-specialist-analysis-v2`,
`resolved=openrouter/free latency_ms=6172` → schema PASSED →
**evidence gate: `no_case / insufficient_evidence / insufficient`** —
authoritative NON-claim despite LLM input (CVE knowledge-evidence rules
unmet: 2 evidence) → learning **12 memories incl. REJECTED, zero
VERIFIED** (the exact hypothesis/gate distinction) → **6
recommendations**: `research_negative_result (gate_insufficient_evidence)`,
`missing_evidence_type:observation`, `missing_signal_evidence:version`,
`missing_signal_evidence:technology`, `reference_prior_verified
(same_target_scope)`, `consult_knowledge` → **no case created (honest,
nothing fabricated)** → lineage digest `954852a95bf3daab3147ae61`.

Post-run verification (deployed modules): SOC agent intelligence blocks
live for both specialists (XSS: 16 memories incl. 1 VERIFIED; CVE: 18
memories incl. 1 REJECTED), case-detail research intel renders lineage
`cf1f33…`, KB usage index live (top doc 10 uses), **secret scan CLEAN**
(no key value, no `sk-or-v1-` literal in any runtime file).

## 15. Resource usage

Bounds (configuration): observations ≤50, context ≤4000 chars (prompt
payload), intel context ≤1600 chars / 24 items, memory query ≤12,
related ≤5, history jobs ≤4, knowledge ≤5 docs, recommendations ≤6,
similarity scan ≤60, concurrency 1, no persistent worker, no systemd
change, HTTP-layer retries 0 (job policy = 3 attempts). Fixture E2E
smoke: job completes sub-second, full audit chain written. Real jobs
(`/usr/bin/time -v`): Job A **5.42 s wall, 1.45 s CPU, 65 808 kB peak
RSS, 1 LLM call (3 320 ms)**; Job B **7.86 s wall, 1.50 s CPU, 65 876 kB
peak RSS, 1 LLM call (6 172 ms)**. Context: A 8 items/1515 chars, B 9
items/1589 chars (limit 24/1600). Knowledge: 5 docs each. Related prior
records: 5 each. Concurrency 1; attempts 1 each (no retries, no
degradations).

## 16. Test matrix

- New: 70 tests — core 31, safety 17, failure 14, SOC 8 (all green).
- Battery: 33 modules run isolated; 30 green. Pre-existing failures
  (IDENTICAL on production main — verified by running production code +
  data): `test_r82_research_dashboard_ui` (4F+1E: stale "Research Cases"
  sidebar expectations + legacy r77 artifact path), `test_research_ui`
  (1F: CVE sort-toggle ordering vs current data), `test_research_activity_api`
  (1F: legacy research cases total on current data). None gate delivery;
  none touched.
- Updated pins: prompt `*-analysis-v2` in test_agent_intelligence +
  security_llm (v1.2 → v2), llm-off structured expectations now assert
  the v2 contract (strengthened, not weakened).
- AEC: 2149 OK. Committed smoke: 95/95 PASS. Runtime E2E smoke: OK
  (full intelligence audit chain observed). Delivery check: READY FOR
  PROMOTION pre-merge (all 6 gates PASS, PATH_GUARD secret-clean);
  post-merge PRODUCTION PASS (`a7a68bc`, 27 dirty).
- Phase 13 real runs: 2/2 COMPLETED attempt 1 (see §14) — both real
  free-router calls schema-valid, zero retries, zero degradations
  (`intelligence_errors: []` on both).

## 17. Documentation

This report (architecture, memory model, states, recommendation model,
provenance, context limits, specialist integration, LLM contract v2,
safety boundaries, failure behavior, SOC representation, operational
validation, known limitations) + inline module docstrings + template
labels. Known limitations in §19.

## 18. Git / delivery state

Branch `agent/daily-development`, worktree `/opt/watch/.worktrees/watch-agent`.
Staged EXPLICITLY (unrelated pre-existing dirty files untouched):
intelligence package (8 files), runtime.py, runtime_store.py,
capabilities.py, soc/agents.py, soc/cases.py, routers/research_pages.py,
4 templates, 4 new test files, 2 updated test files, this report.
Delivery executed: check.sh **READY FOR PROMOTION** (BRANCH/COMMIT/
TESTS/PATH_GUARD/REPORT/PRODUCTION all PASS), report.sh wrote
DELIVERY-REPORT-2026-09-22, push_safe `a80f7ec..cc77a20`,
request **PROMOTION-REQUEST-20260922-1407** → APPROVE → promote
**main `a7a68bc`** → baseline refresh → PRODUCTION PASS → `watch-api`
restarted (openapi 200) → Phase 13 jobs (§14) → this report amendment
(closing promotion request, see §21).

## 19. Known limitations (honest)

- Phase 13 real jobs are pending at code-promotion time; report amended
  after they run (this is the standing two-promotion flow, not a shortcut).
- Similarity signals are structural only (no embeddings/ML) — by design,
  deterministic and auditable.
- Edge-specific recommendation rules exist for XSS and CVE_RESEARCH only;
  the other six specialists run the shared layer with generic rules.
- Knowledge relevance scoring is lexical (topic/hint/signal tokens); no
  semantic reranking.
- `usage` from the free router may be `{}` (not exposed) — reported as
  not_exposed_by_contract, never invented.
- Pre-existing baseline test failures (§16) remain out of this Epic's
  scope.
- Legacy `ai/knowledge` R-engines intentionally untouched: they serve the
  legacy research flow, not the agent runtime.

## 20. Exact production commit(s)

Implementation commit **`cc77a20`** promoted to production main =
**`a7a68bc`** (APPROVE 1407). Production baseline at time of this
amendment: **`a7a68bc`**, 27 dirty entries untouched, `api.py`
untouched. The report-only amendment commit gains `main` on the closing
APPROVE.

## 21. Promotion request ID

1. `PROMOTION-REQUEST-20260922-1407` (implementation, commit `cc77a20`)
   → APPROVED → promoted → main `a7a68bc`.
2. Closing request for THIS report amendment: recorded below when
   created by the delivery step.

READY TO PUSH: YES
