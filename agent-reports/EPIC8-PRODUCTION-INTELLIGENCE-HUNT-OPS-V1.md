# EPIC8 — Production Intelligence & Hunt Operations v1 — Operational Validation Report

Date: 2026-09-23
Branch: `agent/daily-development`
Baseline: worktree `97cfa89`, production main `4d214fd` (27 dirty untouched, `watch-api` active, port 5000)
LLM: provider `OPENROUTER`, model `openrouter/free` only — paid calls: 0

## 1. Epic summary

A deterministic, READ-ONLY production intelligence projection layer over
the existing authoritative stores (runtime, finding/verification,
campaign, hunt, memory/learning, knowledge, activity, SOC adapters),
exposed as 12 authenticated JSON endpoints and integrated into the
existing AI SOC UI (Targets page + enriched Overview/Activity/Agents/
Cases/Finding views), validated end-to-end by a real bounded production
campaign that ran campaign → objective → hunt plan → authorization →
observations → research → candidate → correlation/dedupe → verification →
Evidence Gate → case → handoff → intelligence/learning.

## 2. Files / modules changed

New — `backend/prod_intel/`: `__init__.py`, `semantics.py`,
`sources.py`, `activity.py`, `overview.py`, `targets.py`,
`agents_intel.py`, `effectiveness.py`, `learning_signals.py`,
`case_intel.py`, `knowledge_usage.py` (11 modules).
New — `backend/routers/intel.py` (JSON API).
New — `web/templates/soc/targets.html`.
New — `docs/production-intelligence.md`.
New tests — `tests/prod_intel_fixtures.py` + 9 suites
(`test_prod_intel_{core,activity,targets,agents,effectiveness,
learning_case,failure_security,production,api_ui}.py`).
Modified — `backend/routers/soc.py` (lazy intel mounts/enrichments; NO
`api.py` change — the intel router is included inside the already-mounted
SOC router), `web/templates/soc/{home,activity,agent_detail,case_detail,
finding_detail}.html`, `web/templates/base.html` (Targets nav entry),
nav allowlists in `tests/{test_recon_soc_navigation,test_soc_ux_correction,
test_soc_ui_stabilization}.py` (new required Targets surface).

## 3. New APIs (OpenAPI-documented, global API-key middleware)

`GET /api/intel/overview` · `/targets` · `/targets/{target}` ·
`/agents` · `/agents/{slug}` · `/activity` · `/now` ·
`/hunt-effectiveness` · `/learning` · `/cases/{case_id}` ·
`/knowledge-usage` · `/handoff` — 401 without key, 404 unknown ids,
422 out-of-range params (hours 0–2160, limit 1–200, offset ≥ 0).

## 4. New UI surfaces

Targets page (`/ui/soc/targets`); AI SOC Overview gains "Operational
intelligence" (active agents/campaigns/hunts, findings, cases, handoffs,
blockers, current state) + AI activity; Activity page gains "Right now"
+ meaningful-activity feed; agent detail gains Operational
intelligence; case detail (runtime family) and finding detail gain the
"Analyst package"; sidebar gains Targets (no existing entry removed or
relocated).

## 5. Data model / projection changes

No new stores, no new sources of truth, no state writes (AST-enforced).
Every metric: `source`, `population`, `aggregation`, `time_range`,
`state`, `reason`, `rule_version = production-intelligence-v1`.
Honest states `unknown`/`unavailable`/`not_observed`/(
`insufficient_population`) never zero-fill; a source outage cannot
masquerade as `0` or `0%` (tests enforce per projection).

## 6. Test counts

- New EPIC8 tests: **251** (core 36, activity 31, targets 28, agents 22,
  effectiveness 16, learning/case/knowledge 39, failure/security 31,
  production integration 9, API/UI 39) — target ≥150 exceeded.
- Certified unit battery (per-suite isolated, Epic6 protocol):
  **43/43 suites, 1,111 tests, 0 failures**
  (log: `scratch/socstab/epic8_battery_iso.log`).
- AEC regression: **78 modules, 2,149 tests, OK**.

## 7. Full regression result

PASS on every suite in the certified battery: **43/43 isolated suites,
1,111 unit tests (860 pre-existing + 251 new), 0 failures** + AEC
**78 modules / 2,149 tests OK** (logs:
`socstab/epic8_battery_final.log`). Additional sweep of the 353 legacy
test files outside every Epic's certified scope: 3,574 + 5,782 tests,
31 non-OK modules — every one verified pre-existing: identical failure
or identical 60–90 s timeout on the untouched production baseline
(`test_asset_cve_matching`, `test_component_binding`,
`test_human_decision_safety`, `test_pipeline_tooling_failfast`,
`test_soc_ui_routes::test_no_write_calls_in_adapters` (`open` in
untouched `backend/soc/campaigns.py`),
`test_soc_router_mounting::test_soc_package_modules_are_the_promoted_set`
(stale promoted-set list), `test_r82_research_dashboard_ui`,
`test_research_activity_api`, `test_research_cases_api`,
`test_research_{ui,economics_projection}`, `test_product_api*`,
`test_research_agent*`, `test_sqli/ssrf_agent_result`, the
`test_research_{leads,sessions,outcomes,...}` timeout family), or
cwd/data-dependent (`test_research_agent_r24_{5,8}` pass with worktree
CODE from production cwd; `test_research_agent` is the documented
data-dependent case). Contract-test outcomes AFTER this epic:
`test_router_exposes_soc_routes` (stale list, now covering all 14 UI
routes incl. Targets) and `test_router_uses_shared_templates_and_api_key_qs`
now PASS — no EPIC8 regression anywhere. Logs: `epic8_rest1.log`,
`epic8_rest2.log`, `epic8_battery_final.log`.

## 8. Security checks

R53 guard clean (no `finding_correlation` in `backend/**`); secret scans
clean (no `sk-or-`/key literals/Bearer in new code); paid-model name
scan clean; AST security suite: no `subprocess`/`socket`/`requests`/
`httpx`/`eval`/`exec` in the projection layer, no write-mode `open()`,
no mutating store calls (`transition_*`, `add_case`, `record_*`,
`enqueue`, …) — the layer cannot write state; LLM-free by AST (no
provider/LLM imports); auth: 401 proven for API+UI; cross-target
isolation test (no foreign ids in a target's payload); no prompt
material or secrets in any projection output (§21).

## 9. Production validation (real, bounded, authorized)

- Campaign: **`camp-91bce2c96fac`** — state **COMPLETED**
  (`all_objectives_terminal resolved=1`, scope
  `watch:scope:www.dell.com/www.dell.com`, real budget ledger used:
  objectives 1/6, observations 2/12, hunt_plans 1/8, runtime 3 s ≤ 600,
  llm_calls 0 this run).
- Objective: **`obj-731de29baba4`** RESOLVED
  (`job=job-xss-d5543b51b4 status=COMPLETED gate=evidence_rules_met
  case=case-96a43ffd7ef1 hunt=NEEDS_EVIDENCE`).

## 10. Real target(s)

`www.dell.com` (program www.dell.com; live attack surface via Mongo:
Urls/Endpoints counts — `ok`, never invented).

## 11. Real observations

20 evidence rows recorded for `job-xss-d5543b51b4` (production totals
now 178 observations/evidence rows); hunt objective `obj-ee1f9d358598`
produced plans/auths then terminated honestly
`NEEDS_EVIDENCE / max_plans_per_objective_reached` (bounded, no bypass).

## 12. Candidate outcomes

New candidates **`cand-3d7d73e9cadc`** and **`cand-7c68214c7df1`**
(extracted from the campaign job; lifecycle → VERIFIED via real
verification; correlated against 5 historical peers, 0 fabricated
duplicates). Totals now 8: VERIFIED 3, DUPLICATE 4, BLOCKED 1.

## 13. Verification outcomes

`ver-f56dc9677ee2` VERIFIED and `ver-0907b2ea98ec` VERIFIED — gate
reason `evidence_rules_met` set by the Evidence Gate (LLM advisory
absent/empty this run: `advisor_outcomes: []`, budget `llm_calls` 0 for
this run; free model only, paid 0). Prior blocked/expired verifications
unchanged.

## 14. Case outcomes

Finding cases: **`fcase-52c1b36c7728`** READY_FOR_REVIEW (new),
**`fcase-cc83aba138a7`** READY_FOR_REVIEW (new), plus existing
`fcase-7349be646c50` (READY_FOR_REVIEW), `fcase-3357949469fa`
(BLOCKED), `fcase-35e4f4f4622d` (DUPLICATE) — totals 5, all labels
truthful. Runtime gate case **`case-96a43ffd7ef1`** created by
`evaluate_case_creation` (existing mechanism, no new case system).

## 15. Handoff outcome

Handoff index count **5** (was 3): both new cases emitted
`finding_case_handoff_ready` events; analyst packages render what was
verified (`evidence gate decision VERIFIED (evidence_rules_met)`), what
was not (honest fallback), payload `unavailable — not stored in an
authorized field`, 40-event timeline, 5 knowledge rows, recommended
next step from persisted state.

## 16. Learning / memory changes

Memory heads 145 → **167** (+34 in the campaign window:
`intelligence_memory_learned` ×3, `parameter_pattern OBSERVED`,
`source_reference RESEARCHED` ×5, …). Learning projection: **8 derived
signals**, all `INFERRED` with provenance refs (never promoted to
VERIFIED), kinds valid per `MEMORY_KINDS`.

## 17. Failure / recovery validation

Scenario suite (31 tests) + live probes: LLM unavailable/malformed →
projection layer has zero LLM imports (AST) and renders without it;
knowledge source down → `unavailable` (not "ok / 0 uses"); authorization
store down → hunt metric `unavailable` with reason; plans store down →
funnel `unavailable`, not `insufficient_population`; empty observations →
denominator 0 → `insufficient_population` with `rate: null` (never 0%);
duplicate candidates counted as DUPLICATE, never success; verification
blocked → blocker + BLOCKED case row; case creation blocked → store
refuses and no fake case appears; interrupted/stale worker → overall
state `UNKNOWN` (never false ACTIVE); corrupt/missing state file →
guard returns `unavailable`/fresh-empty, never a crash and never
zero-filled success; audit append-only completeness asserted; failed
jobs counted under `failure`/blockers only.

## 18. Performance observations

Full target list (discovery + attack surface + everything) ≈ **1.4 s**
on production (first-import Mongo connect ~27 s is startup, not per
request); overview ≈ 0.3 s; effectiveness ≈ 0.2 s; activity feed bounded
to 2,000 audit rows; API caps enforced. No cache exists (spec §15: no
second source of truth); documented in
`docs/production-intelligence.md`.

## 19. Known limitations

- Evidence attribution flows only through job→subdomain links.
- Attack-surface counts require Mongo (`unavailable` otherwise).
- Learning signals are derived projections (max state INFERRED).
- `/ui/soc/cases/{fcase}` intentionally404s (finding-family cases are
  viewed at `/ui/soc/findings/{candidate}` — pre-existing design,
  verified on baseline); the new analyst package is reachable there and
  at `/api/intel/cases/{fcase}`.
- Legacy sweep: some non-certified suites time out or fail on baseline
  (pre-existing, out of EPIC8 scope).

## 20. No-fake-data verification

Every rendered/API number comes from persisted rows (projection canary
test proves the UI reads the backend projection, not template literals);
empty stores render honest empty/unknown states (targets page "No target
is present…" in an empty environment); no hardcoded counters, mock
activity, or placeholder rows exist in any new template; production
readbacks (§9–16) quote real ids only.

## 21. No-paid-LLM verification

Model pinned `openrouter/free`; this Epic's runs made **0 LLM calls**
(campaign budget `llm_calls 0` for the run; `advisor_outcomes: []`);
free-only guard untouched; no paid model name appears in new code;
`OPENROUTER_API_KEY` never printed/persisted (`[REDACTED]`, env unset
after each invocation). Paid calls: **0**.

## 22. Production safety verification

Production main unchanged at `4d214fd`; 27 dirty entries untouched;
`api.py` untouched (asserted: diff contains no intel changes);
no force push / no stash / no reset / no history rewrite; no restart
performed (read-only API additions need none — service verified active
on 5000 before/after); runtime campaign writes are confined to the
gitignored runtime store (production git status unchanged apart from
none); worktree fixture pollution cleaned.

## 23. Delivery gates

- Explicit stage list staged (verified staged==planned).
- `push_safe.sh` → agent branch pushed.
- `report.sh` + `check.sh` → READY (delivery, branch, tests,
  path guard, report, production untouched).
- `request.sh` → `PROMOTION-REQUEST-<id>` created; STOP at Telegram
  APPROVE (no merge before APPROVE).

READY TO PUSH: YES
