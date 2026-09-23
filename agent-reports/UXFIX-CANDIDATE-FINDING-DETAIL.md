# Candidate Detail UX / Data Contract Fix — Task Report

Task: URGENT UX + DATA CONTRACT FIX — Candidate / Finding Detail (analyst
usability). Focused correction, explicitly NOT a new Epic.

Work location: `/opt/watch/.worktrees/watch-agent` (branch
`agent/daily-development`). Production `/opt/watch` was never edited.

---

## 1. What changed

| File | Change |
| --- | --- |
| `backend/soc/candidate_workspace.py` (NEW, 1074 lines) | One authoritative current-state projection `build_workspace(detail, fs)` for the detail page: summary, states, why, affected, observations (grouped), verification, verified/not-verified, LLM advisory, case package, next step, related, timeline, links, raw. |
| `backend/soc/findings.py` | `finding_detail()` now attaches `workspace` (all legacy keys preserved) and degrades honestly (`available:false` + error type) if projection ever fails. |
| `backend/soc/cases.py` | `_finding_case_detail()` + `_finding_evidence_artifacts()` — `/ui/soc/cases/{fcase-*}` now resolves (was 404) with honest evidence rows (`not_recorded` columns); `_resolution()` gains the finding branch. AEC/runtime resolution untouched. |
| `web/templates/soc/finding_detail.html` | Full rewrite (749 changed lines) to the §14 section order; presentation-only, `nav()` macro for internal links, external links never receive an `api_key`. |
| `tests/test_candidate_workspace.py` (NEW, 802 lines) | 47 tests covering every §18 bullet. |

## 2. Authoritative state (§1)

`workspace.states` = candidate lifecycle + verification + finding case + gate
decision, read ONLY from persisted rows. Header badges use
`summary.candidate_state` / `summary.case_state`. For the observed candidate
(`cand-7c229c48c455`): candidate **VERIFIED**, verification **VERIFIED**
(`evidence_rules_met`), case **READY_FOR_REVIEW** — all three shown as current.
The stale advisory state is confined to the LLM section.

The blanket line "This is a candidate, not a confirmed vulnerability." is gone.
State-dependent notices replace it; for VERIFIED: "Authoritative Evidence Gate
decision recorded (evidence_rules_met); finding case READY_FOR_REVIEW." If a
VERIFIED candidate ever lacks a gate row, the notice says so honestly instead
of claiming a decision record (regression-tested).

## 3. Sections delivered (§2–§14)

Header summary (type, id, state badges, target, affected URL, specialist,
created/updated) → NEXT STEP → Affected resource (clickable URL, method/
parameters/source records with real routes) → Why this candidate exists
(persisted signals, reason, confidence + provenance, parameter with source,
evidence gaps) → Observations (grouped summary + full event table) →
Verification (status/rule/ids/decided, WHAT WAS VERIFIED, WHAT WAS NOT
VERIFIED, four-way distinction table) → Evidence → Case & Handoff (Analyst
package, limitations, timeline) → Research timeline (human labels) → Related
candidates (deduped) → LLM advisory (historical) → Raw / engineering details.

## 4. Evidence grouping (§5–§6)

Group key = persisted observation identity (`observation_ref` + signal).
Real candidate: **20 unique observations / 40 persisted events**, each group
showing id, type, quality, role, first/last observed, event count, jobs and
the linked URL record (parameters resolved from Mongo `Urls`). The full
40-event table stays below in an explicit `<details>` — presentation only;
nothing is deleted, hidden by CSS, or dropped from storage.

## 5. Related-candidate dedup (§12)

Merged by candidate id: 10 correlation rows + linked duplicates → **7 unique
rows**, one link each, with relations, merged reasons, current state of the
other candidate (store lookup; `not_found`/`unavailable` when absent).
Canonical/preserved evidence shown. Fixed a real defect found by tests: an
empty `canonical_id` could equal an empty `our_id` and mislabel "preserved
evidence" (now guarded; `our_id` also falls back to the nested candidate).

## 6. Verification vs not-verified (§7–§8)

Four distinct dimensions are rendered separately: Evidence Gate verification
(decision, rule, ids, timestamps), exploitability (no payload execution
recorded; payload detail `unavailable — not stored in an authorized field`),
severity (value + provenance, `UNASSESSED` kept honest), external-report
readiness (case state). CVE: not established (no persisted CVE field scanned).
`what_was_verified` counts come from persisted evidence ids, with used-vs-total
wording.

## 7. LLM advisory (§9)

Rendered only inside "Historical LLM Advisory", with current authoritative
state beside it. The advisory's claimed state is extracted from the advisory
text itself (bounded token match over the authoritative vocabulary) and
labelled as text-claimed, not persisted: `state_at_generation` is
`not_recorded` (the advisor payload has no state/timestamp fields — verified
against `provenance.advisor`). Model `openrouter/free`, role ADVISORY ONLY,
authority Evidence Gate. Verified: `VERIFICATION_PENDING` never appears outside
the historical section.

## 8. Data contract (§17)

All business logic lives in `candidate_workspace.py`; the template has no
derivation beyond presentation. Missing → `not_recorded`, lookup failed →
`unavailable`, truly absent concept → `unknown`/empty. No inference of
parameter/exploitability/severity/payload/CVE from unrelated text. Mongo
source-record lookups share one fail-closed `_safe` envelope (a dead Mongo
renders `unavailable` instead of hanging; regression-tested with a raising
mock).

## 9. Security (§16)

* External links (affected URL) never carry `api_key` — asserted for both
  empty and populated query context.
* The page never injects the server-side key: `soc._ctx` propagates only the
  caller's own query value; with no key supplied, **0 hrefs** contain
  `api_key=`.
* Secret scan on changed files: 0 `sk-or-`/`sk-or` fragments (assembled
  fragments only where needed — none needed), no `Bearer`/`Authorization`
  values, R53 `finding_correlation` = 0, paid-model mentions = 0.
* **Honest §16 finding:** this app has NO session/cookie/localStorage
  mechanism (`APIKeyMiddleware` accepts header or `?api_key=` only). Removing
  `?api_key=` from internal navigation would 401 every link and would change
  authorization semantics (explicitly forbidden), so the stated conditional
  ("if the application already has authenticated session/API behavior") is NOT
  satisfied — the existing convention was preserved for internal links only.
* **Rotate recommendation:** if the observed key appeared in a shared
  URL/screenshot/log, rotate it. Out-of-scope exposure noted (not touched):
  `pages.py`, `runs.py`, `programs.py`, `research_pages.py`,
  `command_center.py` render `"api_key_qs": API_KEY` (server's own key into
  page HTML for header-authenticated visitors) — recommend a follow-up task +
  rotation review.

## 10. Navigation (§15)

Verified live routes only: `/ui/program/dell`, `/ui/urls?...&program=dell`,
`/ui/endpoints?...`, `/ui/parameters`, `/ui/soc/handoff/{source,verification
job}` (both resolve), `/ui/soc/cases/{gate case}` (resolves),
`/ui/soc/cases/{fcase}` (newly resolving — this fix), `/ui/soc/cases`,
`/ui/soc/handoff`, related `/ui/soc/findings/{id}`, secondary JSON
`/api/intel/cases/{fcase}`. Hunt objective has no UI route → shown in raw with
`no UI route` note (no fake links).

## 11. Validation on real production data

Rendered `cand-7c229c48c455` with `api_key_qs=""` and `"KEY123"`: **31/31
checks pass** (state consistency, notice, 20/40 grouping, 8-entry timeline with
the exact human labels, next step, not-verified list, distinctions, all case
links, external-clean + internal-propagation, no secret fragments, grouped view
shows each observation once, full table lists all 40 events).

## 12. Tests

* New: `tests/test_candidate_workspace.py` — **47 tests, all green** (states
  ×9: DETECTED/TRIAGED/VERIFICATION_PLANNED/VERIFICATION_PENDING/VERIFYING/
  VERIFIED/REJECTED/BLOCKED/DUPLICATE; stale LLM; XSS escaping; auth
  propagation; no-secret; missing/unknown fields; Mongo-down; store-backed
  pipeline; workspace-failure degrade).
* Affected existing suites (isolated): `test_finding_soc`,
  `test_finding_cycle2_fixes`, `test_finding_failure`,
  `test_prod_intel_api_ui`, `test_soc_ui_cases`, `test_recon_soc_navigation`,
  `test_agent_runtime_e2e_soc`, `test_research_intelligence_soc`,
  `test_hunt_planner_soc` — all **OK**.
* House battery (the 51-suite promotion battery from the last promotion):
  part1 **731 tests OK** (combined run, exit=0); part2 **25/25 suites OK**
  isolated. The combined part2 run showed the known cross-module shadowing
  artifact (4 reds: `test_finding_verification_safety`,
  `test_hunt_planner_safety`, 2× `test_research_intelligence_soc`) — all four
  green when re-run isolated (37+24+8 tests OK), which is this repo's
  documented isolated-run rule, not a regression.
* Supplementary corpus sweep (my own extension beyond the house battery):
  255/363 suites run before stopping — 242 green; 12 red/time-boxed, **every
  one baseline-proven** below (none in this diff's blast radius).
* AEC: **78 modules / 2,149 tests / 0 failed** (exit=0).

## 13. Known limitations

1. No session mechanism exists → `?api_key=` remains the browser auth channel
   for internal links (unchanged app-wide convention; documented above with
   rotation advice).
2. Pre-existing red (NOT from this fix, proven identical at production main
   `06922b7`): `test_soc_ui_routes::test_no_write_calls_in_adapters` flags
   `open("r")` in `backend/soc/campaigns.py` (file last touched by `4a1e62d`,
   clean vs HEAD; test file clean).
3. Pre-existing reds (all reproduced identically on untouched production main
   `06922b7` — NOT from this fix): `test_soc_ui_routes` (campaigns.py name-scan),
   `test_component_binding` (local snapshot missing),
   `test_human_decision_safety`, `test_pipeline_tooling_failfast` (PATH
   assertion) fail on both trees; `test_asset_cve_matching`,
   `test_daily_research_workflow`, `test_dashboard_navigation`,
   `test_hunt_queue`, `test_observed_inventory`,
   `test_opportunity_action_queue`, `test_product_api`,
   `test_product_api_client`, `test_product_validation` hang/CPU-spin on both
   trees (time-boxed at 120-150s; baseline exit=124 or spin observed). The 4
   EPIC9-era mongo suites are GREEN today (mongo reachable).
4. Authenticated live-page rendering cannot be exercised end-to-end without
   the production API key (not in agent environment) — verified via template
   render with production data instead; stated honestly.
5. `/ui/soc/cases/{fcase}` now renders the case record with honest
   `not_recorded` columns for AEC-only fields; finding-case handoff content
   stays on the candidate page (matches existing `cases_index` view_url design
   — no competing detail view created).
6. When no parameter-discovery record exists for the affected path, only the
   parameter inventory link is offered (no filtered link fabricated).

---

**TEST SUMMARY:** new suite 47/47; house battery part1 731 OK, part2 25/25
isolated OK; affected suites 9/9 isolated OK (finding 13+10+16, prod_intel 39,
soc_cases 10, recon 26, e2e_soc 14, intel_soc 8, hunt_soc 15); AEC 2,149/0
failed; real-page smoke 31/31; guards R53/paid/secret clean. Corpus reds (12)
all baseline-proven pre-existing.

**READY TO PUSH: YES**
