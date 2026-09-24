# EPIC17 — Analyst Evidence Explorer v1

**Baseline:** `main = c5db861` (EPIC16 promoted, audit seq 97/98)
**Agent branch:** `agent/daily-development`
**Status:** implementation complete, tests green, delivery checks run
**Scope:** projection/UI only — `finding_detail`, `case_detail`, `handoff_detail`
(SOC surfaces). The AEC `case_detail` family was **not** modified.

## 1. Problem (confirmed in the repository, not assumed)

The analyst page could present a reflection + context + sink *indicator* case in a
way that reads as verified, because the finding workspace carried an EPIC10-era
state derivation that is independent of the evidence gate:

* `backend/soc/candidate_workspace.py` — `verification_outcome()` (line 239)
  maps candidate/verification lifecycle strings; `cand_state == "VERIFIED"`
  yields `VERIFIED`, and `_notice_kind()` (841) turns that into a "verified"
  notice rendered as the page's state banner (`finding_detail.html` line 95).
* `backend/soc/cases.py` — `_verdict_state()` (546) is a second, case-level
  derivation (`research_state`).
* `backend/research_agents/verification/projection.py` — the authoritative
  EPIC12/15/16 chain projection (`chain_projection_for_candidate`,
  `project_chain`, `badge_for`, `deep_verification_block`) had **no production
  consumer at all**: no page or API rendered stages, missing evidence,
  blockers, authorization or the badge.

## 2. What EPIC17 changed

**New** `backend/soc/evidence_explorer.py` — one projection module
(`RULE_VERSION = "epic17-analyst-evidence-explorer-1"`). It calls the existing
projections and only re-shapes their output:

| surface | source (authoritative) |
|---|---|
| banner (state) | EPIC12 `badge_for` via the chain projection — verbatim |
| chain steps, missing types, next stage, blockers, contradictions, limitations | EPIC12/15/16 `project_chain` |
| evidence used / negative results / authorization | `project_chain` (authorization lineage read from persisted rows) |
| claim/evidence state, gate reason, matrix, unique/duplicate counters | EPIC11 `_integrity_block` |
| deep state, DOM flow, execution/exploitability | EPIC15 `deep_verification_block` |
| observation vs proof, evidence summary, why-this-state, decision panel | labels/sentences assembled from the four sources above |

**Shared read path:** `backend/soc/findings.py` gained `evidence_rows()` and
`evidence_payload()`; the finding page and the explorer now read the *same*
persisted rows (the previous inline block was replaced by the helper), so the
page and the projection cannot disagree about what was recorded.

**Parity (§3):** `findings.explorer_view(candidate_id)` resolves the canonical
store; `finding_detail()`, `cases._finding_case_detail()`/`case_detail()` and
`handoff._finding_detail_for_job()` all expose the identical `explorer` dict
for the same candidate id. Asserted byte-for-byte in the tests.

**UI:** one shared partial `web/templates/soc/_evidence_explorer.html`
included by the three SOC templates — chain steps, observation vs proof,
"why this state?", evidence summary, "can this be reported?", plus blockers,
trust-boundary mismatches, deep state and limitations. No template-side
computation.

**Decision 1 (as approved):** `verification_outcome()` and `_notice()` are
**unchanged** and still exercised (EPIC10 tests pin them) but are no longer a
UI source — the notice `<p>` was removed from `finding_detail.html` and the
explorer banner is the only analyst-facing state banner. On the case page the
legacy case-lifecycle badge is now labelled `case {{ verdict }}` with a
tooltip pointing at the explorer banner (`_verdict_state` itself untouched).

## 3. Capability/behaviour matrix (as rendered)

* reflection-only XSS → `VERIFICATION_PENDING`, no proof recorded,
  `PAYLOAD_EXECUTION` / `EXPLOITABILITY_ESTABLISHED` shown as missing,
  decision `NO`
* complete chain (payload execution + exploitability evidence) →
  `VERIFIED`, decision `YES`, proof = `PAYLOAD_EXECUTION`,
  `EXPLOITABILITY_ESTABLISHED`
* verdict VERIFIED with an unsatisfied confirmation-required stage →
  `INCONSISTENT` ("do not trust a badge"), never `VERIFIED`
* DOM sink indicator without lineage → `SOURCE_ONLY` / `NOT TESTED`, never
  under Proof
* authorization implied by scope but with no recorded authorization row →
  `SATISFIED WITHOUT A RECORDED GRANT` (the gap is shown, not hidden)
* no projection → explicit "no projection" view, decision `REVIEW`, no state

## 4. Tests

`tests/test_epic17_evidence_explorer.py` — **19 tests OK**, covering the six
required scenarios plus: banner-is-the-badge invariant, duplicate evidence
cannot move the strength digest, LLM advisory cannot change the decision or
the digest, missing stages always rendered, authorization always visible,
three-surface parity, one shared partial, and "no second gate/taxonomy/
lifecycle" source assertions.

Regression: **2,161 tests OK** across the EPIC11–16 suites plus
`test_candidate_workspace`, `test_finding_soc`,
`test_research_intelligence_soc`, `test_aec_ui_pages`.

## 4b. Production read-only validation

The explorer was run against the **real** production store (read-only,
`WATCH_AGENT_RUNTIME_DIR=/opt/watch/ai_data/research/agent/runtime`) on the
candidate from the reported case, `cand-7c229c48c455`:

```
banner      : VERIFICATION_PENDING | Not confirmed — verification pending
verdict     : VERIFICATION_PENDING / epic11_integrity_gate
stages      : 1 / 6   (only PARAMETER_OBSERVED satisfied)
              · REFLECTION_OBSERVED / OUTPUT_CONTEXT_IDENTIFIED /
                DOM_SINK_IDENTIFIED / PAYLOAD_EXECUTION /
                EXPLOITABILITY_ESTABLISHED → missing, with types shown
auth        : GRANTED (authz-35e609a42d32, authz-42bf89ffbcce)
raw/unique  : 40 / not recorded   | dom NOT TESTED | payload NO
proof       : []            decision: NO
integrity   : not_recorded (no EPIC11 contract on the record) → confirmed False
```

So the exact case that previously read as verified — 40 observations, reflection,
an attribute context and an `innerHTML` sink indicator — now renders as
**not confirmed, 1/6 stages, no proof, decision NO**, with the missing evidence
types and the authorization lineage visible. Nothing was written to production.

## 5. Security review (§7)

* LLM takes no decision — the explorer takes no LLM input; an advisory dict
  (including a forged `state: VERIFIED`) changes neither the decision nor the
  strength digest (tested).
* The UI cannot build VERIFIED — the banner is the projection badge; VERIFIED
  requires the gate verdict *and* a complete, clean chain.
* Counts never replace quality — raw/unique/duplicates shown side by side with
  an explicit note; `strength_digest` excludes raw counts.
* Missing stages and the authorization status are always rendered.
* Read-only: no writes, no network calls, no new primitive
  (`record_evidence` is patched to raise in a test).

## 6. Deviations / honest notes

* The explorer reports `unique_observations` as **"not recorded"** when the
  EPIC11 basis does not carry it (pre-contract records) instead of computing a
  substitute — no evidence is recalculated in the UI layer.
* A projected `VERIFIED` verdict with an incomplete chain shows `INCONSISTENT`
  (EPIC12 badge guard). This is intended and is surfaced verbatim rather than
  smoothed over; the finding page therefore never says "Verified" for a chain
  that is not complete.
* Case-page parity applies to finding-family cases (`fcase-*`); AEC/runtime
  cases have no candidate id and show the honest "no projection" view. The AEC
  templates were untouched per the approved scope.

## 7. Files

* new: `backend/soc/evidence_explorer.py`,
  `web/templates/soc/_evidence_explorer.html`,
  `tests/test_epic17_evidence_explorer.py`,
  `docs/analyst-evidence-explorer.md`, this report
* modified: `backend/soc/findings.py`, `backend/soc/cases.py`,
  `backend/soc/handoff.py`, `web/templates/soc/finding_detail.html`,
  `web/templates/soc/case_detail.html`,
  `web/templates/soc/handoff_detail.html`

## 8. Delivery

* `diff_guard`: PASS (see promotion request)
* `check.sh`: six checks PASS, verdict READY FOR PROMOTION
* production untouched (HEAD `c5db861`, 27 unrelated dirty entries preserved)
* **READY TO PUSH: YES**
