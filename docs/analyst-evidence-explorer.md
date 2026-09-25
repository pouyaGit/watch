# Analyst Evidence Explorer (EPIC17)

A projection-only analyst layer over the verification state. It answers, in a
few seconds, four questions on the finding, case and handoff pages:

1. what was **observed** (and what was not);
2. what is **not proven** yet;
3. **why** the current state is what it is;
4. whether this can be **reported**.

## Hard rule

This layer creates **no** gate, taxonomy, lifecycle, authorization model or
evidence rule. EPIC11 (claim/evidence integrity), EPIC12 (verification
chains), EPIC13 (active acquisition), EPIC14 (provenance), EPIC15 (deep DOM
verification) and EPIC16 (multi-class specialists) remain authoritative. The
explorer reads their outputs and re-shapes them; it derives nothing about
evidence.

```
persisted rows
   ↓
EPIC11 Evidence Gate ──────────────► claim/evidence state (authoritative)
   ↓
EPIC12 chain evaluation over the same rows
   ↓
EPIC12/15/16 projection (stages, missing, blockers, authorization, badge)
   ↓
EPIC17 explorer  (labels, counts, sentences, decision interpretation)
```

Implementation: `backend/soc/evidence_explorer.py` (`build()`), rendered by
`web/templates/soc/_evidence_explorer.html`.

## State interpretation

The banner is the EPIC12 badge, shown **verbatim**. `optimistic` is always
`false`, and the badge refuses to read VERIFIED when the verdict leans on an
incomplete chain or on evidence whose declared type disagreed with the
authoritative classification (that combination shows INCONSISTENT).

| badge state | means | must not be read as |
|---|---|---|
| `VERIFIED` | the gate's verdict is VERIFIED, the chain flagged it confirmed, every confirmation-required stage is satisfied, no evidence-type mismatch | a severity or exploitability claim |
| `VERIFICATION_PENDING` | real evidence exists, required stages are still missing | a failed test |
| `BLOCKED` | authorization/scope/budget stopped the run (or the gate refused the claim) | a negative result |
| `NOT_CONFIRMED` | the evidence contradicts or cannot support the claim | "the target is safe" |
| `INCONSISTENT` | the verdict and the chain disagree, or the evidence set is not clean | a valid confirmation |
| `UNKNOWN` / no projection | nothing is persisted for this record | any state at all |

## Chain semantics

Each step is one stage of the class's chain (XSS shown; CORS, Open Redirect,
SSRF, IDOR and CVE use the same mechanism):

```
✓ PARAMETER_OBSERVED            satisfied, required for confirmation
✓ REFLECTION_OBSERVED           satisfied, required for confirmation
✓ OUTPUT_CONTEXT_IDENTIFIED     satisfied, required for confirmation
? DOM_SINK_IDENTIFIED           conditional — not evaluated, never a pass
· PAYLOAD_EXECUTION             missing  (missing [PAYLOAD_EXECUTION])
· EXPLOITABILITY_ESTABLISHED    missing
```

* **glyph/state** comes from the projection (`SATISFIED`, `MISSING`,
  `NOT_APPLICABLE`), never from the template.
* **`required for confirmation`** is the chain's own declaration; a stage
  without it can be skipped, it cannot be counted as evidence.
* **a conditional stage** that was not evaluated is `NOT_PROVEN` — never a
  pass and never a failure.
* **missing evidence types** are always printed, as is the **next stage** and
  what it needs.
* **actions** (with state, safety flag, authorization id, attempt, observation
  count, `blocked_reason`, `error`) and **requests** are rendered straight from
  the projection, so a refused or blocked attempt is visible rather than
  summarised away.
* **capability** (`FULL`, `LIMITED`, `CONTRACT_ONLY`, `NOT_IMPLEMENTED`) says
  whether this runtime can reach the stage at all; a stage this runtime cannot
  reach is unavailable, not "failed".

## Observed vs proven

* **Observation** — stages satisfied by recorded evidence
  (`PARAMETER_OBSERVED`, `REFLECTION_OBSERVED`, `OUTPUT_CONTEXT_IDENTIFIED`).
  These say what exists; they do not say it is exploitable.
* **Proof** — confirmation-capable stages (`PAYLOAD_EXECUTION`,
  `EXPLOITABILITY_ESTABLISHED`) plus the EPIC15 DOM lineage verdict
  (`SOURCE_AND_SINK_LINEAGE`). Only a lineage-bound read→sink flow counts:

```
DOM Sink Indicator : innerHTML mentioned
Lineage            : NOT FOUND
Status             : SOURCE_ONLY      ← presence-only is not proof
```

A declared sink with no traced flow is `SOURCE_ONLY` / `NOT TESTED` and never
appears under Proof.

## Why this state?

Deterministic sentences assembled from projection fields — never LLM text:

* the state, the verdict and which projection produced it (`verdict_source`);
* the authorization status (`GRANTED` / `SATISFIED WITHOUT A RECORDED GRANT` /
  `NOT GRANTED`) and, when not granted, that active verification is blocked;
* stages satisfied and stages not proven;
* the EPIC15 deep state, DOM flow and lane blockers;
* the EPIC11 claim/evidence state and gate reason;
* the reportability interpretation.

## Evidence summary

Raw and unique counts are shown side by side, with duplicate events and the
distinct signals. **A count is not a strength**: adding 40 duplicate rows
raises `Raw observations` only — the badge, the unique count, the missing
evidence set and the explorer's `strength_digest` do not move.

## Can this be reported?

`YES` / `NO` / `REVIEW` plus deterministic reasons, labelled at the bottom as
"interpretation of the persisted verification state only … not a verdict".
`YES` requires the authoritative badge VERIFIED (chain complete, no mismatch)
and no blockers.

## Parity contract

The finding page, the SOC case page and the handoff package render **one**
read-model for the same candidate id — the same page module calls
`soc_findings.explorer_view(candidate_id)`, which resolves the canonical store
and builds the projection once. There is no per-page variant, no template-side
computation and no evidence recalculation.

The contract is enumerated field by field and asserted per field for the same
candidate id (`test_projection_parity_contract_holds_field_by_field`):

* verification state — `banner`, `chain.badge`
* `verdict`, `verdict_source`, `verdict_reason`
* `chain.steps`, `stage_count`, `satisfied_count`
* `next_stage`, `next_stage_label`, `next_stage_missing_types`
* `evidence_used`, `evidence_missing`, `evidence_missing_types`
* `negative_results`, `contradictions`
* `actions`, `requests`, `authorization`
* `why_not_confirmed`, `blockers`, `trust_boundary`, `limitations`
* `capability`
* deep verification block — `deep`
* `banner == chain.badge` on every surface (the UI has no state of its own)
* one shared `strength_digest`, and all three templates include the single
  partial

No page may independently reinterpret or recompute any of these fields.

## Security requirements (§7) and where they are enforced

* **the LLM decides nothing** — the explorer takes no LLM input; an advisory
  cannot change the decision or the digest (tested).
* **the UI cannot create VERIFIED** — the banner is the projection badge;
  VERIFIED requires the gate verdict plus a complete, clean chain.
* **evidence count ≠ evidence quality** — separate counters plus
  `strength_digest`.
* **missing stages are always shown** — steps, missing types, next stage and
  "Stages not proven".
* **authorization is always visible** — the summary cell and the chain
  authorization block are always rendered; an implied-but-unrecorded grant is
  shown as `SATISFIED WITHOUT A RECORDED GRANT`.

## Entry points

* `backend/soc/evidence_explorer.py` — the projection (`build`, `banner`,
  `chain_steps`, `observation_vs_proof`, `evidence_summary`,
  `analyst_decision`, `why_this_state`, `strength_digest`).
* `backend/soc/findings.py` — `evidence_payload()` (one read path),
  `explorer_view()`; `finding_detail()` exposes `explorer`.
* `backend/soc/cases.py`, `backend/soc/handoff.py` — the same key on the
  finding-case and handoff payloads.
* `web/templates/soc/_evidence_explorer.html` — the single rendered partial.
