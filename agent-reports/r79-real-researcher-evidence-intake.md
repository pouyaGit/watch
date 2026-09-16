# R79 — Real Researcher Evidence Intake

Date: 2026-09-16
Base commit: `6369d9e1ebf5eae057089ad839313c35a3e81a32` (R78)
Rule version: `r79-1` (validation module)
**RESULT: REAL EVIDENCE NOT AVAILABLE.** No genuine researcher-supplied
METHOD_AUTH or RESPONSE_BEHAVIOR observation exists in the authorized
read-only archive, so R79 reports that honestly and validates the contract
offline with clearly labelled `NON-REAL/OFFLINE` fixtures. Synthetic data was
never relabelled as real and nothing was persisted.

## 1. Objective

Validate the first real researcher evidence flow: a researcher obtains
evidence outside Watch, submits it through the existing R74 contract, and
Watch processes it through R74 → R75 → R72 → R73 → R76 → R77 — with Watch
never interacting with the target.

## 2. Primary case (REAL)

`case-indeed-a1-endpoint-behavior` from
`ai_data/research/r77/r64-indeed-b1ebaaf9f2211f82.json` (`r77-1`):
`WAITING_FOR_EVIDENCE`, `INSUFFICIENT / NEEDS_EVIDENCE`, blocking
`METHOD_AUTH`, `RESPONSE_BEHAVIOR`, acquisition `HTTP_BEHAVIOR_REVIEW`
(A1/P1/R1/I1, H1).

## 3. R74 input contract (documented, unchanged)

| Aspect | Requirement |
| --- | --- |
| Package | `package_version = "r74-1"`, `items` list (≤16) |
| Item | `hypothesis_ref`, `requirement_kind`, `effect`, `source` |
| Identity | canonical R68 `kind:value` ref via `observations` or `evidence_ref` |
| Effects | `PROVIDES`, `CONTRADICTS`, `INVALIDATES` |
| Sources | `EXISTING_CONTEXT`, `STORED_RESPONSE`, `HUMAN_REVIEW`, `WATCH_DERIVED`, `AUTHORIZED_TEST_CONTEXT` |
| Requirements | explicit kinds that exist for the hypothesis (`METHOD_AUTH`, `RESPONSE_BEHAVIOR`) |
| Bounds | ≤4 observations/item, bounded refs/facts |
| Rejections | unknown hypothesis/requirement, unsupported effect/source, invalid ref, duplicate, ambiguous invalidation, sensitive data, execution instructions, malformed item/package |
| Sensitive data | no URLs, IPs, Mongo ids, credentials, tokens, cookies, auth headers, personal data, raw bodies, secrets |

## 4. Evidence provenance

The only genuine evidence source available in this environment is the
researcher's existing authorized read-only archive (collected earlier by the
researcher's own pipeline). Its provenance would be "stored authorized
observation"; no manual observation was performed for this milestone.

## 5. REAL evidence availability (checked, not assumed)

Bounded read-only archive probe (counts only, no values copied, no target
interaction):

| Check | Result |
| --- | --- |
| `endpoints` records for the case path | 5 |
| `endpoints` documents with an HTTP method field (whole program) | 0 |
| `http` records for the case path | 0 |
| `http` records for the `/api/internal` namespace | 0 |
| `urls` records for the case path | 7 (no method/status fields) |

Conclusion: **REAL EVIDENCE NOT AVAILABLE** — there is no stored HTTP method
observation, no stored authentication-requirement observation and no stored
HTTP response/status observation for the primary endpoint. Per the mission,
no real run is claimed and no evidence was fabricated.

The availability check is implemented as
`real_evidence_availability(client=None, mongo_uri=None)` with read-only
`count_documents` queries; it copies no document values and reports
`REAL_EVIDENCE_NOT_AVAILABLE` / `REAL_EVIDENCE_AVAILABLE` / `NOT_CHECKED`.

## 6. R74 result (offline, NON-REAL/OFFLINE)

Partial fixture (`METHOD_AUTH`): `ACCEPTED`, 1 accepted, 0 rejections,
canonical ref `response:nonreal-contract-method-auth-1`, relation `NEW`.
Complete fixture (both kinds): `ACCEPTED`, 2 accepted; the re-supplied
`METHOD_AUTH` is a legitimate `DUPLICATE`, `RESPONSE_BEHAVIOR` is `NEW`.

## 7. R75 result (offline, NON-REAL/OFFLINE)

Partial: `NEW`. Complete: `DUPLICATE` + `NEW`. Contradiction fixture:
`CONTRADICTS_EXISTING` → `CONFLICTING` with both sides preserved and
`resolved=false` (no automatic resolution).

## 8. R72 result (offline, NON-REAL/OFFLINE)

`INSUFFICIENT/NEEDS_EVIDENCE` → `PARTIALLY_SUFFICIENT/NEEDS_EVIDENCE`
(METHOD_AUTH) → `SUFFICIENT_FOR_REVIEW/READY_FOR_HUMAN_REVIEW` (both). R72 was
not modified.

## 9. R73 result (offline, NON-REAL/OFFLINE)

`EVIDENCE_GAP_REDUCED / REFINE / CONTINUE` → `HYPOTHESIS_REQUIRES_REVIEW /
STOP / HUMAN_REVIEW`. No new state semantics.

## 10. R76 result (offline, NON-REAL/OFFLINE)

Case identity preserved (`case_id`, action, gap, hypothesis correlation),
bounded history appended without rerunning the pipeline; `identity_preserved =
true` for both rounds.

## 11. R77 before/after (offline, NON-REAL/OFFLINE)

| Section | Before (REAL case) | After partial | After complete |
| --- | --- | --- | --- |
| Status | `WAITING_FOR_EVIDENCE` | `ACTIVE` | `READY_FOR_HUMAN_REVIEW` |
| Know | `ENDPOINT_PURPOSE`, `WATCH_SIGNAL` | + `METHOD_AUTH` | + `METHOD_AUTH`, `RESPONSE_BEHAVIOR` |
| Missing | `METHOD_AUTH`, `RESPONSE_BEHAVIOR` | `RESPONSE_BEHAVIOR` | none |
| Next | `PROVIDE_EVIDENCE`, `CONTINUE_RESEARCH` | `PROVIDE_EVIDENCE`, `CONTINUE_RESEARCH` | `HUMAN_REVIEW`, `REVIEW_EVIDENCE` |
| Human review | no | no | yes (`READINESS_READY_FOR_HUMAN_REVIEW`) |

## 12. Negative validations (contract tests, NON-REAL/OFFLINE)

All five passed through the existing R74/R75 gates:

1. missing required field → `MALFORMED_EVIDENCE`
2. invalid canonical reference → `INVALID_EVIDENCE_REF`
3. sensitive data → `SENSITIVE_EVIDENCE_REJECTED`
4. duplicate evidence → `DUPLICATE_EVIDENCE`
5. contradictory evidence → `CONFLICTING` (preserved, not resolved)

Rejected bodies were never persisted; the sensitive fixture value does not
appear in any output.

## 13. REAL vs NON-REAL/OFFLINE boundary

- REAL: the case, the artifact, the archive availability counts, and the
  finding `REAL_EVIDENCE_NOT_AVAILABLE`.
- NON-REAL/OFFLINE: every evidence package in this milestone (partial,
  complete, conflict, all five negatives), all processed in memory with the
  `NON-REAL/OFFLINE` label in every fact; nothing was written to the artifact
  or Mongo and nothing was relabelled as real.

## 14. Safety

No HTTP request to Indeed, no scanner, no payloads, no exploitation, no
authentication attempt, no automated probing, no subprocess for target
interaction, no Mongo writes, no LLM call. Safety block unchanged:
`advisory=true`, `research_only=true`, `execution_performed=false`,
`vulnerability_confirmed=false`, `exploit_authorized=false`,
`confirmation_state=NOT_CONFIRMED`, `human_authority_required=true`.

## 15. Tests

- `tests/local_e2e/test_r79_real_evidence_intake.py` — **16 passed** (contract
  documentation, availability stubs incl. available/not-available/not-checked,
  labelled fixtures, offline transitions, five negatives, determinism, input
  immutability, safety, no-persistence source scan, real-artifact guarded
  tests).
- `pytest tests/local_e2e -q` — **316 passed, 63 subtests**.
- Adjacent suites (R70–R78 engines, R69 skills, OpenRouter, LLM, priorities,
  R31 planners) — **574 passed**.

## 16. Implementation gaps

None that block a real package. The existing R74/R75/R76 contracts process a
researcher package end-to-end (proven offline and by R78). **No production
code was changed in R79.**

## 17. Actual product value

The system now states honestly whether genuine evidence exists before claiming
a real run, and the complete researcher loop is validated at the contract
level: a package either becomes an accepted, provenance-tracked,
readiness-changing case update or it is rejected with a bounded code. This is
the correct posture for the milestone's safety boundary.

## 18. Limitations

- No real researcher evidence was available in the environment, so only the
  `NON-REAL/OFFLINE` contract path is demonstrated; no real case-state change
  is claimed.
- R74/R75/R76 are in-memory/offline contracts: a researcher submission would
  be processed in a run and included in the research artifact envelope; there
  is no database persistence mechanism for evidence packages, by design.
- The availability probe checks only the archive's method/response fields; a
  future authorized source could make REAL evidence available.

## 19. Files changed

- `tests/local_e2e/r79_real_evidence_intake.py` (new)
- `tests/local_e2e/test_r79_real_evidence_intake.py` (new)
- `agent-reports/r79-real-researcher-evidence-intake.md` (this report)

No production files changed; R65/R66/R68–R78 remain untouched.

## 20. Commit

One local commit: `feat(ai): add real researcher evidence intake`
(hash reported in the final task response). No push.
