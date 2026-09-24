# EPIC14 — Evidence Provenance Hardening & Trust Boundary v1

Baseline: `main = c935c56e` (EPIC13 promoted).
Branch: `agent/daily-development`.

## Trust-boundary finding

EPIC13 exposed one weakness, and the audit found a second of the same kind.

1. **`taxonomy.classify_row` consulted the row's `evidence_type` before the
   signal registry** (`elif declared in EVIDENCE_TYPE_SET: evidence_type =
   declared`, plus a second block that re-applied the declared value). A
   persisted row could therefore self-declare a stronger type than its signal
   supports:

   ```
   signal = xss_parameter_inventory      authoritative: PARAMETER_OBSERVED
   evidence_type = PAYLOAD_EXECUTION     declared:      PAYLOAD_EXECUTION
   → pre-EPIC14: the gate honoured the declared type
   ```

2. **No provenance requirement for confirmation-capable evidence.** Any row
   whose signal mapped to `PAYLOAD_EXECUTION` / `EXPLOITABILITY_ESTABLISHED`
   reached `CONFIRMATION_EVIDENCE` with no check that a trusted deterministic
   path produced it. An advisory (`type=llm_insight`) row carrying
   `signal=payload_execution` was accepted as confirmation evidence by the gate
   while EPIC12's chain refused it as inadmissible — the divergence EPIC12 had
   been reporting.

Audit of the full path (`raw observation → signal → row → classification →
type → claim → gate → lifecycle`) found every location where a row-supplied
field could influence authoritative semantics:

| field | pre-EPIC14 influence | EPIC14 |
| --- | --- | --- |
| `evidence_type` | **authoritative** (overrode the registry) | declared only; mismatch recorded |
| `signal` | authoritative input | unchanged (classified against the registry) |
| `category` | display only | unchanged (verified not authoritative) |
| `confidence` | copied, never used in claim status | unchanged (verified not authoritative; pinned by tests) |
| `provenance` / `provenance_class` | did not exist | **derived from structure only**; a row cannot declare its own |
| unknown `signal` + declared type | declared type honoured | **fail closed** → `UNCLASSIFIED_OBSERVATION` |

Also found: `verification/store.py` displayed the raw declared type in the SOC
evidence listing, and EPIC12's engine re-derived mismatches locally.

## Authoritative classification

One path, unchanged vocabulary:

```
RAW SIGNAL → AUTHORITATIVE SIGNAL REGISTRY → AUTHORITATIVE EVIDENCE TYPE
          → EVIDENCE STAGE → CLAIM EVALUATION → EPIC11 EVIDENCE GATE
```

Precedence: negative/not-tested families → **registry (authoritative)** →
unknown signal (fail closed) → non-observation `type` → declared-only stamp
(typing only, never confirmation) → unclassified.

`EVIDENCE_TYPES` (15), `CONFIRMATION_EVIDENCE` (2), `TAXONOMY_RULE_VERSION`
and the stage map are untouched. The classifier version is recorded separately:
`epic14-authoritative-classification-1`.

## Declared vs authoritative

The persisted `evidence_type` field is preserved for compatibility. The
classified item now carries `declared_evidence_type`,
`authoritative_evidence_type`, `mismatch` and `provenance_class`. A declared
value that agrees is accepted; a declared value that differs is a mismatch and
is **never** coerced.

## Provenance

Seven classes (`OBSERVATION_DERIVED`, `ACQUISITION_DERIVED`,
`VERIFICATION_DERIVED`, `RESEARCH_DERIVED`, `ADVISORY`, `LEGACY`, `UNKNOWN`),
derived from row structure. Trusted for confirmation:
`{OBSERVATION_DERIVED, ACQUISITION_DERIVED, VERIFICATION_DERIVED}`. Every
classified row records source, observation key, job, candidate, authorization
ref, scope, agent, rule version and classifier version, so the classification
is reproducible and auditable.

## Mismatch handling

`evidence_type_mismatch` with `class` ∈ {`declared_stronger`,
`declared_weaker`, `declared_unrelated`, `declared_with_unknown_signal`},
carrying signal, declared type, authoritative type, source, evidence id,
observation id, job id, candidate id, timestamp, classifier version and
provenance class. A mismatch that tried to raise strength makes the row
contribute **nothing**; a mismatched confirmation-capable row is excluded with
reason `mismatched_evidence`. Visible to claim evaluation, the gate, the
verification chain (`ChainState.evidence_mismatches` + a `divergence` token),
the audit and the SOC projection (`trust_boundary` block; a verified verdict
carrying a mismatch is never a clean badge).

## Evidence Gate

EPIC11 remains the only authority. It consumes the authoritative classification
through `claims.evaluate_rows`; `IntegrityDecision` now carries
`evidence_mismatches` and `excluded_evidence` so the gate's consumers see the
boundary state. No blocker vocabulary changed, no second gate, no second
taxonomy, no second lifecycle, no second claim evaluator.

## EPIC12 integration

The chain consumes EPIC11's result instead of re-deriving it:
`tx.authoritative_items` / `tx.contributes_to_authoritative_stage` drive stage
membership, and `ChainState.evidence_mismatches` / `.excluded_evidence` /
`.classifier_version` carry the authoritative records. Two EPIC12 tests that
had pinned the *open* boundary (an advisory row reaching the gate) now pin the
closed one.

## EPIC13 integration

`observations.positive()` refuses at the producer to create a row whose
declared type disagrees with its signal (`ObservationError`), so a caller
cannot relabel `PARAMETER_OBSERVED` as `REFLECTION_OBSERVED` or
`PAYLOAD_EXECUTION`. A legitimate acquisition observation is
`ACQUISITION_DERIVED` and contributes normally.

## Cross-class audit

XSS (contract `XSS`), SSRF (contract `SSRF`), SQLI/IDOR/JWT/OAUTH (contracts,
not audited further here), CORS and OPEN_REDIRECT (**no contract of their own**
→ `GENERIC`), CVE_RESEARCH (contract with **no confirmation claim**).

Documented findings, deliberately not "fixed" (new capability work, out of
scope): CORS/OPEN_REDIRECT inherit `GENERIC`, whose confirmation requirement
includes `DOM_SINK_IDENTIFIED` — a type neither chain produces, so confirmation
is unreachable through the gate for those classes (fail-closed by
construction). CVE_RESEARCH has no confirmation claim at all, so an advisory
row asserting exploitability confirms nothing.

## Security validation

The fifteen §19 adversarial cases are encoded as tests, plus the full attack
matrix run through the gate, the claim evaluator, the chain and the projection:
none confirms, none produces an optimistic badge, all are auditable. LLM
injection (evidence_type field, signal+type pair, confidence, prose, a
hand-built object) cannot escalate. API/persistence: `record_evidence` refuses
mislabelled rows, unknown signals with a stamp, and confirmation-capable rows
without the trusted producers' attestation. A directly constructed
`EvidenceItem` carries `UNKNOWN` provenance and can never confirm.

**Stated residual boundary:** EPIC14 closes the *metadata* boundary. It is not
cryptographic attestation — a writer who fabricates an internally consistent row
shape is bounded by the required-evidence rule and the persistence attestation,
not by a mismatch. Documented in `docs/evidence-provenance-hardening.md`.

## Production validation

READ-ONLY against the real production store (`/opt/watch`, 20 real
`xss_parameter_inventory` rows for `cand-7c229c48c455`), no live traffic, no
transport, no writes:

* real rows → all `PARAMETER_OBSERVED`, `OBSERVATION_DERIVED`, 0 mismatches,
  stage 1, verdict `BLOCKED / missing_authorization_confirmation`,
  `confirmed=False`, projection clean;
* the same 20 real rows stamped `PAYLOAD_EXECUTION` → authoritative types still
  `PARAMETER_OBSERVED`, **20 mismatches recorded**, verdict `BLOCKED`,
  `confirmed=False`, badge not optimistic;
* confirmation claim `UNSUPPORTED` in both cases; with the forged stamps, 20
  mismatches and 20 exclusions recorded at the gate, the mismatch record
  carrying class/signal/declared/authoritative/classifier version;
* a legitimate EPIC13-derived acquisition observation → `REFLECTION_OBSERVED`,
  `ACQUISITION_DERIVED`, trusted, contributes, and advances the real
  candidate's chain 1 → 3 (still not confirmed, correctly: no execution
  evidence).

## cand-7c229c48c455

Historical record preserved untouched (20 rows, one signal, no rewriting). The
current authoritative assessment is stage 1 / not confirmed. Adding a forged
`PAYLOAD_EXECUTION` stamp to those rows — or to all 20 — does not move the
verdict, does not move the furthest stage, and is recorded as a mismatch. The
historical persisted VERIFIED state is never re-interpreted as a current
verdict.

## Tests

* EPIC14 focused suite: **291 tests OK**
  * `test_epic14_classification` 71
  * `test_epic14_provenance` 48
  * `test_epic14_claim_gate` 73
  * `test_epic14_persistence_security` 57
  * `test_epic14_regression` 42
* EPIC11 + EPIC12 + EPIC13 regression: **1144 tests OK** (unchanged suites)
* Combined EPIC11/12/13/14: **1435 tests OK**

## Full regression

Full worktree discovery compared against the pre-EPIC14 baseline: no new
failures; all failures are the known artifact-dependent suites (identical
unique-failure set to the baseline). EPIC11/12/13/14 failure count: **0**.

## LLM

`provider=openrouter/free`, `calls=0` — this Epic is deterministic provenance
work; no LLM was invoked, so no LLM failures. The LLM boundary is *tested*
(advisory rows, injected `evidence_type` fields, confidence and prose cannot
escalate evidence).

## Files changed

New:

* `docs/evidence-provenance-hardening.md`
* `tests/epic14_fixtures.py`
* `tests/test_epic14_classification.py`
* `tests/test_epic14_provenance.py`
* `tests/test_epic14_claim_gate.py`
* `tests/test_epic14_persistence_security.py`
* `tests/test_epic14_regression.py`

Modified:

* `backend/research_agents/finding/integrity/taxonomy.py` (authoritative
  precedence, provenance classes, mismatch records, contributor rule)
* `backend/research_agents/finding/integrity/claims.py` (exclusion of
  mismatched / untrusted confirmation evidence; mismatch reporting)
* `backend/research_agents/finding/integrity/gate.py` (mismatch visibility)
* `backend/research_agents/runtime_store.py` (`record_evidence` trust guard,
  `EvidenceTrustError`)
* `backend/research_agents/verification/engine.py` (consume the authoritative
  rule and mismatch result)
* `backend/research_agents/verification/observations.py` (producer-side
  signal↔type guard)
* `backend/research_agents/verification/projection.py` (`trust_boundary` block,
  mismatch-aware badge)
* `backend/research_agents/verification/store.py` (authoritative type in the
  evidence listing)
* `tests/test_epic12_engine.py`, `tests/test_epic12_adversarial.py` (pinned the
  open boundary; now pin the closed one)

## Delivery

Commit: `EPIC14 — Evidence Provenance Hardening & Trust Boundary v1`
Agent branch: `agent/daily-development` (pushed)
Promotion request: `agent-reports/promotions/PROMOTION-REQUEST-<ts>.md`

## READY TO PUSH: YES

The branch is pushed and the promotion request is waiting for Telegram
APPROVE.
