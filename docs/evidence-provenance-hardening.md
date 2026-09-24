# Evidence Provenance Hardening & Trust Boundary (EPIC14)

## The invariant

> **Evidence strength is determined by authoritative provenance and signal
> classification, not by a persisted row's self-declared evidence type.**

A persisted evidence row may carry metadata for compatibility, debugging and
audit. That metadata can never raise the strength of the evidence the row
represents.

Before EPIC14, the EPIC11 taxonomy consulted a row's `evidence_type` *before*
the signal registry, so this attack worked:

```
signal        = xss_parameter_inventory
evidence_type = PAYLOAD_EXECUTION          # hand-written
→ authoritative classification: PARAMETER_OBSERVED  (must be)
→ actual pre-EPIC14 classification: PAYLOAD_EXECUTION  (was)
```

EPIC12 detected the divergence (`evidence_type_mismatch:<signal>-><type>`) but
the gate still honoured the row-supplied type. EPIC14 closes that boundary in
the authoritative layer; EPIC12 and EPIC13 consume the result.

## Authoritative vs declared

| field | who sets it | authority |
| --- | --- | --- |
| `signal` | the deterministic producer / the persisted row | authoritative **input** — classified against the closed signal registry |
| `evidence_type` (persisted) | any writer | **declared only** — never authoritative |
| `declared_evidence_type` (classified) | the taxonomy | the row's declared value, preserved for audit |
| `authoritative_evidence_type` (classified) | the taxonomy | the type derived from the signal registry |
| `provenance_class` (classified) | the taxonomy | derived from row *structure*, never from a row-declared class |

Classification precedence (`taxonomy.classify_row`), in order:

1. a not-tested signal family → `NEGATIVE_EVIDENCE` / `NOT_TESTED`
2. a not-observed / absent signal family, or `type=negative` →
   `NEGATIVE_EVIDENCE` / `NOT_OBSERVED`
3. **a signal in the authoritative registry → the registry's type** (the trust
   boundary: a differing declared value is recorded as a mismatch and ignored)
4. a signal present but **unknown** → `UNCLASSIFIED_OBSERVATION`, fail closed
   (the declared value is recorded, never honoured)
5. no signal at all: a non-observation `type` (`knowledge`, `llm_insight`) →
   its knowledge type
6. no signal, no type, but a declared stamp → the declared stamp (typing only —
   see confirmation eligibility)
7. otherwise → `UNCLASSIFIED_OBSERVATION`

The taxonomy vocabulary itself is unchanged: `EVIDENCE_TYPES`,
`CONFIRMATION_EVIDENCE`, `TAXONOMY_RULE_VERSION` and the stage map are the
EPIC11 ones. EPIC14 changes *precedence and provenance*, not the taxonomy. The
classifier version is recorded separately:
`AUTHORITATIVE_CLASSIFIER_VERSION = "epic14-authoritative-classification-1"`.

## Provenance classes

Derived from row structure only (a row cannot declare its own class):

| class | derived from | trusted for confirmation |
| --- | --- | --- |
| `OBSERVATION_DERIVED` | `type=observation` with a signal | yes |
| `ACQUISITION_DERIVED` | an acquisition marker / marker reference | yes |
| `VERIFICATION_DERIVED` | a verification/action reference | yes |
| `RESEARCH_DERIVED` | knowledge / CVE-research rows | no (knowledge only) |
| `ADVISORY` | `type=llm_insight`, `advisory_id`, `advisory_mode`, an advisor agent | no |
| `LEGACY` | a declared stamp with no signal and no type | no |
| `UNKNOWN` | anything else | no |

Every classified row records provenance: source, observation key, job,
candidate, authorization ref, scope, agent, rule version and classifier
version — so *"why was this classified as PAYLOAD_EXECUTION?"* is answerable
from the record.

## Mismatch handling

A declared type that disagrees with the registry produces an explicit,
auditable record — never a silent coercion:

```
evidence_type_mismatch
  class                      declared_stronger | declared_weaker |
                             declared_unrelated | declared_with_unknown_signal
  signal                     the row's signal
  declared_evidence_type     what the row claimed
  authoritative_evidence_type what the signal registry says
  source                     epic11_evidence_taxonomy
  evidence_id / observation_id / job_id / candidate_id
  observed_at
  classifier_version
  provenance_class
```

Mismatch semantics:

* the row contributes its **authoritative** type only;
* a mismatch that tried to *raise* strength (`declared_stronger`,
  `declared_with_unknown_signal`) makes the row contribute **nothing**;
* a confirmation-capable row that is mismatched is excluded outright with
  reason `mismatched_evidence`.

The mismatch is visible to the claim evaluation
(`ClaimEvaluation.evidence_mismatches` / `.excluded_evidence`), the Evidence
Gate (`IntegrityDecision.evidence_mismatches` / `.excluded_evidence`), the
verification chain (`ChainState.evidence_mismatches` / `.excluded_evidence`,
plus a `divergence` token) and the SOC projection
(`trust_boundary` block; a verified verdict carrying a mismatch is never
presented as a clean badge).

## Confirmation evidence

`CONFIRMATION_EVIDENCE = {PAYLOAD_EXECUTION, EXPLOITABILITY_ESTABLISHED}`
(unchanged). A confirmation-capable item is **eligible** only when all three
hold:

1. its authoritative type is confirmation-capable, **and**
2. it carries no mismatch, **and**
3. its provenance class is a trusted deterministic path
   (`OBSERVATION_DERIVED`, `ACQUISITION_DERIVED`, `VERIFICATION_DERIVED`).

An ineligible confirmation-capable item is excluded with reason
`confirmation_evidence_without_trusted_provenance` and contributes nothing.

## Legacy records

Historical rows are never rewritten and never re-interpreted. A legacy row
without structural provenance classifies as `LEGACY` (or `UNKNOWN`) and can
never contribute authoritative confirmation evidence, so an old persisted
`VERIFIED` state cannot silently become a current integrity verdict. The
stored record remains exactly as it was.

## The LLM boundary

LLM output stays advisory. The runtime keeps evidence candidates deterministic
(the Phase-12 merge assigns reasoning, hypotheses and telemetry, never
`evidence_candidates`). A row produced by an advisory path is
`ADVISORY` provenance and can never be confirmation evidence, whatever
`evidence_type`, `signal`, `confidence` or prose it carries.

## The API / persistence trust boundary

`RuntimeStore.record_evidence` enforces the invariant at the write boundary:

* a declared `evidence_type` that disagrees with the authoritative
  classification of the row's signal is refused
  (`EvidenceTrustError`);
* a declared type on a signal that is **not** in the registry is refused (an
  unclassifiable signal cannot be trusted);
* a confirmation-capable row must carry the trusted producers' structural
  attestation — `job_id`, `observation_ref` and `signal` — or it is refused.

The field is preserved for compatibility; the *invariant* is what is enforced.

## EPIC12 integration

The chain consumes the authoritative result instead of re-deriving it:

* `engine._items_for_stage` and the stage `by_type` map are built from
  `taxonomy.authoritative_items` / `taxonomy.contributes_to_authoritative_stage`
  — one rule, owned by EPIC11;
* `ChainState.evidence_mismatches` / `.excluded_evidence` carry EPIC11's
  records, and the chain reports the mismatch as a divergence token.

Two EPIC12 tests that previously pinned the *open* boundary (an advisory row
with a `payload_execution` signal reaching the gate) now pin the closed one:
the gate refuses it and the exclusion is surfaced.

## EPIC13 integration

Acquisition observations pass through the same path. The producer refuses to
create a row whose declared type disagrees with its signal
(`ObservationError`), so a caller cannot take `PARAMETER_OBSERVED` and relabel
it as `REFLECTION_OBSERVED` or `PAYLOAD_EXECUTION`. A legitimate acquisition
observation is `ACQUISITION_DERIVED` and contributes normally: in production
validation it advanced the real candidate's chain from stage 1 to stage 3.

## Cross-class audit

| class | contract | confirmation requirement | chain stages | mismatch behaviour |
| --- | --- | --- | --- | --- |
| XSS | `XSS` | REFLECTION_OBSERVED, OUTPUT_CONTEXT_IDENTIFIED, DOM_SINK_IDENTIFIED, PAYLOAD_EXECUTION, EXPLOITABILITY_ESTABLISHED | parameter → reflection → context → sink → execution → exploitability | registry wins; stamps refused; mismatch recorded |
| CORS | none → `GENERIC` | GENERIC set (includes DOM_SINK_IDENTIFIED) | origin_supplied → acao_observed → arbitrary_origin_accepted → credentials_evaluated → sensitive_response_available → browser_exploitability | same |
| OPEN_REDIRECT | none → `GENERIC` | GENERIC set (includes DOM_SINK_IDENTIFIED) | redirect_input → controlled_destination → redirect_observed → destination_attacker_controlled → terminal_redirect_confirmed | same |
| SSRF | `SSRF` | RESPONSE_OBSERVED, REFLECTION_OBSERVED, EXPLOITABILITY_ESTABLISHED, PAYLOAD_EXECUTION | url_input → server_side_request → controlled_interaction → observable_server_behaviour → security_impact → ssrf_confirmed | same |
| CVE_RESEARCH | `CVE_RESEARCH` | none (knowledge correlation only) | none | knowledge rows are `RESEARCH_DERIVED`; an advisory row can never confirm |

Findings from the audit (documented, deliberately not "fixed" here):

* **CORS and OPEN_REDIRECT have no contract of their own** and inherit the
  `GENERIC` contract, whose confirmation requirement includes
  `DOM_SINK_IDENTIFIED` — a type neither chain produces. Confirmation for those
  classes is therefore unreachable through the gate: fail-closed by
  construction. Widening it would be new capability work, out of scope for a
  provenance hardening Epic.
* **CVE_RESEARCH has no confirmation claim at all**: an advisory row asserting
  exploitability cannot confirm anything.

## The residual boundary (stated, not hidden)

EPIC14 closes the *metadata* trust boundary: no row can raise its strength by
self-declaring a type, a provenance class or a confidence. It does **not**
provide cryptographic attestation. A writer with direct access to the store who
fabricates a row whose shape is *internally consistent*
(`signal=payload_execution` with `type=observation` and the attestation fields)
is indistinguishable from a legitimate observation row by structure alone.
That residual vector is bounded by:

* the required-evidence rule — a single fabricated execution row cannot confirm
  an XSS finding without reflection, context and sink evidence too;
* the persistence guard, which refuses confirmation-capable rows that lack the
  trusted producers' attestation;
* the EPIC11 authorization requirement and EPIC13's closed live gate, which
  keep active acquisition unavailable in production.

Closing that residual vector would require signed provenance (a second
provenance system), which EPIC14's constraints explicitly exclude.
