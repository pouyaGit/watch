# Phase 5I — Deterministic Verifier Implementation Report

Status: IMPLEMENTATION COMPLETE. Offline, deterministic, verifier-only.
No live execution authorized or activated. B1/B2/B4/B5 remain BLOCKED. 5J NOT started.

## 1. Verdict

**PASS — 5I implementation complete and green.**

The deterministic verifier exists as pure functions over sealed 5H evidence
(`ai/verification/deterministic/`, 14 modules). It is the ONLY security
classification authority for CONFIRMED / VULNERABLE / NOT_VULNERABLE /
severity / finding eligibility / final classification. LLM output, Nuclei
output, browser advisory booleans, executor status, and caller-provided
fields determine none of these (structural: they are not on any input type).

This session's work: the implementation was already present from prior build
work; this phase verified it against the frozen architecture, fixed 7
failing checks (6 test-fixture/test-expectation bugs in the new 5I test file
plus 1 docstring literal that tripped the legacy-reference test — the
implementation itself required only that one-word docstring reword, no logic
change), ran the full 5I matrix plus all frozen regression suites green,
verified the offline/legacy-block invariants, and wrote this report.

Prior finding during verification (NOT a 5I defect, no 5H change made):
the frozen 5H blob layer is content-addressed by the samples-only
`content_hash`, so an adversarial cross-execution marker replay that
reproduces identical sample shapes is refused fail-closed at persist time
("same key with differing bytes"). The replay test now seals-but-does-not-
persist (the classifier is pure over sealed bytes and needs no store row
on the reflected-oracle path). 5H semantics were NOT modified.

## 2. Files created

New 5I implementation (present, verified this phase — no new files needed):

- `ai/verification/deterministic/__init__.py`
- `ai/verification/deterministic/models.py`
- `ai/verification/deterministic/gate.py`
- `ai/verification/deterministic/verified_read.py`
- `ai/verification/deterministic/registry.py`
- `ai/verification/deterministic/result.py`
- `ai/verification/deterministic/classifier.py`
- `ai/verification/deterministic/xss_oracle.py`
- `ai/verification/deterministic/xss_stored.py`
- `ai/verification/deterministic/http.py`
- `ai/verification/deterministic/nuclei.py`
- `ai/verification/deterministic/severity.py`
- `ai/verification/deterministic/materialization.py`
- `ai/verification/deterministic/pipeline.py`
- `ai/test_deterministic_verifier.py` (97 tests, fixed this phase)
- `agent-reports/deterministic-verifier-implementation.md` (this report)

## 3. Files modified

- `ai/verification/deterministic/xss_oracle.py` — one docstring line reworded:
  "legacy ``XSSVerifier.verify()``" → "legacy execute-and-judge entry point
  (``ai/verification/verifier.py``)". Reason: the legacy-bypass test asserts
  the literal `XSSVerifier` appears in no 5I module even in prose; the path
  reference is retained. No logic change.
- `ai/test_deterministic_verifier.py` — 6 test-level fixes (see §16). No
  frozen-suite tests touched. No 5B/5C/5D/5E/5F/5G/5H source file modified.

Frozen phases untouched: 5B authorization, 5C resolver, 5D scope, 5E HTTP
executor, 5F Nuclei executor, 5G browser executor, 5H evidence semantics —
zero modifications.

## 4. Verifier input boundary

`VerifierInput` (`models.py`, `extra="forbid"`, frozen): `{handoff:
EvidenceHandoff, envelope: bytes, verifier_version, rule_version,
policy_version}`. Pinned versions enforced in `model_post_init`
(`deterministic-verifier/5I-v1`, `5i-rules/v1`, `5i-severity-policy/v1`);
any other version fails closed at construction (downgrade refused).
`FORBIDDEN_AUTHORITY_FIELDS` (verdict/finding/matched/vulnerable/confirmed/
not_vulnerable/severity/exploited/confidence/expected_behavior/llm_prose/
browser/executor/network/subprocess/executed_script/
correlation_token_in_runtime) is rejected structurally by `extra="forbid"`
(test: `test_llm_derived_field_mutation_rejected`,
`test_forbidden_authority_fields_closed`). The classifier never receives a
live executor, browser/network/subprocess handle, or LLM text — no such
field exists on any input type. Envelope must be the exact sealed bytes
from a verified read; the gate re-parses and re-verifies them from scratch
(the injected seam is transport, never authority).

## 5. Integrity/provenance gate

`gate.py::verify_handoff_evidence` implements the exact 13-gate frozen
order, first failure wins, every failure a closed `RejectReason`, never a
security result: (1) structural handoff validation → (2) injected verified
read → (3) triple-hash recomputation + envelope byte-equality (both handed
envelope and store bytes) → (4) index claims/keys → (5) SEALED lifecycle →
(6) `REQUIRED_OBSERVATIONS` channel presence → (7/9/11-identity)
program/target/artifact/execution-id bindings → (8) authorization
provenance via `verify_provenance_for_handoff` (CONSUMED accepted as
`AUTHZ_VALID_FOR_PROVENANCE`; REVOKED/EXPIRED-at-start/forged/mismatched →
`HANDOFF_REJECTED`) → (10) artifact/class consistency → (11) stage pairing
(READ requires browser class + round_id + submit ref) → (12) schema/class
support → (13) forbidden lifecycle (BUILDING/INCOMPLETE claims,
tombstoned/quarantined, residual incomplete_reasons). Gate 2 tombstone/
quarantine store errors map to `LIFECYCLE_FORBIDDEN_STATE`. Gate failures
emit `HANDOFF_REJECTED`/`INTEGRITY_REJECTED`; classification is never
entered (`outcome.result is None`, test-enforced). `require_live_for_execution`
is never called anywhere in 5I (string-absent, test-adjacent verified).

## 6. Classification state machine

`classifier.py`: CONFIRMED (full ordered proof only) / POTENTIAL (ceiling
for reflection-only, advisory-only, storage-attributed, legacy single-pass)
 / UNKNOWN (safe default for every predicate failure; gate blocks never
reach classification). POTENTIAL never self-promotes. `route_rule_id`
routes deterministically on sealed class/stage/phase. `not_vulnerable_transition()`
raises `VerifierInvariantError`; `classify_evidence` defensively re-checks
that no rule emitted NOT_VULNERABLE, and `pipeline.py` converts any
classifier exception into a blocked `classification_invariant_violation`
(never a verdict). "No evidence" → UNKNOWN, never NOT_VULNERABLE
(test-enforced across oracle/HTTP/Nuclei scenarios).

## 7. XSS implementation

`xss_oracle.py` (pure; legacy `verify()` never called): identity
re-derived as `oracle_seed(RUN_SALT_AUTHORITY, execution_id, phase)` +
`oracle_value_from_seed` (freshness = execution binding; cross-execution
replay recomputes a different D). E1 = sealed `dialog_marker_hashes`
membership for exact `kind:D` over {alert,confirm,prompt} (wrong
message/kind fail; advisory `e1_observed` ignored; truncated channels
fail). E2 = exact `network:D` hash + sealed page origin == endpoint origin
+ page must not itself be the oracle path (navigation/suffix/wrong-origin
fail). E3 = `executed_payload_hash == sha256(D)` + preimages limited to
locally derived values (D itself, planner-reconstructed payload) with the
≤240 exact-equality bound (over-240 excluded, never prefix-matched) +
closed operators {eval, setTimeout:string} (`new Function` rejected).
Anti-harvest over sealed pre-execution texts (D on wire fails closed);
contract-hash binding checked. Requires full channel list with zero skips
for CONFIRMED.

## 8. Stored XSS implementation

`xss_stored.py`: SUBMIT → READ → EXECUTION, no shortcut. READ leg resolved
via sealed `submit_evidence_ref` content hash through the seam (non-tuple
or ≠1 leg = ambiguous pairing, never guessed); SUBMIT re-verified
SEALED/complete with correct stage/class. Gates: shared `sr-` round_id +
read/submit lease equality, phase pair (stored_submit/stored_read),
per-leg contract-hash integrity + shared source-identity check, READ-leg
oracle identity + executed binding, same-origin READ, strict ordering
(`READ.started > SUBMIT.finished`, 3600 s window; unparseable/reversed/
over-window fail closed), clean READ (no S/D/round in page URL),
anti-harvest across BOTH legs, exact E1/E2/E3 on READ channels, SUBMIT
acceptance as precondition only. Correct round + full proof → CONFIRMED;
wrong round / stale / mismatched / reflected-only / missing execution →
at most STORAGE_ATTRIBUTED/POTENTIAL (when accepted) else UNKNOWN.
Legacy single-pass shape caps at POTENTIAL, never confirms.

## 9. HTTP implementation

`http.py` (pure, never requests): positive requires ALL of transport
`responded` + 2xx + no truncation flags + chain ≤5 + authorized method
pair + sealed request origin == canonical target + every redirect hop
same-origin (downgrade/unparseable fail closed) + exact locally derived
seed marker in sample + structural location in {HTML_ATTRIBUTE,
JAVASCRIPT_STRING, SCRIPT_BLOCK, URL} (classifier derives location from
the sample; HTML_BODY-only → insufficient) + no WAF status / generic-error
confounder. Positive yields POTENTIAL ceiling (`REFLECTION`), never
CONFIRMED (test sweeps all locations for non-CONFIRMED). Truncation is
never guessed through.

## 10. Nuclei implementation

`nuclei.py`: advisory-only gate. Re-validates 5F posture from sealed
bindings (template id/hash equality, locally recomputed closed-spec argv
digest via 5F builders — pure string derivation, no process — execution
class `nuclei_scan`, no derivation binding). `finding_like_text_present`,
stdout/stderr, exit code, severity are untrusted data: clean binding +
text signal → POTENTIAL at most; mismatch/truncation/timeout/killed/
unknown exit → UNKNOWN. Nuclei→CONFIRMED transition is absent by
construction (deferred specificity policy); test asserts CONFIRMED is
unreachable for all Nuclei inputs.

## 11. Severity policy

`severity.py`, pinned `5i-severity-policy/v1`: (vulnerability class ×
rule) → fixed table (reflected_xss×reflected-oracle → high;
stored_xss×stored-round → high; dom/mutation×reflected-oracle → medium;
reflected_xss×meaningful-reflection → low; stored_xss×stored-legacy →
low). No LLM/Nuclei/researcher/caller severity consulted (no such input
exists). Missing entry, UNKNOWN outcome, or weak evidence against a
high/critical row → `UNSET` + explicit reason. Legacy confidence map not
repurposed; no confidence field exists on any 5I model.

## 12. Rule registry/versioning

`registry.py`: 5 replayable rules (`xss-reflected-oracle/v1`,
`xss-stored-round/v1`, `xss-stored-legacy/v1`,
`http-meaningful-reflection/v1`, `nuclei-advisory/v1`), each pinning
verifier + observation-schema (`evidence/v1`) + artifact-schema
(`artifact/v1`) + policy versions and covered execution classes.
`resolve_rule` returns None on unknown rule / version skew / class
mismatch → UNKNOWN (`rule_or_schema_unresolved`). Results cite the
`rule_id/vN` display id. Replay: same envelope bytes + same pinned
versions → byte-identical result and `compute_result_hash` (5H canonical
`hash_payload` discipline over the fixed result field set; no extras;
frozen model). Re-verification under newer versions yields a NEW artifact;
old results retained (immutable models, no update API).

## 13. Finding materialization boundary

`materialization.py`: default-deny seam only.
`PRODUCTION_FINDING_PIPELINE_ACTIVE = False`. `materialize_finding`
requires an eligible 5I result (CONFIRMED + `finding_eligible`), pinned
verifier/policy versions, then a FRESH verified read: integrity
re-verification, SEALED+complete, full identity/binding/triple equality
(any drift → None; stale blobs cleared → None; rebinding → None). No
caller-selected severity/class, no rebinding, no direct
`XSSFinding`/`NucleiFinding` authority. Deterministic `xf-` finding id
over (result hash + evidence triple + version pins). `SealedFinding` is
`extra="forbid"`, frozen. No production pipeline imports this seam.

## 14. Legacy bypass protection

5I imports no legacy execute-and-judge path (AST-verified: no imports of
`ai.verification.verifier`, `ai.researcher.nuclei_runner`,
`ai.researcher.nuclei_pipeline`, `ai.schemas.xss_finding`,
`ai.schemas.finding`; no code references to `XSSVerifier`, `to_findings`,
`save_findings`, `XSSFinding(`, `NucleiFinding(` — the single prose
mention was reworded, §3). Reused legacy code is pure-only:
`ai.verification.oracle` derivation primitives + `OraclePlanner` (no
execution), 5F argv string builders (no process). Advisory booleans,
`finding_like_text_present`, stdout text, caller severity can never become
proof (each covered by dedicated tests).

## 15. Audit

`models.py::VerifierAuditEvent` + `emit_audit` (append-only injected sink):
`HANDOFF_ACCEPTED`, `HANDOFF_REJECTED`, `INTEGRITY_REJECTED`,
`CLASSIFICATION_COMPLETED`, `CLASSIFICATION_BLOCKED_UNKNOWN` —
hashes + decisions + codes only (bounded single-line, secret-screened,
`extra="forbid"`). No payloads/bodies/stdout/browser/LLM text (test scans
all emitted events for secret/body markers). Audit failure is swallowed
and never mutates evidence or classification (verifier holds no
evidence-write capability).

## 16. Test matrix

`ai/test_deterministic_verifier.py` — 97 tests, all offline (`unittest`
only; fakes for store/index/authz/audit). This phase fixed 7 failing
checks; root causes were all on the test side except one docstring word:

1. `test_missing_seal_hash_rejected` — forged hash `"0"*63+"z"` was
   schema-invalid (→ `HANDOFF_MALFORMED`); now `"0"*64` (valid-but-wrong
   → `TRIPLE_HASH_MISMATCH`).
2. `test_no_legacy_callables_referenced` — implementation docstring
   contained the literal `XSSVerifier`; reworded (§3).
3. `test_determinism_across_rebuilds` — compared two fresh builds with
   distinct random `evidence_id` handles (can never hash-equal); now
   verifies byte-identical envelope bytes in two independent worlds.
4. `test_valid_positive_potential` — referenced undefined `S`, unknown
   `body=` kwarg, nonexistent `self.verify`; rewritten to the default
   meaningful-reflection fixture. Companion fixture fix:
   `build_http_record` now reflects the locally derived SEED (S travels
   in-payload by design; D on the wire would violate anti-harvest),
   matching `http.py`'s expectation.
5. `test_transport_failure` — `builder.seal` correctly refuses
   status-less transport-failure records (`EVIDENCE_INCOMPLETE`); test
   now seals via `seal_partial("response_missing")` and classifies the
   sealed bytes → UNKNOWN.
6. `test_marker_replay_across_executions_not_proof` — persisting the
   replay tripped the frozen 5H content-addressed blob dedup (fail-closed,
   correct); test now seals without persisting (classifier is pure).
7. `test_llm_derived_field_mutation_rejected` — `LegacyBypassTests` had
   no `setUp`; added `World()` fixture.

Coverage: Handoff 7 (valid/incomplete/building/quarantined/tombstoned/
unknown-schema/seal-hash) · Integrity 7 · Provenance 8 (incl.
consumed-as-provenance vs consumed-as-permission) · XSS oracle 15 ·
Stored 9 · HTTP 9 · Nuclei 8 (CONFIRMED-unreachable asserted) · Severity
5 · Versioning 6 (replay/hash-equality/mismatch/downgrade) · Legacy 5 ·
Materialization 5 · Audit 4 · Properties 9 (determinism, no-verdict-on-
failure, NOT_VULNERABLE-unreachable, binding completeness,
LLM-independence, idempotency, first-failure-wins).

## 17. Exact test counts

- `ai.test_deterministic_verifier`: **97 tests — OK** (0 failures, 0 errors).
- Frozen regressions batch 1 (evidence_core, evidence_store,
  execution_authorization, scope_evaluator, target_resolver,
  http_pinned_executor, nuclei_executor, browser_executor_5g,
  xss_oracle, xss_verification): **1005 tests — OK**.
- Frozen regressions batch 2 (knowledge_store, xss_researcher,
  xss_llm_researcher, openrouter, xss_stored_round, xss_pipeline,
  http_executor, browser_executor): **278 tests — OK**.
- Combined total: **1380 tests, all passing**.
- No unrelated pre-existing failures observed in any executed suite.
- `git diff --check` NOT run: Git is explicitly forbidden by the 5I
  phase rules (conflict with AGENTS.md noted; phase rule governs).

## 18. Regression results

All green, no frozen files modified, no test in any frozen suite
modified. The only modified non-test file is the one-word 5I docstring
reword (§3); the only modified test file is the new 5I matrix itself
(§16). No 5B/5C/5D/5E/5F/5G/5H semantic change.

## 19. Known limitations

- NOT_VULNERABLE is declared but unreachable: no two-control
  negative-evidence schema exists; any transition attempt raises.
- Nuclei→CONFIRMED unreachable until a separately versioned specificity
  policy ships (architecture-deferred, not invented here).
- HTTP reflection caps at POTENTIAL (proves reflection, never execution).
- Legacy single-pass stored shape caps at POTENTIAL.
- 5H blob dedup side-effect (§1): adversarial replays reproducing sample
  shapes are refused at persist; verifier handles such bytes as UNKNOWN
  when presented, but they cannot be stored twice under one content key.
- `git diff --check` skipped per phase Git ban (§17).

## 20. B1/B2/B4/B5 status

B1 BLOCKED. B2 BLOCKED. B4 BLOCKED. B5 BLOCKED. None closed, none
claimed. `LIVE_BROWSER` = False, `LIVE_NUCLEI` = False,
`LIVE_TRAFFIC_ENABLED` = False (all read back from the frozen executors
this phase). `PRODUCTION_FINDING_PIPELINE_ACTIVE` = False. No live
browser activation, no network execution, no OOB.

## 21. Exact next phase

5J (finding pipeline / production materialization) must NOT start until
ALL §19 exit criteria of the architecture hold; the 5I-side criteria are
met by this report, but B-blockers and any 5J-entry authorization remain
outstanding. Do NOT start 5J. Do NOT close B1/B2/B4/B5. Do NOT activate
any live execution.

---

## Mandatory phase statements

MongoDB production accessed = NO
Network = NO
DNS = NO
Browser = NO
JavaScript = NO
Subprocess = NO
LLM = NO
Git = NO
Live browser = NO
LIVE_BROWSER = False
LIVE_NUCLEI = False
LIVE_TRAFFIC_ENABLED = False
OOB = DENIED
Evidence mutation = NO
Finding generation production path = NO
NOT_VULNERABLE without negative schema = NO
