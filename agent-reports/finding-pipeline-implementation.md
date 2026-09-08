# Phase 5J — Finding Pipeline / Production Materialization Implementation Report

Status: IMPLEMENTATION COMPLETE (offline deterministic pipeline only).
No production persistence enabled. No live execution. B1/B2/B4/B5 remain
BLOCKED. No frozen 5B–5I file modified.

## 1. Implementation verdict

**PASS — 5J offline finding pipeline implemented and green.**

The exact architecture flow now runs as code, against the REAL frozen 5I
pipeline (not stubs): genuine `ClassificationResult` objects produced by
`verify_handoff` over sealed fixtures flow through the 5I
authority/provenance gate → CONFIRMED-only eligibility gate (pinned
`5j-eligibility-policy/v1`) → fresh verified read with full-axis
revalidation → immutable `sealed-finding/v1` → deterministic `xf-`
identity → put-if-absent in-memory persistence with byte-compare refusal
→ CAS-separated workflow records → append-only audit → exactly-once
offline notification seam. 5J classifies nothing, inspects no
observation for vulnerability decisions, computes no severity, and
promotes nothing: POTENTIAL / UNKNOWN / smuggled-INCONCLUSIVE /
NOT_VULNERABLE all fail closed with deterministic closed reasons.

## 2. Files created

- `ai/finding/__init__.py` — package boundary, exports, hard-boundary doc.
- `ai/finding/eligibility.py` — pinned v1 eligibility table + gate.
- `ai/finding/authority.py` — 5I authority/provenance gate (structure +
  fresh-record binding, severity-triple recomputation).
- `ai/finding/sealed.py` — `sealed-finding/v1` immutable contract +
  identity/hash helpers (5H canonical discipline).
- `ai/finding/store_memory.py` — `FindingStore`/`WorkflowStore` ABCs,
  in-memory impls (put-if-absent, CAS), B2-blocked Mongo stub.
- `ai/finding/audit.py` — 8 append-only 5J audit events, secret-screened.
- `ai/finding/notify.py` — offline notification seam + alert ledger
  (deterministic alert identity, no delivery code).
- `ai/finding/materializer.py` — `FindingInfrastructure` bundle +
  `materialize` orchestrator + read-side `finding_availability`.
- `ai/finding/legacy_block.py` — hard-block inventory + AST check helper.
- `ai/test_finding_pipeline.py` — 84 offline tests, full matrix (§15).
- `agent-reports/finding-pipeline-implementation.md` — this report.

## 3. Files modified

**NONE.** Zero modifications to any existing file — frozen 5B/5C/5D/5E/
5F/5G/5H/5I semantics untouched, no test in any frozen suite touched,
no legacy file touched. 5J is purely additive (`ai/finding/*` +
`ai/test_finding_pipeline.py`). 5I semantics were NOT altered to make
5J easier: the 5J severity-consistency check mirrors (never forks) the
frozen 5I projection, and any mirror drift fails closed by construction.

## 4. 5I provenance gate

`ai/finding/authority.py` hardens beyond hash reproduction (a frozen
pydantic model is hand-buildable, so self-consistent hashes prove
nothing alone). `verify_authority_structure` (no evidence needed):
real-`ClassificationResult` type rejection of dicts/legacy shapes;
hash reproduction; exact 5I version pins (verifier/policy/
observation-schema/artifact-schema); `rule_id` parses as `base/vN` and
resolves in frozen `SUPPORTED_RULES` with matching rule version and
finding-eligible flag; closed outcome/detail/state/channel vocabularies;
ID formats; 64-hex hashes; bounded reason. `verify_authority_binding`
(against the FRESH record): triple recomputation, SEALED+complete,
16-axis equality, `resolve_rule` coverage of the record's execution
class, severity-triple equality with a locally recomputed 5I policy
resolution, snapshot presence, stored-round linkage presence. New
defense-in-depth discovered during implementation: the frozen 5H seal
triple covers `target.program_name` but NOT top-level
`record.program_name`, so 5J additionally enforces their internal
equality (honest builder rows always agree; 5H unchanged).

## 5. Eligibility gate

`ai/finding/eligibility.py`, pinned `5j-eligibility-policy/v1`:
CONFIRMED + `finding_eligible=true` → ELIGIBLE; CONFIRMED with flag
false → `FINDING_ELIGIBLE_FLAG_FALSE`; POTENTIAL/UNKNOWN (and
pydantic-bypass-smuggled INCONCLUSIVE) → `OUTCOME_NOT_FINDING_ELIGIBLE`;
NOT_VULNERABLE → `ELIGIBILITY_INVARIANT_VIOLATION` (returned, fail
closed — never raised into a verdict, never a finding). No promotion
switch exists (test-asserted: no allow/promote/enable tokens); no
caller override (no such input); every rejection carries a closed
reason and an audit event.

## 6. Evidence revalidation

`materialize` performs a NEW `read_verified` on every call (never the
classification-time read) and enforces, first-mismatch-wins:
`VerifiedEvidence` + `EvidenceRecord` typing → triple recomputation →
SEALED + complete → index-claim equality (hashes AND keys), live
lifecycle (SEALED/INDEXED), clear tombstone/quarantine flags →
16-axis authority binding → round-leg pinning for stored reads
(exactly-one verified SUBMIT leg, stage/program/target/artifact/plan
consistent — a READ is never rebound). Closed reasons:
`FRESH_READ_UNAVAILABLE/MALFORMED`, `FRESH_EVIDENCE_UNVERIFIABLE/
LIFECYCLE`, `FRESH_INDEX_MISMATCH`, `AUTHORITY_*`,
`ROUND_SUBMIT_UNRESOLVED/LINKAGE_MISSING`. Never repair, never rebind,
never mutate. Verified against quarantine, tombstone, blob-corruption,
missing-row, index-drift (4 variants), and cross-axis mutations.

## 7. SealedFinding

`sealed-finding/v1` (`ai/finding/sealed.py`): frozen,
`extra="forbid"`, exact 36-field closed set (test-asserted — additions
require `sealed-finding/vN`, not drift). All §6 security fields
present: identity triple, resolution/scope identities (snapshot ref +
scope-lists hash), 5 version pins incl. `eligibility_policy_version`,
`classification` locked to CONFIRMED, channels/state/reason,
verbatim severity triple, executed-payload + contract hashes, stored
round linkage (`round_id`, `submit_evidence_ref`,
`submit_content_hash`). No timestamps, no content, no caller metadata —
raw secrets/payloads/bodies/console/stdout/LLM text have no field to
inhabit. Timestamps live only as the ignored `materialized_at`
orchestrator parameter and audit events.

## 8. Finding identity

`finding_id_for`: `"xf-" + sha256(canonical security payload)[:32]`
over classification hash + evidence triple + verifier/rule/policy/
eligibility pins (5H `hash_payload` discipline; extends the 5I
discipline with the eligibility pin, so 5J ids can never collide with
5I seam ids). Same inputs → byte-identical finding + id (replay =
deduplicated no-op); timestamp variance → same id (tested);
version/evidence variance → distinct id (tested). Caller cannot select
it (recomputed, never accepted; store keys are `(program, id)`).

## 9. Persistence

`FindingStoreMemory`: program-scoped `dict` with put-if-absent →
PERSISTED / DEDUPLICATED (identical bytes: idempotent no-op, workflow
ensured, `FINDING_DEDUPLICATED` audit, NO re-notification) /
CORRUPT_COLLISION (differing bytes: no overwrite, `FINDING_STORE_REFUSED`
audit, NO FINDING). Small lock for atomic check-and-insert (safety
still from key rules). NO update/patch/delete/upsert API exists
(AST-asserted). Tombstone/archive flip entry metadata only; bytes and
history retained. `MongoFindingStoreAdapter` exposes the future
two-collection shape but raises `RuntimeError` (B2-blocked) on
construction and every method — no credentials, connections, or indexes.
Concurrency tested: 8-way barrier, exactly 1 PERSISTED, 7 deduplicated,
1 notification, 1 store row, workflow OPEN.

## 10. Workflow separation

`WorkflowStoreMemory`: separate CAS-versioned records (`OPEN →
ACKNOWLEDGED → RESOLVED → REOPENED`, illegal transitions + stale
versions raise). Mutable ONLY: acknowledged/assignee/labels/comments/
resolution/state. `WorkflowRecord` carries zero security fields
(test-asserted field set); workflow mutations provably leave finding
bytes untouched (byte-compare test). No generic PATCH over the security
object exists anywhere.

## 11. Audit

8 events: `FINDING_ELIGIBILITY_ACCEPTED/REJECTED`, `FINDING_MATERIALIZED`,
`FINDING_PERSISTED` (incl. notification outcome), `FINDING_DEDUPLICATED`,
`FINDING_TOMBSTONED` (store path; event type reserved for operator flow),
`FINDING_WORKFLOW_CHANGED` (reserved), `FINDING_STORE_REFUSED`
(corruption path; the one addition beyond the 7-event minimum).
IDs + hashes + closed reasons only; secret-screened; failing sinks
swallowed without blocking materialization (tested with an exploding
sink). Audit never grants authority.

## 12. Notification seam

`notify.py`: `NotificationSink` ABC (single `publish`), in-memory
recording sink, `AlertLedgerMemory` put-if-absent claims,
`alert_id_for` = `alert- + sha256(finding_id + policy)[:32]`. ONLY a
freshly persisted (non-deduplicated) finding claims + publishes;
deduplicated/rejected/corrupt paths never reach the seam (tested).
UNSET findings alert with `severity_pending=True` display marker
(verbatim severity preserved — the marker is display, not assignment).
Zero delivery imports in the seam (AST-asserted: no telegram/requests/
http/socket surface).

## 13. Retention behavior

 Tombstone/archive preserve bytes + history (tested byte-identical).
`finding_availability` (read-side only): PERSISTED (triple reproduces) /
PERSISTED_UNVERIFIABLE (present but diverged — availability event, never
a verdict, history stands) / EVIDENCE_GONE (unreadable). 5H retention
semantics consumed, never modified.

## 14. Legacy hard-blocks

`legacy_block.py` inventory (11 paths) + AST helper ignoring
prose. Test-enforced: no `ai.finding` module imports or code-references
any banned legacy token (`XSSVerifier`, `to_findings`, `save_findings`,
`XSSFinding`, `NucleiFinding`, `nuclei_runner`, `mongo_persist`,
`XssFindings`); no legacy module imports; no offline-violating imports
(socket/subprocess/urllib/http/playwright/selenium/pymongo/mongoengine/
requests/telegram/database/watch_xss_verify); legacy `XSSFinding` /
`NucleiFinding` instances and raw legacy dicts fed to `materialize`
→ `AUTHORITY_NOT_CLASSIFICATION_RESULT`, no finding. No legacy code
deleted per architecture (DEPRECATE/HARD-BLOCK posture preserved).

## 15. Tests

`ai/test_finding_pipeline.py` — **84 tests, all passing**, stdlib
unittest only, genuine 5I results via the real `verify_handoff` over
sealed fixtures (happy paths never hand-built). Coverage of all 30
required areas: CONFIRMED eligible/ineligible-flag (2), POTENTIAL (2:
http + nuclei), UNKNOWN, smuggled-INCONCLUSIVE, NOT_VULNERABLE invariant,
forged result (unknown evidence), hash/triple binding mutations (12
axes), authority/type/version/rule mismatches, quarantine/tombstone/
corrupt-blob/missing/index-drift×4, cross-program/host/artifact/
authorization/execution-id, severity injection ×5 + verbatim-copy +
write-site + literal-allowlist structural tests, deterministic identity
×4 + timestamp independence + model immutability/closure + exact
36-field contract, stored round linkage + missing-leg + legacy
single-pass ceiling, HTTP/Nuclei rejection, duplicate/collision/
8-way-concurrency dedup, workflow CAS + isolation + no-update-API,
tombstone/archive/availability×3, audit sequence + secrecy + sink
failure, notification once-only + identity + no-delivery-imports,
legacy AST + type + inventory tests, resolution/scope binding,
rule-downgrade, Mongo-blocked. Plus DI-boundary tests: lying/garbage
seams fail closed; wrong-typed infra raises TypeError.

## 16. Regression results

- New 5J suite: **84/84 OK**.
- Frozen suites batch 1 (5I verifier, evidence core/store,
  authorization, scope, target resolver): **593/593 OK**.
- Frozen suites batch 2 (HTTP/Nuclei/browser-5G executors, XSS
  oracle/verification/stored-round, knowledge, researchers, openrouter):
  **660/660 OK**.
- Combined: **1337 tests, 0 failures, 0 errors.** No pre-existing
  failures encountered; no frozen test modified; no unrelated behavior
  changed (additive-only diff; Git commands not run per phase rules).

## 17. Remaining blockers

B1 = BLOCKED. B2 = BLOCKED. B4 = BLOCKED. B5 = BLOCKED. None closed,
none touched. Production MongoDB, live browser/Nuclei/network, and
production persistence remain unactivated by design (in-memory backend
only; delivery seams are offline records). Known non-defects documented:
(1) full self-consistent fabrication (forged result + compromised store
serving matching bytes) is outside the threat model — infrastructure is
trusted, same assumption as 5H/5I; (2) INCONCLUSIVE is enforced at 5J
gates even though pydantic `model_copy` skips validation (tested);
(3) UNSET+CONFIRMED cannot arise under the pinned 5I policy, so UNSET
preservation is structural (verbatim copy, no defaulting code) plus
future-proofed by the recomputation check.

## 18. Live-execution status

LIVE_BROWSER = False. LIVE_NUCLEI = False. LIVE_TRAFFIC_ENABLED = False.
No production finding persistence. No Mongo production support. No live
browser/Nuclei/network support. No delivery performed. `ai/finding`
contains no network/DNS/browser/Nuclei/subprocess/LLM/Mongo code
(AST-verified). OOB = DENIED. Evidence mutation = NO. Classification
mutation = NO. Git operations = NONE (per phase rules).
