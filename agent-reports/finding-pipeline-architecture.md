# Phase 5J — Finding Pipeline / Production Materialization Architecture (READ-ONLY)

Status: ARCHITECTURE ONLY. No code written, no files modified, no tests run,
no network/DNS/browser/Nuclei/subprocess/LLM/Mongo touched. No 5J
implementation performed. B1/B2/B4/B5 remain BLOCKED.

## 1. Executive verdict

A production finding pipeline gated exclusively on 5I classification results
is architecturally feasible and PROCEED-TO-DESIGN approved, with one strong
head start and three hard constraints.

Head start: 5I already ships the materialization core as an explicit
default-deny seam (`ai/verification/deterministic/materialization.py`:
`SealedFinding`, `deterministic_finding_id`,
`PRODUCTION_FINDING_PIPELINE_ACTIVE = False`). 5J does not need a new
trust theory; it needs to (a) narrow the eligibility set (5I marks both
CONFIRMED and POTENTIAL outcomes via `FINDING_ELIGIBLE_OUTCOMES`, but only
CONFIRMED may become a production finding), (b) add a persistence +
dedup + lifecycle + audit + downstream-seam layer around the existing
revalidation logic, and (c) sever every legacy finding-producing path
before any production activation.

Hard constraints:

- 5J owns ONLY `ClassificationResult → eligibility gate → fresh evidence
  revalidation → immutable finding → persistence/notification seam`. It
  MUST NOT reclassify evidence, override 5I, compute severity, or inspect
  browser/Nuclei signals to create findings. 5J is a materialization
  layer, not a verifier.
- The repository currently has TWO live legacy finding factories
  (World A `XSSVerifier._build_finding → XSSFinding → watch_xss_verify →
  XssFindings` Mongo collection; `NucleiRunner.to_findings →
  NucleiPipeline.save_findings → ai_data/nuclei/findings/*.json`) plus a
  MongoEngine `XssFindings` document that happily persists POTENTIAL and
  INCONCLUSIVE rows with free-float confidence. None of these may feed,
  coexist as authoritative with, or be readable as 5J findings. They are
  HARD-BLOCK (§21) until migrated or deleted.
- B2 (production MongoDB) is BLOCKED, so 5J architecture must define an
  in-memory/fake persistence backend as the offline-testable primary
  implementation target, with the Mongo adapter fully specified but gated
  (unique indexes, CAS, record separation) and never activated here.

Architecture verdict: PROCEED TO 5J OFFLINE IMPLEMENTATION DESIGN ONLY on
the `5I ClassificationResult → 5J eligibility → fresh revalidation →
SealedFinding → gated persistence/notification seam` boundary, with
`LIVE_BROWSER`/`LIVE_NUCLEI`/`LIVE_TRAFFIC_ENABLED` remaining False and no
production persistence enabled by this report.

## 2. Existing finding architecture

### 2.1 Legacy XSS factory (World A, live-adjacent) — HARD-BLOCK target

- `ai/schemas/xss_finding.py::XSSFinding`: free-form finding shape. No
  `extra="forbid"`; free `confidence` 0–1; `status` documents
  CONFIRMED/POTENTIAL/NOT_VULNERABLE/INCONCLUSIVE (NOT_VULNERABLE is
  schema-level ambiguity — the verifier never produces it);
  `browser_verified` derived from advisory `executed_script` (known
  weakness); `reflection_evidence`/`verification_evidence` free string
  lists (can carry raw page/payload text); `payload_reference` carries the
  raw payload; no verifier/rule/policy version pins; no evidence-triple
  binding; wall-clock `created_at` participates in nothing but is present.
- `ai/verification/verifier.py::XSSVerifier.verify` + `_build_finding`
  (line ~2291): executes attempts AND judges them in one call, then
  materializes `XSSFinding` for POTENTIAL and CONFIRMED alike with
  deterministic `finding_id = "xf-" + sha256(case_id|attempt_id|status)`.
  POTENTIAL findings are emitted as findings — incompatible with 5J
  eligibility (§4).
- `ai/verification/xss_pipeline.py` (`run`, `build_default_verifier`):
  live composition `orchestrator.analyze → verifier.verify`; passes
  findings through untouched (never interprets statuses — safe shape, but
  its output is World A findings, never 5J input).
- `watch_xss_verify.py` (production job): builds cases, skips when
  `XssFindings.case_id` exists, runs the World A pipeline, persists via
  `mongo_persist` with `NotUniqueError → skip` idempotency. Lazy imports
  keep import-time side-effect free (good pattern to preserve).
- `database/db.py::XssFindings` (MongoEngine): one document per case,
  `case_id` unique; persists `status` (CONFIRMED/POTENTIAL/INCONCLUSIVE),
  free `confidence`, serialized `XSSFinding` dicts (`findings` list),
  `verification_audit` dict, `runner` string. No severity field at all;
  no evidence-hash fields; no verifier-version fields; mutable by
  construction (MongoEngine document with no immutability discipline).

### 2.2 Legacy Nuclei factory (researcher) — HARD-BLOCK target

- `ai/schemas/finding.py::NucleiFinding`: `matched` bool, free `severity`
  string, `raw_output` (unbounded stdout persisted verbatim — secret
  container by design), `evidence` free strings, caller-supplied
  `cve_id`/`template_id`, scope/presence/version passthrough strings.
- `ai/researcher/nuclei_runner.py::to_findings` (line 257):
  `matched = status == COMPLETED and stdout.strip() non-empty` +
  caller severity + `raw_output` persistence. Stdout-shaped text becomes a
  verdict — the canonical false-positive path (prior finding F-12).
- `ai/researcher/nuclei_pipeline.py` (lines 346–359, 399+): calls
  `to_findings`, dumps `model_dump()` dicts, `save_findings` writes
  `ai_data/nuclei/findings/<cve>.json` research files. File-based,
  no identity key, no dedup key, no audit linkage.
- 5E/5F/5G sealed executors and 5I never import any of the above
  (AST-gated by their test suites).

### 2.3 5I materialization seam (the 5J foundation) — REUSE + WRAP

- `ai/verification/deterministic/materialization.py`: `SealedFinding`
  (frozen, `extra="forbid"`, version-pinned), `materialize_finding`
  (default-deny: eligibility + hash re-verification + fresh verified read
  + full binding equality, any mismatch → None), `deterministic_finding_id`
  (`xf-` + sha256 over result hash + evidence triple + version pins),
  `PRODUCTION_FINDING_PIPELINE_ACTIVE = False`. This is the ONLY
  finding-construction logic 5J may build on. Gap for 5J to close: it
  admits both CONFIRMED and POTENTIAL via `FINDING_ELIGIBLE_OUTCOMES`;
  production eligibility must narrow to CONFIRMED-only (§4); it has no
  persistence, dedup, lifecycle, or downstream seam.

### 2.4 Downstream consumers today

- Flask apps (`app.py`, `app_local.py`): recon APIs only
  (programs/subdomains/lives/http). No finding endpoints.
- FastAPI Dashboard v2 (`api.py`, `backend/routers/*`, `backend/dashboard.py`):
  recon pages/aggregations + task runner + change events. No finding
  routes, no `XssFindings` reads, no `ai_data` finding reads found.
- Alerting (`database/notifications.py`, `database/telegram.py`):
  recon-only notifications (new/updated subdomains, title/status changes);
  Telegram is a dumb transport with retry. No finding-triggered alerts
  exist anywhere — 5J alertability starts from a clean slate (§18).
- `database/change_events.py`: recon change events (title/cdn/status/ip/
  tech). No finding semantics.

## 3. 5J input boundary

5J accepts EXACTLY ONE input shape: a genuine 5I `ClassificationResult`
plus an injected read-only seam bundle (verified evidence read,
persistence handle, audit sink). Preferred pipeline (normative):

```
ClassificationResult
  → FindingEligibilityGate (outcome CONFIRMED + finding_eligible + pinned versions)
  → FreshEvidenceVerification (full §5 revalidation from a NEW verified read)
  → ImmutableFinding (SealedFinding, deterministically identified)
  → PersistenceSeam (deduped, CAS) + NotificationSeam (alert-eligible only)
```

The caller MUST NOT supply, and the input types MUST NOT contain:
vulnerability class, severity, confirmed/vulnerable flags, finding
eligibility, target/program/artifact bindings, evidence identity,
confidence, or arbitrary metadata with security meaning. Every
security-relevant field is sourced from (a) the 5I result, (b) the
freshly re-read immutable evidence bindings, or (c) deterministic policy.
Caller-supplied corroboration (screenshots, analyst notes, ticket IDs) may
exist ONLY as clearly-namespaced operational annotations on a SEPARATE
workflow record (§14), never on the security record, never hashed into
finding identity.

Structural enforcement: `extra="forbid"` on all 5J input/output models;
a `FORBIDDEN_FINDING_FIELDS` set mirroring the 5I discipline
(verdict, matched, vulnerable, confirmed-by-caller, confidence,
expected_behavior, llm_prose, executor/browser/network/subprocess handles,
raw_output, console/DOM text); constructor-level rejection of any 5I
result whose `compute_result_hash` does not reproduce (forged result →
no finding, closed reason `CLASSIFICATION_HASH_MISMATCH`).

5J MUST NOT reclassify: it performs zero observation inspection beyond
equality comparison against the classification's pinned hashes. Any
temptation to "take a second look" at browser signals inside 5J is a
verifier bypass and is forbidden (§9).

## 4. Eligibility policy

Pinned eligibility table (versioned alongside the severity policy,
e.g. `5j-eligibility-policy/v1`):

- CONFIRMED + `finding_eligible == true` + pinned verifier/rule/policy
  versions → ELIGIBLE (proceeds to §5 revalidation).
- POTENTIAL (any detail: meaningful reflection, storage-attributed,
  nuclei-advisory-weak, legacy single-pass ceiling) → INELIGIBLE,
  closed reason `OUTCOME_NOT_FINDING_ELIGIBLE`. 5I's broader
  `FINDING_ELIGIBLE_OUTCOMES` set is a classifier-internal ceiling, NOT
  production eligibility; 5J narrows it and the narrowing itself is
  version-pinned and audited.
- UNKNOWN / INCONCLUSIVE → INELIGIBLE (`OUTCOME_NOT_FINDING_ELIGIBLE`).
- NOT_VULNERABLE → unreachable in 5I; 5J treats any such outcome as an
  invariant violation (`ELIGIBILITY_INVARIANT_VIOLATION`, no finding,
  loud audit) rather than inventing negative-finding semantics.

No promotion path exists: POTENTIAL → FINDING, UNKNOWN → FINDING, and
INCONCLUSIVE → FINDING are absent transitions. Any future exception
(e.g. a second-gate human-review confirmation) requires its own
deterministic, versioned policy with full binding re-checks — it MUST
NOT be a 5J configuration flag, and this architecture does not design it.

## 5. Fresh evidence revalidation

Before materializing, 5J MUST perform a NEW verified read (never reuse
the classification-time read) and check ALL of the following; the FIRST
mismatch yields NO FINDING (`FINDING_BLOCKED_STALE_EVIDENCE` family),
never repair, never rebind, never mutate:

existence · SEALED lifecycle · `complete == true` · not quarantined ·
not tombstoned · triple-hash recomputation verifies · index claims equal
sealed hashes AND index keys · evidence_id / execution_id /
authorization_id equality · program equality · canonical host / scheme /
effective port / path-scope equality · target resolution identity
equality (sealed snapshot binding) · scope evaluation identity equality
(scope-lists hash) · artifact_id + artifact content-hash equality ·
derivation/template hash consistency · verifier/rule/policy version
equality with the classification · `compute_result_hash(classification)`
reproduction.

Rationale: classification is a point-in-time statement; persistence is a
durability promise. Evidence may be quarantined, tombstoned, or superseded
between the two. A finding bound to dead evidence is a finding that can
never be re-audited — worse than no finding.

## 6. Immutable finding contract

Future sealed finding schema (`sealed-finding/v1`, frozen, `extra="forbid"`):

Security record (immutable, hashed into identity): `finding_id`,
`finding_schema_version`, `classification_result_hash`, `evidence_id`,
`execution_id`, `authorization_id`, `program_name`, `canonical_host`,
`scheme`, `effective_port`, `path_scope`, `target_resolution_identity`
(snapshot ref + scope-lists hash + resolution binding hash),
`scope_evaluation_identity` (scope policy version + scope-lists hash),
`artifact_id`, `artifact_content_hash`, `evidence_content_hash`,
`evidence_bindings_hash`, `evidence_observations_hash`,
`verifier_version`, `rule_id` (display `id/vN`), `observation_schema_version`,
`artifact_schema_version`, `policy_version`, `eligibility_policy_version`,
`classification` (CONFIRMED only in v1), `confirmation_state`,
`oracle_channels` (sorted), `severity` (or UNSET + reason),
`severity_policy_version`, round linkage for stored XSS
(`round_id`, `submit_evidence_ref`, `submit_content_hash`).

Audit envelope (NOT hashed into identity): `materialized_at`,
`materializer_version`, `persistence_backend`, audit event refs.

Timestamps MUST NOT affect finding identity (audit-only leaves, same
discipline as 5H). No caller-controlled IDs anywhere on the security
record. Replayable (same inputs → byte-identical finding) and idempotent
(§12). The existing 5I `SealedFinding` already satisfies most of this;
5J deltas: add resolution/scope identities, eligibility policy pin,
stored-round linkage, and the audit envelope split.

## 7. Finding identity

`finding_id = "xf-" + sha256_hex(classification_result_hash \x00
evidence_bindings_hash \x00 evidence_observations_hash \x00
evidence_content_hash \x00 verifier_version \x00 rule_id \x00
policy_version \x00 eligibility_policy_version)` (extend the existing
5I `deterministic_finding_id` with the eligibility pin). Properties:

- Same classification + same evidence + same versions → same id
  (idempotent no-op on re-materialization).
- Any change to evidence bytes, classification bytes, or any version pin
  → distinct id (new immutable record; old record retained, never
  overwritten — history is append-only).
- No random IDs in the security identity. Random operational handles
  (row `_id`, task tokens) may exist OUTSIDE the hashed payload and MUST
  be documented as non-identity.
- Collision behavior: SHA-256 collision is out of scope by standard
  assumption; KEY-REUSE collision (same id, differing bytes) is the live
  threat and is handled by CAS/unique-index refusal (§12), mirroring the
  5H blob "same key with differing bytes refused" discipline.

## 8. Severity

5J MUST NOT calculate, adjust, round, map, or default severity. It copies
the 5I-authorized `(severity, severity_unset_reason, severity_policy_version)`
triple verbatim onto the finding. Explicitly blocked from overriding:
LLM severity, Nuclei template/caller severity, researcher severity,
caller severity, database-stored severity, dashboard-selected severity.
UNSET is preserved as UNSET with its reason (downstream renders it as
"pending triage at lowest handling priority" per policy — a DISPLAY rule,
not a severity assignment). Enforcement is structural: no severity input
on any 5J constructor; the persistence layer has no severity column it can
write except the copied triple; any finding whose severity differs from a
recomputed 5I policy resolution is rejected at audit/replay time.

## 9. XSS finding materialization

Materialization per 5I rule (CONFIRMED-only):

- Reflected oracle (E1/E2/E3): finding binds `oracle_channels` (sorted),
  `confirmation_state` (JAVASCRIPT_EXECUTION / OBSERVABLE_EFFECT),
  executed-payload hash, and the sealed derivation identity. 5J performs
  NO browser-signal inspection: `executed_script`, `e1/e2/e3_observed`,
  `browser_verified`, console/DOM text are not inputs, not copied, not
  hashed.
- Stored round: finding preserves the immutable linkage SUBMIT evidence
  (content hash + bindings) → READ evidence → execution channels →
  classification → finding (`round_id`, `submit_evidence_ref`,
  `submit_content_hash` on the security record). No round rebinding: a
  READ re-presented against a different SUBMIT is a different finding or
  (on mismatch) no finding.
- Finding content discipline (§8 of the task spec): hashes, bounded
  redacted samples already present on sealed evidence (by reference/ID,
  not by copy), structured summaries (channels, states, locations),
  evidence/artifact IDs. NEVER: secrets, auth headers, cookies, bearer
  tokens, raw oracle S/D values, OOB material, unrestricted bodies,
  console text, Nuclei stdout/stderr, LLM prompts, arbitrary page
  content. Note `XSSFinding.payload_reference` (raw payload) MUST NOT
  survive migration — executed-payload HASH replaces it.

## 10. HTTP findings

Current policy: 5I HTTP reflection caps at POTENTIAL → 5J eligibility
rejects ALL HTTP-observation findings (`OUTCOME_NOT_FINDING_ELIGIBLE`).
Reflection proves reflection, never execution; silently elevating it
would convert every reflected-input echo into a vulnerability.

Prerequisite for a future HTTP CONFIRMED path (NOT designed here, listed
so 5J cannot accidentally admit it): a versioned execution-proof-grade
HTTP rule (e.g. sealed active-behavior confirmation with the same
freshness/anti-harvest/binding rigor as the oracle channels) shipped as a
pinned rule version + eligibility-table entry + dedicated tests. Until
then the transition stays absent by construction.

## 11. Nuclei findings

Current policy: Nuclei→CONFIRMED is unreachable in 5I → 5J materializes
NOTHING from `NucleiObservation` (`OUTCOME_NOT_FINDING_ELIGIBLE` for the
POTENTIAL advisory ceiling; rejections for the rest). Untrusted as proof:
`finding_like_text_present`, stdout/stderr samples and hashes, exit code,
timed_out/killed, matcher text, template/caller severity. A future Nuclei
finding requires the separately versioned deterministic specificity
policy (exact template identity + closed matcher allowlist + sealed
observed-response binding + confounder absence) — explicitly NOT invented
in 5J. The `NucleiFinding.raw_output` persistence pattern MUST NOT be
replicated: stdout/stderr are never stored in findings.

## 12. Deduplication

Dedup key = `finding_id` (§7). Same id re-presented → idempotent no-op
(return existing record identity, emit `FINDING_DEDUPLICATED`, no write,
no alert re-fire — §18). Different evidence or classification or versions
→ distinct immutable finding (no upsert-merge, no "latest wins" mutation).

- In-memory backend: dict keyed by `finding_id` with put-if-absent +
  byte-compare refusal on differing bytes (same discipline as the 5H blob
  layer).
- Future Mongo backend (B2-gated): unique index on `finding_id`;
  duplicate-key → read-back-compare → identical bytes means benign replay
  (dedup event), differing bytes means corruption/attack (quarantine path,
  loud audit, no overwrite). No read-modify-write anywhere: all writes
  are single-document inserts; workflow state lives on a SEPARATE
  document/collection keyed by `finding_id` with its own CAS version
  (§14). Crash recovery = replay-safe inserts (idempotent by key).

## 13. Finding lifecycle

Security identity and operational workflow are SEPARATE records:

- Security record lifecycle (append-only, forward-only):
  `MATERIALIZED → PERSISTED → (ARCHIVED | TOMBSTONED)`. Transitions are
  events, never edits. Tombstoning the security record hides it from
  default reads but preserves bytes + audit history.
- Workflow record lifecycle (mutable, CAS-versioned, keyed by
  `finding_id`): `OPEN → ACKNOWLEDGED → RESOLVED → (REOPENED)*`,
  assignment, labels, comments. Workflow transitions MUST NOT alter
  classification, severity, evidence/target/artifact bindings, or
  versions — enforced by storing them on a different document with no
  field overlap except `finding_id`.
- Evidence later unavailable/corrupt: finding becomes
  `PERSISTED_UNVERIFIABLE` (a READ-model flag computed at query time
  from evidence liveness, never a rewrite of history). A finding NEVER
  becomes "safe"/"not vulnerable" because its evidence was deleted —
  deletion is an availability event, not a verdict.

## 14. Finding updates

Immutable (security record — no update API under any name, test-asserted
absent like the 5H builder): classification, severity triple, evidence
binding, target binding, artifact binding, all version pins, round
linkage. Mutable (workflow record ONLY, CAS-guarded): acknowledged,
assignee, workflow labels, comments, resolution note. No generic
PATCH/PUT over the security object; no endpoint, function, or adapter
that accepts a security-field write. Migration-time schema additions
require a NEW `sealed-finding/vN` with re-materialization from the
original classification (old findings retained).

## 15. Retention / tombstone

Integrates with 5H retention hooks/state only (no 5H changes):

- Evidence tombstoned/unavailable → finding flagged
  `PERSISTED_UNVERIFIABLE`; historical classification stands.
- Finding retention expiry / operational resolution → security record
  `ARCHIVED` (query-side default-hide), workflow record closed.
  Archival is never deletion.
- Explicit tombstone (abuse/false-positive-with-proof, operator action):
  security record `TOMBSTONED` with reason + actor + audit event; bytes
  retained; audit history never silently deleted.
- Resolved findings are NOT deleted and do NOT alter severity or
  classification. "No rows returned" (expiry/archival) must be
  distinguishable from "no vulnerability" at every API boundary.

## 16. Audit

Append-only, frozen-trail discipline (hashes + IDs + codes, never
secrets/bodies/stdout/page/LLM text):
`FINDING_ELIGIBILITY_ACCEPTED` (finding id + classification hash +
versions), `FINDING_ELIGIBILITY_REJECTED` (closed reason),
`FINDING_MATERIALIZED` (finding id + classification hash),
`FINDING_PERSISTED` (finding id + backend + dedup outcome),
`FINDING_DEDUPLICATED` (finding id), `FINDING_TOMBSTONED` (finding id +
reason class + actor), `FINDING_WORKFLOW_CHANGED` (finding id + from/to
workflow states ONLY — no security fields). Audit is accounting: never
read to grant permission, never overrides recomputed hashes; audit-sink
failure → gap event, never evidence/finding mutation.

## 17. API/dashboard boundary

Current state: NO dashboard or API surface reads findings today (Flask
apps and Dashboard v2 serve recon; verified by grep — zero finding
references in `backend/`). Migration boundary therefore starts clean:

- Authoritative source (post-5J): the 5J finding store, served via NEW
  read-only endpointsnamespaced apart from recon (e.g. `/api/v2/findings`),
  returning the sealed shape minus nothing (it is already secret-free by
  construction) with `PERSISTED_UNVERIFIABLE`/archival flags computed at
  read time.
- Legacy compatibility source: NONE authoritative. `XssFindings`
  collection rows and `ai_data/nuclei/findings/*.json` files MUST NOT be
  served alongside 5J findings as peers. If a transitional read is ever
  needed, it lives behind an explicitly labeled `legacy/` namespace
  carrying a non-authoritative banner, and 5J implementation is the
  wrong phase to build it — migration execution belongs to a later,
  explicitly authorized phase.
- Write precedence: only the 5J materializer writes the finding store;
  no dashboard/API write path to security records (workflow writes go to
  the workflow record via CAS). Alert precedence (§18).

## 18. Alert / notification boundary

No finding alerts exist today (Telegram transport is recon-driven). 5J
alert rule: alerts may originate ONLY from `FINDING_PERSISTED` events for
newly persisted (non-deduplicated) 5J findings. Never from LLM output,
researcher output, Nuclei stdout, legacy `XSSFinding`/`NucleiFinding`,
raw DB rows, or recon change events. Duplicate-alert prevention:
deterministic alert identity `alert = sha256(finding_id \x00
alert_policy_version)` with put-if-absent alert ledger (same dedup
discipline as §12); finding replay → `FINDING_DEDUPLICATED` → no alert.
Severity-UNSET findings alert at the lowest handling priority with an
explicit "severity pending" marker (display rule, §8). No delivery
implementation in 5J architecture scope beyond the seam contract
(transport interface + identity + dedup); Telegram may serve as a future
transport, never as authority.

## 19. Multi-program isolation

Every finding is bound to exactly one
(program, canonical target, authorization, evidence, classification)
tuple: `program_name` + (host, scheme, effective port, path-scope) +
`authorization_id` (+ issuance nonce lineage via the classification) +
evidence triple + classification hash. Revalidation (§5) compares ALL
axes — cross-program, cross-target, or cross-artifact evidence is
rejected at the first divergent gate with a closed binding-mismatch
reason. Persistence keys are program-scoped (`(program_name, finding_id)`
unique pair in Mongo; namespace prefix in memory). No query path may
return findings across programs without an explicit program parameter;
no aggregation may blend severities across programs into a shared
"vulnerable" label. Workflow records inherit the same program binding
and the same isolation.

## 20. Security threat model

For each adversary, the defeating gate (defense in depth — at least two
independent gates for the critical paths):

- Forged classification result → constructor hash reproduction (§3) +
  fresh revalidation version/identity equality (§5).
- Forged finding (hand-built row/file) → deterministic-id byte-compare
  refusal (§12) + no write path except the materializer (§17).
- Stale evidence (quarantined/tombstoned between classify and persist) →
  fresh read liveness gates (§5) → NO FINDING.
- Tampered evidence → triple recomputation + index-claim comparison
  (inherited 5H) → NO FINDING, never reinterpreted.
- Cross-program/target/artifact confusion → full-axis binding equality
  (§5, §19) → closed mismatch, NO FINDING.
- Severity injection (any source) → structural absence of severity
  inputs + verbatim-copy + replay check (§8).
- Caller-selected classification/eligibility → `extra="forbid"` +
  eligibility table evaluated over 5I fields only (§3, §4).
- Duplicate finding / race → put-if-absent + unique index + CAS
  workflow separation (§12, §14); concurrent identical persists collapse
  to one record + dedup event.
- Evidence tombstone/corruption post-persist → `PERSISTED_UNVERIFIABLE`
  flag, history preserved (§13, §15).
- Verifier/rule/policy/eligibility downgrade → version pins on result,
  finding, and dedup key; unknown or non-pinned versions fail closed
  (§4, §6, §7).
- Legacy bypasses (`verify`/`_build_finding` direct, `to_findings`,
  `save_findings`, direct `XSSFinding(`/`NucleiFinding(` construction,
  `watch_xss_verify → XssFindings` job, dashboard/alert ingestion of
  legacy rows/files) → enumerated HARD-BLOCK list (§21); 5J input type
  is unreachable from all of them (no shared constructor, no adapter).
- LLM prompt injection / malicious page / malicious Nuclei output →
  untrusted-data posture inherited from 5I; 5J copies hashes and IDs
  only, never content (§9, §11).
- Secret leakage → content allowlist (§9: hashes/references/summaries);
  `raw_output`/bodies/console/LLM text have no field to inhabit;
  audit-scan tests mirror the 5I secrecy tests.
- Finding-ID collision (malicious key reuse) → byte-compare refusal +
  quarantine path (§7, §12).
- Workflow-state mutation of security fields → separate documents, no
  overlapping writable fields, no generic update API (§14).

## 21. Legacy migration map

- KEEP (unchanged, still useful outside authority): `ai/verification/oracle.py`
  pure predicates; `xss_pipeline.py` pass-through shape (never interprets);
  recon dashboards/APIs; Telegram transport; `database/change_events.py`.
- REUSE (frozen contracts): 5I `ClassificationResult` + `compute_result_hash`,
  `materialize_finding` core logic (narrowed by 5J eligibility), 5H
  verified-read/index/blob/audit/retention contracts, 5B issuance types,
  `watch_xss_verify` lazy-import + injectable-collaborator JOB SHAPE
  (pattern only — the World A pipeline it drives is HARD-BLOCK).
- WRAP (adapt behind the 5J boundary, then freeze): `SealedFinding` →
  full `sealed-finding/v1` (add resolution/scope identities, eligibility
  pin, round linkage, audit envelope — §6); `XssFindings` DOCUMENT SHAPE
  may inform the future Mongo adapter's index choices (case-dedup via
  unique key) but its ROWS are never migrated as findings (no severity,
  no version pins, POTENTIAL/INCONCLUSIVE rows exist — migrating them
  would launder non-eligible outcomes into the authoritative store).
- DEPRECATE (non-authoritative, no path to 5J, clearly marked):
  `NucleiFinding` (+ `raw_output` persistence), `XSSFinding` legacy
  fields (`browser_verified`, free `confidence`, `payload_reference`,
  raw `reflection_evidence`/`verification_evidence` strings),
  `XSSVerificationResult.findings` as a consumable list,
  `ai_data/nuclei/findings/*.json` as a readable finding source.
- HARD-BLOCK (sever before any production activation; each gets a
  bypass test in 5J implementation): `XSSVerifier.verify` /
  `_build_finding`; any `XSSFinding(` / `NucleiFinding(` construction
  outside the 5I-authorized materializer; `NucleiRunner.to_findings`;
  `NucleiPipeline.to_findings` call + `save_findings`; `watch_xss_verify`
  `mongo_persist`/`mongo_already_verified` LOOPS AS PRODUCTION PATHS
  (the dedup pattern is reused, the World A content is blocked);
  any API/dashboard/alert ingestion of `XssFindings` rows or
  `ai_data/nuclei` files as findings; any severity/confidence passthrough
  from Nuclei/LLM/caller into stored or displayed findings.

## 22. Persistence architecture

Primary (offline, testable now): in-memory finding store —
`dict[(program_name, finding_id)] → sealed finding bytes` with
put-if-absent + byte-compare refusal; separate dict for workflow records
with CAS version integers; fake audit sink (append-only list). Deterministic,
single-threaded-hostile by design (no locks relied upon; key-identity
rules carry safety, mirroring the 5H in-memory fakes).

Future Mongo adapter (B2-GATED, specified not built): two collections —
`sealed_findings` (unique index `(program_name, finding_id)`; inserts
only; application-level insert-only discipline since MongoEngine
documents are mutable by default — the adapter exposes no update method)
and `finding_workflows` (`finding_id` unique; CAS via version field /
`findAndModify` on expected version). Audit linkage via finding id +
classification hash on every event. Dedup = duplicate-key → read-back-
compare. Crash recovery = replay-safe inserts (all writes idempotent by
key; job checkpoints OUTSIDE the security store). No migrations, no
credentials, no connections in this phase (B2 BLOCKED).

## 23. 5J offline implementation plan

New modules ONLY (no frozen-file modification expected):

- `ai/finding/eligibility.py` — pinned eligibility table + gate
  (`ClassificationResult → ELIGIBLE/INELIGIBLE + closed reason`).
- `ai/finding/sealed.py` — `sealed-finding/v1` schema (extends the 5I
  `SealedFinding` shape per §6) + `finding_identity_for` + hash/verify
  helpers (5H canonical hashing discipline).
- `ai/finding/materializer.py` — orchestrator: eligibility → fresh
  revalidation (§5 checklist) → construct → persistence seam →
  notification seam → audit. Wraps (not forks) 5I `materialize_finding`.
- `ai/finding/store_memory.py` — in-memory finding + workflow stores
  with put-if-absent/CAS semantics (§12, §14).
- `ai/finding/audit.py` — 5J audit event models + closed reason
  vocabulary (§16).
- `ai/finding/legacy_block.py` — documentation + import-surface
  assertions backing the HARD-BLOCK tests (AST scans mirroring the 5I
  legacy-bypass tests).
- `ai/test_finding_pipeline.py` — offline matrix: eligibility
  (CONFIRMED/POTENTIAL/UNKNOWN/NOT_VULNERABLE-attempt), forged-result
  rejection, every §5 mismatch axis, tamper/cross-program/artifact-drift,
  severity-injection attempts, Nuclei/HTTP non-eligibility, stored-round
  linkage preservation, dedup/idempotency, CAS workflow isolation,
  tombstone/unverifiable-flag behavior, audit secrecy, legacy-bypass
  invocation (each HARD-BLOCK path called directly → no finding),
  determinism (same inputs → byte-identical finding + id).

Test doubles only: fake evidence store + seam, hand-built (validly
hashed) classifications via the REAL 5I pipeline over sealed fixtures,
fake audit sink, in-memory finding store. No network/Mongo/browser/
subprocess/LLM in any test.

## 24. 5J exit criteria

5J implementation is PASS only when ALL hold (each test-enforced):

1. Only a genuine 5I `ClassificationResult` (hash-reproducing) can
   authorize findings; forged results rejected.
2. Fresh evidence revalidation passes on every §5 axis before any write;
   any mismatch → NO FINDING, no repair, no rebind.
3. Immutable `sealed-finding/v1` schema (frozen, `extra="forbid"`,
   hashed, replayable, idempotent); timestamps excluded from identity.
4. Deterministic finding identity (§7); version changes fork identity;
   no random security identity.
5. Severity verbatim from 5I incl. UNSET preservation; injection from
   every listed source rejected structurally.
6. POTENTIAL/UNKNOWN/INCONCLUSIVE can never become findings (no
   exception path without a versioned policy that does not exist).
7. Nuclei observations can never become findings (specificity policy
   absent); HTTP reflection can never become a finding (POTENTIAL cap).
8. XSS bindings complete (program/target/resolution/scope/artifact/
   derivation); stored-round SUBMIT→READ→EXECUTION linkage preserved
   with no rebinding.
9. Every §21 HARD-BLOCK path invoked directly produces no finding and
   reaches no persistence/notification seam.
10. Dashboard/alert sources explicitly controlled: only 5J `FINDING_PERSISTED`
    events feed alerts (deduped by alert identity); no legacy ingestion.
11. Idempotency + concurrency (duplicate persist = no-op + dedup event;
    no read-modify-write) verified.
12. Retention/tombstone semantics (§13, §15) implemented; history never
    rewritten; unverifiable-flag behavior verified.
13. B1/B2/B4/B5 remain BLOCKED; `LIVE_BROWSER`/`LIVE_NUCLEI`/
    `LIVE_TRAFFIC_ENABLED` False; no live execution; no production
    persistence activated beyond the in-memory backend.

## 25. Blocking prerequisites

B1 (Production AddressSource selection/review), B2 (production MongoDB
authorization/ledger/audit/evidence/finding adapters + sweep), B4
(payload corpus source-of-truth), B5 (live browser containment/network
boundary) remain BLOCKED — this report closes none of them, assumes none
of them, and designs nothing that requires them active. No 5J
implementation, no finding generation, no finding persistence, no
notification delivery, no evidence/classification mutation, no OOB, and
no live execution of any kind is authorized by this architecture phase.

---

## Mandatory phase statements

MongoDB production access = NO
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
Classification mutation = NO
Production finding persistence = NO
Finding generation implementation = NO
