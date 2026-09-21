# AEC-1 EPIC7 — Authorized Observation Runtime v1 — Execution Plan

**Status:** PLAN (RED-first implementation follows)
**Base:** main `a9fed3f` (EPIC6), agent branch `aad20e4`
**Hard criterion:** ≥400 new GREEN tests; full AEC regression; all guards.

## Mission

Connect the EPIC6 execution bridge (Watch Data → Candidate → Case →
ResearchJob → Specialist → Authorization Gate → AUTHORIZED_OBSERVATION_REQUEST
→ Evidence Bridge → Review) to a real, narrowly scoped observation runtime
that *executes only explicitly authorized, policy-compliant observation
requests* and fails closed for everything else. Not scanning, not exploit
execution, not autonomous exploitation. The Authorization Gate stays
authoritative; the runtime independently re-validates the authorization
artifact before execution.

## Deliverables (new modules only; EPIC6 contracts consumed, not modified)

```
aec/runtime/policy/__init__.py, models.py, limits.py
    ObservationPolicy (types/methods/evidence levels/versions),
    ResourceLimits (timeouts, bytes, redirects, concurrency, per-host,
    total runtime, retries); limits are policy-driven, closed vocab.

aec/runtime/execution/__init__.py, states.py, validation.py, runtime.py,
    idempotency.py
    ObservationRuntime 11-state machine (RECEIVED VALIDATING AUTHORIZED
    DISPATCHED OBSERVING COLLECTING COMPLETED REFUSED BLOCKED TIMED_OUT
    FAILED); every transition records request_id, research_job_id, case_id,
    prev/next, reason, tick, policy version, authorization reference.
    validation.py: the 12 explicit checks (authz exists/valid/not expired,
    identity/case/target match, type/method/scope permitted, evidence level
    compatible, policy version supported, not already executed). No implicit
    defaults, no wildcard interpretation.

aec/runtime/adapters/__init__.py, target.py, http_observation.py
    target.py: accepts only normalized Watch/AEC target identities (host,
    endpoint, scheme, explicit port) — a specialist can never pass a raw URL.
    http_observation.py: THE single sanctioned HTTP transport. Imports
    http.client lazily inside functions (module import touches nothing);
    explicit timeouts, bounded response size, bounded redirects, records
    status + allowlisted headers + content metadata + timing, deterministic
    redaction, provenance; transport injected for tests. Every other module
    in aec/ remains network-free (new invariant pins exactly this one
    exception).

aec/runtime/results/__init__.py, evidence.py, redaction.py, audit.py
    evidence.py: §8 artifact (evidence_id, request_id, research_job_id,
    case_id, target_id, observation_type, timestamp, status, selected
    headers, content metadata, response size, timing, scope validation,
    authorization reference, policy version, redaction status, integrity)
    fed through EPIC6 bridge.ingest — never a finding.
    redaction.py: deterministic policy covering Authorization, Cookie,
    Set-Cookie, API-key/token/password-shaped values, known secret headers.
    No perfect-secret-detection claims; policy documented.
    audit.py: append-only hash-chained audit (request, authorization,
    target, policy, decision, state, result, evidence, refusal reason);
    supports investigation and deterministic replay.

aec/runtime/integrate.py            # ResearchJob wiring + specialist boundary
aec/runtime/__init__.py (extended)
backend/routers/aec.py +5 GET       # /api/aec/runtime{,/requests,/audit,/limits,/health}
tests/test_aec_runtime_*.py (19 modules)   # ≥400 tests
agent-reports/AEC-1-EPIC7-authorized-observation-runtime.md
```

## Frozen dependencies (consumed unchanged)

- `aec/authorization_gate.py` (gate ALLOW/REFUSE), `aec/execution/executor.py`
  (`submit_plan` mints `AUTHORIZED_OBSERVATION_REQUEST` — the ONLY acceptable
  observation request source), `aec/runtime/jobs.py` 13-state table
  (READY_FOR_OBSERVATION → OBSERVATION_RUNNING → EVIDENCE_PENDING →
  ANALYSIS_PENDING), `aec/runtime/loop.py` (untouched — the runtime is
  additive, wired via `aec/runtime/integrate.py`), `aec/evidence_bridge`
  `ingest`/`apply_to_gap`, `aec/research/sources.py` `ORIGIN_MODES`,
  `aec/redaction.scrub_text`, `aec/replay` identity/kernel.
- **Unchanged:** `ai/` verification chain, `backend/tasks_registry.py`,
  `api.py`, `.env`, `systemd`, production `/opt/watch`.

## Safety boundaries (fail-closed, tests prove each)

1. Only `executor.submit_plan` output (with valid authz, GRANTED, in scope)
   may seed an observation; a raw specialist dict or raw URL is refused.
2. DRY_RUN and OFFLINE_FIXTURE modes never invoke the transport (proven
   with an exploding transport — calling it fails the test).
3. Redirects outside scope → REFUSED; no DNS-derived expansion, no userinfo
   URLs, no IP substitution, localhost/private refused unless explicit.
4. Limits are policy-driven; no infinite retry; retries only for explicitly
   classified retryable kinds, never unsafe operations.
5. Sensitive values absent from logs/reports/evidence/failure traces
   (redaction tests scan serialized outputs for planted secrets).
6. Every failure → explicit runtime state; no silent failures.
7. Audit log append-only with hash chain (tamper-evident, replayable).
8. No verdict vocabulary anywhere in new code (`finding`, `confirmed`,
   `vulnerable`, `exploit`, `bypass` …); invariants keep the enforcer
   exemption plus the single transport exemption.

## Test strategy (RED → GREEN, ≥400 new)

Modules: policy (validate/limits/allowlist), states (11-state machine +
transition records + invalid refusals), validation (12 checks), scope
(host/scheme/port/path/redirects), target adapter (no raw URLs, mismatch
refusals), http adapter (timeouts/size/redirects/recording/redaction via
injected transport; secrets never logged), limits (per-request/per-run/
concurrency/per-host/retry), redaction (deterministic, secrets absent from
all outputs), dry-run (plan output, zero traffic, distinguishable),
execution gating (impossible to reach transport without all gates),
idempotency, failures (14 kinds → states), audit (append-only + hash chain
+ replay), integration (job wiring + specialist boundary), isolation
(fixture/dry-run zero traffic), acceptance scenarios A–N, router (5
endpoints, 19 routes, no secrets), invariants (only sanctioned adapter may
import http/socket; lazy import; vocabulary; frozen files).

Acceptance A–N implemented verbatim as deterministic tests.

## Verification sequence

1. RED: run new modules, record failures (modules absent).
2. Implement, GREEN per module.
3. Full AEC regression (`discover -p "test_aec_*.py"`).
4. `git diff --check`; `check-aec-readonly.sh`; frozen-file `cmp -s`;
   no-network denial suite incl. new runtime suites.
5. Delivery `report.sh` + `check.sh`.
6. Doc → commit → `push_safe.sh` → promotion request → ONE Telegram
   APPROVE → `promote.sh --yes`. Production untouched until then.

## Explicitly out of scope (no speculative work)

Arbitrary POST, file upload, credential submission, destructive actions,
exploit payloads, authentication bypass, unrestricted crawling, severity
rankings, finding fabrication, any modification of EPIC6 executor/loop/
gate contracts, api.py mounting.