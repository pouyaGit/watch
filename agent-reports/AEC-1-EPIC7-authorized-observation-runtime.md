# AEC-1 EPIC7 — Authorized Observation Runtime v1

Status: implementation complete, verification complete, promotion requested.

## Implementation status

The first controlled observation runtime on the EPIC6 execution bridge
(EPIC6 promoted to main as `a9fed3f`). New packages:

- `aec/runtime/` — runtime package root + ResearchJob integration
  (`integrate.py`) and specialist-request validation
- `aec/runtime/policy/` — `models.py` (observation-type allowlist,
  policy versions), `limits.py` (Part 7: policy-driven resource limits
  and the `LimitsEnforcer`)
- `aec/runtime/adapters/` — `target.py` (Part 4: normalized target
  identities, scope binding), `http_observation.py` (Part 5: the SINGLE
  sanctioned transport adapter, lazy imports, bounded redirects)
- `aec/runtime/execution/` — `states.py` (Part 1: 11-state lifecycle,
  fail-closed transition table), `validation.py` (Part 2: request
  validation), `scope.py` (Part 6: explicit scope enforcement),
  `idempotency.py` (Part 12: dedup keys + explicit retry classification),
  `failures.py` (Part 13: 14 failure kinds → explicit states),
  `runtime.py` (Parts 10/11: DRY_RUN vs LIVE_OBSERVATION modes, no
  fallback from refusal to execution)
- `aec/runtime/results/` — `evidence.py` (Part 8: bridge-compatible
  evidence artifact, never a finding), `redaction.py` (Part 9:
  deterministic redaction), `audit.py` (Part 16: append-only hash-chained
  audit trail)

Additive Command Center API (Part 18): 5 new GET endpoints
(`/api/aec/runtime`, `/runtime/requests`, `/runtime/audit`,
`/runtime/limits`, `/runtime/health`) — 14 → 19 routes, still GET-only,
simulation-backed (DRY_RUN, no network).

## Tests / results

- **1827 AEC tests OK** (1421 EPIC6 baseline + 463 new EPIC7 tests across
  18 new runtime test modules: states, validation, target, policy,
  redaction, http adapter, scope, dry-run, audit, idempotency, failures,
  limits, evidence, integration, acceptance A–N, router, invariants,
  orchestration).
- `test_aec_no_network` + `test_aec_import_guard`: hardened for the
  single sanctioned transport adapter (EPIC7 §5) — transport imports are
  function-local only, verified statically.
- The full-project discovery (12900 tests) has 367 failures/errors that
  are PRE-EXISTING environment issues outside EPIC7 scope (missing
  `dnsx` binary, missing `ai_data/research/*.json` fixtures, Track A
  research modules) — none originate from EPIC7 changes; AEC-only
  discovery is fully green.

## Guards / results

- Read-only manifest (116 pinned files): **READ-ONLY VERIFIED** — no
  pinned file drifted.
- Whitespace: clean (`git diff --check`).
- Import guard: sanctioned-transport exemption is narrow and asserted
  (function-local; no other runtime file may import transport names).
- Forbidden words / verdict vocabulary invariants: pass.

## Changed areas

- New: `aec/runtime/**` (29 files), 18 test modules, EPIC7 plan report.
- Extended: `backend/routers/aec.py` (+5 GET endpoints, builders),
  route-count pins 14 → 19 in three router test modules.
- Hardened: `test_aec_import_guard.py` (sanctioned transport carve-out +
  2 new assertions), `test_aec_no_network.py` (pre-warm stdlib imports
  so the deny patch cannot break `ssl` at import time).
- Production: untouched (HEAD still `a9fed3f`; no EPIC7 change in prod).

## Security boundary verification

- Authorization Gate remains authoritative: runtime independently
  validates the authorization artifact (existence, status, expiry,
  identity, target scope, policy version, duplicate check) before any
  execution; no alternate authorization paths.
- No arbitrary URLs: specialists pass a normalized target identity only;
  raw-URL submission is rejected by contract and asserted by test.
- No raw HTTP from specialists: the one sanctioned transport module is
  function-local and statically pinned; every other runtime module is
  network-free.
- No exploit payloads / credential attacks / destructive requests /
  unrestricted crawling: observation type allowlist is closed
  (HTTP_METADATA, HTTP_HEADERS, HTTP_STATUS, HTTP_BODY_METADATA only).
- Fail-closed lifecycle: invalid transitions raise; unknown failure
  kinds → FAILED; DRY_RUN never executes; OFFLINE_FIXTURE never
  executes; refusal has no fallback to execution.
- Redaction proven in tests: authorization/cookie/set-cookie/API-key
  values absent from logs, reports, stored evidence, failure traces.
- Evidence artifacts never become findings (vocabulary asserted).

## Remaining issues

- The real transport adapter (`http_observation.py`) is implemented and
  unit-tested with an injected transport; LIVE_OBSERVATION execution in
  production remains behind an operator authorization handoff (same
  posture as EPIC6: the offline half is complete, live activation is a
  separate, explicit authorization step).
- Pre-existing environment test failures outside AEC scope (see above).

## Promotion readiness

READY FOR PROMOTION: YES

(Per brief: no auto-promotion. Promotion request generated; awaiting
explicit approval.)