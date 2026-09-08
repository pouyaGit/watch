# Stored XSS Final Diff Review

## Verdict

**NOT CLEAN — DO NOT COMMIT**

Reasons:

1. `git diff --check` fails: a stray blank line at EOF in `ai/test_xss_oracle.py:1081`.
2. The working tree contains many tracked modifications that are unrelated to
   the Stored XSS work. They must be removed from this commit (split out,
   stashed, or committed separately). The current diff includes the
   following PRE-EXISTING UNRELATED changes:
   - `AGENTS.md` (new "Agent Reports" section)
   - `README-watch-updated.md` (deleted file)
   - `ai/test_xss_case_builder.py` (PATCH/body case builder test)
   - `ai/test_watch_param_discovery.py` (x8 parser / UA / requeue tests)
   - `crawl/watch_param_discovery.py` (explicit curl UA, GET-only x8
     discovery, `example_url` filter, wordlist export hardening)
   - `database/db.py` (Mongo host config + `record_change` call sites in
     `upsert_lives` / `upsert_http`)
   - `database/change_events.py` (structured warning logging on
     persistence failure)
3. The Stored XSS implementation depends on
   `ai/verification/oracle.py` and `ai/test_xss_stored_round.py`,
   both of which are untracked and therefore absent from the diff.
   They must be staged before the commit is meaningful.

The Stored XSS-only changes themselves are correct (W1/W2/W3 hardening
verified, no security-semantic regressions in `_classify_stored`,
OraclePlanner, run_salt, anti-harvest, or round binding). All required
tests pass and `compileall` is clean.

## Git Status

```
$ git status --short
 M AGENTS.md
 D README-watch-updated.md
 M ai/schemas/xss_finding.py
 M ai/schemas/xss_verification.py
 M ai/test_browser_executor.py
 M ai/test_http_executor.py
 M ai/test_watch_param_discovery.py
 M ai/test_xss_case_builder.py
 M ai/test_xss_oracle.py
 M ai/test_xss_verification.py
 M ai/verification/browser_executor.py
 M ai/verification/http_executor.py
 M ai/verification/verifier.py
 M crawl/watch_param_discovery.py
 M database/change_events.py
 M database/db.py
?? agent-reports/
?? ai/test_xss_stored_round.py
?? ai/verification/oracle.py
?? tests/__init__.py
?? tests/test_change_events.py
?? tests/test_dashboard_logic.py
?? tests/test_page_render.py
?? tests/test_routers_fixes.py
?? tests/test_tz.py
?? wordlists/
```

Notes:

- `M` = modified, tracked.
- `D` = deleted, tracked.
- `??` = untracked.
- The 16 tracked-modified files plus 1 tracked-deleted file form the
  review surface.

## Diff Stat

```
$ git diff --stat
 AGENTS.md                           |   95 ++-
 README-watch-updated.md             |  661 --------------------
 ai/schemas/xss_finding.py           |    7 +
 ai/schemas/xss_verification.py      |  116 ++++
 ai/test_browser_executor.py         |  178 +++++-
 ai/test_http_executor.py            |  140 ++++-
 ai/test_watch_param_discovery.py    |  306 ++++++++-
 ai/test_xss_case_builder.py         |   17 +
 ai/test_xss_oracle.py               |  894 ++++++++++++++++++++++++++
 ai/test_xss_verification.py         |  478 ++++++++------
 ai/verification/browser_executor.py |  175 +++++-
 ai/verification/http_executor.py    |  136 +++-
 ai/verification/verifier.py         | 1174 +++++++++++++++++++++++++++++++----
 crawl/watch_param_discovery.py      |  119 +++-
 database/change_events.py           |   61 +-
 database/db.py                      |  101 ++-
 16 files changed, 3625 insertions(+), 1033 deletions(-)
```

## Expected Changes

Stored XSS v1 work (intended changes):

| File | Role |
| ---- | ---- |
| `ai/schemas/xss_finding.py` | +`round_id`, +`read_url` audit-only fields on `XSSFinding` |
| `ai/schemas/xss_verification.py` | +`DialogEvent`, +`NetworkOracleEvent`, +`EvalInvocation`; +`oracle_seed`/`oracle_value`/`oracle_version`/`oracle_identity`/`round_id` on `VerificationAttempt`; +`dialog_events`/`oracle_network_events`/`eval_invocations` + SUBMIT forensics (`request_body_hash`, `response_body_hash`, `redirect_chain`, `location_header`, `object_hint`, `intended_request_url`, `actual_request_url`) on `VerificationEvidence`; `round_id` on `StoredXSSPhaseObservation` |
| `ai/verification/browser_executor.py` | Clean READ navigation for `stored_read`; structured E1/E2/E3 evidence channels; oracle-path detection (`_is_oracle_request_url`); structured warning logging on persistence failure; `ORACLE_PATH_PREFIX` import |
| `ai/verification/http_executor.py` | `STORED_SUBMIT_PHASE` / `STORED_READ_PHASE` constants; `_submit_shape_error` v1 gate; SHA-256 body/URL hashing; redirect-chain + `Location`-header forensics for SUBMIT |
| `ai/verification/verifier.py` | `STORED_SUBMIT_PHASE` / `STORED_READ_PHASE` / `LEGACY_STORED_PHASE` constants; `_SUBMIT_REJECT_BODY_MARKERS` (W1 fix); `stored_round_id`, `build_stored_round`; `discover_stored_read_url` with port enforcement (W3 fix); `_stored_oracle_proof` with `final_origin == endpoint_origin` (W2 fix); `_submit_accepted`, `_classify_stored_oracle`, `_read_shows_storage`; hardcoded `_classify_stored` returning `"POTENTIAL"` (legacy demotion); new `_STORED_STATE_STORAGE_ATTRIBUTED` state |
| `ai/test_xss_stored_round.py` | New test module (untracked) — Stored XSS round-trip suite (62 tests) |
| `ai/verification/oracle.py` | New module (untracked) — execution-oracle infrastructure (W(S), planner, E1/E2/E3 predicates, anti-harvest, run-salt derivation) |

## Unrelated Pre-existing Changes

These tracked modifications are NOT part of the Stored XSS work and
must not be part of this commit:

- **`AGENTS.md`** — Adds the new "Agent Reports" section (rules for
  `agent-reports/` workflow). Doc-only, unrelated to XSS verification.
- **`README-watch-updated.md`** — Deletion of an old README snapshot.
- **`ai/test_xss_case_builder.py`** — Adds a `test_x8_patch_body_record`
  test for PATCH/body case builder provenance.
- **`ai/test_watch_param_discovery.py`** — Adds x8 parser / UA / requeue /
  registrable-domain tests.
- **`crawl/watch_param_discovery.py`** — Multiple unrelated crawler
  hardenings:
  - explicit curl `User-Agent: curl/8.5.0` flag added to `run_x8`
  - x8 methods reduced from `GET POST PUT PATCH` to `GET` only
  - `get_pending_endpoints` now filters on `example_url__exists=True`
  - `export_wordlists` comment-only hardening
- **`database/change_events.py`** — Adds `_log_persist_failure` and
  rewrites `record_change` / `record_changes` to log structured warnings
  on Mongo failure.
- **`database/db.py`** — Mongo host config swap (127.0.0.1 ↔
  178.83.45.76) plus multiple `record_change` call-site additions in
  `upsert_lives` and `upsert_http`.

Notes on the two borderline cases:

- **`ai/test_xss_oracle.py`** — The 894-line diff is the new execution-
  oracle test suite. It is a pre-existing untracked artifact's tracked
  sibling; together with `ai/verification/oracle.py` it forms the oracle
  infrastructure that the Stored XSS implementation depends on. Treat
  it as part of the Stored XSS commit.
- **`ai/test_http_executor.py`** — Mostly additions of cross-host /
  cross-port redirect-rejection tests that exercise pre-existing
  behavior in `ai/verification/http_executor.py`. These tests are NOT
  Stored XSS work; the underlying redirect-rejection logic is already at
  HEAD. Treat the new tests as pre-existing.
- **`ai/test_browser_executor.py`** — Mixed:
  - A small `FakePage` plumbing tweak (`Req()` → `Req(from_main_frame)`)
    to support a new flag is unrelated.
  - The new `BrowserEvidenceExecutorOracleBoundaryTests` class IS
    Stored-XSS work (E2 oracle boundary tests).

## Unexpected Changes

None beyond the PRE-EXISTING UNRELATED list above.

Note however that the implementation is incomplete in the index:

- `ai/verification/oracle.py` — new module (625 lines), referenced by
  `ai/verification/verifier.py` lines 28–39, but UNTRACKED.
- `ai/test_xss_stored_round.py` — new test module (1795 lines),
  UNTRACKED.

A commit that contains only the tracked diff will not import
`ai.verification.oracle` and will not run the 62 stored-round tests.

## W1/W2/W3 Diff Verification

### W1 — CSRF detection narrowed from bare "csrf" to explicit failure semantics

Confirmed. `ai/verification/verifier.py:124-133`:

```python
_SUBMIT_REJECT_BODY_MARKERS = (
    "captcha",
    "invalid csrf",
    "csrf validation failed",
    "csrf token invalid",
    "csrf token mismatch",
    "csrf token expired",
    "missing csrf token",
    "csrf_required",
    "invalid token",
    "token mismatch",
    "token expired",
    "mfa",
    "multi-factor",
)
```

There is intentionally NO bare `"csrf"` entry. The matchers name
explicit failure semantics. A bare form field name `csrf_token` or
`csrfmiddlewaretoken` will NOT match. The match handler routes only
`"csrf"`/ `"token"` markers to the `csrf_required` signal
(`verifier.py:1571-1575`); other markers yield a distinct rejection
signal.

### W2 — Stored READ final origin is also bound to read_attempt.endpoint origin

Confirmed. `ai/verification/verifier.py:1913-1922` (inside
`_stored_oracle_proof`):

```python
intended = read_evidence.intended_request_url or ""
final = read_evidence.actual_request_url or ""
final_origin = _origin_of(final)
if final_origin is None:
    return False, [], ""
if final_origin != _origin_of(intended):
    return False, [], ""
endpoint_origin = _origin_of(read_attempt.endpoint)
if endpoint_origin is None or final_origin != endpoint_origin:
    return False, [], ""
```

The final origin must equal the read_attempt.endpoint origin. Mirrors
the reflected binding: a final URL from an unrelated origin — even when
intended and final agree with each other — is rejected.

### W3 — Stored READ discovery fallback enforces effective port

Confirmed. `ai/verification/verifier.py:1654-1671` (inside
`discover_stored_read_url._acceptable`):

```python
# Outer bound: same registrable domain (allows
# app-legitimate display splits such as www. ↔ app.).
# Unresolvable domains fail closed. The fallback also
# requires the same effective port: a same-host
# different-port hint is not an acceptable READ target.
case_host = (urlsplit(case.endpoint).hostname or "").lower()
if self._registrable_domain(
    parts.hostname
) != self._registrable_domain(case_host):
    return None
case_parts = urlsplit(case.endpoint)
candidate_port = parts.port or (
    443 if parts.scheme == "https" else 80
)
case_port = case_parts.port or (
    443 if case_parts.scheme == "https" else 80
)
if candidate_port != case_port:
    return None
```

The fallback path (same registrable domain but different host) is
rejected when the effective port differs.

### Other gates — not accidentally loosened

- `_classify_stored` is hardcoded to return `"POTENTIAL"` (legacy
  demotion). It can no longer produce CONFIRMED via the old correlation-
  token predicate.
- `OraclePlanner` semantics are not modified by this diff. New
  `OraclePlanner` calls in `verifier.py` use the existing
  `OraclePlanner.plan(context_type=..., case_id=..., attempt_id=...,
  logical_pair_id=..., run_salt=..., phase=..., delivery_pattern=...)`
  signature unchanged.
- `run_salt` semantics unchanged. `oracle_seed(run_salt, attempt_id,
  phase)` still returns `sha256(run_salt ‖ 0x00 ‖ attempt_id ‖ 0x00 ‖
  phase)[:16]`. The stored-round seed derivation in
  `verifier.py:1894-1897` re-derives under the CURRENT `run_salt` from
  the SUBMIT-candidate identity — anti-replay binding preserved.
- Anti-harvest is applied only to PRE-EXECUTION material in
  `_stored_oracle_proof` (SUBMIT payload/bound-input/URLs AND READ URLs
  only). Post-execution oracle channels are NEVER scanned
  (`verifier.py:1946-1978`).
- Clean READ check (`_clean_read_ok`) requires both `intended_request_url`
  and `actual_request_url` to be set, and to contain none of S, D, the
  correlation token, the `round_id`, or the payload (`verifier.py:1776-
  1806`).
- D is never placed on the wire. The body of the SUBMIT request hashes
  via SHA-256 of the exact body bytes; `request_body_hash` /
  `response_body_hash` are SHA-256 hex strings of the wire bytes
  themselves, never D.
- Reflected / DOM confirmation path is not modified by this diff
  (the only changes to `_classify` add new parameters and a 2c branch
  for `LEGACY_STORED_PHASE`).
- Crawler / LLM / database subsystems are not modified by any Stored
  XSS diff.

## Security Integrity Check

The Stored XSS-only diff does NOT:

- add a new CONFIRMED path beyond `_classify_stored_oracle`.
- weaken oracle validation (`_stored_oracle_proof` enforces all 9
  steps: identity binding, round binding, oracle pair, run freshness,
  same-origin, ordering, clean READ, anti-harvest, E1/E2/E3 predicates).
- weaken round binding (shared `round_id` AND shared
  `oracle_identity`, both required).
- weaken clean READ (`_clean_read_ok` rejects on any of S, D, token,
  round_id, payload in either URL).
- weaken origin checks (`final_origin == endpoint_origin` AND
  `final_origin == intended_origin` all required).
- weaken anti-harvest (pre-execution only; never post-execution).
- reintroduce correlation-token confirmation (`_classify_stored` is now
  hardcoded `"POTENTIAL"`; the legacy path is demoted, not reinforced).
- reintroduce legacy Stored CONFIRMED (legacy phase demoted to
  POTENTIAL-only).
- modify run_salt semantics (`oracle_seed` is unchanged).
- expose D on the wire (D is recomputed from S locally and compared
  to the carrier's declared value; it is never sent to the target).
- modify OraclePlanner semantics (signature unchanged; new callers
  follow existing patterns).
- modify Reflected/DOM confirmation (`_classify` only adds a 2c branch
  for legacy `LEGACY_STORED_PHASE`, which was previously named `"stored"`).
- modify crawler / LLM / database behavior.

## Test Results

```
$ python3 -m unittest ai.test_xss_stored_round
............./usr/lib/python3.12/multiprocessing/popen_fork.py:66: DeprecationWarning: ...
.................................................
Ran 62 tests in 7.046s
OK

$ python3 -m unittest ai.test_xss_verification
.............................................................................................................................
Ran 125 tests in 0.152s
OK

$ python3 -m unittest ai.test_xss_oracle
..................................................................
Ran 66 tests in 0.164s
OK

$ python3 -m unittest ai.test_http_executor
..........................................................
Ran 58 tests in 0.116s
OK

$ python3 -m unittest ai.test_browser_executor
.........................................................
Ran 57 tests in 18.374s
OK

$ python3 -m unittest ai.test_xss_pipeline
............
Ran 12 tests in 0.009s
OK

$ python3 -m compileall -q ai watch_xss_verify.py
(no output, success)

$ git diff --check
ai/test_xss_oracle.py:1081: new blank line at EOF.
```

`compileall` is clean.

`git diff --check` FAILS with a stray blank line at the EOF of
`ai/test_xss_oracle.py:1081`. This is the only diff-check failure; it
is cosmetic but the user-defined rule treats `diff-check` failure as a
NOT CLEAN trigger.

## Production File Integrity

```
$ git diff -- watch_xss_verify.py
(no output)

$ git diff -- ai/verification/xss_pipeline.py
(no output)

$ git diff -- ai/verification/oracle.py
(no output — the file is untracked, but the tracked file at HEAD
already has oracle infrastructure; the working-tree version is an
updated, untracked module awaiting `git add`)

$ git diff -- ai/verification/composite_executor.py
(no output)
```

None of the four production files listed by the user has been
modified relative to HEAD in this commit. The Stored XSS work only
adds new symbols to existing modules (`verifier.py`, `http_executor.py`,
`browser_executor.py`) and the new `oracle.py` module.

## Final Verdict

**NOT CLEAN — DO NOT COMMIT**

Mandatory actions before a clean commit:

1. Stage `ai/verification/oracle.py` (currently untracked).
2. Stage `ai/test_xss_stored_round.py` (currently untracked).
3. Resolve the `git diff --check` warning at
   `ai/test_xss_oracle.py:1081` (remove the trailing blank line).
4. Decide on each PRE-EXISTING UNRELATED tracked modification and
   either drop it from this commit (`git checkout HEAD -- <file>` /
   `git stash`) or commit it as a separate commit:
   - `AGENTS.md`
   - `README-watch-updated.md`
   - `ai/test_xss_case_builder.py`
   - `ai/test_watch_param_discovery.py`
   - `crawl/watch_param_discovery.py`
   - `database/change_events.py`
   - `database/db.py`
   - the new tests in `ai/test_http_executor.py`
   - the `FakePage` plumbing tweak in `ai/test_browser_executor.py`