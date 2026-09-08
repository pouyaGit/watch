# XSS Execution-Oracle Implementation Report

**Repository:** `/opt/watch`
**Branch:** `main` (HEAD `a3ad8c1`)
**Task:** Implement ONLY the execution-oracle infrastructure defined by
`/opt/watch/xss-oracle-design.md` (verdict: READY FOR ORACLE IMPLEMENTATION).
**Date:** 2026-09-02

## Implementation Verdict

**ORACLE INFRASTRUCTURE IMPLEMENTED** — trusted, deterministic, and verified.

FULL XSS CONFIRMATION IS **NOT** IMPLEMENTED. This task built the primitives
(seed/value transform, planner, evidence schemas, E1/E2/E3 evidence
predicates, anti-harvest validation, run-salt binding) and left them as
**isolated, not yet wired into final classification**. Global verdict
behaviour (POTENTIAL / CONFIRMED / INCONCLUSIVE / NOT_VULNERABLE) is
unchanged; `ai/verification/verifier.py` has an empty diff.

---

## Files changed

### New files
- `ai/verification/oracle.py` (566 lines) — trusted oracle primitives.
- `ai/test_xss_oracle.py` (628 lines) — oracle infrastructure tests.

### Modified files (only oracle-related additions)
- `ai/schemas/xss_verification.py` (+90) — new evidence schemas + attempt/evidence
  oracle fields.
- `ai/verification/browser_executor.py` (+92) — executor-owned dialog,
  network-oracle, and eval instrumentation; records intended/actual URL.
- `ai/verification/http_executor.py` (+6) — records intended/actual request URL
  (redirect info preserved, never destroyed).

### Explicitly NOT modified
- `ai/verification/verifier.py` — empty diff. No verdict logic touched.
- `ns/`, `crawl/` (other than pre-existing unrelated work), `database/`,
  Nuclei/CVE — untouched by this task.

> Note: `git status` shows many pre-existing modifications from other work
> (e.g. `README-watch-updated.md` D, `database/`, `crawl/`,
> `tests/test_*.py`, `wordlists/`, design `.md` files). These predate this
> task and were left intact.

---

## Schema changes

All new/optional fields are backward compatible (empty defaults / `None`).

New classes in `ai/schemas/xss_verification.py`:
- `DialogEvent` — `kind`, `message`, `timestamp`. First-class E1 dialog evidence.
- `NetworkOracleEvent` — `url`, `path`, `method`, `resource_type`,
  `is_navigation`, `timestamp`. First-class E2 network evidence.
- `EvalInvocation` — `operator`, `value`, `timestamp`. First-class E3 eval evidence.

`VerificationAttempt` additions (all `None` by default):
- `oracle_seed: str | None`
- `oracle_value: str | None`
- `oracle_version: int | None`

`VerificationEvidence` additions (all `default_factory=list` / `None`):
- `dialog_events: list[DialogEvent]`
- `oracle_network_events: list[NetworkOracleEvent]`
- `eval_invocations: list[EvalInvocation]`
- `intended_request_url: str | None`
- `actual_request_url: str | None`

Also updated `__all__` with the three new event classes.

---

## Oracle generation

### Seed (S)
```
S = sha256(run_salt || attempt_id || phase)[:16]
```
where `||` is NUL-joined canonical concatenation
(`f"{run_salt}\x00{attempt_id}\x00{phase}"`). Rendered as exactly 32 lowercase
hex characters. NUL-joining prevents field-boundary aliasing
(`("a","bc") != ("ab","c")`). The run salt participates in the derivation.

### Oracle value (W / D)
```
h1 = fnv1a32(S)
h2 = fnv1a32(hex8(h1) + ":" + S)
D  = hex8(h1) + hex8(h2)      # exactly 16 lowercase hex chars
```
FNV-1a 32-bit over UTF-16 code units (matching JS `charCodeAt`), 32-bit
wrap-around multiply (`& 0xFFFFFFFF`), `hex8` is exactly 8 zero-padded
lowercase hex digits so `D` is always exactly 16 characters.

### Python W(S)
`fnv1a32` in `ai/verification/oracle.py` walks UTF-16 code units and applies
`((h ^ unit) * 0x01000193) & 0xFFFFFFFF`.

### JavaScript W(S)
`JS_W_SOURCE` (in `oracle.py`) uses `Math.imul(...)` and `>>> 0` only:
```
var s='<SEED>',a=2166136261,b=2166136261,i,t;
for(i=0;i<s.length;i++)a=Math.imul(a^s.charCodeAt(i),16777619)>>>0;
t=('00000000'+a.toString(16)).slice(-8)+':'+s;
for(i=0;i<t.length;i++)b=Math.imul(b^t.charCodeAt(i),16777619)>>>0;
var d=('00000000'+a.toString(16)).slice(-8)+('00000000'+b.toString(16)).slice(-8);
```
Pure JS, no `crypto.subtle`, no cryptographic hash in the runtime payload. W is
a deterministic execution oracle, **not** a cryptographic PRF (design §7).

### Cross-language vectors
`JavaScriptEquivalenceTests` validates Python vs. live Node.js
(node v24.20.0 was available). The 12 vector seeds: empty string, short ASCII
(`a`), 32-char hex seed (`0`*32), all-max hex (`f`*32), repeated chars
(`ab`*16), boundary ASCII (`\x01\x02\x7f`), `the quick brown fox`, and
deterministic hex vectors `e5f3a1`, `00ff10ee`, `deadbeef`, `9f8e7d6c5b4a`,
`1234567890abcdef1234567890abcdef`. Both `test_python_matches_javascript` and
`test_embedded_js_source_matches_python` passed. **No skips.**

## Seed generation

Trusted Watch code only. `oracle_seed(run_salt, attempt_id, phase)` is
deterministic and NUL-domain-separated. The LLM cannot generate S/D/W/oracle
payload/marker because the planner owns all of it (see below). Tests confirm
different attempts, phases, and run salts produce different seeds, and the
NUL boundary cannot alias distinct field tuples.

## Trusted planner

`OraclePlanner.plan(...)` is deterministic and consumes:
`context_type`, `case_id`, `attempt_id`, `logical_pair_id`, `run_salt`, `phase`,
optional `delivery_pattern` (attribution only), optional `max_payload_length`,
`network_oracle` flag.

The planner owns S, D, W, the snippet, the composed payload, and metadata. The
LLM's `delivery_pattern` is recorded for attribution but **never executed and
never allowed to alter the seed/value/snippet/expected oracle** — verified by
`test_llm_pattern_cannot_control_oracle` (a hostile pattern changes nothing and
is not present in the payload).

The planner performs its own anti-harvest self-check (seed exactly once in
payload; D absent) before returning.

## Supported contexts

Canonical planner-owned skeletons (compact, not the long design example):
- `html_body`   → `<img src=x onerror="{snippet}">`
- `html_attribute` → `<img src=x onerror="{snippet}">`
- `script_block` → `<script>{snippet}</script>`
- `generic`     → `<script>{snippet}</script>` (safe generic executable context)

Unsupported contexts (e.g. `url`) are returned with `supported=False`,
`reason="unsupported_context"`, empty payload, and a populated
`unsupported_reason` — never silently treated as supported.
`html_body`/`html_attribute` additionally reject the plan if the snippet
contained a double quote (it cannot: all snippet strings are single-quoted).

---

## E1 — Dialog oracle

- Schema: `DialogEvent(kind, message, timestamp)`.
- Transport: executor-owned Playwright `dialog` listener (page JS cannot inject
  fake dialog events).
- Predicate `evaluate_e1_dialog`: `kind in {alert, confirm, prompt}` **AND**
  `message == D` (exact full-string equality).
- Verified failures: D+suffix, D+prefix, whitespace-padded D, D-as-substring,
  wrong case, and S.

## E2 — Network oracle

- Oracle request path: `/.watch-oracle/<D>`.
- Payload action: `new Image().src='/.watch-oracle/'+d;` (page-initiated,
  non-navigation, same-origin; a 404 response is fine — the attempt is the
  signal).
- Predicate `evaluate_e2_network`: path percent-decoded once then compared
  exactly to `/.watch-oracle/<D>`; single path segment; query string excluded
  from matching; same-origin only; navigation or cross-origin never matches.
- No external/OOB canary. No raw S or raw marker in the oracle path.
- Schema `NetworkOracleEvent` records the raw URL; `evidence`
  `intended_request_url` vs `actual_request_url` distinguishes intended vs.
  final URL, preserving redirect information.

## E3 — Eval oracle

- Schema: `EvalInvocation(operator, value, timestamp)`.
- Predicate `evaluate_e3_eval`: exact recorded `value == P` for operators in
  `{eval, "setTimeout:string"}` AND `len(P) <= 240`.
- If `P > 240` E3 is **disabled** (returns `False`), never approximated by
  prefix compare. Boundary 240 enabled.
- `new Function` is **unsupported in v1** (no instrumentation hook); documented
  as v1.1.

---

## Anti-harvest enforcement

`anti_harvest_violations(...)` independently re-derives whether D occurs in any
of: payload, bound_input, intended URL, actual request URL, request body,
response snippet, referrer-derived strings, and any provided pre-execution
inputs. It also enforces seed validity, D validity, and that S appears exactly
once in the payload. It returns violation codes (empty = invariant holds) and
never trusts planner metadata.

`validate_oracle_pair` enforces: S exactly 32 lowercase hex, D exactly 16
lowercase hex, `D == W(S)`, and `D != S`.

Invariant: S MAY appear on the wire (inside the payload body), D MUST NOT
appear anywhere on the wire. This is enforced by the planner self-check and
independently by the test/verifier layers.

## Run-salt / replay behavior

- `RunSaltReplayTests` proves `run A != run B` yields different S and D for the
  same attempt identity, and that an old D is rejected against a new run's
  seed (`validate_oracle_pair` raises).
- Note: this is **anti-replay / run-binding infrastructure only** — the
  implementation makes no cryptographic anti-forgery claim.

---

## Tests executed

All commands run from `/opt/watch` (Python 3.12.3, node v24.20.0).

| Suite | Result |
|---|---|
| `ai.test_xss_oracle` (focused oracle) | **46 OK** (0.135s), no skips; JS equivalence ran under node |
| `ai.test_xss_verification` | **84 OK** |
| `ai.test_knowledge_store` | **15 OK** |
| `ai.test_xss_researcher` | **12 OK** |
| `ai.test_xss_llm_researcher` | **36 OK** |
| `ai.test_openrouter` | **26 OK** |
| `ai.test_http_executor` | **58 OK** |
| `ai.test_composite_executor` | **14 OK** |
| `ai.test_xss_case_builder` | **47 OK** |
| `ai.test_browser_executor` (real Chromium, local server) | **54 OK** |
| `ai.test_browser_executor_smoke` (real Chromium, local server) | **12 OK** |

Non-unit checks:
- `python -m py_compile` on `oracle.py`, `test_xss_oracle.py`,
  `xss_verification.py`, `browser_executor.py`, `http_executor.py`: **OK**.
- `git diff --check`: **OK** (no whitespace errors).

## Skipped / unavailable tests

- **JS/Python equivalence: ran** — node v24.20.0 present, `_HAS_NODE = True`,
  all Node-based vector tests executed. None skipped.
- **Linters:** no `ruff`/`mypy`/`flake8`/`black` binaries and no
  `pyproject.toml`/`setup.cfg`/`.flake8`/`tox.ini` exist in the repo, so no
  project-configured type/lint gate could be run. Syntax check via
  `py_compile` was used instead.
- **Browser/executor tests:** all ran successfully against real Chromium
  (Playwright present, `chromium-1234` / `chromium_headless_shell-1234`
  cached); pages were served from a local in-process HTTP server bound to
  `127.0.0.1` — nothing touched the public internet.

## Limitations

- W is a deterministic execution oracle, **not** a cryptographic PRF; the
  guarantee is non-reproduction by copy/echo classes, not cryptographic
  unforgeability. A Watch-aware adversarial page can still synthesize D (design
  A4) and is locally indistinguishable from execution.
- `new Function` eval hooks are not present in v1; E3 is disabled for that
  operator (documented v1.1).
- Payloads > 240 chars lose E3 (E1/E2 unaffected; never weakened to prefix).
- CSP-blocked execution yields no oracle → conservative (INCONCLUSIVE in the
  future state machine).
- The observation window bound (existing) may miss very delayed execution.
- The `url` context is explicitly unsupported.

## Deviations from `xss-oracle-design.md`

- **Compact planner skeletons** used instead of the long design example; the
  inline snippet is functionally identical to W(S) but shorter (explicitly
  permitted by the brief: "Do NOT blindly copy the long example ... if a
  shorter equivalent is possible").
- **Seed hashing uses NUL-joined concatenation** `run_salt \x00 attempt_id
  \x00 phase` — a canonical realization of `run_salt ‖ attempt_id ‖ phase`
  that prevents boundary aliasing; documented and tested.
- `generic` context mapped to the `<script>` skeleton as a safe generic
  executable context.
- E3 operator canonical name recorded as `"setTimeout:string"`.
- `e3_enabled` tracked explicitly on `OraclePlan`.

## Integration points intentionally left for the next task

- Wire `evaluate_e1_dialog` / `evaluate_e2_network` / `evaluate_e3_eval` into
  `XSSVerifier._classify` to promote evidence stages to verdicts; the
  predicates are deliberately isolated and not yet connected.
- Full confirmation state machine (S4/S5 stage mapping, confidence scoring).
- Stored XSS SUBMIT → READ round protocol (explicitly out of scope here).
- Mutation XSS redesign (explicitly out of scope).
- `new Function` eval-hook instrumentation (v1.1).

---

## Git diff / status summary

`git diff --stat` for this task's oracle-related changes (a subset of the
working tree):
```
 ai/schemas/xss_verification.py      |  90 +++++
 ai/verification/browser_executor.py |  92 +++++
 ai/verification/http_executor.py    |   6 +-
```
Untracked (task deliverables): `ai/verification/oracle.py`,
`ai/test_xss_oracle.py`, and this report. Pre-existing unrelated
modifications remain untouched (`README-watch-updated.md` D, `database/`,
`crawl/watch_param_discovery.py`, `ai/test_http_executor.py`,
`ai/test_watch_param_discovery.py`, `ai/test_xss_case_builder.py`,
`tests/test_*.py`, `wordlists/`, design `.md` files).

`git diff --check`: **OK**.
No commits or pushes were made.
