# Phase 5K-live B4 — Close Live-Egress Security Blockers

**STAGE:** Phase 5K-live B4 — Close B1/B2/B3 + H1/H2 (implementation + offline verification)
**Date (UTC):** 2026-09-07
**Acceptance criteria:** `agent-reports/phase-5k-live-b3-security-review.md` §16
**Verdict on implementation quality: GO** (real egress must remain disabled regardless)

---

## 1. Verdict

**GO** — all five acceptance-criteria items are implemented and verified
offline, and the lane remains fail-closed with live egress still disabled.

- B1 REDIRECT: **FIXED**
- B2 DNS PINNING: **FIXED**
- B3 EGRESS BOUNDARY: **FIXED**
- H1 REDACTION: **FIXED**
- H2 CANONICALIZATION: **FIXED**

`LIVE_NUCLEI = False` (frozen literal) is untouched; `LiveNucleiRunner` and
`B3NetnsNucleiRunner` still raise `NUCLEI_EXECUTION_BLOCKED` before any
process primitive; `WATCH_AI_LIVE_VALIDATION=false` remains the default.
No live egress gate was opened.

---

## 2. Files changed

| File | Change |
|------|--------|
| `ai/live_validation/lane.py` | H2 shared canonicalization (Gate 2 authz/scope); B2 address validation in `_build_resolution`; B3 egress gate (Gate 6b); removed hardcoded `host_kind="dns"` |
| `ai/execution/nuclei_executor.py` | B1 `-no-redirects`; B3 `-disable-interactsh` in `build_nuclei_argv` |
| `ai/evidence/scrubber.py` | H1 added secret/credential/cookie/token redaction patterns |
| `ai/test_live_validation.py` | Added B4 test classes (33 new tests) |
| `ai/test_nuclei_executor.py` | Updated `test_exact_argv_shape` to reflect new frozen argv |

No production network/DNS/subprocess/Nuclei was executed, enabled, or
touched. No git commit/stage/push; working tree left for the next review.

---

## 3. B1 fix (redirect containment)

**Problem (BLOCKER):** Nuclei followed HTTP redirects internally with no
re-authorization/re-scope/re-resolution; the lane only ever evaluated the
initial target (`evaluate`, never `evaluate_chain`).

**Fix:** the plain `-no-redirects` flag is now pinned in the frozen argv
(`ai/execution/nuclei_executor.py` `build_nuclei_argv`). With redirects
disabled, an authorized target's `Location:` response can never become a
new network destination — the security invariant ("authorized target's
Location MUST NOT automatically become another network destination") holds.
For CVE-2026-1557 the intended behavior is a **single GET with redirects
disabled**, which this enforces structurally.

The fallback re-scope option (`evaluate_chain` + `require_fresh_scope_for_redirect`)
was intentionally NOT wired because redirects are now disabled at argv level;
the B3 redirect machinery remains available if a future CVE requires it.

Verified: no `-max-redirects`, `-disable-redirects` ambiguity — the frozen
argv now includes `-no-redirects` and tests assert its presence.

---

## 4. B2 fix (DNS pinning / anti-rebinding)

**Problem (BLOCKER):** the lane hand-built a `TargetResolution` from a
static `dns_mapping`/default `8.8.8.8` with hardcoded `host_kind="dns"`,
`dns_source="live-validation-dns/v1"`, and never validated addresses; a
real Nuclei subprocess would resolve the hostname itself, ignoring the pin.

**Fix:** `_build_resolution` now passes every injected/anonymous address
through the shared `classify_address` (frozen 5C deny policy). Any private,
loopback, link-local, multicast, reserved, unspecified, metadata
(`169.254.169.254`), or malformed address — including IPv4-mapped IPv6
unfolded to an unsafe inner address — raises `DnsError` **inside the
address gate**, fail-closed, before the scope evaluator runs
(`_evaluate_scope` catches it and returns `SCOPE_DENIED: <closed-code>`).
Mixed safe/unsafe sets fail the whole set (no "first clean wins"). The
resulting `DialBinding` carries only validated, globally-routable
addresses with correct `sni_host`.

`host_kind` is now derived from `canonicalize_target` (not hardcoded `"dns"`),
and `dns_source` was renamed to the honest `"live-validation-address/v1"`.
Dial-by-IP (the transport proving the peer matches the pin) remains the
future live-runner's job; that runner is still a blocked placeholder, so
today no transport can re-resolve. The offline FakeNucleiRunner performs
zero network, so no answer can be polled at dial time.

---

## 5. B3 fix (Nuclei network boundary)

**Problem (BLOCKER):** unbounded Nuclei network behavior — no OOB
disable, no redirect bounds, no egress sandbox wiring.

**Fix (two layers):**

1. **Frozen argv containment** (`build_nuclei_argv`): `-disable-update-check`
   (already present) + **`-no-redirects`** (B1) + **`-disable-interactsh`**
   (OOB/callback prohibition). Combined with the existing `-silent`,
   `-no-color`, `-stats-interval 0`, `-json`, `-bulk-size 1`, `-timeout 5`,
   `-nc`, this closes update/redirect/OOB/secondary-request surfaces at the
   binary boundary. Retries and concurrency are already pinned (retries
   ceiling 0, `-bulk-size 1`).

2. **Lane egress gate (Gate 6b):** after scope approval and before any
   execution, every resolved address is checked via the existing
   `is_forbidden_destination` + `check_destination_allowed`
   (`ai/execution/b3_boundary.py`). Any forbidden/non-canonical destination
   blocks with `EGRESS_DENIED`/`EGRESS_FORBIDDEN`. No execution (not even
   the offline runner path) proceeds past an unapproved address. The
   existing `check_egress_dial`/`acquire_sandbox`/`assert_dial_matches_egress`
   are reused as available; the raising `B3NetnsNucleiRunner` was NOT
   unblocked (its exception remains the live sandbox gate).

Fail-closed: sandbox/egress-policy failure ⇒ no execution (bounded output,
wall under `nuclei_wall_seconds`).

---

## 6. H1 fix (evidence redaction)

**Problem (HIGH):** `scrub_text` only redacted operational-secret shapes
(URIs, bearer/basic, API keys) and left response-body credentials/cookies/
tokens/hostnames unredacted in `stdout_sample`/`stderr_sample`.

**Fix:** added deterministic patterns to `_SECRET_TEXT_PATTERNS`
(`ai/evidence/scrubber.py`) for: `Cookie:`/`Set-Cookie:` values,
`X-Api-Key:`/`api-key`/`api_key` values, `Authorization:` (incl. Bearer),
`{auth,access,refresh}_token`, `{session,password,secret,passwd}` values
(in both `key:value` and `key value` forms), and `DB_PASSWORD <val>` /
`db_password <val>` assignments.

**Evidence preservation verified:** the CVE's word-matcher tokens
(`[CVE-2026-1557]`, `DB_NAME`, `DB_PASSWORD`, status `200`/`403`,
`vulnerable`) survive intact — only *assignment* shapes
(`DB_PASSWORD secret123`, `password=...`, `token=...`) are redacted, so
detection evidence is preserved. Broad hostname redaction was deliberately
**not** attempted (per the B3 report guidance against destroying detection
evidence); a `Host: internal.corp` sample is logged verbatim, matching the
existing scrubber design. Output remains bounded by the existing per-stream
cap.

---

## 7. H2 fix (shared target canonicalization)

**Problem (HIGH):** Gate 2 used `urlparse`-only local helpers; userinfo was
silently stripped, unsupported schemes reached issuance, and malformed/
encoded/alternate-numeric forms were handled through downstream incidental
policy failures instead of an explicit canonical gate.

**Fix:** Gate 2 now calls a new `_parse_raw_target` wrapper that (1) rejects
`@` userinfo explicitly, (2) parses scheme/host/port, and (3) runs the
**shared `canonicalize_target`** (`ai/resolver/canonicalization.py`) for
scheme allowlist (http/https), hostname lowercase + trailing-dot strip +
IDNA, numeric-IP unfolding (decimal/hex/octal), IPv4-mapped IPv6 unfolding,
and port validation. `user:pass@`, `user@`, `ftp://`, `file://`, `data:`,
`javascript:`, out-of-range/zero ports, encoded separators
(`%2e`/`%40`), and missing hosts all fail `TARGET_INVALID`
(at Gate 2, before authorization). Authorization (`_issue_and_verify_authz`)
and scope (`_evaluate_scope`) reuse the same canonical output, so a target's
identity is fixed at Gate 2 and no alternate textual form later changes it.

---

## 8. Runtime authority flow (post-fix)

```
config (env gate, default false)
  ↓
target (shared canonicalize_target — H2; userinfo/unsupported rejected)
  ↓
candidate (CVE-2026-1557 pinned)
  ↓
template (pinned digest + safety/specificity)
  ↓
authorization (5B issue + verify)
  ↓
resolution (addresses validated via classify_address — B2)
  ↓
scope (5D ScopeEvaluator.evaluate)
  ↓
egress policy (B3 is_forbidden_destination / check_destination_allowed — B3)
  ↓
execution (5F execute_nuclei; live runner still blocked)
  ↓
evidence (scrub_text — H1; capped)
  ↓
deterministic verification (5I)
```

No network/DNS/dial happens before the required authorization and scope
gates. IP-literal and unsafe-address targets fail closed at scope/egress.

---

## 9. Network boundary (Nuclei argv)

Frozen argv (verified, `ai/execution/nuclei_executor.py`):

```
/usr/bin/nuclei -t <pinned template> -u <scheme://host[:port]>
  -disable-update-check -no-redirects -disable-interactsh
  -silent -no-color -stats-interval 0 -json -bulk-size 1
  -timeout 5 -nc
```

Controls: update **off** (`-disable-update-check`), redirect **off**
(`-no-redirects`), OOB/interactsh **off** (`-disable-interactsh`),
concurrency/count pinned (`-bulk-size 1`), timeout pinned (`-timeout 5`),
retries ceiling 0. Executable fixed (`SERVER_CONTROLLED_NUCLEI_BINARY`),
template pinned to scratch, argv structurally validated + digest-bound,
environment closed allowlist, `shell=False` (no shell construction; module
imports no process-creation facility). No caller- or LLM-controlled flags:
all flags come from the frozen builder, template supplies path/query/body
only.

---

## 10. DNS pinning (B2)

- Single-pass resolution: addresses are validated through the 5C deny
  policy (`classify_address`) at Gate 6, fail-closed on any unsafe/mixed/
  malformed/mapped answer.
- Preserved `DialBinding` with validated addresses + correct `sni_host`.
- No hostname is dialed today (offline FakeNucleiRunner, zero transport).
- A real live runner must dial the pinned addresses with SNI/Host preserved
  and abort on re-resolution mismatch (`verify_socket_peer`/
  `check_egress_dial`/`assert_dial_matches_egress`); that runner is still a
  blocked placeholder, so no re-resolution is possible today.

## 11. Redirect handling

- Redirects disabled at argv (`-no-redirects`); a redirect cannot become a
  second network request.
- The B3 redirect machinery (`check_redirect_target`,
  `require_fresh_scope_for_redirect`, `evaluate_chain`) is preserved and
  available; it is intentionally not enabled because redirects are off.

## 12. Nuclei argv

See §9. Bounds enforced at argv (redirect/OOB/update/count/timeout) plus
the B3 egress gate at the lane and the blocked live-runner boundary.

## 13. Resource limits

Enforcement is structural for the live lane's single-CVE intended behavior:
1 request, redirects off, OOB off, `-bulk-size 1`, `-timeout 5`, retries 0.
The frozen ceiling metadata in `ai/limits/ceilings.py` remains authoritative;
the wall/output accounting is enforced at the (still blocked) B3 boundary
and by the executor's `_observe_stream` cap. **Explicitly not claimed:** a
kernel-level cgroup/rlimit is not wired (no live runner exists to bind it);
that remains a documented future-B3-live-runner responsibility, not silently
"enforced."

## 14. Evidence redaction

See §6. Observation output is scrubbed via the enhanced `scrub_text` before
persistence; sensitive values are redacted; CVE/path/status evidence
preserved.

## 15. Canonicalization

See §7. Userinfo rejected; scheme/host/port canonicalized consistently;
unsupported schemes, malformed ports, missing hosts, encoded/alternate
numeric forms fail closed at Gate 2 before authorization. Downstream
re-checks (resolver canonicalization, 5D, executor binding) remain in place
as defense-in-depth.

## 16. Fail-closed guarantees

- Unsafe/private/loopback/metadata/mapped addresses → `SCOPE_DENIED`
  (address gate) and/or `EGRESS_DENIED` (egress gate) — no execution.
- Malformed/unsupported targets → `TARGET_INVALID` at Gate 2.
- Redirects → disabled at argv (no second request possible).
- OOB/update → disabled at argv.
- Live runners → `NUCLEI_EXECUTION_BLOCKED`; `LIVE_NUCLEI=False` frozen.
- Every security-control failure prevents execution; evidence-only
  inconclusive outcomes (`MATCH_UNVERIFIED`) carry no verdict.

## 17. Tests

**Focused:** `ai.test_live_validation` — 73 tests (40 prior + 33 new) OK.
New coverage:
- Canonicalization (H2): userinfo, trailing dot, casing, encoded
  separators, decimal/hex IP, IPv4-mapped IPv6, unsupported scheme,
  malformed port, missing host.
- DNS pinning (B2): safe resolution, private/loopback/link-local/metadata
  answers, mixed safe+unsafe, IPv4-mapped IPv6 loopback.
- Egress boundary (B3): global address passes, unsafe address blocks.
- Nuclei argv containment (B1/B3): `-no-redirects`, `-disable-interactsh`,
  `-disable-update-check`, fixed executable, no shell markers, bounded
  count/timeout.
- Evidence redaction (H1): Cookie, Set-Cookie, Authorization/Bearer,
  X-Api-Key, token, session, password, `DB_PASSWORD <val>` redacted; safe
  CVE evidence preserved.
- Fail-closed: dry-run never touches network.

## 18. Regressions

- `ai.test_nuclei_executor` `test_exact_argv_shape` updated to match the
  new frozen argv (expected change from the B1/B3 fixes). No other test
  required modification.
- **Affected regression (772 tests):** executor, resolver, scope, evidence,
  B3 boundary/validation, dial policy, execution authorization, reference
  canonicalization, research CLI — **OK (2 skipped, pre-existing)**.
- **AI/XSS regression (89 tests):** xss_researcher, openrouter,
  knowledge_store, xss_llm_researcher — **OK**.
- **Pre-existing failures (not introduced, documented in B3 report I2):**
  `ai.test_nuclei_cve_2026_1557_dryrun::test_template_content_is_safe_and_grounded`
  ("version" string in research template description prose) and
  `ai.test_nuclei_offline_prepare` — both stem from unchanged research-track
  artifacts in the working tree, outside B4 scope.

## 19. Remaining observations (not blockers for offline review)

- Dial-by-IP / kernel rlimit enforcement is deferred to the future live
  B3-boundary runner (still blocked). Not silent-enforced today.
- Broad hostname redaction intentionally not added (would destroy detection
  evidence); `Host: internal...` samples pass through as informational.
- IP-literal non-DNS targets remain scope-denied by the single-host
  explicit policy (consistent with prior fail-closed behavior).
- The B3 review's M1/M3 (operator-trust documentation, authz expiry) are
  unchanged process/documented items, not gate failures.

## 20. Explicit confirmations

- **No real target or network was contacted.** All tests and verification
  used fakes/in-memory stores/pure local parsing. No DNS, no subprocess,
  no Nuclei invocation, no sockets.
- **Live egress remains disabled.** `LIVE_NUCLEI=False` frozen,
  `LiveNucleiRunner`/`B3NetnsNucleiRunner` still raise
  `NUCLEI_EXECUTION_BLOCKED`, `WATCH_AI_LIVE_VALIDATION=false` default.
- No authoritative finding, no 5J invocation, no alert emitted.
- No git commit/stage/push; working tree preserved for the next security
  review.
