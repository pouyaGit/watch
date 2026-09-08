# Phase 5K-live B5 — Post-Fix Security Review

**STAGE:** Phase 5K-live B5 — Post-Fix Security Review (REVIEW-ONLY)
**Date (UTC):** 2026-09-07
**Scope:** Re-verification of B4 fixes against B3 findings (B1/B2/B3/H1/H2):
`ai/live_validation/lane.py`, `ai/execution/nuclei_executor.py`,
`ai/evidence/scrubber.py`, `ai/resolver/canonicalization.py`,
`ai/resolver/dns.py`, `ai/execution/b3_boundary.py`,
`ai/execution/egress_guard.py`, `ai/limits/ceilings.py`, plus test
suites `ai.test_live_validation`, `ai.test_nuclei_executor`,
`ai.test_b3_boundary`, `ai.test_evidence_core`.
**Method:** Static code tracing + offline adversarial input matrix only.
Explicitly stated: **no live network traffic was generated** — no DNS
lookups against external targets, no Nuclei invocation against any
target, no browser execution, no LLM/provider calls, no MongoDB
modification. The Nuclei binary is not even present in this environment
(`/usr/bin/nuclei` does not exist), so flag-honoring could not be
executed even had execution been permitted.
**Verdict: NO-GO for real live egress.**

---

## Scope

Exactly what was reviewed:

1. B4's B1 claim: `-no-redirects` pinned in frozen argv.
2. B4's B2 claim: `classify_address` validation of injected addresses in
   `_build_resolution`, honest `dns_source`, derived `host_kind`.
3. B4's B3 claim: `-disable-interactsh` pinned + Gate 6b egress check
   (`is_forbidden_destination` / `check_destination_allowed`).
4. B4's H1 claim: extended `_SECRET_TEXT_PATTERNS` in scrubber.
5. B4's H2 claim: `_parse_raw_target` wrapper over shared
   `canonicalize_target` at Gate 2 with explicit userinfo rejection.
6. Cross-cutting: fail-closed behavior, caller authority, authz expiry,
   proxy bypass, TLS boundary, subprocess boundary, evidence identity.
7. Offline test suites listed above (existing tests only; no tests
   added or modified).

Production working-tree modifications pre-existing this review (e.g.
`M ai/config.py`, `M ai/research_cli.py`, among ~31 files shown by
`git status`) were left untouched. No source file was modified by this
review.

---

## Method

Static code tracing + offline tests only. Explicitly stated: **no live
network traffic was generated.** Dynamic evidence is limited to:

- `python3 -m unittest ai.test_live_validation` → 73 tests OK.
- `python3 -m unittest ai.test_nuclei_executor ai.test_b3_boundary
  ai.test_evidence_core` → 264 tests OK.
- Pure-local `python3 -c` adversarial matrices against `scrub_text`
  and `_parse_raw_target` (no sockets, no DNS, no subprocess).
- Line-level reads of the files listed in Scope. No Nuclei process was
  spawned (no binary exists), no external DNS was queried, no LLM or
  browser was invoked, no database was touched.

---

## B3 Findings Reassessment

### B1 — Redirect scope bypass

**Status: PARTIALLY CLOSED**

**Evidence:**

- `ai/execution/nuclei_executor.py:755-774` (`build_nuclei_argv`):
  frozen argv now contains `-no-redirects` (line 762) alongside
  `-disable-update-check`, `-disable-interactsh`, `-silent`,
  `-no-color`, `-stats-interval 0`, `-json`, `-bulk-size 1`,
  `-timeout 5`, `-nc`. Test `test_interactsh_oob_disabled_flag_present`
  and argv-shape tests assert presence
  (`ai/test_live_validation.py:735-757`,
  `ai/test_nuclei_executor.py:887-892`).
- No other execution path can follow redirects: `FakeNucleiRunner`
  performs no transport (`nuclei_executor.py:845-887`);
  `LiveNucleiRunner.launch` and `B3NetnsNucleiRunner.launch` raise
  `NUCLEI_EXECUTION_BLOCKED` unconditionally (lines 890-918); the
  5F template gate denies `redirects`/`max-redirects` template keys
  (lines 276-277); the lane never calls `evaluate_chain` because with
  redirects disabled there is no second hop to evaluate.
- Environment is closed (`build_nuclei_environment`, lines 790-811:
  `HOME/LANG/LC_ALL/PATH/TMPDIR` only), so no proxy/redirect-shaping
  environment reaches the subprocess. No `shell=True`, no shell
  interpolation, fixed binary `/usr/bin/nuclei`.
- Redirect `Location` headers therefore cannot become a new network
  destination **provided the flag is honored** — and the runner is
  still blocked, so today nothing dials at all.

**Why not CLOSED:**

- **Flag validity is unproven.** No pinned Nuclei version exists
  anywhere in the repository (no version pin in `requirements.txt`,
  no `NUCLEI_VERSION` constant, no vendored binary; `/usr/bin/nuclei`
  absent). The string `-no-redirects` appears only in
  `ai/execution/nuclei_executor.py` and its tests. Per the task
  instruction, presence of the argument is not proof it is honored by
  the Nuclei version this project will actually run. Unknown/renamed
  flags are silently ignored by many CLI tools — an unhonored flag
  would silently restore the B3-era redirect-following behavior.
- **No per-hop re-scope wiring exists as fallback.**
  `ScopeEvaluator.evaluate_chain` / `require_fresh_scope_for_redirect`
  remain unwired to the lane (intentionally, per B4). If the flag is
  ever unhonored, there is no second line of defense.

**Residual Risk:** A Nuclei version that does not recognize
`-no-redirects` (or recognizes it with different semantics, e.g.
only for SeClore-style redirectors) would follow a hostile
`Location:` to another hostname / IP / localhost / metadata address /
alternate scheme with no re-authorization.

**Required Action:** Pin the exact Nuclei version, cite its
documentation/source proving `-no-redirects` disables all redirect
following for the template type used, and add a startup version
assertion (fail closed on mismatch) — or wire observed-hop
re-scoping (`evaluate_chain` + fresh resolution + egress policy) as
defense in depth — before real egress.

---

### B2 — DNS bypass / rebinding

**Status: PARTIALLY CLOSED** (offline validation boundary only;
proven live boundary: **absent**)

**Evidence:**

- `ai/live_validation/lane.py:573-594` (`_build_resolution`): every
  injected address now passes through shared `classify_address`
  (`ai/resolver/dns.py:167-204`, frozen deny policy: private,
  loopback, link-local, multicast, reserved, unspecified, non-global,
  `%`-scoped, IPv4-mapped unfolded to inner address). Any unsafe entry
  raises `DnsError`, caught in `_evaluate_scope` (lane.py:559-561) as
  `SCOPE_DENIED` — mixed safe/unsafe sets fail the whole set (raise on
  first unsafe entry, no "first clean wins"). Verified by B4 tests
  (private/loopback/link-local/metadata/mapped-loopback denials).
- `host_kind` is now derived from `canonicalize_target`
  (lane.py:595-596), removing the hardcoded `"dns"` incoherence.
- `dns_source` renamed to the honest `"live-validation-address/v1"`
  (lane.py:629) — no longer misrepresents provenance.
- Gate 6b (lane.py:324-342) re-checks every resolved address via
  `is_forbidden_destination` + `check_destination_allowed`
  (`ai/execution/b3_boundary.py:255-292`).
- Today no transport can re-resolve: `FakeNucleiRunner` performs zero
  network; both live runners raise before any process primitive.

**Why not CLOSED for real live execution:**

- The lane still builds `TargetResolution` from `dns_mapping`/default
  `8.8.8.8` (lane.py:543-545). It never instantiates `TargetResolver`,
  never calls `FakeDnsResolver`/`ProductionAddressSource`, and never
  calls `validate_answers` — so the `dns_answers` ceiling (8) and
  deterministic ordering are unenforced on this path, and empty-list
  input relies on Gate 6b / executor binding rather than an explicit
  resolution failure.
- **No transport-level IP pinning exists.** `build_nuclei_argv` passes
  `scheme://canonical_host[:port]` — the hostname
  (`nuclei_executor.py:718-733`, lane Gate 7). A real Nuclei
  subprocess resolves that hostname through system DNS at dial time
  via libc/Go resolver, `/etc/hosts`, resolver config, or proxy
  settings, completely bypassing `resolved_addresses`/`DialBinding`.
  `LiveSocketFactory`, `verify_socket_peer`, `check_egress_dial`, and
  `assert_dial_matches_egress` remain unwired to this lane.
- `LiveNucleiRunner` remains blocked (verified true,
  `nuclei_executor.py:890-902`) — which is exactly why no peer proof
  exists: there is no live runner to prove anything about.
- Host/SNI preservation under eventual dial-by-IP, certificate
  verification against the authorized identity, and rebinding defense
  (safe-at-authorize → attacker flips DNS to `127.0.0.1`/metadata with
  short TTL) are all undesigned-on-this-path, not merely untested.
- IPv4/IPv6/mapped forms are consistently *classified* (good), but
  consistency of classification is not consistency of dialing — the
  dialer is Nuclei's internal resolver, unobserved.

**Classification:** current state is an **offline validation
boundary** (injected-address hygiene, fail-closed). It is not a
**proven live boundary**. The planned live boundary (dial-by-IP +
peer proof) remains future work, exactly as B4 states.

**Residual Risk:** Under real egress, an authorized hostname resolving
safe at Gate 6 can resolve private/loopback/metadata at dial time
(SSRF, cloud-metadata access); classic DNS rebinding between
authorization and connection has no TTL-pinning, single-resolution, or
peer-verification defense on this path.

**Required Action:** Resolve once per execution through the reviewed
address source + `validate_answers`; dial IP literals only with
SNI/Host preserved; abort on any re-resolution/peer mismatch
(`verify_socket_peer` / `check_egress_dial` /
`assert_dial_matches_egress`); stamp the real resolver identity; add
rebinding tests (safe-at-validate → private-at-dial, TTL flip,
mixed sets, mapped IPv6). Re-review before egress.

---

### B3 — Nuclei network behavior

**Status: PARTIALLY CLOSED**

**Evidence (verified in code):**

- A) Updates: `-disable-update-check` pinned (argv line 761). No other
  update mechanism exists in `nuclei_executor.py` (no template fetch,
  no second binary invocation on the lane path).
- B) OOB: `-disable-interactsh` pinned (line 763); 5F gate denies
  `interactsh/oast/oastify/callback/workflows/fuzz/extractors`
  template keys (lines 249-284); pinned CVE-2026-1557 template contains
  no OOB markers.
- C) Redirects: see B1.
- D) Concurrency: `-bulk-size 1` pinned (lines 769-770);
  `nuclei_concurrency` ceiling is 1 (`ceilings.py:57`); single pinned
  template, single `-u` target.
- E) Retries: **see gap N1 below** — no `-retries`/`-retry` flag in
  argv; "retries 0" is `ceilings.py:59` metadata only.
- F) Timeouts/resources: `-timeout 5` pinned (lines 771-772);
  `_observe_stream` caps each stream at 1 MiB, fail-closed with
  `SUBPROCESS_OUTPUT_LIMIT` (lines 1124-1140); `ResourceLimitsSpec` /
  `default_resource_limits` record wall 120 s / CPU 60 s / mem
  512 MiB / fd 64 / proc 1 (lines 646-681) — **metadata only** (the
  docstring states "No active enforcement lives here: enforcement
  belongs to the future B3 boundary").
- G) Egress: Gate 6b checks every resolved address
  (`is_forbidden_destination` + `check_destination_allowed`);
  `B3NetnsNucleiRunner` still raises `NUCLEI_EXECUTION_BLOCKED`
  (lines 905-918) — sandbox shape documented, not active. No
  netns/veth/nftables/cgroup/seccomp/rlimit is created or enforced by
  the lane.
- H) Environment: closed allowlist, no `HTTP_PROXY/HTTPS_PROXY/
  ALL_PROXY/NO_PROXY`/CA/resolver inheritance possible through the
  spec (`build_nuclei_environment`). The lane/escalation path never
  passes caller environment.
- I) Templates: 5F deny-list + `NucleiTemplateContent(extra="forbid")`
  + executor-time `_revalidate_artifact` (hash + identity + safety
  recheck) confine the template to one GET exchange; arbitrary
  templates cannot reach the lane (pinned candidate digest).

**Why not CLOSED:**

- CLI flags are version-dependent (same version-pin gap as B1) for
  `-disable-interactsh` / `-disable-update-check`.
- Kernel-level enforcement (cgroup/rlimit/seccomp/netns/firewall),
  wall-time kill, request/redirect counters against
  `requests_per_execution = 7` / `redirect_hops = 5`, and child-process
  / fd accounting are recorded but not wired to any runner that can
  execute.
- Secondary requests outside the target exchange (TLS OCSP/CRL,
  Nuclei-internal telemetry despite the flag on some versions,
  favicon/conditional follow-ups) have no accounting on this path.
- "Runner exists but remains blocked" is correctly **not** counted as
  containment — B4 does not claim otherwise.

**Residual Risk:** Bounded **if and only if** the pinned Nuclei
version honors every flag **and** the future sandbox enforces the
recorded ceilings. Neither is true today.

**Required Action:** Pin Nuclei version + prove each flag;
add `-retries 0` (or equivalent) to the frozen argv or prove the
default is zero for the pinned version; wire wall-time kill,
rlimit/cgroup, request counters, and the netns/egress sandbox into
the real runner; account every socket against ceilings. Re-review.

---

### H1 — Evidence redaction

**Status: PARTIALLY CLOSED**

**Evidence:**

- `_SECRET_TEXT_PATTERNS` (`ai/evidence/scrubber.py:98-117`) now
  covers: `Cookie:`/`Set-Cookie:` values, `X-Api-Key:`/`api-key`
  values, `Authorization:` incl. Bearer/Basic, `{auth,access,refresh}
  _token/key`, `{session,password,secret,passwd}` in `key=value` and
  `key: value` forms, `session_id/key/token`, `DB_PASSWORD <val>` /
  `db_password <val>` assignments, plus pre-existing URI/private-key/
  AKIA/GitHub-token/Stripe shapes.
- Adversarial probe (offline `scrub_text`, this review) confirms
  redaction of: `Cookie:`, `Authorization: Bearer/Basic`, `X-Api-Key:`,
  `token=`/`password:`/`passwd=`/`api_key=` (any case), `session:`/
  `sessionid=`, `DB_PASSWORD secret`, `?password=`/`?token=` query
  echoes, `mongodb://`, private-key blocks.
- Redaction occurs in `_observe_stream` (scrub → cap → hash → store;
  `nuclei_executor.py:1124-1140`) before `NucleiObservation`/
  `EvidenceBuilder.seal` persistence. Both stdout and stderr flow
  through `_observe_stream`. `ExecutorError` details are bounded
  200 chars, single-line, secret-screened. Subprocess command lines
  carry no secrets (fixed binary + pinned template path + canonical
  target only). Environment values cannot enter evidence (closed env,
  no secret inputs on this lane: pinned template headers `{}`).
- Intentional exception confirmed: internal target hostnames
  (`Host: internal.corp.local`) pass through verbatim — by design
  (detection evidence preservation), not an oversight.

**False negatives found (exact, reproduced offline):**

1. **JSON credential shapes pass through verbatim** —
   `{"password": "hunter2"}`, `{"api_key": "AAAA"}`,
   `{"token":"abcdef"}` are NOT redacted (patterns require
   `key[:= ]value` with no quote/colon-JSON handling). This matters:
   Nuclei `-json` output **is JSON**, so response-extracted fields in
   exactly this shape are the likely carrier.
2. `DB_PASS=` / `SECRET_KEY=` / `client_secret=` / `credential=` are
   NOT matched (patterns cover `password|passwd|secret` as whole-key
   alternatives but not `secret_key`, `client_secret`, `db_pass`,
   or `credential` stems).
3. `#fragment` carriers (`#fragtoken=abc`) are NOT redacted; only
   `?query` forms are.
4. Multi-value `Cookie: a=1; b=2` redacts only the first value
   (`[REDACTED]; b=2`); `Set-Cookie:` leaves a `Set-` prefix artifact
   (`Set-[REDACTED]`) — value hidden, shape sloppy.
5. `scrub_headers` (which *would* catch header-dict shapes) is still
   never called on the Nuclei free-text/JSON path — observation
   scrubbing rests on `scrub_text` alone.

**Residual Risk:** Target-returned session tokens/cookies in JSON or
multi-value forms, and non-canonical secret names, can persist in
sealed evidence samples (up to 1 MiB per stream).

**Required Action:** Add JSON-aware redaction (quoted
`"key" : "value"` for the secret-name set, at minimum) to the
observation path or parse-and-scrub Nuclei `-json` fields before
`attach_nuclei`; extend the stem set (`secret_key`, `client_secret`,
`db_pass`, `credential`); redact fragment carriers; fix multi-value
cookie handling; add the scrubber-matrix unit test B3 §16 demanded
(B4 added redaction tests but the JSON shape remains uncovered).
Do NOT overclaim: current protection is `key=value/colon`-form only.

---

### H2 — Target normalization

**Status: CLOSED** (offline normalization boundary; residual notes
below, none egress-opening while runners stay blocked)

**Evidence:**

- Gate 2 now calls `_parse_raw_target` (lane.py:109-149), which
  rejects `@` userinfo explicitly (`ValueError: userinfo not allowed`)
  and delegates to shared `canonicalize_target`
  (`ai/resolver/canonicalization.py:324-338`): scheme allowlist
  (`http`/`https` only), hostname lowercase + single-trailing-dot
  strip + IDNA + label validation, numeric-IP unfolding
  (decimal/hex/octal/`inet_aton`, 1-4 components), IPv4-mapped IPv6
  unfolding, bracket handling with zone-ID rejection, port 1-65535.
- Adversarial matrix (offline, this review — all fail closed as
  required): `user:pass@`, `user@`, `example.com\@attacker` (userinfo
  reject); `ftp/file/gopher/data/javascript` (INVALID_SCHEME);
  `:0`/`:99999` (INVALID_PORT); `%2e`/`%40` encoded separators,
  `%2f`, backslash hosts, whitespace/control hosts, empty authority,
  `*`/wildcard (INVALID_HOST); `2130706433`/`0x7f.0.0.1`/
  `0177.0.0.1`/`127.1` unfold to `127.0.0.1` (then scope/egress-deny
  downstream); `::ffff:127.0.0.1` unfolds to `127.0.0.1`;
  `EXAMPLE.COM` lowercases; trailing dot strips; explicit-default
  ports canonicalize.
- Authorization (`_issue_and_verify_authz`, lane.py:482-531) and scope
  (`_evaluate_scope`, lane.py:533-571) re-derive from the same
  canonical function over the same stripped target string, and the
  executor `_check_binding` (nuclei_executor.py:969-1044) re-verifies
  canonical host/scheme/port/hash/`DialBinding` coherence
  (`sni_host == canonical_host`, `pin_required is True`, non-empty
  address set within `dns_answers` ceiling). No second parser
  reinterprets the target after authorization: `build_target_string`
  uses the canonical triple only.
- Unsupported schemes now fail at Gate 2 (`TARGET_INVALID`) instead of
  reaching issuance — the B3 H2 symptom (`ftp://host:port` →
  `ISSUANCE_FAILED`) is gone (now `INVALID_SCHEME` at Gate 2).

**Residual notes (not boundary failures):**

- `localhost` and IP literals (e.g. `0.0.0.0`) pass canonicalization
  as identities and are denied later at scope/egress — correct
  defense-in-depth, but the canonicalizer is an identity function,
  not a safety function; safety rests on `classify_address` + 5D +
  Gate 6b.
- Gate 2 parses the raw string three times (Gate 2, authz, scope)
  rather than passing one canonical object downstream. Same pure
  function on the same stripped input → same identity, so this is a
  shape note, not a bypass; a future refactor should thread the
  `CanonicalAuthority` through.
- Mixed-case scheme (`HTTP://`) is accepted via lowercasing (correct
  per architecture; noted for completeness).

**Required Action before egress:** none for H2 itself; keep
downstream re-checks as defense in depth; thread the canonical object
instead of re-parsing when convenient.

---

## Cross-Cutting Findings

A) **Fail-closed behavior — PASS.** Malformed/ambiguous/unsupported
inputs fail at Gate 2 (`TARGET_INVALID`), unsafe addresses at
scope/egress (`SCOPE_DENIED`/`EGRESS_DENIED`), blocked runners at
execution (`NUCLEI_EXECUTION_BLOCKED`), over-cap output at
`SUBPROCESS_OUTPUT_LIMIT`. No path falls through to execution or
`VERIFIED` on failure (`MATCH_UNVERIFIED` is the inconclusive sink).

B) **Caller authority — PASS with documented operator trust.** The
caller supplies only `(cve_id, target, mode)`; artifact, executable,
argv, and environment are frozen server-side; issuer
(`human-review-board`) and `caller_scope` (`manual`) are hardcoded;
`issue/get/consume` type-gates reject dict/LLM output as authority.
The caller *does* choose any public target (single-host explicit
policy) — operator-trust assumption (B3 M1), unchanged, must be
documented with audit logging before egress.

C) **Authorization expiry — WEAK (carried M3).** `EXPIRES_FAR_FUTURE =
2030-12-31` (lane.py:92,514) with deterministic `NOW_ISO` clock.
CAS single-consume limits replay per execution, but a stolen/far-future
authorization record is long-lived. Production needs short-lived authz
and real clocks before egress.

D) **Proxy bypass — PASS for the Nuclei spec; GAP for the process.**
`build_nuclei_environment` cannot carry proxy/CA/resolver variables
(closed tuple). However, the lane never calls
`egress_guard.check_environment` on the launcher process environment,
and Nuclei's own Go/proxy behavior under a dirty process env is
unproven for the future live launcher. The future runner must call
`check_environment` (or launch with the scrubbed environment) and
fail closed on `PROXY_DETECTED`. (New finding N4.)

E) **TLS boundary — UNPROVEN (future-work, blocks egress).**
No SNI/Host/cert-verification logic exists on the lane path beyond
`sni_host = canonical_host` in the `DialBinding` record. How SNI and
Host are selected when dialing by IP, how certificates are verified,
and whether TLS can connect to a different peer than authorized are
all unanswered — necessarily so, since no live runner exists. Must be
designed and reviewed before egress. (Confirms B2 NO-GO.)

F) **Subprocess boundary — PASS (offline).** Fixed binary, frozen
argv + `argv_digest_for` SHA-256 with runner-return digest equality,
no `shell=True`/`os.system`/`popen` (module imports no
process-creation facility), closed stdin, template path confined to
`/srv/watch/scratch/nuclei/`, runner allowlist type-gate
(`Fake/Live/B3Netns` only), working directory derived from validated
execution id. Child-process/file-descriptor limits are recorded, not
enforced (see B3).

G) **Deterministic evidence identity — PASS.** `canonical_target_hash`,
`resolution_id_for` lineage, artifact hash/identity binding,
`_check_binding` coherence, `bind_provenance`, and envelope hashing
tie evidence to the authorized execution; `finding_eligible=False`
ceiling preserved.

**New findings summary:**

- **N1 (MEDIUM, B3-adjacent): retries unenforced.** No `-retries` /
  `-retry` flag in the frozen argv; "retries 0" is `ceilings.py`
  metadata, never placed on the command line. Nuclei's default retry
  behavior for the pinned (unpinned — see N2) version applies.
- **N2 (MEDIUM, B1/B3-adjacent): no Nuclei version pin.** No version
  constant, requirement, or binary in repo; flag semantics for
  `-no-redirects` / `-disable-interactsh` / `-disable-update-check`
  cannot be proven from this tree.
- **N3 (MEDIUM, H1-adjacent): JSON credential blind spot.** Detailed
  under H1; listed here because Nuclei `-json` output makes it the
  likely carrier shape.
- **N4 (LOW, D): lane skips `check_environment`.** Proxy-shaped
  process env is never asserted on the lane path.
- **N5 (LOW, B2-adjacent): lane skips `validate_answers`.**
  `dns_answers` ceiling + deterministic ordering unenforced on the
  lane path (relies on downstream binding checks).

---

## Live-Egress Readiness

**NO-GO**

Socket-level destination pinning is not proven (B2: hostname `-u`
with independent Nuclei-side resolution; no dial-by-IP; no peer
proof; rebinding undefended), and the network sandbox/resource
boundary is not actually enforced for any real runner (B3: raising
placeholder; ceilings recorded, not applied; version-dependent flags
unproven). The offline lane is genuinely blocked and correctly
fail-closed today — but "implementation exists" is not "security
boundary proven." Real live egress must not be enabled.

---

## Required Next Stage

Minimum concrete remediation before another security review:

1. **Pin the Nuclei version** (constant + installed-binary assertion,
   fail closed on mismatch) and cite primary-source proof that
   `-no-redirects`, `-disable-interactsh`, and `-disable-update-check`
   hold for that version; add `-retries 0` (or version-grounded proof
   the default is zero) to the frozen argv. (B1/B3/N1/N2)
2. **Prove dial-by-IP with peer verification**: resolve once via the
   reviewed source + `validate_answers`; pass IP literals to the
   transport with SNI/Host preserved; abort on re-resolution/peer
   mismatch; define the TLS peer check (SNI, Host, cert verification).
   (B2/E)
3. **Enforce the sandbox**: netns/egress-allowlist (or equivalent),
   wall-time kill, rlimit/cgroup, request/redirect/socket counters
   against ceilings, output caps, child-process/fd limits — in the
   real runner, with dial proof. (B3/F)
4. **Close the JSON redaction gap** and extend secret stems
   (`secret_key`, `client_secret`, `db_pass`, `credential`), fragment
   carriers, and multi-value cookies; add the scrubber-matrix unit
   test. (H1/N3)
5. **Short-lived authorizations + real clocks**, operator-trust
   documentation with (cve, target, operator) audit logging, and
   `check_environment`/`validate_answers` wiring on the lane path.
   (C/B/D/N4/N5)
6. **Re-review (B6 or equivalent)** covering the unblock diff itself
   (H3): the diff that lifts `LIVE_NUCLEI` / unblocks a live runner /
   sets `WATCH_AI_LIVE_VALIDATION` must pass review with the above
   proven — a flag flip is not an accepted unblock.

---

## Confirmations

- No source code modified; no tests added or modified; no commits; no
  push. Pre-existing working-tree modifications left untouched.
- No real network request, DNS lookup against external targets,
  Nuclei invocation, browser execution, LLM/provider call, or
  MongoDB/project-data modification performed or triggered.
- Existing local/offline tests executed as listed in Method (all
  passing); `git diff --check` introduces no new issues from this
  review (this report is the only new file).
