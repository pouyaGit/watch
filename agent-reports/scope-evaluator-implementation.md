# Phase 5D — Scope Evaluator + Canonicalization
# Implementation Report

## 1. Verdict

**IMPLEMENTED AND VERIFIED**

All Phase 5D requirements are implemented per the approved read-only
architecture (`scope-evaluator-architecture.md`), with 117 new
deterministic offline tests passing and 1424 existing tests
regressed green. No live execution surface was added. Two
implementation-time findings (a hop-tuple contract bug caught by
tests, and the `resolution_id` echo semantics below) were resolved
without inventing unsafe behavior; no blockers remain.

## 2. Files Created

| File | Purpose |
|---|---|
| `ai/schemas/scope_evaluation.py` | `ScopeEvaluation` / `HopDecision` / `AddressDecision` contracts, `ScopeDecision` ternary, closed 17-code failure vocabulary, deterministic `evaluation_id_for` |
| `ai/scope/__init__.py` | Phase 5D package boundary + exports |
| `ai/scope/policy.py` | Strict policy compiler (`compile_policy`), `CompiledScopePolicy`, `PolicyStore` DI protocol, `InMemoryPolicyStore` fake |
| `ai/scope/matcher.py` | Label-aware exact/wildcard matcher (no regex, no substring) |
| `ai/scope/evaluator.py` | `ScopeEvaluator.evaluate()` / `evaluate_chain()` + `require_allowed()` transport gate |
| `ai/test_scope_evaluator.py` | 117 deterministic offline tests incl. 30 adversarial cases |

## 3. Files Modified

**None.** Zero modifications to existing code, including legacy
scope code (`http_executor.py`, `browser_executor.py`,
`xss_case_builder.py`, `nuclei_runner.py`, `db.py`, ceilings).
Frozen contracts are reused by import only: 5C canonicalizer +
`scope_lists_hash_for()` + `classify_address()`, 5H-core hashing /
scrubber / `require_live_for_execution`, 5B typed authorization
boundary.

## 4. Exact Scope

Implemented: compiled policy contract + strict all-or-nothing
parser, exact-host and single-level label-aware wildcard matching,
absolute exclusion, program-keyed policy access, live-authorization
+ resolution + dial binding checks, drift detection, host-only
scheme/port defaults (upgrade only for `http_probe`, downgrade
never), dual address gating (ALL must pass), pure per-hop redirect
evaluation (canonical visited-set, 5-edge cap, per-hop policy
re-read), immutable decision contract, closed failures, secret-free
errors, `require_allowed()` executor gate, full offline test suite.

Explicitly NOT implemented (§0): 5E–5J, scheduler, queue, findings,
classification, CONFIRMED/NOT_VULNERABLE, live/network/browser/
Nuclei/subprocess/DNS execution, MongoDB (reads or writes), LLM,
executor wiring, legacy-code fixes.

## 5. Scope Policy Contract

`CompiledScopePolicy{program_name, inclusions, exclusions,
policy_version, scope_lists_hash}` — frozen dataclass,
program-keyed, network/LLM/evidence independent. `ScopeRule{kind,
host, source, text}` with `kind ∈ {exact, wildcard}`. Policy hash
is 5C `scope_lists_hash_for()` over the RAW source lists (the exact
5B-issuance basis); `policy_version` is audit-only and can never
override the content hash (tested with a `v999` spoof attempt →
still `SCOPE_DRIFT`).

## 6. Policy Compilation

`compile_policy()` treats stored lists as hostile input: rejects
(empty, whitespace/control, userinfo, URL-like, IP literals in any
notation, CIDRs, multi/non-leftmost wildcards, suffix/single-label
wildcard bases, single-label exact entries, malformed IDNA,
over-long/over-count entries) with closed `SCOPE_POLICY_INVALID`.
One bad entry fails the whole policy — no partial compile (tested).
Frozen bounds: `MAX_POLICY_ENTRIES = 1024` (architecture left the
number to implementation; conservative vs single-digit real data),
`MAX_POLICY_ENTRY_LENGTH = 258`. `InMemoryPolicyStore` compiles
fresh on every read (models read-fresh semantics), has no write
surface, and is keyed by `program_name` only — a host-keyed lookup
is unrepresentable (asserted).

## 7. Canonicalization

No second implementation exists (source-asserted: no
`canonicalize_host` def, no `idna` codec in `ai/scope/*`). 5D
reuses `ai/resolver/canonicalization.py` at three points: policy
compile (entries), evaluation entry (re-canonicalize the 5C host,
require idempotent equality → else `TARGET_NOT_CANONICAL`), and
every redirect hop. Raw strings never reach matching. `tldextract`
/ `get_domain_name` / registrable-domain logic appear nowhere in
the 5D path (import- and token-scan tested).

## 8. Exact Host Matching

String equality on canonical forms: `example.com` matches only
itself — `www/api/foo.api/deep` all DENY (`TARGET_NOT_IN_SCOPE`),
`evil-example.com` DENY. Parent/child/sibling/site/company/
certificate/CNAME inference does not exist in the matcher (there is
no code path that could express it: equality or label-counted
wildcard, nothing else).

## 9. Wildcard Matching

`match_rule()` splits already-canonical names on `.` and requires
`len(candidate) == len(base)+1` with equal trailing labels — no
regex (ReDoS excluded by construction), no `endswith`, no
backtracking. `*.example.com` → one-label children ALLOW (apex
DENY, depth DENY, `evil-example.com` DENY). Wildcards never match
IPs (IP candidates match no host rule at all). Malformed forms
(`*.*`, `api.*`, `*example`, `*.`, `*`, `*.com`, single-label)
die at compile.

## 10. Include/Exclude Precedence

Absolute exclusion (B1, implemented as frozen): any exclusion match
→ `TARGET_EXCLUDED` DENY with both `include_rule` and
`exclude_rule` recorded. Verified: wildcard-IN + exact-OUT DENY;
exact-IN + exact-OUT DENY; wildcard-OUT spares the apex (label
semantics, not specificity — apex ALLOWED while subhosts DENY).
Conflicts always resolve to DENY, never by specificity comparison
(there is no specificity comparator in the codebase).

## 11. Program Isolation

Evaluation key `(program_name, canonical_host)` end to end; policy
accessor takes only a program name. Tests: same host under two
programs uses only the authorized program's policy; unknown program
→ `PROGRAM_NOT_FOUND`; caller/host-type misuse → `TypeError`.

## 12. Scheme/Port

Host-only data ⇒ explicit safe defaults (no scheme-aware scope
syntax invented): allowlist `{http, https}`; effective-port
allowlist `{80, 443, resolved-port}`; no silent rewrite in either
direction. Redirect http→https upgrade ALLOWED only for
`execution_class == "http_probe"` (recorded `upgraded=True`),
DENY for all other classes; https→http always DENY; cross-port
hops get full independent evaluation with no inheritance (a hop to
a non-allowlisted port DENYs via the allowlist).

## 13. IP/CIDR Handling

B2 implemented as refusal: any IP-literal (v4/v6/mapped/decimal/
octal/hex/dotted-numeric) or CIDR-shaped entry → whole policy
`SCOPE_POLICY_INVALID` (never silently skipped). IP *candidates*
match no host rule, so obfuscated-loopback (`2130706433`),
mapped (`::ffff:7f00:1`), and `localhost` targets DENY at scope
even when observation succeeds. `ADDRESS_NOT_IN_SCOPE` is reserved
in the vocabulary for a future IP-rule grant; it fires nowhere
today (documented, not hidden).

## 14. DNS Boundary

5D resolves nothing: banned imports (`socket/requests/httpx/
subprocess/ssl/tldextract/drivers/LLM/browser/Nuclei`) asserted by
source scan; `urllib` appears solely as `urljoin/urlsplit` for
redirect joining (allow-listed and separately asserted). Address
facts come only from 5C records and per-hop caller observations;
`classify_address()` is pure local computation, not resolution.
`SCOPE-EVALUATED == DISPATCHED` is contracted to transport via the
pinned `DialBinding`; enforcement is 5E/5F/5G work (not claimed).

## 15. Redirect/Per-Hop Contract

Pure `evaluate_chain(authz, resolution, hops: HopObservation)`:
raw Location → `urljoin` → split → userinfo/empty-host/scheme/
port/backslash/control checks → 5C canonicalization (IP-literal
destinations DENY — no IP scope) → downgrade/upgrade rules →
canonical-URL visited set (fixes the legacy raw-string cycle
bypass) → host rules (sibling/out-of-scope DENY, exclusion
absolute) → port allowlist → address observations (missing →
INCONCLUSIVE stop, never assumed; unsafe → `UNSAFE_ADDRESS`) →
record `HopDecision`. Budget: hop 0 + max 5 edges, 6th →
`REDIRECT_LIMIT`; per-hop policy re-read with pinned-hash compare
(mid-chain change → `SCOPE_DRIFT` stop, proven by a drifting-store
test). Initial DENY short-circuits (hops unevaluated). No live HTTP
anywhere; observations are caller-supplied facts.

## 16. Authorization Binding

Typed `IssuedExecutionAuthorization` only (dict/JSON/None →
`TypeError`); liveness re-asserted at entry via frozen
`require_live_for_execution` (expired/consumed/revoked →
DENY/`AUTHZ_NOT_LIVE` records, provenance never accepted).
Execution-id equality (`AUTHZ_BINDING_MISMATCH`), program/target
equality (`TARGET_BINDING_MISMATCH`), resolution cross-checks
(`RESOLUTION_BINDING_MISMATCH`), dial consistency
(`DIAL_BINDING_MISMATCH`), all as DENY records. 5B lifecycle logic
is reused, never duplicated. `require_allowed()` gates future
transport on `ALLOWED` + exact id-triple match.

## 17. Scope Drift

Entry compare `authz.scope_lists_hash` vs fresh policy hash;
mid-chain re-compare per hop. Any difference → DENY/`SCOPE_DRIFT`,
no compatible-change carve-outs. Stale TI/evidence/cached lists
are not inputs (they are not even importable as authority —
`EvidenceRecord` token-absent from all 5D modules).

## 18. ScopeEvaluation Contract

Frozen, `extra="forbid"`: `evaluation_id` (`se-` + deterministic
hash over the full binding incl. chain digest — verified
byte-exact in tests), authz/execution/resolution ids, program,
target hash, current policy hash, `decision ∈ {ALLOWED, DENIED,
INCONCLUSIVE}`, `include_rule`/`exclude_rule` (named to avoid the
`matched` alias), per-address outcomes (`outcome ∈ {ALLOW, DENY,
UNKNOWN}` — renamed from `verdict` during implementation when the
forbidden-field scan caught it), hop decisions, failure code,
`evaluated_at` (caller clock), `scope-evaluator/v1`.
`is_authorizing()` is true only for ALLOWED; INCONCLUSIVE (missing
hop observations) is rejected by `require_allowed()`. No
`scope_allowed`/`execution_allowed`/verdict/finding fields exist
(structurally + negatively tested).

## 19. Immutability

`ScopeEvaluation`/`HopDecision`/`AddressDecision` frozen pydantic
(assignment → `ValidationError`, tested);
`CompiledScopePolicy`/`ScopeRule` frozen dataclasses; no
replace/rebind/mutate/update/patch APIs (attribute-scan tested).
New policy/target/chain → new objects and new `evaluation_id`
(chain digest binds hop URLs; address/execution changes bind ids).

## 20. Failure Model

Closed 17-code vocabulary + `INVALID_REQUEST` (programmer-shape
only), all bounded/secret-free/single-line via shared 5H-core
screening (no second scrubber). Raw exceptions never escape:
parsers raise closed `PolicyError`/`ScopeError` with static
details; hostile entry text is never reflected (asserted);
Location echoes are secret-screened (`[REDACTED]` on secret
shape) and truncated to 200 chars.

## 21. Secret/Error Handling

§20 plus: no nonce/credential/cookie/header/URI in records, errors,
or audit projections; `host_as_authorized`-style echoes do not
exist in 5D outputs (only canonical forms + rule texts, both
operator-shape). `require_allowed()` messages are static.

## 22. Resource Limits

`redirect_hops = 5` (edges; hop 0 + 5 follows, 6th DENY — 5-allow/
6-deny boundary tested both sides), `dns_answers = 8` inherited
via 5C facts (never re-counted, never re-resolved), hostname
253/label 63 inherited via the shared canonicalizer, policy
1024 entries / 258 chars, Location 2048 (reject-not-truncate),
error 200. No recursion (iterative hop fold), no regex matching,
linear label compare.

## 23. Existing Legacy Code Findings

Unchanged (read-only mandate), documented for future phases:
`http_executor._check_redirect_safety` still allows same-eTLD+1
sibling redirects + raw-string visited set + `int/""` port mix +
unrefused userinfo Locations (HIGH, F-02/F-08/F-08b — the 5D
evaluator is the replacement, not a patch); transport loop has no
per-hop DNS/scope (F-03/F-09 → 5E pinned-dial work);
`browser_executor` exact-origin route policy is the correct model
but needs pinned-resolver backing (5G); `nuclei_runner`/binary
owns an uncontrolled network stack (HIGH → 5F egress forcing);
`xss_case_builder._host_in_scope` eTLD+1 rule stays triage-only;
collectors/`http_fingerprint` `follow_redirects=True` stays
recon-only; `db.get_domain_name` live-tldextract stays off the
execution path; hardcoded DB credentials observed in `db.py`
(never reproduced here; resolver/evaluator processes must receive
injected connections, strings never in audit).

## 24. Security Invariants

All 24 architecture invariants hold and are test-pinned:
deterministic authority; program-scoping; explicit exact-host;
eTLD+1 absence (import + behavior tests); non-expanding
canonicalization; label-aware wildcards; absolute exclusion;
drift closure; mandatory `TargetResolution` (raw targets are
`TypeError`); zero DNS; dual-gated addresses (hand-built unsafe
records DENY); independent hop evaluation; no sibling
inheritance; no CDN/CNAME/ASN/cert inference (no such inputs
exist); evidence/LLM/TI inability (not inputs, scan-enforced);
transport gate (`require_allowed` triple); immutability;
verdict-field absence; secret-free errors; evaluated==dialed
address equality; cross-program impossibility; no stale-policy
authorization (fresh-read + hash + per-hop re-assertion, no
sensitive cache — memoization, if added later, must key on
`(program, policy-hash, target-hash)` within one call only).

## 25. Tests

`ai/test_scope_evaluator.py` — **117 tests, all passing**:
A compilation (11) · B exact (3) · C wildcard (4) · D isolation
(3) · E exclusion (4) · F/G scheme-port (4) · H/I addresses (5) ·
J authz (8) · K resolution binding (9) · L drift (3) ·
M redirects (17) · N canonicalization (3) · O/P/Q boundaries (9) ·
30 adversarial · store/matcher hygiene (4).

## 26. Adversarial Results

30/30 fail closed: evil-prefix (DENY); evil-sibling (allowed iff
operator wildcard covers it, DENY via explicit exclusion —
documents breadth-is-intent); depth/apex vs wildcard (DENY);
homoglyph (different slot, DENY); trailing dot (converges,
ALLOW); userinfo/scheme-relative/malformed/encoded-Location hops
(DENY); IPv4 obfuscation + mapped + localhost (DENY at scope or
5C gate, dual asserted); metadata/private/mixed addresses (DENY,
no first-clean-wins); cross-program (DENY); drift/stale/consumed/
forged authz (DENY/`TypeError`); sibling/CDN/cert-sibling hops
(DENY); loop/overflow (DENY); port/scheme attacks incl.
non-probe upgrade (DENY); eTLD+1 assumption (DENY).

## 27. Regression Results

- 5D + 5C + 5B + 5H-core: **403 tests OK**
- artifact/store/retrieval, hypothesis/testplan, TI, matcher,
  test-plan builder, hypothesis engine, knowledge, XSS researcher,
  LLM researcher, openrouter: **550 tests OK**
- oracle, readiness, pattern store/projector, research pattern,
  knowledge ingestion, case builder, XSS verification, HTTP +
  browser executors: **588 tests OK**

Total **1541 tests, 0 failures**. No existing test modified.

## 28. Existing Failures

None. All in-scope suites pass unmodified. (Heavy/live suites
requiring network were not run.)

## 29. Deferred 5E–5J Work

5E/5F/5G transports (pinned-dial enforcement, per-hop
observation supply, `require_allowed()` wiring, Nuclei/browser
egress forcing); 5H production store/audit persistence of
decisions (one-way observation); 5I verifier consumption;
5J scheduling/queue/E2E + B3 multi-worker snapshot primitive;
production Mongo-backed `PolicyStore`; operator sign-off B1
(absolute exclusion ratification) and B2 grants (IP-scope
programs stay denied until then); non-standard-port policy
schema (O4) and CDN registry (O7) remain deny-by-default.

## 30. Confirmation No Live Execution

Confirmed: no `socket`/`requests`/`httpx`/`subprocess`/`ssl`/
DNS-driver/LLM/Mongo-driver/browser/Nuclei imports in any 5D
module (source-scan tested, `urllib` allow-listed to
`urljoin/urlsplit` only and separately asserted); fake policy
store + genuine-but-offline 5B/5C fixtures are the only inputs;
full 5D suite runs in ~0.15 s with zero I/O.

## 31. Confirmation No Git Operations

Confirmed: no git command of any kind was executed in this phase.
All changes are uncommitted working-tree files listed in §2.

## 32. Final Verdict

**IMPLEMENTED AND VERIFIED**

Notes carried forward (not hidden): (i) `resolution_id` is an
echo label inside `evaluate()` — its integrity is enforced at
the transport triple gate, tested both sides; (ii) B1/B2/B3
architectural decisions implemented exactly as frozen
(absolute-exclusion / IP-refusal / no-multi-worker-atomicity-
claims); (iii) `ADDRESS_NOT_IN_SCOPE` reserved but unfired
pending a future IP-rule grant.

REPORT:
 /opt/watch/agent-reports/scope-evaluator-implementation.md
