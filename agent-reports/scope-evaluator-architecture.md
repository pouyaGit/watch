# Phase 5D — Scope Evaluator + Canonicalization
# READ-ONLY SECURITY ARCHITECTURE

> Mode: architecture/design only. No code was written, modified, or
> executed against live targets for this report. No network, DNS,
> browser, Nuclei, subprocess, MongoDB, LLM, finding, or verdict
> activity was performed. No git operation was performed.

## 1. Verdict

**ARCHITECTURE READY FOR IMPLEMENTATION** — with explicitly marked
blocking decisions (§31) that the 5D implementation phase must close
in the order given. The core design (exact-host + label-aware
wildcard + absolute-exclusion matcher over 5C canonical facts, bound
to live authorization and hashed policy, per-hop re-evaluation, no
verdict fields) is fully specified below. Three decisions are
BLOCKING because they change enforcement semantics and cannot be
defaulted safely: include/exclude precedence is resolved here by
fiat (absolute exclusion, §8) but requires operator sign-off;
IP/CIDR scope support is rejected by default (§11) pending an
explicit grant; and the atomic policy-snapshot mechanism (§19) must
be chosen before any multi-worker execution.

## 2. Existing Repository Findings

Verified read-only facts this architecture rests on:

- **5B Authorization** (`ai/schemas/execution_authorization.py`,
  `ai/authorizer/`): `TargetBinding{program_name, host, scheme,
  effective_port, path_scope, snapshot_ref, scope_policy_version,
  scope_lists_hash}` is data, not resolution. Authority exists only
  as a genuine `IssuedExecutionAuthorization` via the typed store
  boundary; `AUTHZ_LIVE_FOR_EXECUTION` (5H-core
  `require_live_for_execution`) is the pre-execution gate;
  `AUTHZ_VALID_FOR_PROVENANCE` grants nothing. `max_executions = 1`.
- **5C Target Resolver** (`ai/schemas/target_resolution.py`,
  `ai/resolver/*`): `TargetResolver` emits immutable
  `TargetResolution` with canonical `(program, host, scheme, port)`,
  pinned `resolved_addresses` + `DialBinding{addresses,
  effective_port, sni_host, pin_required=True}`, inventory binding
  (`scope_lists_hash_authorized/current`, `scope_drift`,
  `inventory_endpoint_base`, `reassigned`), advisory snapshot facts,
  closed statuses, deterministic `resolution_id` /
  `canonical_target_hash`, and `scope_view()` exposing exactly the
  facts 5D needs. 5C performs no verdicts. DNS safety (global-unicast
  only, any-denied fails set, 8-answer ceiling) is already enforced
  at observation time.
- **Scope data reality** (`database/db.py`, `programs/*.json`):
  `Programs.scopes` holds bare registrable domains (`dell.com`);
  `Programs.ooscopes` holds exact FQDNs (`educate.dell.com`). No
  wildcards, no CIDRs, no ports, no schemes, no paths exist in
  current data. Ingestion (`watch_sync_programs.py` →
  `upsert_program`) copies operator JSON verbatim — **no validation
  or normalization** (an empty-string ooscope entry exists in
  `indeed.json`). Any 5D parser must therefore treat stored entries
  as hostile input and reject malformed ones fail-closed.
- **Live scope rules today** (`db.py:217`,
  `xss_case_builder.py:340-353`, `http_executor.py:502-528`):
  inclusion = `get_domain_name(host) in scopes` (eTLD+1);
  exclusion = exact `host in ooscopes`; HTTP redirects allow
  cross-host within one eTLD+1 (finding F-02: sibling-host escape,
  contradicts the exact-host rule); browser enforces exact origin
  via `context.route` + post-hoc audit (correct model, §15
  generalizes it). `visited` redirect-cycle sets use **raw URL
  strings** (canonicalization bypass); port comparison mixes
  `int/""` types (F-08b); `Location` values accept userinfo without
  rejection; no per-hop DNS/scope re-check (F-03, F-09).
- **`ScopePolicy.evaluate`** (`ai/correlator/scope_policy.py`) is
  product/version readiness, **not URL scope** — it must be wrapped
  + renamed, never wired to execution decisions (unchanged from the
  executor-architecture disposition).
- **Hypothesis/TestPlan `TargetRef`** are explicitly
  descriptive/non-authoritative in-schema; **TargetIntelligence
  `ScopeSnapshot`** is observed data that "grants nothing". 5D must
  not read any of them (they are not even inputs).
- **Frozen ceilings** (`ai/limits/ceilings.py`): `redirect_hops = 5`,
  `dns_answers = 8` (already consumed by 5C), plus transport caps 5D
  inherits by reference. Nothing is modified.
- **Prior adversarial findings** (executor-architecture-adversarial-
  review §16): F-02 (sibling redirect), F-03 (no dial binding),
  F-08/F-08b (normalization/port), F-09 (TOCTOU/stored-READ),
  F-11 (secrets), F-13 (caller scope), F-19 (clock). F-03's 5C half
  is closed (pin preserved); its enforcement half is specified in
  §13–§14 below. F-02/F-08/F-08b are closed by this architecture and
  must be regression-tested at 5D implementation.

## 3. Trust Model

UNTRUSTED (never policy inputs, never allow-causes): LLM output and
research prose; Hypothesis/Plan `TargetRef`; TargetIntelligence
(incl. `ScopeSnapshot`); matcher output; arbitrary URLs and
redirect `Location`s; `Host` headers; historical IPs/DNS; evidence
bodies; Nuclei/browser output; CNAME/IP/ASN/certificate/org facts;
stored scope strings until parsed + validated (they are operator
data, validated at policy-compile time, never trusted raw).

AUTHORITATIVE (only allow-causes, §25): a live
`IssuedExecutionAuthorization` (by typed reference); the 5C
`TargetResolution` canonical facts + pinned addresses; the compiled
scope policy for the exact `program_name` (read fresh, hashed);
explicitly approved auxiliary mappings (CDN registry, if ever
created — §16; none exists today, so none authorizes anything).

5C is a fact witness, never scope authority: 5D re-derives every
decision from canonical facts + policy, and `RESOLVED` implies
nothing about allowability.

## 4. Scope Authority

One centralized, pure, deterministic evaluator owns all scope
verdicts for 5E/5F/5G. No per-executor scope forks: the HTTP,
Nuclei, and browser paths call the same function with the same
canonical inputs and receive `ALLOWED/DENIED/INCONCLUSIVE`. Any
indeterminacy (missing program, unparseable policy, unresolvable
suffix, empty answer set, policy-hash mismatch) → `DENY`
(`SCOPE_UNKNOWN`-family, §21). The evaluator has no network, clock
(except caller-supplied `now`), LLM, or store-write surface; policy
reads arrive via an injected read-only accessor so tests fake them.

## 5. Target Canonicalization

5D **reuses `ai/resolver/canonicalization.py` verbatim** — a second
implementation is forbidden. Canonicalization occurs at three
normative points: (a) once for the 5C canonical host at evaluation
entry (re-canonicalize and require equality with
`TargetResolution.canonical_host`; mismatch →
`RESOLUTION_BINDING_MISMATCH`, closing any 5C/5D drift); (b) for
every redirect `Location` after `urljoin` against the current hop;
(c) for every scope-list entry at policy-compile time (malformed
entries rejected, never skipped-silently-when-they-would-allow).
Policy matching operates only on canonical forms. Case, trailing
dots, IDNA, IPv4/IPv6/mapped forms, and explicit-default ports are
therefore already converged before any rule sees them, and
canonicalization can never expand scope because matching rules (§6,
§7) are defined over canonical labels with no substring fallback.

## 6. Exact Host Semantics

Matching is over explicit entries, never registrable-domain
equality. Given scope `example.com` ONLY: `example.com` ALLOWED;
`www.example.com`, `api.example.com` DENIED (they are distinct
identities; the current eTLD+1 rule that allows them is the
vulnerability this phase retires). Given only `api.example.com`:
apex and `foo.api.example.com` DENIED. Parent never implies child,
child never implies parent, sibling never implies sibling. The
legacy `get_domain_name(host) in scopes` check is **deleted from
the execution path** (kept only in recon-ingestion triage, which is
not authority). eTLD+1/same-site/same-origin/same-company similarity
is not a rule, not a fallback, and not a tiebreaker — tests must
assert its absence (negative test: remove the eTLD+1 helper import
from the 5D module and fail review if reintroduced).

## 7. Wildcard Semantics

Current data contains no wildcards; the architecture supports them
only under this exact, label-aware definition (to be enforced by the
policy compiler, which rejects everything else):

- Syntax: exactly `*.` + valid canonical DNS name, single `*` as the
  full leftmost label, nothing else (`*.*.example.com`,
  `api.*.example.com`, `*example.com`, `*.` alone → reject).
- `*.example.com` matches exactly **one** leftmost label
  (`api.example.com` yes; `example.com` (apex) NO;
  `foo.api.example.com` NO). Arbitrary depth requires explicit
  deeper entries — depth expansion is never inferred.
- Never matches public suffixes (`*.com` rejected at compile;
  single-label and suffix-only entries rejected).
- IDNA: matching is over canonical A-labels; a Unicode entry is
  compiled to punycode once, mixed-script/confusable entries are
  rejected at compile (5C canonicalizer already rejects them as
  targets).
- Never matches IP literals (v4/v6/mapped/obfuscated numerics):
  an IP candidate only matches IP rules (§11), never host rules.
- Matching is label-split comparison (`host.labels[-n:] ==
  rule.labels`), never `endswith` (so `evil-example.com` cannot
  match `example.com` — the naive-suffix bug is structurally
  unrepresentable).

## 8. Include/Exclude Precedence

**Absolute exclusion (blocking decision B1, resolved here by fiat,
operator sign-off required):** any matching exclusion rule denies,
regardless of inclusion specificity. Rationale: exclusion lists
(`ooscopes`) are the operator's explicit "never touch" set; letting
a broader inclusion override them inverts the safety default, and
specificity-comparison games between independent list sources are
not decidable without a precedence oracle. Consequences, all
explicit: IN `*.example.com` + OUT `admin.example.com` →
`admin.example.com` DENIED; IN `example.com` + OUT `*.example.com`
→ every subhost DENIED while the apex stays allowed (rules apply to
what they match, nothing more); exact-IN vs exact-OUT on the same
host → DENIED. A conflict is never "resolved implicitly" — it
resolves to DENY by this stated rule, and both matched rules are
recorded in the decision (§20).

## 9. Program Isolation

Evaluation key is `(program_name, canonical_target)` end to end:
policy accessor loads **only** the named program's lists; there is
no global evaluation entry point. Missing program, missing/empty
scope lists, or a target whose inventory binding belongs to another
program → `DENY` (`PROGRAM_NOT_FOUND` / `SCOPE_POLICY_MISSING`).
Empty scopes mean "nothing allowed" (never "everything allowed").
The program name is taken from the live authorization binding, and
any caller-supplied program that disagrees with it fails with
`AUTHZ_BINDING_MISMATCH` before policy is read.

## 10. Scheme/Port Policy

Current policy data expresses **hosts only** — scheme and port are
not representable in `Programs.scopes/ooscopes` today. Security
consequence: a host-only policy cannot distinguish
`http://host:80` from `https://host:8443`, so 5D must enforce the
safe default explicitly rather than pretend the data says more than
it does. Normative rules: scheme allowlist `{http, https}` (else
DENY); effective port allowlist `{80, 443, <5C-resolved port>}`
(anything else, including redirect-introduced ports, DENY);
`https://host` authorizes port 443 only; `host:8443` is a distinct
target requiring its own 5C resolution (host-only scope match does
not bless the port — the port allowlist does); **no silent
upgrade** (http→https) and **no silent downgrade**
(https→http: DENY, redirect or otherwise). A future
`scheme/port`-aware policy schema is an additive extension (§31,
non-blocking); until it exists, the 5C-resolved scheme/port plus
these defaults are the whole port/scheme authority.

## 11. IP/CIDR Policy

**Default: IP/CIDR scope entries are NOT supported (blocking
decision B2).** Current data has none, and supporting them would
require answering CIDR breadth, mapped-form, and
safety-vs-scope interaction questions against operator intent that
does not exist. Safe default: any IP-literal or CIDR-shaped scope
entry is rejected at policy-compile time (`SCOPE_POLICY_INVALID`
→ DENY everything until the operator removes it — loud, not
silent). If a future program explicitly requires IP scope, it needs
a separate typed grant covering: exact-address vs CIDR (max prefix
lengths, e.g. v4 ≥ /24, v6 ≥ /64 — illustrative, to be frozen
then), mapped/6to4/teredo unfolding before match, and the
non-override rule below. **Non-override invariant (unconditional):**
an "in-scope IP" never overrides 5C DNS safety — safety policy and
scope policy are sequential AND-gates (unsafe → DENY even if some
rule would include it; allowed scope + safe address are both
necessary, neither sufficient).

## 12. DNS Interaction

5D performs **zero DNS**. Inputs are exactly
`TargetResolution.scope_view()` + the compiled policy + live
authorization: canonical host, scheme, port, `resolved_addresses`
(already ceiling- and safety-checked by 5C), program binding,
`scope_lists_hash_current`, snapshot facts. Multi-address
semantics (unambiguous by fiat): **ALL pinned addresses must
independently satisfy the address gate** (safe — inherited proven
from 5C — AND scope-evaluated where IP rules exist; under the
default host-only policy the address gate is "5C-safe", recorded
per address in the decision). Any unsafe address → total DENY
(5C already guarantees this, 5D re-asserts rather than re-checks).
Hostname scope can never "allow" an address that safety denies;
address scope can never allow a hostname that host rules deny —
both gates must pass.

## 13. DNS Rebinding

5D pins, transport enforces. 5D records into the decision:
`canonical_host`, scheme, port, `canonical_target_hash`,
`resolution_id`, the exact pinned address tuple, and
`scope_lists_hash_current`. Normative invariant:
**SCOPE-EVALUATED ADDRESS == DISPATCHED/DIALED ADDRESS.** Future
5E/5F/5G MUST dial a pinned address with SNI/Host preserved
(HTTPS verified against the hostname), re-resolve per hop, and
abort on any re-resolution mismatch or unpinned dial — or
re-submit the new address to 5D for a fresh decision and halt
otherwise. `5D approves A → transport connects B` without a new
5D decision is a BLOCKING violation to be asserted by 5E/5F/5G
tests, not a 5D runtime check (5D has no dial visibility by
design).

## 14. Redirect Policy

Every redirect hop is a new scope decision, never an inheritance.
Per hop, in order: take raw `Location` → `urljoin` against current
canonical URL → canonicalize (split, re-canonicalize host via 5C
function, effective-port, userinfo→DENY, non-http(s)→DENY,
downgrade→DENY, cross-port→DENY) → evaluate host rules against the
**same program policy** (sibling `evil.example.com` from approved
`api.example.com` → DENY unless an explicit rule covers it;
eTLD+1 equality confers nothing — this is the F-02 closure) →
evaluate address gate against 5C-pinned-or-freshly-observed
addresses per §12/§15 → record hop. Same-host path-only redirects
still re-run the full check (cheap, closes parser-confusion
smuggling). Redirects never update the authorized target: the
authorization binds the initial target; hops are evaluated
destinations, and any hop that changes the registrable base in a
way the policy does not cover terminates the chain.

## 15. Per-Hop Evaluation

Chain semantics: hop 0 = initial 5C-resolved target (full 5D
decision). Each subsequent hop requires: canonicalization (5D,
§5b), scope evaluation (5D, §14), address observation with 5C-grade
safety (transport-owned resolver, 5E/5F/5G duty; 5D specifies the
contract: ceiling 8, any-denied-aborts, pin-per-execution), and dial
binding to the evaluated address (§13). "Initial allowed ⇒ chain
allowed" is forbidden and must be a negative test. Hop cap: frozen
`redirect_hops = 5` counts **redirect edges** (hop 0 initial + up
to 5 follows; the 6th redirect → `REDIRECT_LIMIT` DENY). Loop
detection on **canonical URLs** (fixes the raw-string `visited`
bypass in the current executor); userinfo-bearing, empty-host,
malformed-authority, or unparseable `Location` → `REDIRECT_INVALID`
DENY. Scheme/port/IP changes mid-chain are evaluated as new
destinations, never carried permissions.

## 16. CDN / Third-Party Relationships

No CDN relationship authorizes anything today: there is no CDN
registry in the repo (only flat `cdn` string labels on
`LiveSubdomains`, which are recon trivia, not policy). Therefore:
CNAME, IP ownership, ASN, certificate, org, and eTLD+1 facts grant
zero scope — a CDN-fronted `example.com` is in scope iff the host
rule says so, and a provider-owned hostname (`*.cloudfront.net`)
is DENIED unless explicitly listed. If operators later need CDN
aliases, the architecture requires a **typed, versioned,
per-program mapping** `{program, mapping_version, allowed_pairs,
approved_by, valid_until}` bound into authorization
(`cdn_binding`-style) and hashed into the policy hash — never
inferred. Until that registry exists, any "CDN exception" request
is DENY by default. (Open question O7 tracks the registry design;
non-blocking because the default is safe.)

## 17. Authorization Binding

5D consumes the live record + `TargetResolution` + fresh policy and
binds `authorization_id, execution_id, program_name,
canonical_target_hash, resolution_id, scope_lists_hash_current`
into the decision. Pre-checks before any rule evaluation: liveness
(`AUTHZ_LIVE_FOR_EXECUTION`, re-asserted at 5D entry — expiry
between 5C and 5D fails closed), program/target equality between
authorization and resolution (`TARGET_BINDING_MISMATCH` /
`RESOLUTION_BINDING_MISMATCH` on any divergence), and
`scope_lists_hash_authorized == scope_lists_hash_current` (else
`SCOPE_DRIFT`, §18). Post-authorization substitution of program,
target, or policy is unrepresentable: the decision echoes the
bound values and executors must present the same ids back.

## 18. Scope Policy Hash / Drift

Reuse `scope_lists_hash_for()` (sorted-lists SHA-256, single source
of truth — no second hash). At 5D entry compare
`authorization.target.scope_lists_hash` vs freshly computed current
hash: any difference → deterministic `DENY/SCOPE_DRIFT`, no silent
accept, no "compatible change" carve-outs. This closes the
T0-issue/T1-change/T2-execute window at decision time; the residual
intra-execution window (policy changes *during* the 5-hop chain) is
handled by per-hop hash re-assertion (§19). Technology/CDN/endpoint
drift remains advisory (5C semantics preserved).

## 19. Freshness / TOCTOU

Authoritative policy is **read-fresh at each evaluation point**:
initial decision reads current lists + hash; every redirect hop
re-reads (or re-asserts a hash pinned at chain start — implementation
choice, but a mid-chain hash change aborts the chain rather than
continuing on stale rules). Historical TI scope, evidence scope, and
cached lists are never authority. **No security-sensitive scope
cache**: memoization is permitted only keyed by
`(program_name, scope_lists_hash, canonical_target_hash)` within a
single evaluation call (pure function memo, no TTL, no cross-call
state). Atomicity claim is bounded and honest: 5D guarantees
"this decision reflects policy hash H read at time T" (both
recorded); it does NOT claim policy immutability across the chain —
per-hop re-reads are the control, and concurrent modification
manifests as `SCOPE_DRIFT`, never silent continuation. Multi-worker
evaluation is safe by construction (pure function of
{authz, resolution, policy snapshot}); cross-worker dedupe is a 5J
concern, not 5D's.

## 20. Scope Decision Contract

Minimum safe immutable contract (`ScopeEvaluation`, frozen,
`extra="forbid"`, no verdict fields):

- `evaluation_id` (`se-` + 16 hex, deterministic over the binding
  tuple — same inputs, same id; never proof, only dedupe),
- `authorization_id`, `execution_id`, `resolution_id`,
  `program_name`, `canonical_target_hash`,
  `scope_lists_hash_current`,
- `decision: ALLOWED | DENIED | INCONCLUSIVE` (`INCONCLUSIVE`
  reserved for explicit "cannot decide without defined data" paths
  and treated as DENY by all consumers; recommended: collapse to
  DENY with `SCOPE_UNKNOWN`-family codes and keep the ternary only
  if 5I needs the distinction — default binary),
- `matched_include: str | None` (rule text that matched),
  `matched_exclude: str | None`,
- `address_decisions: tuple[(address, ALLOW/DENY)]` (per-address
  gate results, §12),
- `hop_decisions` (per-hop canonical URL + decision + codes, §15),
- `failure_code: <closed §21 code> | None`,
- `evaluated_at` (caller-supplied `now`, deterministic),
  `evaluator_version` (`scope-evaluator/v1`).

Forbidden on the contract (structurally + tested): `verdict`,
`finding`, `vulnerable`, `confirmed`, `severity`, `scope_allowed`
as a boolean alias — the decision enum is the only outcome shape.

## 21. Failure Model

Smallest correct closed vocabulary (bounded, secret-free,
single-line; raw parser/network exceptions never escape):

- `TARGET_NOT_CANONICAL` (re-canonicalization mismatch)
- `PROGRAM_NOT_FOUND` / `SCOPE_POLICY_MISSING` /
  `SCOPE_POLICY_INVALID` (absent/unparseable policy)
- `SCOPE_DRIFT` (authz hash ≠ current hash)
- `TARGET_NOT_IN_SCOPE` (no inclusion match)
- `TARGET_EXCLUDED` (exclusion match — absolute, §8)
- `ADDRESS_NOT_IN_SCOPE` / `UNSAFE_ADDRESS` (address gate)
- `REDIRECT_NOT_IN_SCOPE` / `REDIRECT_INVALID` / `REDIRECT_LIMIT`
- `TARGET_BINDING_MISMATCH` / `AUTHZ_BINDING_MISMATCH` /
  `RESOLUTION_BINDING_MISMATCH` / `DIAL_BINDING_MISMATCH`
  (cross-stage identity divergence)
- `AUTHZ_NOT_LIVE` (inherited frozen code, re-asserted at entry)

`INCONCLUSIVE` (if kept) maps to `SCOPE_UNKNOWN`. No other codes
may be added without an architecture note.

## 22. Resource Limits

All frozen ceilings reused unmodified: `redirect_hops = 5` (§15
counting), `dns_answers = 8` inherited via 5C facts (5D never
re-resolves, so it never re-counts — but per-hop transport
observations obey the same cap by contract). 5D-specific bounds
(new, explicit): hostname ≤ 253 / label ≤ 63 (inherited from 5C
canonicalizer, re-asserted at policy compile); policy entry cap
(e.g. ≤ 1024 entries per program — generous vs current data,
fail-closed `SCOPE_POLICY_INVALID` above it, exact number frozen at
implementation); compiled-wildcard fan-out is O(entries), no
recursion (label-split compare, no backtracking regex — **regex is
banned from matcher implementation** to exclude ReDoS);
per-decision URL/Location input cap 2048 (matches current executor
truncation, but as reject-not-truncate); error strings ≤ 200 chars
via the shared scrubber pattern.

## 23. Audit / Evidence Boundary

Persisted per decision (audit trail, later evidence observation):
`evaluation_id`, decision, `failure_code`, matched rule ids/texts,
`canonical_target_hash`, `resolution_id`, `execution_id`,
`authorization_id`, `scope_lists_hash_current`, `evaluator_version`,
`evaluated_at`. Never persisted: secrets, credentials, nonces,
cookies, raw `Location` bodies, response content, full URLs with
query (log canonical authority + path hash, query redacted via the
5H-core scrubber — reuse it, no second redaction). Flow is one-way:
decisions may be observed by evidence; evidence never feeds back
into scope inputs (compile-time assertion: 5D module imports no
evidence/artifact/plan/matcher packages — import-scan tested).

## 24. Executor Handoff

```
5B Authorization ──(typed record, live)──→ 5C TargetResolver
      ──(TargetResolution, immutable)──→ 5D ScopeEvaluator
      ──(ScopeEvaluation ALLOWED + pinned dial)──→ 5E/5F/5G
```

Per boundary: INPUT (typed only, `TypeError` on dicts/text) /
OUTPUT (immutable record, deterministic id) / AUTHORITY (5B: store;
5C: inventory+DNS observation; 5D: policy) / REVALIDATION (each
stage re-checks prior bindings, never trusts them) /
HASH-BINDING (authz↔resolution↔decision↔policy-hash chain) /
FAILURE (closed codes, terminal for the execution). The executor
receives the canonical authority + validated path + pinned
addresses — never an arbitrary URL slot — and cannot bypass 5D
because 5E/5F/5G entry requires a `ScopeEvaluation` with
`decision == ALLOWED` whose `(authorization_id, execution_id,
resolution_id)` triple matches the execution context
(structural check in each translator; generic "execute this URL"
entry points are banned by test).

## 25. Existing Code Audit

| FILE | FUNCTION | CURRENT BEHAVIOR | SECURITY RISK | 5D REQUIREMENT | FUTURE PHASE |
|---|---|---|---|---|---|
| `ai/verification/http_executor.py` `_check_redirect_safety` | cross-host redirect | allows same-eTLD+1 sibling hosts | **HIGH — F-02 sibling escape**; also reflects raw `target_host` into errors, raw-string `visited` cycle set, `int/""` port mix (F-08b), no userinfo/Location rejection | replace with §14 per-hop evaluator; canonical-URL visited set; closed errors | 5D (+5E transport) |
| `ai/verification/http_executor.py` `_send_following_redirects` | transport loop | no per-hop DNS/scope, re-resolves via session implicitly | F-03/F-09: rebinding window | pinned-dial transport + per-hop 5D re-evaluation | 5E |
| `ai/verification/browser_executor.py` nav + `_resolve_redirect` | navigation | exact-origin `context.route` + audit (strong), but `urljoin` without canonicalize, route as primary IP control | route policy must be defense-in-depth behind pinned `--host-resolver-rules`/proxy (§13 arch) | 5D same-origin-per-hop rule aligns; transport pinning required | 5G |
| `ai/researcher/nuclei_runner.py` (+ binary) | scan launch | no redirect/DNS controls visible in wrapper; binary owns its stack | HIGH: binary-initiated DNS/redirects bypass all wrapper checks (F-05 2nd half) | egress proxy/namespace forcing + per-execution pinning | 5F (B19) |
| `ai/verification/xss_case_builder.py` `_host_in_scope` | scope check | eTLD+1 inclusion + exact ooscope (correct for triage, wrong for authority) | MEDIUM: pattern reused as authority would inherit sibling escape | retire from execution path; keep for candidate triage only | 5D |
| `ai/collectors/discovery.py:30`, `reference.py:84`, `correlator/http_fingerprint.py:170` | recon fetch | `follow_redirects=True` | MEDIUM if reused by executors (SSRF/escape primitives) | isolate: recon-only, never executor transport | 5E |
| `database/db.py:29-31` `get_domain_name` | suffix parse | live `tldextract.extract` (network-capable) + bare `f"{domain}.{suffix}"` (dotless/IP inputs yield garbage-matchable strings) | LOW for 5D (not on path) but policy-adjacent | 5D uses offline 5C canonicalizer only | 5D |
| `database/db.py:36-38` | connect | hardcoded credentials in source (F-11 adjacent) | HIGH (credential incident surface; resolver-process dumps) | 5D/5C read via credential-injected connection owned outside evaluator; connection strings never in audit | ops + Mongo adapter phase |

Nothing above is fixed in this phase (read-only by mandate).

## 26. Security Invariants

1. Scope authority is deterministic (pure function of
   {live authz, 5C facts, fresh policy} + caller `now`).
2. Scope is always program-scoped; global evaluation is
   unrepresentable.
3. Exact-host semantics explicit; eTLD+1 never authorizes (import
   ban tested).
4. Canonicalization precedes comparison and never expands scope
   (no substring fallback exists).
5. Wildcards are label-aware, single-level, apex-excluding,
   suffix/IP-safe.
6. Exclusion is absolute; conflicts resolve to DENY with both rules
   recorded.
7. Scope drift (authz hash ≠ current hash, or mid-chain change)
   cannot silently pass.
8. `TargetResolution` is required input; raw URLs/Host headers are
   not inputs at all.
9. 5D never performs DNS; multi-address rule is ALL-must-pass.
10. 5C-unsafe addresses stay denied (re-asserted, dual-gated).
11. Every redirect hop is independently evaluated; sibling hosts
    never inherit approval.
12. CDN/CNAME/IP/ASN/cert/org facts never authorize (no registry →
    no exception).
13. Evidence, TI, matcher, plans, LLM output cannot cause ALLOWED
    (not inputs; import-scan enforced).
14. Executors cannot bypass 5D (ALLOWED triple required at each
    translator; no generic URL entry point).
15. Decisions immutable, deterministic ids, verdict-field-free.
16. Errors closed, bounded, secret-free (shared scrubber).
17. Dial-time address must equal scope-evaluated address
    (transport-enforced, 5E/5F/5G tests assert).
18. Cross-program confusion impossible (pair-keyed policy access).
19. Stale policy cannot silently authorize (fresh-read + hash bind
    + per-hop re-assertion; no security-sensitive cache).

## 27. Adversarial Review

Attack → precondition → control → enforcement → expected result
(B = blocked by this architecture; D = deferred to named phase):

1. **SSRF** → needs allowed-but-internal target → dual-gate (§11,
   §12) → 5C-unsafe DENY even if host-listed → **B**.
2. **localhost** (`localhost`, `127.0.0.1`, `0x7f.0.0.1`,
   decimal/octal forms) → 5C canonical→IP + unsafe-DENY before 5D;
   5D re-denies IP candidates → **B** (defense in depth).
3. **Metadata service** (`169.254.169.254`, `metadata.google*`) →
   link-local DENY + denied-token list → **B**.
4. **Private network** (RFC1918, CGNAT, `100.64/10`) → non-global
   DENY → **B**.
5. **IPv6 bypass** (`::1`, `fe80::/10`, `fc00::/7`, `::`) →
   classification DENY; textual variants converge canonically → **B**.
6. **IPv4-mapped** (`::ffff:10.0.0.1`) → unfolded + inner policed
   at 5C; 5D matches IPs only against IP rules (none by default) →
   **B**.
7. **Wildcard bypass** (`evil-example.com` vs `example.com`;
   `*.example.com` vs apex/depth) → label-compare, no suffix match,
   single-level, apex excluded → **B**.
8. **eTLD+1 bypass** (sibling under one registrable domain) →
   exact-host + import ban; legacy rule retired → **B** (F-02
   closed).
9. **Sibling-host redirect** (`api` → `evil`, same eTLD+1) →
   per-hop independent evaluation → DENY → **B**.
10. **CDN bypass** (CNAME/provider host/same IP) → never inferred;
    no registry → DENY → **B** (safe default).
11. **Cross-program confusion** (same host, program B) →
    pair-keyed policy + authz program bind → DENY → **B**.
12. **Scope drift** (T0 issue → T1 change → T2 execute) → hash
    compare at entry + per-hop re-assertion → `SCOPE_DRIFT` → **B**.
13. **DNS rebinding** (A approved → B dialed) → pin + invariant +
    transport enforcement contract → **B** iff 5E/5F/5G implement
    §13 (asserted there; **D-5E/5F/5G** for the mechanism).
14. **Redirect chain escape** (loop/limit/scheme/port smuggling) →
    canonical visited-set, 5-edge cap, per-hop gates → **B**.
15. **URL parser confusion** (userinfo, `//host`, `%2e`, backslash,
    empty host) → canonicalizer rejects + hop validation DENYs →
    **B**.
16. **Unicode/IDNA confusion** (homoglyph, mixed-script, case/dot)
    → canonical convergence or reject; policy compiled to A-labels
    → **B**.
17. **Port confusion** (`:443` vs omitted, `:8443`, cross-port
    redirect, `int/""` mix) → effective-port identity + allowlist +
    cross-port DENY → **B** (F-08b closed).
18. **Scheme confusion** (downgrade/upgrade, non-http(s)) →
    allowlist + downgrade DENY + no auto-upgrade → **B**.
19. **Path confusion** (`/api` vs `/api/`, traversal, encoding) →
    path is not host authority (§10 arch: host-only policy +
    executor path equality); traversal rejected at artifact
    validation → **B**.
20. **Stale-policy execution** (cached lists) → no sensitive cache;
    fresh-read + hash → **B**.
21. **Authorization confusion** (expired/consumed/revoked/forged/
    wrong-triple) → liveness re-assertion + binding checks → DENY →
    **B**.
22. **TOCTOU** (change mid-chain, DNS change post-5C, expiry
    mid-flight) → per-hop re-read/re-resolve/abort; residual window
    bounded by short chains + recorded hashes → **B** (mechanism
    **D-5E/5F/5G** for dial-time half).

## 28. Implementation Plan

5D.1 — Compiled policy representation: `ScopePolicy{program_name,
rules: tuple[HostRule|WildcardRule], exclusions, version, policy_hash}`
+ strict parser over stored lists (malformed → `SCOPE_POLICY_INVALID`;
empty-string entries rejected; IDNA compiled once). Fuzz the parser.
5D.2 — Deterministic label-aware host matcher (no regex, no
`endswith`; IP candidates refused by host matcher). 5D.3 —
Absolute-exclusion precedence + matched-rule recording. 5D.4 —
Initial-target evaluation (authz + resolution + policy binding
checks, §17–§18). 5D.5 — Address-gate evaluation (ALL-must-pass,
dual safety/scope). 5D.6 — Redirect/per-hop chain evaluator
(canonical join, visited-set, 5-edge cap, per-hop policy re-read).
5D.7 — Binding + hash layer (ids, hash compare, liveness
re-assertion). 5D.8 — Immutable `ScopeEvaluation` contract +
`scope_view`-style projection for 5E/5F/5G. 5D.9 — Adversarial
suite (§30 test strategy) + eTLD+1-absence + no-verdict + offline
import scans. Each step lands with its tests; no step enables
transport.

## 29. Test Strategy

Offline `unittest` (mirroring 5B/5C style), all deterministic with
fake policy accessor + fake 5C facts: canonicalization
(re-canonicalize equality; case/dot/IDNA/malformed/IP/mapped);
exact-host (exact/sibling/parent/child matrices); wildcard (one
label, depth, apex, suffix-entry rejection, malformed, IP vs
wildcard, `evil-` prefix negative); program isolation (same host
two programs; missing/empty policy); precedence (exact/wildcard ×
in/out conflicts → DENY + both rules recorded); scheme/port
(http/https, 80/443/8443, downgrade, cross-port hop); IP
(compile-rejection default; mapped/unsafe negatives); drift
(unchanged/changed hash, mid-chain change abort); redirect
(same-host, sibling, OOS, scheme/port/IP hop, loop, 6th-edge
limit, malformed/userinfo Location); authorization (wrong
program/target/resolution/execution, expired/consumed/revoked,
forged shape); TOCTOU (policy/target/resolution change matrices);
boundary (forbidden-field scan, no-evidence-import scan, no-network
import scan, no-LLM import scan, eTLD+1-absence scan).

## 30. Open Questions

- **O1. Precedence sign-off (B1).** Fact: absolute exclusion chosen.
  Safe default: DENY on conflict (already the rule). Matters: it
  may deny intended apex/subhost combos. Blocks: 5D implementation
  acceptance (operator must ratify).
- **O2. Wildcard demand (non-blocking).** Fact: zero wildcards in
  data. Default: supported-but-unused strict semantics (§7).
  Matters: avoids over-permissive future entries. Blocks: nothing.
- **O3. IP/CIDR grant (B2).** Fact: none in data. Default:
  compile-reject. Matters: any future IP program needs a typed
  grant + prefix bounds. Blocks: IP-scoped programs only.
- **O4. Scheme/port policy schema (non-blocking).** Fact: host-only
  data. Default: 5C-resolved + allowlist (§10). Matters:
  `:8443`-style programs need explicit entries later. Blocks:
  non-standard-port programs (deny-by-default until schema lands).
- **O5. Path scope (non-blocking).** Fact: no path scope exists
  (5B `path_scope` is a binding echo, not policy). Default:
  unsupported; paths never authorize hosts. Matters: prevents path
  strings becoming host authority. Blocks: nothing.
- **O6. Policy version authority (non-blocking).** Fact:
  `scope_policy_version` string + content hash both bound.
  Default: content hash decides, version is audit. Matters:
  version-string games can't override bytes. Blocks: nothing.
- **O7. CDN registry (non-blocking).** Fact: none exists. Default:
  no exception. Matters: safe until a typed registry is designed.
  Blocks: CDN-alias programs only.
- **O8. Atomic snapshot mechanism (B3).** Fact: read-fresh +
  hash-bind specified. Default: per-evaluation re-read; single
  shared Mongo read + in-memory hash compare. Matters: multi-worker
  races need a defined primitive. Blocks: 5J multi-worker
  enablement (single-process 5D implementation may proceed).
- **O9. Per-hop resolution owner (non-blocking).** Fact: contract
  specified (§15), implementer unassigned. Default: transport
  resolves, 5D evaluates. Matters: avoids double-DNS divergence.
  Blocks: 5E/5F/5G design acceptance.
- **O10. Dial topology (non-blocking).** Fact: pinned-dial vs
  egress-proxy both satisfy §13. Default: pinned-dial for HTTP,
  forced-egress for Nuclei/browser-binary. Matters: binary stacks
  can't self-constrain. Blocks: 5F/5G transport design.

## 31. Blocking Decisions

- **B1 (ratification):** absolute-exclusion precedence — resolved
  in §8, requires operator sign-off at 5D implementation review.
- **B2 (grant-gated):** IP/CIDR scope rejected by default —
  implementation proceeds; IP-scoped programs stay denied until an
  explicit typed grant lands.
- **B3 (mechanism):** atomic policy-snapshot primitive for
  multi-worker futures — single-process 5D proceeds on
  read-fresh + hash-bind; 5J must present the primitive before
  multi-worker execution.

No BLOCKING item prevents starting 5D implementation; all three
are closed or safely defaulted within it.

## 32. Final Architecture Verdict

**ARCHITECTURE READY FOR IMPLEMENTATION**

5D is specified as a pure, centralized, exact-host evaluator over
5C canonical facts and freshly-read hashed policy, with absolute
exclusion, label-aware single-level wildcards, host-only policy +
explicit scheme/port defaults, no IP scope without grant, zero DNS
of its own, per-hop redirect re-evaluation with canonical loop
detection and a 5-edge cap, full authorization/hash binding, a
verdict-free immutable decision contract, closed failure codes,
frozen ceilings, one-way audit flow, and a 22-attack adversarial
closure table. The legacy eTLD+1 execution path (F-02) is retired
by this design; the dial-binding enforcement half (F-03) is
contracted to 5E/5F/5G with test-assertable invariants. Proceed to
5D implementation per §28, in order, with §29 tests landing per
step.

REPORT:
 /opt/watch/agent-reports/scope-evaluator-architecture.md
