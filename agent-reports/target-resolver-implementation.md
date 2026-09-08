# Phase 5C — Target Resolver
# Implementation Report

## 1. Verdict

**IMPLEMENTED AND VERIFIED**

All Phase 5C requirements are implemented per the approved read-only
architecture, with 110 new deterministic offline tests passing and
1074 existing tests regressed green. No live execution surface was
added. One architecture-vs-reality note (§2, conflict C1) was
resolved without inventing security-sensitive behavior; no blockers
remain.

## 2. Files Created

| File | Purpose |
|---|---|
| `ai/schemas/target_resolution.py` | `TargetResolution` / `DialBinding` / `ResolutionRequest` contracts, closed error vocabulary, deterministic identity helpers |
| `ai/resolver/__init__.py` | Phase 5C package boundary + exports |
| `ai/resolver/canonicalization.py` | Fail-closed host/scheme/port canonicalizer (arch §18) |
| `ai/resolver/dns.py` | `DnsResolver` DI interface, `FakeDnsResolver`, IP-safety classification, answer-limit enforcement |
| `ai/resolver/inventory.py` | `InventoryRepository` DI protocol, `InMemoryInventoryRepository`, read-only program/asset records |
| `ai/resolver/resolver.py` | `TargetResolver.resolve()` pipeline (authz gate → canonicalize → inventory → DNS → immutable record) |
| `ai/test_target_resolver.py` | 110 deterministic offline tests incl. 18 adversarial cases |

## 3. Files Modified

**None.** Zero modifications to existing code. No additive changes to
frozen contracts were needed: 5C reuses `ai.evidence.hashing`
(`hash_payload`), `ai.evidence.scrubber` (`contains_secret_shape`),
`ai.limits.ceilings` (`dns_answers`), `ai.evidence.handoff`
(`require_live_for_execution`), and the 5B issuance boundary
(`IssuedExecutionAuthorization`, `InMemoryAuthorizationStore`) by
import. `database/db.py` untouched; no writes anywhere.

Architecture-vs-reality conflicts encountered (all resolved without
invention):

- **C1 — No standalone "Phase 5C architecture report" exists.**
  `agent-reports/` contains no 5C-titled document. The 5C contract was
  derived from the three frozen sources that normatively define it:
  `executor-architecture.md` §6 (resolution protocol) + §23 (5C phase
  scope), `execution-authorization-architecture.md` §§13–18
  (isolation key, re-resolution, scope/DNS/canonicalization rules),
  `evidence-core-architecture.md` G-5C. Nothing was implemented that
  these sources do not describe.
- **C2 — DNS lives in 5C observation, enforcement in transport.**
  The architecture resolves DNS "at request time by the transport"
  (§6.2) with 5C treating DNS-vs-inventory as advisory, while the
  phase task requires a 5C DNS abstraction. Resolution: 5C implements
  the resolution-time **observation + pinning** half (injected
  interface + deterministic fake, safety classification, ceiling);
  **dial-time enforcement** is structurally exposed (`DialBinding`)
  but explicitly deferred to 5E/5F/5G. No live adapter was written.
- **C3 — Scope-hash function undefined by 5B.** 5B binds an opaque
  `scope_lists_hash` string. Drift detection needs a canonical
  function, so 5C defines `scope_lists_hash_for()` (sorted lists over
  the shared `hash_payload`) as the single source of truth issuers
  must use. This is additive plumbing, not a policy invention.

## 4. Exact Scope

Implemented: canonical target identity, fail-closed canonicalization,
scheme/port rules, `(program, host)` isolation, read-only inventory
boundary (DI protocol + in-memory fake), DNS observation abstraction
(DI interface + fake only), DNS safety classification, DNS answer
ceiling, closed error vocabulary, live-authorization binding,
snapshot advisory binding, immutable `TargetResolution`, dial-binding
exposure, 5D handoff projection, deterministic offline tests.

Explicitly NOT implemented (per §0): 5D–5J, scheduler, queue, live
findings, CONFIRMED/NOT_VULNERABLE, classification, automatic scope
authorization, live DNS adapter, Mongo adapter, Mongo writes,
redirect handling, LLM use, any network/subprocess/browser use, any
executor wiring.

## 5. Target Identity

Canonical identity is the exact tuple
`(program_name, canonical_host, scheme, effective_port)` hashed via
`canonical_target_hash_for()` (SHA-256 over canonical JSON, shared
5H-core `hash_payload` — no duplicate hashing). The record
explicitly separates `program_name`, `host_as_authorized` (secret-
scrubbed echo), `canonical_host`, `host_kind` (dns/ipv4/ipv6),
`scheme`, `effective_port`, `resolved_addresses`, `base_authority`,
and `path_scope_ref` (descriptive 5B echo; query strings are never
part of resolution). Effective-port-only hashing makes
`https://host` ≡ `https://host:443` structurally (tested). No
implicit scheme upgrade or port rewrite exists anywhere.

## 6. Canonicalization

`ai/resolver/canonicalization.py` (pure stdlib `re` + `ipaddress`):
lowercase, single trailing-dot strip (double-dot fails),
std-lib IDNA (`UnicodeError` → reject), per-label validation
(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`, ≤63/≤253), and rejection of
empty input, any whitespace/control byte (never trimmed), `@`
(userinfo), `*` (wildcard), `/ ? #` and port-like `:` suffixes,
`%` zones, malformed brackets, and ambiguous numerics. Non-decimal
IP literals are policed as IPs per arch §17: `0x7f.0.0.1`,
`2130706433`, `0177.0.0.1`, `127.1` → `127.0.0.1`; numeric-looking
tokens that fail `inet_aton` rules (`999.999.999.999`, `1.2.3.4.5`,
`08.9.9.9`) are rejected, never guessed. IPv4-mapped IPv6 unfolds
to inner IPv4 at canonicalization time. All errors are static
value-free codes (`INVALID_HOST/SCHEME/PORT`).

## 7. Program Binding

The isolation key `(program_name, canonical_host)` is threaded
through every lookup; a host-only lookup is unrepresentable
(`get_asset(program, host)` — no global overload). Tests prove
`prog-a + shared.host` resolves prog-a's row while an identical
hostname under `prog-b` is invisible, unknown programs yield
`TARGET_PROGRAM_GONE`, and a host existing only under another
program yields `TARGET_GONE` (never borrowed).

## 8. DNS Architecture

`DnsResolver` protocol (`resolve(canonical_host) -> tuple[str, ...]`,
closed `DnsError`) with **no live implementation** — only the
boundary plus `FakeDnsResolver` (closed-world mapping; unknown hosts
→ `DNS_NXDOMAIN`; `localhost`/metadata aliases → always
`DNS_UNSAFE_ADDRESS`). Pipeline order per call: resolve → ceiling →
per-address classification → numeric sort/dedupe. Raw third-party
adapter exceptions collapse to `DNS_RESOLUTION_FAILED` with message
text discarded (proven by a `mongodb://…s3cret…` explosion test).

## 9. DNS Safety

`classify_address()` denies by explicit enumeration **plus**
`not is_global` backstop: private (incl. CGNAT `100.64/10`),
loopback, link-local, multicast (caught an `is_global=True` hole for
`224.0.0.1` found during development), reserved, unspecified,
documentation ranges, unique-local v6, scoped literals, and
IPv4-mapped inner addresses. Any-denied fails the whole set —
mixed safe/unsafe answers yield `DNS_UNSAFE_ADDRESS` with empty
addresses and null dial binding (no silent discard, no first-clean-
wins), exactly per arch §17.

## 10. DNS Rebinding Boundary

`RESOLVED` records pin resolution-time addresses and expose them as
`DialBinding{addresses, effective_port, sni_host,
pin_required=True}`. Documented invariant:
`RESOLVED ADDRESS == AUTHORIZED/DISPATCHED DIAL ADDRESS` — future
transport must dial a pinned address with SNI/Host preserved and
abort on re-resolution mismatch. Rotation across two resolutions is
tested to produce two distinct `resolution_id`s (never silent
sameness). Enforcement is **not claimed**: it belongs to 5E/5F/5G or
the egress layer.

## 11. Authorization Binding

`resolve()` accepts only `ResolutionRequest` carrying a genuine
`IssuedExecutionAuthorization` (dicts/JSON/strings/`None`/snapshots
→ `TypeError`; never coerced). Liveness is enforced first via the
frozen 5H-core `require_live_for_execution` (`AUTHZ_LIVE_FOR_
EXECUTION`): CONSUMED/REVOKED/expired → `AUTHZ_NOT_LIVE`, so a
consumed authorization never permits another resolution and replay
with a new execution id fails. `AUTHZ_VALID_FOR_PROVENANCE` is never
consulted. Binding forgeries surface as `SCOPE_DRIFT`/`TARGET_GONE`
(test 12). The resolver never consumes/revokes (no lifecycle
mutation; CAS authority stays with the 5B store at executor start).

## 12. Snapshot/Freshness

`snapshot_ref` (5B echo) / `snapshot_observed` (caller TI context) /
`snapshot_current` (inventory) produce advisory `snapshot_match` /
`snapshot_stale` flags that play **no role** in the `RESOLVED`
decision (tested: stale and mismatched snapshots still resolve when
live facts check out; absent hashes stay null). A bare snapshot hash
without a live authorization is not a valid request input
(`TypeError`). No TTLs invented.

## 13. TargetResolution Contract

Frozen pydantic (`frozen=True`, `extra="forbid"`), statuses
`RESOLVED | TARGET_GONE | TARGET_PROGRAM_GONE | TARGET_REASSIGNED |
SCOPE_DRIFT | RESOLUTION_FAILED`, closed `failure_code` only on
`RESOLUTION_FAILED` (`TARGET_MALFORMED`, `INVENTORY_ERROR`, six
`DNS_*` codes). Contains resolution/authorization/execution ids,
canonical identity, pinned addresses + dial binding, scope-hash pair
+ drift flag, inventory base + reassigned flag, snapshot triple,
timestamps/version/hashes. Contains zero verdict/scope/finding
fields (structurally forbidden + enumerated in tests).

## 14. Immutability

Frozen models; assignment to any field raises `ValidationError`
(tested for host/program/IP/authz/status/dial). No
replace/rebind/update/mutate API exists (asserted by attribute
scan). New target or new execution → new `resolution_id` via
`resolution_id_for()`; old records are never touched.

## 15. 5D Handoff

`TargetResolution.scope_view()` returns a facts-only mapping:
program, canonical host, scheme, effective port, pinned addresses,
current scope hash, current snapshot, DNS count, ids, status. No
verdict-shaped key present (asserted). 5D can independently deny a
`RESOLVED` record; 5C computes no `scope_allowed`/`execution_allowed`
(the names are in `FORBIDDEN_RESOLUTION_FIELDS`).

## 16. Executor Handoff

No wiring was added (forbidden). Read-only inspection found the
future integration points 5E/5F/5G must close: `ai/collectors/*` and
`ai/correlator/http_fingerprint.py` use `follow_redirects=True`
(intel-only paths — the executor transport must not reuse them);
`ai/verification/http_executor.py` already loops hops with
`allow_redirects=False` (right shape; needs dial-binding +
per-hop scope checks wired in 5D/5E); `xss_case_builder.py`
`get_domain_name` scope rule is registrable-domain-only (exact-host
extension is 5D's job). Nothing was fixed outside 5C scope.

## 17. Failure Model

Terminal inventory outcomes (`TARGET_GONE`, `TARGET_PROGRAM_GONE`,
`TARGET_REASSIGNED`, `SCOPE_DRIFT`) are self-describing records with
null `failure_code`; observation failures are `RESOLUTION_FAILED`
with the closed DNS/malformed code. Authz liveness failures raise
the frozen `AUTHZ_NOT_LIVE` (fail-closed, pre-resolution).
Programmer-shape errors raise `TypeError`/`ResolutionError
(INVALID_REQUEST)`. Adapter exceptions never leak text.

## 18. Resource Limits

`MAX_DNS_ANSWERS = CEILINGS["dns_answers"]` (= 8, read-only import —
ceilings unmodified); 9 answers → `DNS_TOO_MANY_ANSWERS`, 8 →
resolves (both tested). Hostname bounds (253/63), error-detail caps
(200), host-echo cap (253), secret screening via the shared
5H-core scrubber (no second redaction implementation). No retries,
recursion, CNAME chasing, or unbounded lists anywhere.

## 19. Security Invariants

1. Only a genuine, live 5B record starts resolution; provenance ≠ permission.
2. Canonical identity is `(program, host, scheme, port)` — nothing else is authority (not LLM, plans, TI, matcher, history, IPs, Host headers, redirects).
3. Inventory reads are pair-keyed and read-only (no write surface exists).
4. Addresses come only from fresh injected observation, pinned for dial; history (`ips_observed`) is advisory.
5. Mixed/oversized/unsafe DNS fails closed, never filtered to safe-looking.
6. Snapshots observe, never authorize. 7. Records immutable, never rebound.
8. Errors/findings/verdicts unrepresentable (extra-forbid + absence tests).
9. No secrets in errors/logs/records (value-free messages, host-echo scrubbing, secret screening).
10. Offline by construction (import-scan tested).

## 20. Tests

`ai/test_target_resolver.py` — **110 tests, all passing**
(`python3 -m unittest ai.test_target_resolver`): A canonicalization
(20) · B scheme/port (7) · C program isolation (4) · D DNS (17) ·
E authorization (9) · F snapshot (5) · G determinism (5) ·
H error safety (5) · I immutability (4) · J boundary (3) ·
K network isolation (2) · adversarial (18) · inventory outcomes (6) ·
record hygiene (4).

## 21. Regression Results

- `ai.test_execution_authorization ai.test_evidence_core ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter` — 265 tests OK
- `ai.test_artifact ai.test_artifact_store ai.test_artifact_retrieval ai.test_hypothesis_testplan ai.test_target_intelligence ai.test_target_matcher ai.test_test_plan_builder ai.test_hypothesis_engine` — 461 tests OK
- `ai.test_xss_oracle ai.test_test_plan_readiness ai.test_pattern_store ai.test_pattern_projector ai.test_research_pattern ai.test_knowledge_ingestion ai.test_xss_case_builder` — 348 tests OK

Total: **1074 existing tests pass, 0 failures.** No existing test was modified.

## 22. Adversarial Results

All 18 hostile cases fail closed: (1) Cyrillic-homoglyph host →
`TARGET_GONE`, never the real slot; (2) trailing dot converges, no
bypass; (3) case folds to one identity; (4) v6 textual variants
converge; (5) v4-mapped private → unsafe; (6) localhost alias →
unsafe; (7) private-via-DNS poisons whole set; (8) DNS rotation
changes resolution id, dial pins; (9) 11 answers → too-many; (10)
cross-program same host never borrows; (11) stale TI authorizes
nothing; (12) dict forgery dies by type, binding forgery → drift/gone;
(13) consumed replay → `AUTHZ_NOT_LIVE`; (14) sibling host is a
different slot; (15) no Host-header parameter exists; (16) bad ports
rejected at issuance; (17) http-vs-https drift → `TARGET_REASSIGNED`,
never silent downgrade; (18) credentials → `TARGET_MALFORMED` with
secrets scrubbed from the record.

## 23. Any Existing Failures

None. All 1074 pre-existing tests in the in-scope suites pass
unmodified. (Out-of-scope heavy/live suites such as
`test_real_research` were not run — they require network.)

## 24. Deferred 5D–5J Work

5D ScopeEvaluator + per-hop/redirect/DNS-shape verdicts; 5E/5F/5G
transports with dial-binding enforcement + egress proxying; live DNS
adapter; Mongo-backed `InventoryRepository`; issuer-side adoption of
`scope_lists_hash_for()`; 5H production EvidenceStore; 5I verifier
runtime; 5J scheduler/queue/E2E. The `InventoryRepository` protocol
is the contract the Mongo adapter must implement (pair-keyed,
read-only); the `DnsResolver` protocol is the contract a future
pinned live adapter must implement (single resolution per
execution, no unbounded retry).

## 25. Confirmation No Live Execution

Confirmed: no `requests`/`httpx`/`urllib`/`socket`/`ssl`/
`subprocess`/DNS-driver/LLM/Mongo-driver imports in any 5C module
(source-scan tested); `FakeDnsResolver` is the only `DnsResolver`;
`InMemoryInventoryRepository` is the only repository; no
requests/dial/connect/fetch/browser/Nuclei/curl code exists in 5C;
unit tests run fully offline in 0.06 s.

## 26. Confirmation No Git Operations

Confirmed: no git command (`status/diff/add/commit/log/branch/
checkout/push/…`) was executed during this phase. All changes are
uncommitted working-tree files listed in §2.

## 27. Final Verdict

**IMPLEMENTED AND VERIFIED**
