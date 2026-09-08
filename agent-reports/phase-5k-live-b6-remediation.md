# Phase 5K-live B6 — Live Egress Boundary Remediation

**STAGE:** Phase 5K-live B6 — Live Egress Boundary Remediation (implementation, offline verification only)
**Date (UTC):** 2026-09-07
**Input:** B5 NO-GO verdict (5 blockers).
**Live Egress Status: DISABLED** (unchanged; no egress gate opened by this stage)
**Method:** Static implementation + offline tests only. No real target invoked, no external network traffic generated, no Nuclei scan executed, no browser/LLM/Mongo touched. The only Nuclei invocations were local, target-less flag/version probes (`-h`, `-version`, bare single flags) with proxy blackholing (`HTTP(S)_PROXY=http://127.0.0.1:9`) so no external traffic was possible. No git operations performed.

---

## Implemented

Exact files changed (nothing else touched):

| File | Change |
|------|--------|
| `ai/execution/nuclei_executor.py` | B6-A version contract (`PINNED_NUCLEI_VERSION`, `SUPPORTED_NUCLEI_FLAGS`, `parse/require/check` functions); B6-B corrected frozen argv + `assert_frozen_argv_supported` |
| `ai/live_validation/lane.py` | B6-C resolver injection (`resolver` param), `LIVE_RESOLVER_REQUIRED` gate in live mode, `_resolve_addresses` (resolve-once + `validate_answers` + honest provenance) |
| `ai/execution/pinned_peer.py` | NEW — B6-D `prove_pinned_peer` transport adapter (egress check → IP-literal dial → peer proof → TLS/SNI bind → dial proof) |
| `ai/execution/nuclei_launcher.py` | NEW — B6-E environment gates + B6-F bounded process runner, rlimit accounting, sandbox gate, `LIVE_LAUNCH_ENABLED=False` |
| `ai/test_b6_remediation.py` | NEW — 37 offline tests covering all 16 B6-G cases |
| `ai/test_live_validation.py` | Updated: live-mode tests inject `FakeDnsResolver` (`_live_resolver` helper); B4 containment assertions corrected to real flag names; retry/concurrency assertions added |
| `ai/test_nuclei_executor.py` | Updated: `test_exact_argv_shape` to the corrected frozen argv |

`WATCH_AI_LIVE_VALIDATION` untouched (default false). `LIVE_NUCLEI=False` untouched. Both live runners still raise `NUCLEI_EXECUTION_BLOCKED`. No production network/DNS/subprocess path enabled.

---

## B1 — Version pin + corrected redirect containment

**Pinned version: `v3.11.1`** (`PINNED_NUCLEI_VERSION`, server-side constant; "latest" never accepted; caller cannot choose — no parameter, env var, or artifact influences it).

**How support was proven (local authoritative evidence, no network):**
- Environment binary reports `Nuclei Engine Version: v3.11.1` (`-version`, offline).
- Full `-h` flag table captured locally (proxy-blackholed).
- Per-flag acceptance probes on the same binary, each flag alone, offline, no target:
  - **Accepted:** `-disable-update-check`, `-disable-redirects`, `-no-interactsh`, `-silent`, `-no-color`, `-stats-interval`, `-jsonl`, `-bulk-size`, `-concurrency`, `-timeout`, `-retries`, `-restrict-local-network-access`, `-t`, `-u`, `-nc` (value forms `-retries 0`, `-concurrency 1`, `-timeout 5`, `-bulk-size 1`, `-stats-interval 0` each accepted).
  - **Rejected (`flag provided but not defined`): `-no-redirects`, `-disable-interactsh`, `-json`.**
- Consequence: **B4's frozen argv contained three fictional flags.** `-no-redirects` and `-disable-interactsh` are not Nuclei flags in v3.11.1 (goflags fatals on unknown flags), so B4's B1/B3 "containment" never constrained any real release. B6 corrects them (below). This is recorded in-code (`SUPPORTED_NUCLEI_FLAGS`, contract note) and asserted by tests.

**Fail-closed gates (pure, injected-output testable):** `parse_nuclei_version` (strict `Nuclei Engine Version: vX.Y.Z` match; anything else → `NUCLEI_RUNTIME_UNSUPPORTED`), `require_pinned_nuclei_version` (any skew incl. newer → same code), `check_nuclei_runtime(binary_present, version_output)` (missing binary → same code). Wired into the launcher: presence probe → version probe (`-disable-update-check -version`, minimal `PATH`-only env, bounded timeout) → pin check, in that order.

**Corrected frozen argv** (`build_nuclei_argv`): `-disable-update-check -disable-redirects -no-interactsh -silent -no-color -stats-interval 0 -jsonl -bulk-size 1 -concurrency 1 -timeout 5 -retries 0 -restrict-local-network-access -nc`, fixed binary, scratch-confined `-t`, canonical `-u`. `assert_frozen_argv_supported` cross-checks every `-flag` against the proven set, denies redirect-enabling flags (`-follow-redirects/-follow-host-redirects/-max-redirects` + shorts), and requires exact `-bulk-size 1/-concurrency 1/-timeout 5/-retries 0` + `-disable-redirects` presence. Redirect budget is therefore **zero with a real flag**, proven on the pinned release.

---

## B2 — Resolution → IP pinning → peer verification flow

**Lane (B6-C):** `ControlledLiveValidationLane(resolver=...)` accepts a reviewed `DnsResolver`-shaped source (`FakeDnsResolver` offline; `ProductionAddressSource` for activation). New flow per execution: canonical host → **exactly one `resolve()`** → **`validate_answers`** (dns_answers ceiling 8, whole-set failure on unsafe/malformed, deterministic numeric order, empty sets fail) → `DialBinding`/scope/egress. Provenance is the resolver's own `name` (must be non-empty; else fail closed); the mapping fallback keeps the honest `live-validation-address/v1` label. **Live mode without a resolver is structurally refused** (`resolution/LIVE_RESOLVER_REQUIRED`) — `dns_mapping` can never authorize live execution; it remains a dry-run/test-only fallback through the same `validate_answers` gate.

**Transport (B6-D, `ai/execution/pinned_peer.py::prove_pinned_peer`):** reuses only reviewed abstractions — `check_egress_dial` (exact triple match first: no policy, no SYN) → `LiveSocketFactory.connect(selected_address, …)` (**IP literal only**; `require_ip_literal` rejects hostnames before any socket exists — re-resolution is unrepresentable, no resolver/DNS/proxy input exists on this path; `isinstance` admission refuses foreign factories) → `verify_socket_peer` (kernel `getpeername` equality) → https: `LiveTlsWrapper.wrap(sni_host=canonical_host)` (system CA, `CERT_REQUIRED`, hostname verification; IP SNI refused) + **post-handshake re-verification** of the peer → `assemble_dial_proof` + `assert_dial_matches_egress` binding peer to policy/resolution/evaluation/authorization lineage. http: no TLS performed, plaintext marker recorded, SNI intent still pinned. Socket closed on every path. Returns the verified `DialProof`.

**Reported architectural blockers (not worked around):**
1. `build_egress_policy` admits only `http_probe` (`FORBIDDEN_EXECUTION_CLASS`), so **no `EgressPolicy` — and therefore no peer proof — can exist for `nuclei_scan` lineage** until B3 admits the class under its own review (proven by test: nuclei authz → `FORBIDDEN_EXECUTION_CLASS`). The prover refuses to bypass this gate.
2. The Nuclei child (`-u <hostname>`) resolves independently via its internal resolver (v3.11.1 offers only `-r`/`-sr`; SNI defaults to input domain) with no FD-passing/dial-hook interface, so the child cannot be forced through the proven socket — subprocess containment additionally needs the netns egress allowlist, which remains ungated (see below).

---

## B3 — Argv + sandbox + resource enforcement

- **Argv:** as in B1 plus explicit `-retries 0` (upstream default is 1 — B5-N1 closed), `-concurrency 1` (default 25), `-restrict-local-network-access` (binary-level SSRF guard: refuses local/private destinations inside the child). `assert_single_target_argv` additionally enforces exactly one `-u` (http/https) and one `-t` (scratch-confined): no second request or destination is representable.
- **Bounded process (`run_bounded_process`):** `shell=False` only (string commands rejected — tested); wall-clock `communicate(timeout)` → kill + wait → `SUBPROCESS_TIMEOUT` (kill verified by test); stdout/stderr caps → `SUBPROCESS_OUTPUT_LIMIT`; rlimit ceilings (AS/CPU/NPROC/NOFILE/FSIZE) applied in-child via `preexec_fn` where POSIX supports them, with honest `AppliedLimits(applied, unavailable)` accounting — only `applied` entries may be claimed.
- **Sandbox gate (`require_production_sandbox`):** admits only mode `production-netns`; the only existing B3 mode (`dry-run-blocked`, creates nothing) is refused with `SANDBOX_UNAVAILABLE`. Production netns/veth/nftables/cgroup provisioning is **not implemented in B6 — deliberately**: the gate refuses rather than pretends. No kernel-level enforcement is claimed.
- **Master switch:** `LIVE_LAUNCH_ENABLED = False` (frozen literal); `launch_nuclei_bounded` runs env → binary → version → argv → digest → sandbox → switch, and cannot pass gates 6–7 today. **Live egress stays DISABLED structurally.**

---

## Environment Boundary

- `require_clean_launch_environment(snapshot)`: reuses `egress_guard.check_environment` (proxy/PAC/WPAD shapes, any case, presence-including-empty → `PROXY_DETECTED`) plus closed denylist `FORBIDDEN_LAUNCH_ENV_VARS` (`HOSTALIASES`, `LOCALDOMAIN`, `RES_OPTIONS`, `GODEBUG`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` → `FORBIDDEN_ENVIRONMENT`). No override parameter. Entries type-checked (non-string keys/values fail closed).
- Child receives **only** the explicit allowlist (`build_nuclei_environment`: `HOME/LANG/LC_ALL/PATH/TMPDIR` — verified to contain no proxy/forbidden names and to pass the gate itself). The version probe inherits only `{"PATH": "/usr/bin:/bin"}` with update-check disabled on the probe command line.
- Residual note: denylist matching is exact-case (these names are case-sensitive on the platform; lowercase variants are inert for libc/OpenSSL/Go). Documented, not hidden.

---

## Tests

Exact commands and results (all offline; no network/DNS/subprocess-against-target/LLM/Mongo):

- `python3 -m unittest ai.test_live_validation` → **73 tests OK** (includes updated live-mode resolver injection + corrected flag assertions).
- `python3 -m unittest ai.test_nuclei_executor ai.test_b3_boundary ai.test_evidence_core` → **264 tests OK**.
- `python3 -m unittest ai.test_b6_remediation` → **37 tests OK** — maps to the 16 B6-G cases: (1) wrong/newer/unparsable version fail closed; (2) missing binary fail closed; (3) `-retries 0` in argv; (4) upper/lower/empty proxy + all 9 resolver/CA vars fail closed, clean+allowlist pass; (5) safe set accepted; (6) mixed set rejected; (7) empty set rejected; (8) foreign peer → `PEER_MISMATCH`; (9) pinned peer accepted with dial record `[(IP_A, 443)]`; (10) hostname dial raises, dial log stays empty; (11) SNI log == canonical host, `proof.tls_sni` == host ≠ IP; (12) `-disable-redirects` present, enablers absent, single `-u`; (13) `-retries 0`/`-concurrency 1`/`-bulk-size 1`, single `-t`; (14) over-cap output → `SUBPROCESS_OUTPUT_LIMIT`, within-cap passes; (15) hanging child → killed + `SUBPROCESS_TIMEOUT`; (16) `policy=None` and `dry-run-blocked` spec → `SANDBOX_UNAVAILABLE`, full `launch_nuclei_bounded` refuses at the sandbox gate with `LIVE_LAUNCH_ENABLED=False`. Plus: live-without-resolver → `LIVE_RESOLVER_REQUIRED`; over-ceiling (9 answers) rejected; deterministic ordering; resolver provenance; foreign-adapter refusal; wrong-authorization refusal; genuine http plaintext proof; string-command (shell) rejection; nuclei-class egress-policy refusal documented by test.
- Directly-affected wider set (`ai.test_b1_dial_policy ai.test_b3_validation ai.test_target_resolver ai.test_scope_evaluator ai.test_execution_authorization ai.test_http_executor ai.test_http_pinned_executor ai.test_research_cli ai.test_pilot_readiness ai.test_legacy_severance_5k`) → 579 tests, 1 failure + 4 skips: the failure (`test_location_secret_redacted_in_chain`, http_probe redirect chain, `REDIRECT_INVALID`) is in code this stage did not touch (`http_executor` imports neither the lane nor the nuclei modules — verified by import scan) and reproduces from the pre-existing dirty working tree; the 4 skips are pre-existing.
- `ai.test_nuclei_cve_2026_1557_dryrun ai.test_nuclei_offline_prepare` → same 2 pre-existing failures B4 documented (research-track `version`-string and stored-template artifacts outside B6 scope).

---

## Remaining Blockers

Anything still not actually enforced (explicit; no substitute created):

1. **B3 class admission:** `build_egress_policy` refuses `nuclei_scan` (`FORBIDDEN_EXECUTION_CLASS`) — peer proof cannot serve Nuclei lineage until B3 admits the class under its own review.
2. **Subprocess dial forcing:** the Nuclei child resolves hostnames independently; containment needs the provisioned netns egress allowlist (`(approved_address, port, tcp)` only) — not built in B6; sandbox gate refuses.
3. **Production resolver wiring:** operator must inject `ProductionAddressSource` (pinned server IPs + `dns_tcp_exchange`) at activation; `research_cli` still constructs the default lane (live → fail-closed `LIVE_RESOLVER_REQUIRED`, which is the safe default).
4. **Output-cap shape:** stream caps are enforced post-`communicate` (parent-side buffering before the check); a streaming cap reader is follow-up work. Child-side `RLIMIT_AS` bounds the child, not parent buffers.
5. **`rlimit` accounting:** `AppliedLimits` records names of applied vs unavailable ceilings; where the platform hard-limit is lower than requested, values clamp down — recorded as applied-by-name (values not individually attested).
6. **Carried non-blockers:** far-future lane authz expiry + deterministic clock (B5-M3/C), operator-trust documentation/audit logging (B5-M1/B), `-stats-interval 0` disable-semantics (carried, pre-existing), H1 JSON-shape redaction gap (unchanged by B6 scope — flagged for its own stage).
7. Pre-existing failures unrelated to B6 (listed in Tests) remain with their owning tracks.

---

## Live Egress Status

**DISABLED**

Do not declare GO: socket-level pinning is proven only for the reviewed transport (not yet admittable for `nuclei_scan` lineage), the Nuclei child cannot be forced through the proven socket, and the network sandbox is refused-by-design until provisioned. Three independent structural gates keep egress closed: live runners raise `NUCLEI_EXECUTION_BLOCKED`, the launcher refuses at `SANDBOX_UNAVAILABLE`/`LIVE_LAUNCH_DISABLED` with `LIVE_LAUNCH_ENABLED=False`, and live lane runs require an injected reviewed resolver. The next stage must provision the netns boundary, admit (or re-scope) the execution class under B3 review, wire the production resolver, and re-review the unblock diff itself.

---

## Confirmations

- No live egress enabled; `WATCH_AI_LIVE_VALIDATION` default untouched; no real target invoked; no external network traffic (local probes proxy-blackholed); no Nuclei scan executed; no browser/LLM/Mongo/production-data contact.
- No unrelated pre-existing work modified (NS/DNS, crawl, database, Nuclei/CVE research tracks untouched). No git operations performed (no commit/stash/push; no status/diff commands run under the B6 no-git constraint — change set is exactly the 7 files listed above).
- B6-H self-review of the change set for hostname fallback, alternate DNS, proxy inheritance, shell invocation, redirect/retry fallback, unsafe addresses, peer/TLS mismatch, caller-controlled parameters, env injection, and limit bypass: all gates verified in code and covered by the 37-test module (findings: none open; residuals listed above).
