# Phase 5K-live B7: Production Egress Boundary — Implementation Report

Date: 2026-09-07
Workspace: /opt/watch (uid 1000, no CAP_SYS_ADMIN, no nft/iptables binary)
Companion: Phase 5K-live B6 remediation report (`phase-5k-live-b6-remediation.md`).

## Scope

B7 implements the production egress boundary for live Nuclei execution:
it admits `nuclei_scan` to the B3 `EgressPolicy` under a distinct policy
identity, derives a default-deny network-namespace allowlist from the
reviewed policy, and runs the Nuclei child only inside a verified,
freshly created namespace whose sole permitted egress tuples are the
approved `(ip, port, tcp)` destinations — with teardown on every path.

Constraints honored: no live egress was opened (`WATCH_AI_LIVE_VALIDATION`
was never set; `LIVE_LAUNCH_ENABLED` remains `False`). No real target,
external DNS, Nuclei binary, browser, LLM call, Mongo, or production data
was touched. No Git operations were performed. All tests are offline and
deterministic (stdlib `unittest`); the namespace materializer in tests is
a local fake backend; the one real-process test uses an injected popen
factory.

## Files Changed

- `ai/execution/b3_boundary.py` — B7-A policy admission + policy hash +
  sandbox-spec recording (edited).
- `ai/execution/netns_sandbox.py` — NEW: B7 sandbox module (policy→rules,
  capability probe, backends, lifecycle runner).
- `ai/execution/nuclei_launcher.py` — sandbox gate wiring + B8 seams
  (edited; `LIVE_LAUNCH_ENABLED=False` unchanged).
- `ai/test_b6_remediation.py` — B6-G case 10 updated: `nuclei_scan` now
  admitted under the B7 policy identity (the old "no egress policy"
  assertion was the B6 boundary this phase closes).
- `ai/test_b7_egress_boundary.py` — NEW: 39 B7-G/H tests.

## B7-A EgressPolicy

- `ADMITTED_EXECUTION_CLASSES = frozenset({"http_probe", "nuclei_scan"})`.
- New identity `NUCLEI_EGRESS_POLICY_VERSION = "b7-nuclei-egress/v1"`;
  `http_probe` keeps `B3_POLICY_VERSION`.
- `build_egress_policy` still refuses any class outside the admitted set
  (`FORBIDDEN_EXECUTION_CLASS`).
- For `nuclei_scan` the policy shape is explicit and narrow:
  - transport encoded `tcp`; scheme restricted to `http`/`https`;
  - exactly one target (single canonical host) and one approved
    destination at a time (the B3 dial still admits only the single
    `approved_address`);
  - `port == resolution.effective_port` (no ranges, no wildcards);
  - `allowed_addresses` = the full validated resolution set, every entry
    passed through `check_destination_allowed` (globally routable only:
    loopback, private, link-local, multicast, reserved, unspecified,
    metadata-169.254.169.254, and unparseable all fail closed);
  - lineage preserved through the policy: `authorization_id`,
    `resolution_id`, `execution_id`, `canonical_target_hash`,
    `artifact_id`, `artifact_hash`;
  - the caller cannot supply an approved address independently: every
    allowed address MUST already be inside the reviewed resolution, and
    the selected address MUST be a member of that set.
- `egress_policy_hash` now folds the new fields (execution_class,
  transport, canonical_target_hash, artifact_id, artifact_hash,
  allowed_addresses) into the audit identity.
- `check_egress_dial` and `acquire_sandbox` accept both policy versions;
  anything else is `STALE_EGRESS_POLICY`.
- `acquire_sandbox` records `mode="production-netns"` + the exact
  `egress_rules` tuple set only for the nuclei_scan shape; every other
  shape stays `dry-run-blocked` (preserves all B6 sandbox refusals).
- `test_nuclei_scan_admitted_under_b7_policy_identity` and the updated
  B6-G case 10 prove the shape end-to-end.

## B7-B DNS Bypass Resolution

The child's own DNS resolution is NOT relied on to pick the destination,
and Nuclei's argv is not manipulated to force it. Enforcement is
structural: the child runs inside a network namespace whose netfilter
default policies are DROP on OUTPUT and INPUT, with ACCEPT rules that
match only the exact `(allowed_ip, effective_port, tcp)` tuples. A
packet to any other destination — including whatever the child resolved
on its own, cached, or was pointed at by the caller — is dropped by the
kernel before it can leave. No resolver service is installed in the
namespace, no UDP egress is permitted, no unrestricted default route
exists, and no proxy/resolver env vars survive the launch gate. The
approaches the B6 review flagged (host `/etc/hosts`, "Nuclei should
resolve the same IP", caller resolver, env vars alone) are all rejected:
the invariant below holds because the ONLY permitted packet set is the
allowlist derived from the reviewed EgressPolicy.

## B7-C Network Sandbox

New module `ai.execution.netns_sandbox`:

- `netns_rules_for_policy(policy)` — pure, deterministic derivation of
  `NetnsRuleSet` from a `nuclei_scan` policy: re-validates every address
  (globally routable, rejects IPv4-mapped literals explicitly), requires
  transport `tcp`, scheme `http(s)`, a port in 1..65535, a non-empty
  allowlist, and `approved_address ∈ allowed_addresses`. Emits exactly
  one `ACCEPT` per allowed `(ip, port, tcp)` tuple plus explicit
  `DROP`s for metadata (tcp+udp), `udp/53`, and all `udp`. The rule set
  carries the flags `default_drop_output`, `default_drop_input`,
  `no_unrestricted_default_route`, `dns_unavailable`, and
  `loopback_only_inside` — all forced true.
- `check_nuclei_egress_dial(...)` — exact-match authorization of one
  sandbox egress tuple (address, port, transport, authorization_id,
  resolution_id); any deviation is `SANDBOX_EGRESS_DENIED`.
- `probe_netns_capabilities()` / `NetnsCapabilities` — local probe
  (`unshare -n true`, `ip` presence, `nft`/`iptables` presence). Fails
  closed: no capability ⇒ no materialization attempt.
- `NetnsBackend` protocol + `SystemNetnsBackend` — real materialization
  (`ip netns add/exec`, nft/iptables install, verification, teardown),
  `shell=False` throughout, every command failure raises a closed
  `SandboxError`. Never falls back to host networking.

## B7-D Rebinding Protection

Because egress is default-deny with an exact allowlist, a DNS rebind to
a loopback/private/metadata/link-local address cannot escape the
namespace: the kernel drops any non-allowlisted packet regardless of the
hostname the child used to reach it. `-restrict-local-network-access`
remains in the frozen argv as defense in depth. `require_default_deny`
+ `require_no_default_route` are enforced before every spawn and at
VERIFY.

## B7-E Nuclei Child Execution

The frozen argv produced by `build_nuclei_argv` is preserved exactly
inside the namespace (tests diff the spawned argv against it):
`-disable-update-check -disable-redirects -no-interactsh -silent
-no-color -stats-interval 0 -jsonl -bulk-size 1 -concurrency 1
-timeout 5 -retries 0 -restrict-local-network-access -nc` plus the fixed
binary, the scratch-confined `-t`, and the canonical `-u`. No new flags
were added. Single target (`-u` count == 1) and single pinned template
(`-t` count == 1) are asserted by the executor contract and re-checked
in the B7 tests. The child runs with `shell=False`, allowlist-only
environment (`HOME, LANG, LC_ALL, PATH, TMPDIR`), no proxy/resolver/CA
env shapers (`require_clean_launch_environment` re-checked inside the
sandbox before spawn), a confined scratch cwd, and is only ever spawned
via the namespace-exec prefix — never on the host network.

## B7-F Sandbox Lifecycle

`run_nuclei_in_sandbox` implements the mandated lifecycle:

```
CREATE -> CONFIGURE -> VERIFY -> EXECUTE -> COLLECT -> TEARDOWN
```

- Every stage is logged (`SandboxStageLog`); the child is spawned ONLY
  after VERIFY confirms default-deny + exact allowlist + no default
  route.
- TEARDOWN runs in a `finally` on every path: success, timeout,
  exception, crash, output-limit, or signal; the namespace is named from
  the `execution_id` and is always removed (`backend.torn` asserts in
  tests). No orphan namespace, interface, or route is ever left behind.
- Failures map to closed codes: `SANDBOX_CAPABILITY_MISSING`,
  `SANDBOX_UNAVAILABLE`, `SANDBOX_CREATE_FAILED`,
  `SANDBOX_CONFIGURE_FAILED`, `SANDBOX_VERIFY_FAILED`,
  `SANDBOX_RULES_REJECTED`, `SANDBOX_EGRESS_DENIED`,
  `SANDBOX_EXECUTE_FAILED`, `SANDBOX_LIFECYCLE_FAILED`. A child
  `LauncherError` (timeout/output-limit) propagates intact for proper
  accounting.
- Tests prove teardown after success, timeout, and exception, and that
  create/configure/verify/capability failures cannot produce a spawn.

## B7-G Resource Enforcement

The child is executed by the existing `run_bounded_process`, fed
`NucleiExecutionSpec.limits` (`ResourceLimitsSpec`: `wall_seconds`,
`cpu_seconds`, `memory_bytes`, `proc_limit`, `fd_limit`,
`file_size_bytes`) plus `stdout_cap_bytes`/`stderr_cap_bytes`. The B7
tests capture the runner kwargs and assert every ceiling is passed
through unchanged. Applied-vs-unavailable rlimit reporting remains the
launcher's `AppliedLimits` (honest accounting; no ceiling is claimed as
enforced when it cannot be applied on the host).

## Tests

Command: `python3 -m unittest <module>` (offline, deterministic).

- `ai.test_b7_egress_boundary` — 39 tests. OK.
- `ai.test_b6_remediation` — 37 tests. OK (incl. updated G-case 10).
- Affected suite (b1, b3, b6, b7, nuclei_executor, evidence_core,
  live_validation, execution_authorization, deterministic_verifier):
  646 tests. OK.
- `ai.test_live_validation` — 73, OK. `ai.test_nuclei_executor` — 102,
  OK. `ai.test_b3_boundary` — 52, OK. `ai.test_evidence_core` — 110,
  OK. `ai.test_b1_dial_policy` — 68, OK.
- Full `discover -s ai -p test_*.py` — 3009 run: 4 failures + 4 errors
  + 11 skipped. Classification:
  - 3 pre-existing failures, reproduced standalone BEFORE any B7 diff
    (baseline carried from B5/B6): `http_pinned_executor`
    `test_location_secret_redacted_in_chain` (REDIRECT_INVALID), and the
    two stored-template content tests in `test_nuclei_cve_2026_1557_dryrun`
    + `test_nuclei_offline_prepare`. Not touched by B7.
  - 1 discovery-order artifact: `test_stage2_production_reads`
    `test_no_database_db_import` passes in isolation (openai module
    leakage from earlier discovery order).
  - 4 `_FailedTest` loader errors on non-AI run scripts (`watch_xss_verify.py`,
    `crawl/watch_param_discovery.py`, etc.) whose `config` imports clash
    under discovery — pre-existing, unrelated to AI/execution, and
    outside the AI scope protection boundary.
- No B7 change introduced any new failure.

## Remaining Blockers

1. This host cannot materialize a network namespace: `unshare -n true`
   fails ("Operation not permitted", uid 1000, no effective
   CAP_SYS_ADMIN), and `nft`/`iptables` binaries are absent. The real
   `SystemNetnsBackend` therefore fails closed
   (`SANDBOX_CAPABILITY_MISSING`/`SANDBOX_UNAVAILABLE`) — by design, not
   workaround. Kernel-level enforcement is implemented and offline-tested
   against a fake backend, but it has NOT been demonstrated against a
   real kernel boundary in this environment.
2. B8 must validate on a capable host: real `ip netns add/exec` +
   nft/iptables across all six lifecycle stages, including races and
   kill-on-timeout under load, before any live switch.
3. Live egress remains structurally disabled (see status below); the
   `require_production_sandbox`/`launch_nuclei_bounded` seams are wired
   for B8 but still refuse today.

## Live Egress Status = DISABLED

`LIVE_LAUNCH_ENABLED` is `False` (frozen). `WATCH_AI_LIVE_VALIDATION`
was never set true. The full launch gate refuses before any child spawns:
`test_full_launch_refuses_live_egress` (B6) and
`test_launch_refuses_even_when_sandbox_provisionable` (B7) prove that
even a fully provisionable fake sandbox ends in `LIVE_LAUNCH_DISABLED`.
No live egress occurred during B7.

## Security Invariant

```
reviewed EgressPolicy (nuclei_scan, B7 identity)
    -> netns_rules_for_policy  (exact (ip, port, tcp) allowlist, default-DROP)
    -> SystemNetnsBackend      (CREATE -> CONFIGURE -> VERIFY)
    -> child spawned ONLY inside the verified namespace
    -> actual packet destination  ==  approved tuple  (anything else = kernel DROP)
```

"Live Nuclei execution is permitted only when the child process is
inside a verified default-deny network sandbox whose only permitted
egress destinations are the addresses and ports derived from the
reviewed EgressPolicy." Sandbox/policy/resolver unavailable, namespace
setup failed, unknown Nuclei version, or proxy detected ⇒ execution is
never attempted. `SANDBOX_INVARIANT` in `netns_sandbox.py` carries the
same statement and is structurally enforced: there is no code path that
spawns the child argv without the namespace-exec prefix.

## Final B7 Assessment

**READY_FOR_B8_REVIEW**

Rationale: all B7-A..G deliverables are implemented and covered by 39
offline tests plus the 646-test affected suite (all OK). The security
invariant holds structurally — policy→rules→sandbox→packet, fail-closed
at every layer — and live egress stays DISABLED. The honest caveat: real
kernel runtime enforcement could not be exercised in this environment
(no CAP_SYS_ADMIN, no nft/iptables), so the runtime half of the boundary
must be validated by B8 on a capable host before any live activation.
This report does not claim that runtime containment was demonstrated
here.