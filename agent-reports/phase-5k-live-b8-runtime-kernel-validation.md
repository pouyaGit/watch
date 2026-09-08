# Phase 5K-live B8 — Runtime Kernel Boundary Validation

**Mode:** VALIDATION ONLY. No live egress enabled. No external network contacted.
No `WATCH_AI_LIVE_VALIDATION`, no `LIVE_LAUNCH_ENABLED`, no Nuclei scan,
no external DNS, no browser, no LLM/provider API, no MongoDB/production-data
change, no git operation, no source-code modification.

**Implementation under validation:** `ai/execution/netns_sandbox.py`
(`SystemNetnsBackend`, boundary `b7-netns-sandbox/v1`, rules
`b7-netns-rules/v1`), as built in B7
(`agent-reports/phase-5k-live-b7-egress-boundary.md`).

**Honesty rule applied throughout:** only actual Linux namespace + actual
kernel firewall behavior counts as runtime proof. Generated Python rules,
pure-function checks, and mocked namespaces are NOT runtime proof and are
labelled as such. Each section ends with an explicit verdict:
`PROVEN` / `NOT PROVEN` / `NOT TESTABLE`.

---

## Environment

| Fact | Observed value |
|---|---|
| Distribution | Ubuntu 24.04.4 LTS (noble) |
| Kernel | `6.18.33.2-microsoft-standard-WSL2` (WSL2 guest kernel, `#1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026`, x86_64) |
| UID / euid | `1000 (pouya)` / `1000` — unprivileged user |
| Effective capabilities (`CapEff`) | `0000000000000000` — **empty** |
| `CAP_SYS_ADMIN` effective | **Absent** (present only in bounding set, not in effective set) |
| `CAP_NET_ADMIN` effective | **Absent** |
| `ip` | Present (`/usr/sbin/ip`) |
| `unshare` | Present (`/usr/bin/unshare`) |
| `nsenter`, `lsns` | Present |
| `nft` | **Missing** (`nft not found`, `shutil.which("nft")` → `None`) |
| `iptables` / `iptables-nft` / `iptables-legacy` | **Missing** (all variants `not found`, `shutil.which("iptables")` → `None`) |
| User namespaces (`unshare -U`) | Works (exit 0) |
| Privileged netns (`unshare -n` alone) | **Fails**: `unshare: unshare failed: Operation not permitted` (exit 1) |
| Unprivileged user+net ns (`unshare -Urn`) | Works (exit 0; see below — NOT the production backend path) |
| `ip netns list` | Empty, exit 0 |
| `lsns -t net` | Single host entry `4026531833` (plus `unassigned` NETNSID), unchanged before/after all probes |
| Live flags | `WATCH_AI_LIVE_VALIDATION` and `LIVE_LAUNCH_ENABLED` **not set** (verified via `env | grep`) |
| Nuclei binary (local) | Present at `/home/pouya/go/bin/nuclei`; `nuclei -version` → `v3.11.1` (matches pinned release). Version probe only — **no scan executed** |

Unprivileged-namespace note (recorded for precision, NOT used as proof):
`unshare -Urn` yields a genuinely distinct namespace identity
(host `net:[4026531833]` vs child `net:[4026532480]`, `user:[4026532477]`,
uid mapped to 0/root inside, single `lo` interface `DOWN`). This proves the
kernel *can* isolate a network namespace for an unprivileged user via a user
namespace. It does **not** satisfy B8, because the production
`SystemNetnsBackend` path requires the privileged sequence
(`unshare -n` probe + `ip netns add/exec/del` + `nft`/`iptables`), which this
host cannot provide. Per the B8 stop-rule, the unprivileged mechanism was
**not** substituted for the production backend.

## Capability Check

`probe_netns_capabilities()` (offline, local kernel call, zero network) returns:

```
NetnsCapabilities(unshare_ok=False, ip_present=True, netfilter_present=False,
    can_create_netns=False,
    reason='unshare -n failed (no CAP_SYS_ADMIN); nft/iptables missing')
```

`SystemNetnsBackend().capabilities()` returns the identical record.

Missing capabilities (exact):

1. Effective `CAP_SYS_ADMIN` (and `CAP_NET_ADMIN`) — `CapEff` is zero;
   `unshare -n true` fails with `Operation not permitted`.
2. A netfilter frontend — neither `nft` nor `iptables` exists on `PATH`.
3. Consequently `can_create_netns = False`; the backend's documented
   precondition (root/`CAP_SYS_ADMIN` + tooling) is unmet.

**Verdict: ENVIRONMENT_NOT_CAPABLE.** Per §1 of the B8 brief, the runtime
materialization sequence is STOPPED here; the implementation is NOT weakened
to make B8 pass, and no fake backend is substituted. All sections below
report what was honestly observable under this constraint.

## Real Namespace Creation

Attempted exclusively through the REAL `SystemNetnsBackend`:

- `SystemNetnsBackend().create_namespace('ex-b8-probe')` →
  `SandboxError: SANDBOX_CAPABILITY_MISSING: unshare -n failed (no CAP_SYS_ADMIN); nft/iptables missing`.
- Full lifecycle entry `run_nuclei_in_sandbox(..., backend=SystemNetnsBackend(),
  bounded_runner=no_spawn)` with genuine offline B7 fixtures
  (execution `ex-cccc…`, approved `8.8.8.8:443/tcp`, pure in-memory records,
  zero network) →
  `SANDBOX_CAPABILITY_MISSING` at the CREATE stage; the injected
  `bounded_runner` (which raises on any call) was **never invoked**, proving
  no child was spawned past the failed CREATE.
- `lsns -t net` before vs after: identical single host namespace
  (`4026531833`); `ip netns list` empty. No namespace created, no orphan.

No `CREATE → CONFIGURE → VERIFY → EXECUTE → COLLECT → TEARDOWN` runtime
sequence could be materialized, because CREATE itself is correctly refused.

**Verdict: NOT PROVEN** (creation correctly refused; fail-closed behavior
itself is PROVEN — see Fail-Closed Cases — but that is refusal evidence,
not boundary-materialization evidence).

## Firewall State

No kernel firewall state could be installed or inspected at runtime:

- No `nft`, no `iptables` → `configure()` has no frontend and is unreachable
  (CREATE fails first).
- There is no real namespace in which to read back `OUTPUT`/`INPUT` policy,
  rule counters, routes, or NAT tables.

The B7-generated `NetnsRuleSet` (default-deny + exact ACCEPT tuples + explicit
DROP denials for metadata/DNS/UDP) was reviewed as source code only. Generated
rules are NOT kernel state.

**Verdict: NOT PROVEN** (and NOT TESTABLE on this host).

## Default-Deny Evidence

No real namespace existed in which to assert `OUTPUT`/`INPUT` policy DROP,
remove default routes, or send a blocked packet to a non-allowlisted local
endpoint. No packet was sent anywhere (no external network per §2; no local
test endpoint was materialized because there is no sandbox to attach it to).

Pure-function design evidence (NOT runtime proof): `require_default_deny`
and `require_no_default_route` enforce the contract on the `NetnsRuleSet`
object, and `netns_rules_for_policy` always emits `default_drop_output=True,
default_drop_input=True, no_unrestricted_default_route=True`. This is static
semantics, not packet filtering.

**Verdict: NOT PROVEN.**

## Allowlist Evidence

No allowlisted tuple could be demonstrated as ALLOWED at runtime, and no
deviation (wrong port / different IP / UDP / second destination) could be
demonstrated as BLOCKED at runtime — there is no kernel filter to exercise.

Pure-function design evidence (NOT runtime proof), executed offline against
genuine B7 fixtures with zero network traffic:

- `check_nuclei_egress_dial(ip=8.8.8.8, port=443, tcp, matching lineage)` →
  allowed (in-memory exact-match only).
- Same IP + wrong port → `SANDBOX_EGRESS_DENIED`.
- Different IP + approved port → `SANDBOX_EGRESS_DENIED`.
- UDP + approved IP/port → `SANDBOX_EGRESS_DENIED`.

These prove the *authorization predicate* is exact-match; they prove nothing
about kernel packet behavior.

**Verdict: NOT PROVEN.**

## DNS Rebinding Simulation

No external DNS was used (per §6). No runtime simulation was possible: with
no namespace and no filter, there is no boundary in which
`SAFE_TEST_IP → allowed / UNSAFE_TEST_IP → blocked` could be observed, and no
interface/firewall counters exist to record packet-level evidence.

Design note (NOT runtime proof): the B7 architecture makes the child's
resolver output irrelevant *in principle* — the filter, when materialized,
permits only the allowlisted `(ip, port, tcp)` tuples, installs no resolver
service, permits no UDP, and keeps loopback inside the namespace — but none
of this was instantiated here.

**Verdict: NOT PROVEN.**

## Host Network Escape

There was no child process to test, because no sandboxed child could be
launched (CREATE refused; no fallback to host networking exists — the
`no_spawn` guard in the lifecycle probe confirms no host-network execution
occurred as a substitute).

The unprivileged `unshare -Urn` observation (distinct `net:[4026532480]`
identity, lone `DOWN` loopback) is recorded as a kernel fact about user
namespaces, NOT as a production-escape test: the production backend never
ran, so host-network/default-route/forwarding/loopback/veth escape verdicts
cannot be issued for it.

**Verdict: NOT PROVEN** (no escape occurred — but absence of a child is not
proof of containment).

## Proxy Escape

Runtime verdict: **NOT PROVEN** — no production child environment was ever
materialized, so there is no runtime child environment to audit.

Static design evidence (NOT runtime proof), verified by reading
`ai/execution/nuclei_launcher.py` and `ai/execution/egress_guard.py`:

- `FORBIDDEN_LAUNCH_ENV_VARS` denies `HOSTALIASES, LOCALDOMAIN, RES_OPTIONS,
  GODEBUG, SSL_CERT_FILE, SSL_CERT_DIR, NODE_EXTRA_CA_CERTS,
  REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE` (`FORBIDDEN_ENVIRONMENT`).
- `egress_guard.check_environment` denies any proxy-shaped variable
  (`PROXY_DETECTED`), which is the mechanism covering `HTTP_PROXY,
  HTTPS_PROXY, ALL_PROXY, NO_PROXY` — presence alone, regardless of value.
- `require_clean_launch_environment` runs before any spawn in
  `run_nuclei_in_sandbox` (EXECUTE stage, post-VERIFY), with no override
  parameter by design.
- Whether an unreached host-side proxy could be contacted from a future
  sandbox remains a property of the (uninstantiated) filter, not an observed
  runtime fact.

**Verdict: NOT PROVEN** (mechanism present in code; never executed at runtime
here).

## Lifecycle Cleanup

Exercised the REAL backend only (no fake backend, per the B8 prohibition):

- CREATE-refusal path: `run_nuclei_in_sandbox` with `SystemNetnsBackend`
  raised `SANDBOX_CAPABILITY_MISSING`; `handle` remained `None`; `lsns`/`ip
  netns` show no namespace, no interface, no route artifact.
- The six required cases (normal exit, exception, timeout, kill,
  output-limit failure, configuration failure) all require a materialized
  namespace to clean up; none could be executed because CREATE is refused.
  The B7 suite proves teardown-after-every-path against an injected fake
  backend — that is lifecycle-*semantics* evidence, explicitly NOT runtime
  evidence, and is not claimed here.

**Verdict per case: NOT TESTABLE** on this host (no namespace to leak or
reclaim). Namespace-before = absent, namespace-after = absent; no orphan
interfaces/routes/namespaces observed — trivially, since nothing was created.

## Fail-Closed Cases

These are PROVEN — refusal (not bypass) is directly observable at runtime
through the real backend, offline, with zero network:

| Case | Observation | Verdict |
|---|---|---|
| Capability missing | `create_namespace` → `SANDBOX_CAPABILITY_MISSING` with exact reason | PROVEN |
| Namespace creation fails | Lifecycle runner surfaces `SANDBOX_CAPABILITY_MISSING` at CREATE; child never spawned (`no_spawn` guard never tripped) | PROVEN |
| Namespace configuration fails | Unreachable past CREATE; code path raises `SANDBOX_CONFIGURE_FAILED` on any command failure with no host fallback (source-verified) | NOT TESTABLE at runtime |
| Firewall setup / verification fails | Unreachable (no frontend); `verify()` returns `False` unless `-P OUTPUT DROP` is read back; runner raises `SANDBOX_VERIFY_FAILED` on `False` (source-verified) | NOT TESTABLE at runtime |
| Allowlist empty | `netns_rules_for_policy` → `SANDBOX_RULES_REJECTED: allowlist empty` (offline pure-function, zero network) | PROVEN (predicate-level; not kernel-level) |
| Policy / hash mismatch, wrong execution class | `SANDBOX_RULES_REJECTED` / `SANDBOX_EGRESS_DENIED` on version, class, transport, scheme, port-range deviations (offline) | PROVEN (predicate-level; not kernel-level) |
| Unauthorized destination / UDP / invalid port / unsafe address | `check_nuclei_egress_dial` exact-match denials incl. wrong-port, diff-IP, UDP (offline probes above) | PROVEN (predicate-level; not kernel-level) |
| Host-network fallback on any failure | Never occurs: CREATE refusal propagates as exception; `bounded_runner` never called; no `ip netns exec` prefix is ever built past failed VERIFY | PROVEN |

No failure observed or reachable in code results in host-network execution:
every failure raises a closed `SandboxError`/`LauncherError` before spawn.

## Nuclei Child Validation

- Pinned binary available locally: `nuclei -version` → `v3.11.1`
  (matches `PINNED_NUCLEI_VERSION`). **Target-less version probe only.**
- No Nuclei scan was run (forbidden by the brief, and impossible without a
  sandbox): no frozen-argv execution, no `ip netns exec` prefix, no
  environment binding, and no second-destination representability test could
  be performed at runtime.
- Static design facts (NOT runtime proof): `build_nuclei_argv` freezes flags
  (`-disable-update-check`, `-disable-redirects`, `-no-interactsh`, `-jsonl`,
  `-bulk-size 1`, `-concurrency 1`, `-timeout 5`, `-retries 0`,
  `-restrict-local-network-access`); the sandbox runner builds the child argv
  exclusively via `backend.launch_prefix(handle, spec.argv)`.

**Verdict: runtime child execution could NOT be validated — NOT PROVEN.**
The binary's presence proves availability only.

## Resource Enforcement

Frozen ceilings recorded from `default_resource_limits()` (metadata, NOT
evidence of enforcement):

```
wall_seconds=120, cpu_seconds=60, memory_bytes=536870912 (512 MiB),
proc_limit=1, fd_limit=64, file_size_bytes=16777216,
stdout_cap_bytes=1048576, stderr_cap_bytes=1048576, scratch_bytes=16777216
```

`run_bounded_process` accepts all of these as parameters (signature verified),
but no bounded child was ever launched at runtime here, so no ceiling was
observed to bite (no timeout fired, no OOM, no fd/proc exhaustion, no output
cap truncated).

| Ceiling | Verdict |
|---|---|
| Wall timeout | NOT TESTABLE |
| CPU limit | NOT TESTABLE |
| Address-space / memory | NOT TESTABLE |
| Process count | NOT TESTABLE |
| FD count | NOT TESTABLE |
| File size | NOT TESTABLE |
| stdout/stderr caps | NOT TESTABLE |

No security-critical limit is *disproven*, but none is proven either. Per the
brief, an unproven security-critical limit is a blocker — carried to
Remaining Blockers.

## Runtime Evidence

Exact commands run (all local, zero external traffic, zero DNS, zero target
contact):

1. `cat /etc/os-release; uname -a; cat /proc/version; id;
   cat /proc/self/status | grep -i -E 'cap|uid|gid'; capsh --print`
   → Ubuntu 24.04, WSL2 kernel 6.18.33.2, uid 1000, `CapEff 0`, no effective
   `CAP_SYS_ADMIN`.
2. `which ip unshare nft iptables …; ip --version; unshare --help;
   ls -l /proc/self/ns/net …; cat /proc/sys/user/max_user_namespaces`
   → `ip`/`unshare`/`nsenter`/`lsns` present; `nft`/`iptables` absent.
3. `unshare -Urn true` → exit 0; `unshare -n true` → `Operation not
   permitted` exit 1; `unshare -U true` → exit 0.
4. `unshare -Urn bash -c 'readlink /proc/self/ns/net; …; ip link show'`
   → child `net:[4026532480]` ≠ host `net:[4026531833]`; lone `DOWN` `lo`.
5. `python3 -c probe_netns_capabilities()` → `can_create_netns=False` with
   exact reason string (twice: free function + backend method).
6. `SystemNetnsBackend().create_namespace('ex-b8-probe')` →
   `SANDBOX_CAPABILITY_MISSING` (fail-closed PROVEN).
7. `run_nuclei_in_sandbox(real backend, genuine offline fixtures, no_spawn
   runner)` → `SANDBOX_CAPABILITY_MISSING` at CREATE; runner never called.
8. `lsns -t net` / `ip netns list` before and after → unchanged, empty.
9. Offline predicate probes (`check_nuclei_egress_dial` SAFE allow +
   wrong-port/diff-IP/UDP denials) → exact-match confirmed at predicate level.
10. `nuclei -version` → `v3.11.1` (no scan).
11. `env | grep -i -E 'LIVE|WATCH_AI'` → no live flags.
12. Source reads: `ai/execution/netns_sandbox.py` (full, 862 lines),
    `require_clean_launch_environment`, `check_environment`,
    `FORBIDDEN_LAUNCH_ENV_VARS`, `run_bounded_process` signature,
    `default_resource_limits`, `NucleiExecutionSpec` shape.

What was NOT done (deliberately): no packet sent, no listener bound, no
`ip netns add/exec/del`, no firewall command, no DNS query, no Nuclei scan,
no LLM call, no MongoDB access, no git operation, no source edit, no env-flag
change.

## Remaining Blockers

1. **Host lacks production prerequisites** (effective `CAP_SYS_ADMIN`,
   `nft`/`iptables`) — `ENVIRONMENT_NOT_CAPABLE`. A capable host (root or
   file-capability holder, `ip` + `nft`/`iptables`, non-WSL2 kernel with full
   netfilter) is required to re-run B8.
2. **No real netns was created** via the production backend.
3. **No real firewall was installed or read back** (no counters, no DROP/ACCEPT
   proof).
4. **Default-deny and exact-allowlist unverified at packet level.**
5. **DNS-rebinding containment unverified at runtime.**
6. **Host-network and proxy escape unverified at runtime.**
7. **Lifecycle cleanup under failure unverified at runtime** (six cases).
8. **Resource ceilings unverified at runtime** (all seven ceilings NOT
   TESTABLE; each security-critical until proven ENFORCED).
9. **Nuclei child boundary unverified at runtime** (binary present, never
   launched in a sandbox).
10. **WSL2 kernel caveat:** even with capabilities, the
    `microsoft-standard-WSL2` kernel's netfilter/netns fidelity for
    `ip netns`-based testing should be confirmed on the re-run host; prefer a
    bare-metal/VM kernel for the proving run.

## Live Egress Status

**DISABLED** — and not merely unconfigured:

- `WATCH_AI_LIVE_VALIDATION` unset; `LIVE_LAUNCH_ENABLED` unset.
- No production configuration modified.
- `probe_netns_capabilities().can_create_netns` is `False`, so every live
  path through `SystemNetnsBackend` is refused before any network action.
- The lifecycle result model carries `live_egress=False`.
- No real CVE validation performed; no real target contacted.

No "GO" decision is made or implied in B8.

## Final Assessment

**RUNTIME_BOUNDARY_NOT_PROVEN**

**ENVIRONMENT_NOT_CAPABLE** — this WSL2 host (uid 1000, empty effective
capability set, no `nft`/`iptables`) cannot materialize the B7 production
backend (`unshare -n` fails; netfilter frontend absent). The implementation
itself behaved correctly under these conditions: it refused every live path
with `SANDBOX_CAPABILITY_MISSING`/`SANDBOX_RULES_REJECTED`/
`SANDBOX_EGRESS_DENIED` as appropriate, spawned no child, fell back to no
host network, and left no namespace/interface/route artifact. Refusal is
correct fail-closed behavior — but refusal is not a runtime boundary proof.
Predicate-level exactness (allowlist, denylist, proxy guards) is confirmed in
code and offline checks; kernel-level filtering, containment, escape
resistance, cleanup, and resource enforcement all remain unproven pending a
capable-host re-run. B8 therefore produces evidence *for* the next security
review, not authorization for live egress.
