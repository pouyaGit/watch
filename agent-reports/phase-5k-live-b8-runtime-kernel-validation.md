# Phase 5K-live B8 — Runtime Kernel Boundary Validation

**Mode:** VALIDATION ONLY. No live egress enabled. No external network contacted.
No `WATCH_AI_LIVE_VALIDATION`, no `LIVE_LAUNCH_ENABLED`, no Nuclei scan,
no external DNS lookup, no browser execution, no LLM/provider API call,
no MongoDB/production-data change, no git mutation, no source-code modification.

**Implementation under validation:** `ai/execution/netns_sandbox.py`
(`SystemNetnsBackend`, boundary `b7-netns-sandbox/v1`, rules
`b7-netns-rules/v1`), as built in B7
(`agent-reports/phase-5k-live-b7-egress-boundary.md`).

**Privilege note:** the login shell is uid 1001 (empty `CapEff`; the prior
B8 run correctly reported `ENVIRONMENT_NOT_CAPABLE` for that context).
This run exercises the REAL kernel boundary via passwordless
`sudo -n` (uid 0, full effective set incl. `CAP_SYS_ADMIN`/`CAP_NET_ADMIN`),
as directed. Every privileged command below is local-only test
infrastructure (`ip netns`, `iptables`/`nft` readback, veth topology,
local listeners); no packet ever left the host (verified by routing
inspection — §Runtime Evidence).

**Honesty rule applied throughout:** only actual Linux namespace + actual
kernel firewall behavior counts as runtime proof. Each section ends with an
explicit verdict: `PROVEN` / `NOT PROVEN` / `NOT TESTABLE`. Where the
production path itself is defective, the defect is documented with exact
kernel-tool output and NO code change was made.

**Prior-report note:** per agent rules the previous B8 report file was
deleted; this report is written FROM SCRATCH from this run's observations.

---

## Environment

| Fact | Observed value |
|---|---|
| Distribution | Ubuntu 24.04.4 LTS (noble) |
| Kernel | `6.17.0-1022-gcp` (`#25-Ubuntu SMP Sat Jul 25 01:12:40 UTC 2026`, x86_64, GCP guest) |
| Login UID | `1001 (pouya_behnia)`, `CapEff 0000000000000000` |
| Privileged context | `sudo -n` → `uid=0(root)`, `capsh Current: =ep`, bounding set includes `cap_sys_admin`, `cap_net_admin` |
| `probe_netns_capabilities()` as root | `NetnsCapabilities(unshare_ok=True, ip_present=True, netfilter_present=True, can_create_netns=True, reason='')` |
| `unshare -n true` as root | exit 0 |
| `ip` | `/usr/sbin/ip` |
| `nft` | `nftables v1.0.9` |
| `iptables` | `v1.8.10 (nf_tables)` (`iptables-nft`, `iptables-legacy` also present) |
| `unshare`, `nsenter`, `lsns` | present |
| Nuclei binary | `/usr/local/bin/nuclei`, Engine `v3.11.1` (matches pinned release). **Note:** the server-controlled frozen path is `/usr/bin/nuclei`, which does NOT exist on this VM (see §Nuclei Child Validation) |
| Live flags | `WATCH_AI_LIVE_VALIDATION` and `LIVE_LAUNCH_ENABLED` **not set** (checked before and after) |
| Host route (untouched) | `8.8.8.8 via 10.128.0.1 dev ens4` — host routing was never modified |

**Verdict: ENVIRONMENT CAPABLE** (`can_create_netns=True` as root).

## Capability Check

- Root-context probe: all three preconditions green (`unshare -n` ok,
  `ip` present, netfilter frontend present).
- Unprivileged-context probe (uid 1001): `can_create_netns=False`,
  `reason='unshare -n failed (no CAP_SYS_ADMIN)'`, and
  `SystemNetnsBackend().create_namespace()` as uid 1001 still raises
  `SANDBOX_CAPABILITY_MISSING` — the fail-closed gate is intact for
  unprivileged callers.

**Verdict: PROVEN** (capable as root; correctly refused without privilege).

## Real Namespace Creation

Exclusively through the REAL `SystemNetnsBackend` (no fake backend):

- `create_namespace('ex-b8c0…01')` → `_NamespaceHandle(name='watch-ex-b8c0…01')`;
  `ip netns list` shows it; `lsns -t net` shows new entry `4026532481`
  vs host `4026531833`.
- Child executed via the namespace (`ip netns exec <ns> readlink
  /proc/self/ns/net`) reports `net:[4026532481]` ≠ host `net:[4026531833]`.
- `teardown(handle)` → `ip netns list` empty; `lsns -t net` back to the
  single host entry. Repeated across all probe namespaces (b8c0-01/02,
  b8d0-01, fixture-id namespaces from lifecycle probes): **no orphan
  namespace remained after any run.**

Full `CREATE → CONFIGURE → VERIFY → EXECUTE → COLLECT → TEARDOWN` through
`run_nuclei_in_sandbox` with genuine offline B7 fixtures (real
`NucleiExecutionSpec` + real `nuclei_scan` `EgressPolicy` for
`8.8.8.8:443/tcp`) and a recording stub runner:

- nft branch (default `PATH`): `CREATE ok → CONFIGURE raises
  SANDBOX_CONFIGURE_FAILED → TEARDOWN removes the namespace`
  (namespace absent afterward; stub runner recorded 0 calls).
- iptables branch (`nft` hidden from `PATH`, see §Firewall State):
  `CREATE ok → CONFIGURE ok → VERIFY raises SANDBOX_VERIFY_FAILED →
  TEARDOWN removes the namespace` (absent afterward; 0 spawn calls).

**Verdict: PROVEN** for CREATE (real namespace, distinct identity) and
TEARDOWN (no orphans on every path). EXECUTE via the production lifecycle
is **NOT TESTABLE** end-to-end (blocked by defects #1/#2 below) — the
lifecycle never reaches spawn, and no host-network fallback occurs.

## Firewall State

Real kernel state, read back from a backend-created + backend-configured
namespace (`iptables -S`, `iptables -L -v -n -x`, `iptables -t nat -S`):

**Branch A — nft (backend default when `nft` is on `PATH`): CONFIGURE
FAILS. Critical defect #1.** `configure()` feeds `nft -f -` a script that
the kernel tool rejects with three errors (reproduced verbatim via
`nft -c -f`):

1. `Error: syntax error, unexpected drop, expecting … dport` — the bare
   `udp drop;` rule and the `ip daddr <ipv4> drop;` rule without a
   transport match are invalid; additionally `ip6 daddr 169.254.169.254`
   pairs an IPv6 match with an IPv4 literal (type error).
2. `Error: you cannot set chain policy twice` — the script emits TWO
   `type filter hook …` statements (`output` then `input`) inside ONE
   chain block; a chain admits exactly one type/hook.
3. Cascading `unexpected '}'` from the above.

Observed backend behavior: `SANDBOX_CONFIGURE_FAILED: nft install: ^`.
No firewall state is installed on this branch.

**Branch B — iptables (backend's own fallback when `nft` is absent from
`PATH`): CONFIGURE SUCCEEDS.** This is production code
(`SystemNetnsBackend.configure`, iptables leg), exercised unmodified; only
the test harness `PATH` omits the `nft` binary (documented scaffolding —
no fake backend, no source change). Installed kernel state, read back
verbatim:

```
-P OUTPUT DROP
-A OUTPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 443 -j ACCEPT
-A OUTPUT -d 169.254.169.254/32 -p tcp -j DROP
-A OUTPUT -d 169.254.169.254/32 -p udp -j DROP
-A OUTPUT -p udp -m udp --dport 53 -j DROP
-A OUTPUT -p udp -j DROP
-P INPUT DROP
```

NAT table: empty (four base-chain `ACCEPT` policies, zero rules) — no NAT
escape. This exact state hosted every packet test below.

**Critical defect #2 — `verify()` always crashes.** `_run_checked`
returns `res.stdout` (bytes); `verify()` tests
`"-P OUTPUT DROP" in out` (str) → `TypeError: a bytes-like object is
required, not 'str'`, surfacing as `SANDBOX_VERIFY_FAILED: namespace
verify raised` even when the kernel state is perfect. Consequence: the
production lifecycle can NEVER reach EXECUTE on either branch.

**Verdict: PROVEN** (iptables-branch kernel state: default DROP + exact
ACCEPT + explicit DROPs + empty NAT, all read from the kernel).
**NOT PROVEN** for the nft branch (nothing installs). Defects #1/#2 are
carried as blockers; no code was changed.

## Default-Deny Evidence

Isolated local topology (no external contact possible): veth pair
`sandbox(vb8-s, 10.250.0.2/30) ↔ helper(vb8-h, 10.250.0.1/30 +
8.8.8.8/32 + 8.8.4.4/32)`; sandbox routes are ONLY `8.8.8.8/32`,
`8.8.4.4/32`, and the link scope — **no default route** (pre-topology,
`ip route get 8.8.8.8` inside the sandbox returned `Network is
unreachable`). Host routing untouched. All destinations below are
host-local; zero packets could egress `ens4`.

Blocked-destination results (rule counters before → after, child outcome):

| Test | Counter delta | Child outcome | Verdict |
|---|---|---|---|
| Same IP + wrong port `8.8.8.8:444/tcp` | chain policy DROP 0 → 6 pkts | `TimeoutError` | PROVEN blocked |
| Different IP + approved port `8.8.4.4:443/tcp` (listener present) | policy DROP 6 → 12 | `TimeoutError` | PROVEN blocked |
| UDP `8.8.8.8:443` | all-UDP DROP 0 → 1 | `PermissionError EPERM` (synchronous kernel refusal) | PROVEN blocked |
| Loopback `127.0.0.1:9999/tcp` (live listener in-sandbox) | policy DROP 12 → 18 | `TimeoutError` (no loopback abuse) | PROVEN blocked |
| DNS `8.8.8.8:53/udp` | `udp dpt:53` DROP 0 → 1 | `PermissionError EPERM` | PROVEN blocked |
| Host proxy `10.250.0.1:3128/tcp` (live listener) | policy DROP 24 → 29 | `TimeoutError` | PROVEN blocked |

`INPUT -P DROP` confirmed by readback; no unrestricted route, no
forwarding path (helper → host-LAN dial returned `ENETUNREACH`), no NAT
rules.

**Verdict: PROVEN** — non-allowlisted packets are demonstrably dropped by
the kernel boundary (counters + child-visible refusals/timeouts), not by
application code.

## Allowlist Evidence

Approved tuple `(8.8.8.8, 443, TCP)` — the only ACCEPT in the kernel table:

- OUTPUT ACCEPT counter `0 → 7 pkts / 420 B` on first attempt (SYN +
  retransmits), `7 → 14`, `14 → 20` on repeats.
- Concurrent observation in the helper namespace: `ss -tn state syn-recv`
  showed `8.8.8.8:443 ← 10.250.0.2:35818` **while the child was
  transmitting** — the approved SYN verifiably traversed the filter and
  arrived at the local listener. No other tuple's ACCEPT counter ever moved.
- Child `connect()` itself timed out: the SYN-ACK return is dropped by
  `INPUT -P DROP` (no conntrack/established rule exists). **Functional
  finding:** with the as-built ruleset, even the approved tuple cannot
  complete a TCP handshake — return traffic is unconditionally dropped.
  Approved egress is therefore PROVEN at the OUTPUT-filter level only;
  usable approved connectivity is NOT PROVEN (and structurally impossible
  without an established-traffic rule). Recorded as a blocker, not patched.

**Verdict: PROVEN** (exact-tuple OUTPUT allowance with packet delivery;
wrong-port/different-IP/UDP/second-destination all PROVEN blocked above).

## DNS Rebinding Simulation

No external DNS used. Staged local mapping files only
(`test-target.example → 8.8.8.8`, then `→ 8.8.4.4`); a child inside the
sandbox resolves the SAME hostname twice and connects:

- Phase 1 (SAFE `8.8.8.8`): `RESOLVED → 8.8.8.8`; OUTPUT ACCEPT 14 → 20
  (+6 SYNs passed the filter).
- Phase 2 (rebound UNSAFE `8.8.4.4`): `RESOLVED → 8.8.4.4`; chain policy
  DROP 18 → 24 (+6 blocked).

The child resolving the hostname differently cannot bypass the firewall:
enforcement is on the `(ip, port, tcp)` tuple, independent of whatever the
child resolved. No interface/firewall counters beyond the iptables
per-rule counters exist on this branch (nft absent by scaffolding);
counter deltas above are the packet-level evidence.

**Verdict: PROVEN** (rebound destination blocked; safe destination passed;
bypass-by-resolution impossible against the kernel filter).

## Host Network Escape

- Namespace identity: host `net:[4026531833]` vs child `net:[4026532481]`
  — distinct. PROVEN.
- Child-visible interfaces: `lo` + `vb8-s` only (`vb8-s` is explicit,
  documented test scaffolding; no other veth, no docker/host bridge
  visible). No unexpected interface. PROVEN.
- Child-visible routes: two test `/32`s + link scope; **no default route,
  no gateway**. PROVEN.
- Forwarding: `net.ipv4.ip_forward=1` is a host-global sysctl (GCE
  default) visible from all namespaces — noted as a caveat — but no
  forwarding occurs: the sandbox has no transit routes, the filter is
  default-DROP, and the helper namespace cannot reach host-LAN addresses
  (`connect_ex 10.128.0.4:22` → `ENETUNREACH`). No forwarding bypass.
  PROVEN for the tested topology.
- NAT table empty; no MASQUERADE/SNAT/DNAT rule that could smuggle egress.
  PROVEN.
- No inherited host-network execution: every child ran under
  `ip netns exec <sandbox>` with verified distinct identity; lifecycle
  probes recorded 0 host-network spawns. PROVEN.

**Verdict: PROVEN** (no escape observed; sysctl caveat documented).

## Proxy Escape

- Production child env (`spec.environment`): exactly
  `{HOME, LANG, LC_ALL, PATH, TMPDIR}` (scratch-confined `HOME`/`TMPDIR`);
  none of the 13 banned names present.
- `require_clean_launch_environment` gate exercised: `HTTP_PROXY`,
  `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` → `PROXY_DETECTED`; all 9
  `FORBIDDEN_LAUNCH_ENV_VARS` (`HOSTALIASES`, `LOCALDOMAIN`,
  `RES_OPTIONS`, `GODEBUG`, `SSL_CERT_FILE`, `SSL_CERT_DIR`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`) →
  `FORBIDDEN_ENVIRONMENT`; clean env accepted.
- Live proxy on the test topology (`10.250.0.1:3128`, reachable L2 from
  the sandbox): connection attempt from inside the sandbox blocked by the
  kernel filter (policy DROP +5, child timeout) — a host-side proxy is
  unreachable unless its exact tuple is allowlisted (it is not).

**Verdict: PROVEN.**

## Lifecycle Cleanup

Via the REAL backend (creation failures also verified through
`run_nuclei_in_sandbox`'s `finally`-teardown):

| Case | Observation | Verdict |
|---|---|---|
| Normal process exit | CREATE+CONFIGURE via backend, child exit 0, backend teardown → ns absent, `lsns`/`ip netns` clean | PROVEN |
| Process exception | Stub runner raising inside lifecycle-equivalent path; teardown in `finally` → ns absent | PROVEN |
| Sandbox configuration failure | `run_nuclei_in_sandbox` on nft branch → `SANDBOX_CONFIGURE_FAILED`; ns absent afterward, 0 spawns | PROVEN |
| Firewall verification failure | `run_nuclei_in_sandbox` on iptables branch → `SANDBOX_VERIFY_FAILED`; ns absent afterward, 0 spawns | PROVEN |
| Timeout / kill / output-limit failure | Cannot reach EXECUTE through the production runner (defect #2); `run_bounded_process` behaviors proven directly (timeout kill, output-limit raise — see §Resource Enforcement), and teardown-after-spawn is the same `finally` block proven above | NOT TESTABLE end-to-end (partially PROVEN at component level) |

No orphan interfaces/routes/namespaces after any case (`ip netns list`
empty, `lsns` single host entry at end of run).

**Verdict: PROVEN** for all materializable paths; EXECUTE-stage failure
cleanup NOT TESTABLE end-to-end pending defect #2 fix.

## Fail-Closed Cases

| Case | Observation | Verdict |
|---|---|---|
| Capability missing (uid 1001) | `create_namespace` → `SANDBOX_CAPABILITY_MISSING` | PROVEN |
| Namespace creation failure | Lifecycle surfaces `SANDBOX_CAPABILITY_MISSING` at CREATE; 0 spawns | PROVEN |
| Configuration failure | `SANDBOX_CONFIGURE_FAILED`, teardown, 0 spawns, no host fallback | PROVEN |
| Verification failure | `SANDBOX_VERIFY_FAILED`, teardown, 0 spawns, no host fallback | PROVEN |
| Allowlist empty | `SANDBOX_RULES_REJECTED: allowlist empty` | PROVEN |
| Policy version / class / transport / scheme / port deviations | `SANDBOX_RULES_REJECTED` (5 cases) | PROVEN |
| Unsafe address (`127.0.0.1`) | `SANDBOX_RULES_REJECTED: unsafe allowed address` | PROVEN |
| Unauthorized dial (wrong port / diff IP / UDP / bad lineage) | `SANDBOX_EGRESS_DENIED` (4 cases) | PROVEN |
| Host-network fallback on any failure | Never occurs: 0 spawn calls recorded across all failure probes | PROVEN |

No failure observed or reachable in code results in host-network execution.

**Verdict: PROVEN** (all cases).

## Nuclei Child Validation

Local-only; NO scan executed (would require an external target — forbidden):

- Pinned binary present: `/usr/local/bin/nuclei`, Engine `v3.11.1`.
- `/usr/local/bin/nuclei -version -disable-update-check` executed INSIDE
  the real backend-created/configured sandbox via the production
  `launch_prefix` (`['ip','netns','exec',<ns>]` prefix asserted) with the
  EXACT `spec.environment`: printed `Nuclei Engine Version: v3.11.1`;
  child ns `net:[4026532481]` ≠ host; child env exactly the 5 allowlist
  keys with scratch-confined `HOME`/`TMPDIR` (config/cache dirs honored
  the sandbox scratch path — no host-home pollution). Target-less probe;
  zero dials attempted (and the DROP filter would have stopped any).
- Frozen argv: `prefix[4:] == spec.argv` identity asserted; 23 tokens;
  single `-u`, single `-t`; `argv_digest` matches. Static + construction
  level (runtime scan not attempted).
- **Observation (deployment, not boundary):** the frozen
  `SERVER_CONTROLLED_NUCLEI_BINARY` is `/usr/bin/nuclei`, which does not
  exist on this VM (binary at `/usr/local/bin/nuclei`); executing the
  frozen argv verbatim here fails closed at spawn (`exec … failed: No
  such file`). Fail-closed is correct; deploy-time placement must provide
  the path before any live use.

**Verdict: PROVEN** for child-in-namespace + frozen-argv + prefix + env.
Full scan execution **NOT TESTABLE** (no external target permitted) — not
claimed.

## Resource Enforcement

Real `run_bounded_process` children as root (local only; all ceilings from
`default_resource_limits`: wall 120s, cpu 60s, mem 512MiB, proc 1, fd 64,
file 16MiB, stdout/stderr caps 1MiB):

| Ceiling | Test | Observation | Verdict |
|---|---|---|---|
| Wall timeout | `sleep 30`, wall 3s | `SUBPROCESS_TIMEOUT` at 3.0s, child killed | ENFORCED — PROVEN |
| stdout cap | 3MB output, 1MB cap | `SUBPROCESS_OUTPUT_LIMIT` | ENFORCED — PROVEN |
| Memory (`RLIMIT_AS`) | 900MB alloc, 512MB limit | exit 1, `MemoryError` | ENFORCED — PROVEN |
| CPU (`RLIMIT_CPU`) | spin, cpu 2s | killed (`-9`) at 2.0s | ENFORCED — PROVEN |
| File size (`RLIMIT_FSIZE`) | 32MB write, 16MB limit | exit 1, `EFBIG File too large` (16,777,216 B file left, cleaned) | ENFORCED — PROVEN |
| FD count (`RLIMIT_NOFILE`) | 200 opens, limit 64 | exit 1, `EMFILE Too many open files` | ENFORCED — PROVEN |
| Process count (`RLIMIT_NPROC=1`) | spawn 10 `sleep` children | **exit 0, all 10 spawned** — NOT enforced for root (`CAP_SYS_RESOURCE` bypasses `RLIMIT_NPROC` in-kernel) | NOT ENFORCED — finding |

`AppliedLimits` honestly reported `applied=('memory','cpu','proc','fd','file')`.
The NPROC bypass is a documented kernel behavior for privileged UIDs, not a
code bug; it means fork-pressure is bounded only by wall/memory caps until a
cgroup `pids` controller is added. Carried as a (non-blocking) finding.

**Verdict: all security-critical ceilings PROVEN except proc-count, which
is NOT ENFORCED as root.**

## Runtime Evidence

Commands executed (all local; zero external traffic, zero DNS, zero target
contact; host routing/firewall untouched):

1. Privilege + tooling: `id`, `capsh --print`, `which ip unshare nft
   iptables`, `unshare -n true`, `nuclei -version`,
   `probe_netns_capabilities()` as root → `can_create_netns=True`;
   `env | grep` → no live flags (before and after).
2. `SystemNetnsBackend().create_namespace()` (×several) → real handles;
   `lsns -t net` / `ip netns list` before/during/after (distinct identity
   `4026532481`, empty after teardown).
3. `configure()` on nft branch → `SANDBOX_CONFIGURE_FAILED`; generated
   script re-checked with `nft -c -f` → 3 verbatim kernel-tool errors.
4. `configure()` on iptables branch → OK; `iptables -S OUTPUT/INPUT`,
   `iptables -L OUTPUT -v -n -x`, `iptables -t nat -S` read back verbatim.
5. `verify()` → `TypeError` (bytes vs str) reproduced twice; lifecycle
   probes on both branches → `SANDBOX_CONFIGURE_FAILED` /
   `SANDBOX_VERIFY_FAILED` with 0 spawns and no orphans.
6. Topology: `ip netns add b8-helper`, veth pair split across namespaces,
   addresses/routes as documented; `ip route get` inside sandbox (test IPs
   via veth; everything else `Network is unreachable`); host `ip route get
   8.8.8.8` unchanged (via `ens4`).
7. Packet probes: `/tmp` child scripts (`connect` ×6 tuples, hostname
   rebinding ×2 phases, proxy attempt) executed via `ip netns exec`;
   per-rule counter deltas recorded; helper `ss -tn state syn-recv`
   captured mid-flight (`8.8.8.8:443 ← 10.250.0.2:35818`).
8. Escape reads: `readlink /proc/self/ns/net` (host vs child), `ip route`,
   `ip link`, `ip_forward` (both), `iptables -t nat -S`, helper→host-LAN
   dial (`ENETUNREACH`), child `env` audit.
9. Gate probes: `require_clean_launch_environment` (clean accept; 4 proxy
   + 9 denylist denials); `spec.environment` audit (5 keys).
10. Fail-closed matrix: 10 predicate denials + unprivileged refusal.
11. Resources: 7 `run_bounded_process` runs (`_rlimit_preexec` read for
    mechanism + `AppliedLimits` accounting).
12. Nuclei: version probe in-ns with exact env; frozen-argv/prefix/digest
    assertions; binary-path observation (`/usr/bin` vs `/usr/local/bin`).
13. Cleanup: backend `teardown` + `ip netns del b8-helper`; final
    `ip netns list` empty, `lsns` host-only; `/tmp` scaffolding removed.

What was NOT done: no packet sent outside the veth topology, no DNS query
issued, no Nuclei scan, no LLM call, no MongoDB access, no git mutation
(`git status` read-only), no source edit, no env-flag change.

## Remaining Blockers

1. **Defect #1 (critical): `configure()` nft script is invalid** — three
   kernel-tool errors (bare-`udp`/typeless-`ip daddr` matches,
   `ip6 daddr` with IPv4 literal, two hooks in one chain). Default branch
   installs nothing. (No code changed per B8 rules.)
2. **Defect #2 (critical): `verify()` `TypeError`** (bytes `in`-tested
   against str) — VERIFY can never pass; the production lifecycle can
   never reach EXECUTE on any branch. (No code changed per B8 rules.)
3. **Functional finding: `INPUT -P DROP` with no established-traffic rule**
   makes even approved TCP uncompletable (proven: SYN passes, SYN-ACK
   dies). Usable approved egress requires a return-path rule by design
   decision, not by accident.
4. **Weak `verify()`:** even absent defect #2, it asserts only
   `-P OUTPUT DROP` via iptables — not the exact ACCEPT set, not INPUT
   policy, not routes, not counters. Kernel-level VERIFY should confirm
   the full contract it gates.
5. **Proc-count ceiling not enforced as root** (`RLIMIT_NPROC` bypass via
   `CAP_SYS_RESOURCE`); needs a cgroup `pids` controller for a real
   fork bound. Wall/memory caps bound the damage meanwhile.
6. **Deploy note:** frozen binary `/usr/bin/nuclei` absent on this VM
   (present at `/usr/local/bin/nuclei`); live use must provide the exact
   frozen path (failure mode is closed: spawn error).
7. **Caveat:** `ip_forward=1` host-global sysctl (GCE default); harmless
   here (no transit routes + default-DROP) but a hardening review should
   decide its desired state for the live host.

## Live Egress Status

**DISABLED** — and not merely unconfigured:

- `WATCH_AI_LIVE_VALIDATION` unset; `LIVE_LAUNCH_ENABLED` unset (verified
  before and after; no production configuration modified).
- Defects #1/#2 additionally make live execution structurally unreachable
  through `run_nuclei_in_sandbox` (every path raises closed before spawn;
  0 spawn calls recorded).
- No real CVE validation performed; no real target contacted; no external
  packet transmitted.

No "GO" decision is made or implied in B8.

## Final Assessment

**RUNTIME_BOUNDARY_NOT_PROVEN**

The kernel boundary was genuinely materialized and measured: real
namespaces with distinct identity, a real backend-installed default-deny
filter (iptables branch) with exact-allowlist semantics proven at packet
level (ACCEPT/SYN-RECV evidence for the approved tuple; DROP-counter
evidence for wrong-port/different-IP/UDP/loopback/DNS/proxy/rebound
destinations), containment/escape resistance proven, teardown proven on
every path, six of seven resource ceilings proven enforced, and fail-closed
behavior proven across the matrix. BUT the production lifecycle cannot
reach EXECUTE: the default nft branch installs nothing (defect #1) and
`verify()` unconditionally crashes (defect #2). A boundary the production
runner cannot traverse is not a proven runtime boundary. Fix #1/#2 (plus
decisions on #3/#4), then re-run B8; live egress remains DISABLED until
that re-run proves `RUNTIME_BOUNDARY_PROVEN`.
