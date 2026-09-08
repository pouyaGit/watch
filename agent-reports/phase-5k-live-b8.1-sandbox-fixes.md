# Phase 5K-live B8.1 — Sandbox Fixes

**Mode:** FIX ONLY. No live egress enabled. No `WATCH_AI_LIVE_VALIDATION`,
no `LIVE_LAUNCH_ENABLED`, no real target, no external network, no external
DNS, no Nuclei scan, no production-data change, no git operations
(`git status`/`git diff` read-only). No unrelated files changed.

**Scope:** `ai/execution/netns_sandbox.py` (the four B8 blockers) plus
directly-related tests in `ai/test_b7_egress_boundary.py`. `EgressRule`,
`NetnsRuleSet`, `netns_rules_for_policy`, the lifecycle runner, and the
`NetnsBackend` protocol are unchanged; all 39 pre-existing B7 tests pass
unmodified.

**Validation basis:** every nft construct below was proven against the real
kernel tool (`nft -c -f`, `nft -f`, `nft list ruleset` in a real netns as
root) before being encoded; the fixed backend then passed a privileged
local-only end-to-end run (CREATE→CONFIGURE→VERIFY→EXECUTE→COLLECT→TEARDOWN
all True, approved TCP handshake completing, blocked tuples dropped, no
orphans). Unit tests are offline and deterministic.

## Changes

`ai/execution/netns_sandbox.py` (+~530/−63):

- New deterministic renderers: `render_nft_statements`,
  `render_nft_script`, `render_iptables_plan` (single source of truth
  shared by configure and verify; exported in `__all__`).
- New pure contract checkers: `check_nft_ruleset`, `check_iptables_state`
  (exported; unit-testable without privilege).
- New `_decode_command_text` (explicit bytes handling).
- Rewritten `SystemNetnsBackend.configure` (both legs) and
  `SystemNetnsBackend.verify` (+ `_verify_iptables_family`).
- `_run_checked` return annotation corrected (`object`; it returns bytes).

`ai/test_b7_egress_boundary.py` (+30 tests, 39 → 69): `NftRenderB81Tests`,
`NftCompileB81Tests`, `VerifyRegressionB81Tests`,
`VerifyContractB81Tests`, `EstablishedReturnB81Tests`.

## nft Backend Fix

Blocker #1: the old generator emitted one chain with two
`type filter hook` lines (kernel: "you cannot set chain policy twice"),
bare `udp drop` / `ip daddr X drop` without transport detail (kernel:
"unexpected drop"), and `ip6 daddr <ipv4>` cross-family matches.

Fixed script structure (proven with `nft -c -f`, exit 0, then loaded and
read back from a real namespace):

```
table inet watch {
  chain output {
    type filter hook output priority 0; policy drop;
    ip daddr 8.8.8.8 ip protocol tcp tcp dport 443 accept;
    ip daddr 169.254.169.254 ip protocol tcp drop;
    ip daddr 169.254.169.254 ip protocol udp drop;
    udp dport 53 drop;
    ip protocol udp drop;
    ip6 nexthdr udp drop;
  }
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related ip protocol tcp accept;
    ct state established,related ip6 nexthdr tcp accept;
  }
}
```

Rules enforced in the renderer (fail closed, no unsafe output generatable):

- Exactly two chains, one hook each; default DROP on both.
- ACCEPT only for a full `(ip, port, tcp)` tuple — anything broader
  (`ACCEPT udp`, missing ip/port, non-OUTPUT chain) raises
  `SANDBOX_CONFIGURE_FAILED` ("broad accept refused") instead of emitting.
- Family-correct matches throughout (`ip`/`ip protocol` vs `ip6`/`ip6
  nexthdr`, dispatched by `ipaddress`; unparseable literal fails closed).
  IPv6 tuples render as `ip6 daddr … ip6 nexthdr tcp tcp dport … accept`
  (proven to compile); family-agnostic UDP denial is emitted as the twin
  `ip protocol udp` + `ip6 nexthdr udp` (an `ip protocol` match never
  matches IPv6 and vice versa).
- No NAT, no default route, no UDP allowance, no broad ACCEPT.

Two renderer bugs were caught by `nft -c -f` during this fix (bare `tcp`/
`udp` header matches need dport detail; duplicated proto token) and
corrected before final validation — the compile gate works as intended.

## Verify Fix

Blocker #2: `_run_checked` returns bytes; `verify()` tested
`"-P OUTPUT DROP" in out` → `TypeError` on every call, surfacing as
`SANDBOX_VERIFY_FAILED: namespace verify raised`. The lifecycle could
never reach EXECUTE on any branch.

Fix: `_decode_command_text` (bytes → `str`, anything else → `None`) plus
a fully fail-closed `verify()` — unexpected output, tool failure, wrong
handle type, or any exception yields `False`, never a crash. The caller
mapping is unchanged (`False` → deterministic `SANDBOX_VERIFY_FAILED`).

Regression tests feed the real method canned BYTES dumps (the exact old
crash input) plus tool-failure and garbage inputs.

## Firewall Contract

Blocker #4: old `verify()` checked a single substring (`-P OUTPUT DROP`)
on one chain and only when `iptables` existed.

New contract, read from REAL kernel state on the active leg:

- nft leg (`nft list ruleset`): exactly table `inet watch`; exactly chains
  `output`/`input`; `policy drop` in both hook headers; OUTPUT statements
  exactly the rendered allowlist + explicit drops (set equality — no
  unexpected ACCEPT possible); INPUT statements exactly the two
  ESTABLISHED TCP return statements; no `type nat` anywhere.
- iptables leg (`-S OUTPUT`, `-S INPUT`, `-t nat -S` on `iptables` and,
  when present, `ip6tables`): `-P OUTPUT DROP` + rule set exactly the
  canonical renderer lines; `-P INPUT DROP` + exactly the
  `-p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` line;
  NAT with zero `-A` lines. A needed-but-missing family frontend fails
  closed. ctstate member ordering is normalized (iptables prints
  `RELATED,ESTABLISHED`) so version canonicalization cannot false-fail.
- Verification failure still prevents execution (unchanged
  `SANDBOX_VERIFY_FAILED` gate; 0 spawns recorded on every failure path).

Contract tests mutate each axis independently (extra ACCEPT, missing
allowlist, ACCEPT policies, missing return rule, NAT MASQUERADE rule,
extra table, injected nat chain, unparseable/bytes/None dumps) — all
correctly `False`, exact state `True`.

## Return Traffic Model

Blocker #3: `INPUT -P DROP` with no return rule made even approved TCP
uncompletable (B8 proved SYN passes, SYN-ACK dies).

Model (B8.1-D): OUTPUT admits only approved `(ip, port, tcp)` new flows;
INPUT admits only `ESTABLISHED,RELATED` return traffic, TCP-scoped
(`… ip protocol tcp` / `… ip6 nexthdr tcp` on nft;
`-p tcp -m conntrack` on iptables). TCP-scoping matters: OUTPUT drops all
non-approved new flows, so no UDP flow can legitimately reach
ESTABLISHED — scoping additionally closes blind port-guess ingress
against conntrack entries of dropped UDP packets. No inbound port is
opened; no new inbound flow is admitted; unsolicited inbound still hits
default DROP.

Privileged local-only proof (isolated veth topology, helper namespace
holding `8.8.8.8/32`, zero external packets): approved-tuple fetch
returned `HTTP/1.0 200 OK` (handshake completes); wrong-port, different-IP,
loopback → `TimeoutError`; UDP → `PermissionError`; full production
lifecycle `CREATE→CONFIGURE→VERIFY→EXECUTE→COLLECT→TEARDOWN` all True with
`live_egress: False` and no orphans.

## Tests

- `ai.test_b7_egress_boundary`: 39 → **69 tests, OK** unprivileged
  (1 skip: live `nft -c -f` needs privilege) and **69 OK as root**
  (compile test executes, 0 skips).
- Related suites, unmodified code paths: `test_b6_remediation` +
  `test_b1_dial_policy` + `test_b3_boundary` (157, OK);
  `test_nuclei_executor` + `test_live_validation` +
  `test_execution_authorization` + `test_deterministic_verifier` +
  `test_evidence_core` (450, OK).
- New coverage: nft render exactness/structure/IPv6/refusals (8),
  real-`nft -c -f` compile + skip logic (1), verify bytes regression (4),
  verify contract iptables (7) + nft (6), established return (5).
- `git diff --check`: clean.

## Remaining Findings

- **B8.1-E (deferred by design):** `RLIMIT_NPROC` is not enforced for root
  (`CAP_SYS_RESOURCE` bypasses it in-kernel; B8 proved 10 children spawn
  with `proc_limit=1`). Documented only, per scope — needs a cgroup `pids`
  controller discussion. Wall/memory caps bound the damage meanwhile.
- Deploy note (pre-existing): frozen `SERVER_CONTROLLED_NUCLEI_BINARY`
  (`/usr/bin/nuclei`) is absent on this VM (`/usr/local/bin/nuclei`
  instead); verbatim frozen-argv execution fails closed at spawn here.
- `ip_forward=1` host-global sysctl (GCE default): harmless under this
  boundary (no transit routes + default-DROP) but flagged for the live-host
  hardening review.
- Packet-level re-proof of the final code on a clean host is recommended
  as B8-retest (this fix was validated exactly so, locally).

## Live Egress Status

**DISABLED**

- `WATCH_AI_LIVE_VALIDATION` unset; `LIVE_LAUNCH_ENABLED` unset and
  untouched; no production configuration modified.
- `test_launch_refuses_even_when_sandbox_provisionable`-class gates
  intact (B7 suite green); every privileged probe used local-only
  fixtures/listeners.
- No real CVE validation performed; no external packet transmitted.

## Final Assessment

**READY_FOR_B8_RETEST**

Rationale: all four B8 blockers are fixed in `ai/execution/netns_sandbox.py`
— the nft script compiles and loads, `verify()` cannot crash and enforces
the full kernel contract on both legs, and approved TCP completes while
every deviation stays blocked — with 30 new offline tests green (plus
privileged compile/lifecycle/packet proof recorded above) and zero
regressions in the 646 related tests. No GO decision is made here; live
egress stays DISABLED pending the B8 retest verdict.
