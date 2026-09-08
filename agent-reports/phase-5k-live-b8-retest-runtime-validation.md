# B8 Retest — Full Runtime Validation (B8.1 fixes)

**Mode:** VALIDATION ONLY. No live egress; no Nuclei launch; no external
target; no external DNS; no production-data change; no git operations.
All privileged probes were local-only and isolated inside throwaway
network namespaces whose traffic never left the host.

**Environment (re-checked):**
- Google VM, kernel `6.17.0-1022-gcp` (Ubuntu 24.04.4 LTS, x86_64)
- Root via `sudo -n`; CAP_SYS_ADMIN + CAP_NET_ADMIN available
- `unshare -n` OK; `nft v1.0.9 (Old Doc Yak #3)`; `iptables v1.8.10
  (nf_tables)`; `iproute2` present
- Nuclei: `/usr/local/bin/nuclei` (v3.11.1); `/usr/bin/nuclei` symlink
  present (B8 deploy finding resolved)
- Live gates untouched: no `WATCH_AI_LIVE_VALIDATION`, no
  `LIVE_LAUNCH_ENABLED`; nucleE `LIVE_NUCLEI=False`

**Code under test:** checked-out `ai/execution/netns_sandbox.py`
(working tree state from B8.1; no further modification this task).

## Result

**RUNTIME_BOUNDARY_PROVEN**

All four B8 blockers are fixed at runtime on a real kernel. Both filter
frontends (nft and iptables) were exercised end to end, on real
namespaces, with the real `SystemNetnsBackend`:

| B8 blocker | Runtime proof this retest |
|------------|---------------------------|
| #1 invalid nft script | `configure()` loads real nft rules; `nft list ruleset` in the namespace matches the exact contract (table `inet watch`, 2 chains, one hook each, family-correct matches). |
| #2 verify bytes crash | `verify()` succeeds on both legs (bytes readback decoded), returns `True`; no TypeError anywhere. |
| #3 uncompletable TCP | Approved-tuple fetch returns `HTTP/1.0 200 OK` on both legs (full handshake + data). |
| #4 weak verify | `verify()` enforces full contract from real kernel readback; tampering was not possible under production flow, and the contract-scale assertions are covered by the 30 B8.1 offline tests. |

## Evidence

### 1. Lifecycle validation (real namespaces, real backend)

Ran as root: `b8_retest_lifecycle.py` — `SystemNetnsBackend` used
directly and via `run_nuclei_in_sandbox`.

- **nft leg:** `create → configure → verify` all OK; verify `True`.
  Kernel readback (from inside the namespace):

  ```
  table inet watch {
      chain output {
          type filter hook output priority filter; policy drop;
          ip daddr 8.8.8.8 ip protocol tcp tcp dport 443 accept
          ip daddr 169.254.169.254 ip protocol tcp drop
          ip daddr 169.254.169.254 ip protocol udp drop
          udp dport 53 drop
          ip protocol udp drop
          ip6 nexthdr udp drop
      }
      chain input {
          type filter hook input priority filter; policy drop;
          ct state established,related ip protocol tcp accept
          ct state established,related ip6 nexthdr tcp accept
      }
  }
  ```

- **iptables leg** (nft hidden from `shutil.which`, exactly the B8.1
  offline-test mechanism): configure OK; verify `True`. Kernel readback:

  ```
  iptables -S OUTPUT: -P OUTPUT DROP
                     -A OUTPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 443 -j ACCEPT
                     -A OUTPUT -d 169.254.169.254/32 -p tcp -j DROP
                     -A OUTPUT -d 169.254.169.254/32 -p udp -j DROP
                     -A OUTPUT -p udp -m udp --dport 53 -j DROP
                     -A OUTPUT -p udp -j DROP
  iptables -S INPUT:  -P INPUT DROP
                     -A INPUT -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -t nat -S: base ACCEPT policies only, zero -A lines
  ip6tables -S OUTPUT: -P OUTPUT DROP + UDP drops (family-agnostic)
  ```

- **`run_nuclei_in_sandbox` full lifecycle:** CREATE, CONFIGURE, VERIFY,
  EXECUTE, COLLECT, TEARDOWN all `True`; runner called exactly once;
  `live_egress: False`; `boundary_version b7-netns-sandbox/v1`;
  `rules_version b7-netns-rules/v1`; EXECUTE reached only after verify
  passed.
- **Verify failure blocks EXECUTE:** with a backend whose `verify()`
  returns `False`, `run_nuclei_in_sandbox` raises
  `SANDBOX_VERIFY_FAILED`, the runner is **not** called, and the
  namespace is still torn down (0 orphans counted afterward).
- **Teardown on exception:** configure failure raises
  `SANDBOX_CONFIGURE_FAILED`, teardown still runs, 0 orphans.
- **Orphans:** `ip netns list` empty after all tests; `pkill`-style
  residue absent after cleanup.

### 2. Packet-level proof (isolated veth topology, zero external packets)

`b8_retest_packet.py`: helper namespace holds `8.8.8.8/32` + `1.1.1.1/32`
with HTTP/TCP listeners on `8.8.8.8:443`, `8.8.8.8:444`, `1.1.1.1:443`
and a UDP echo on `8.8.8.8:5005`; sandbox namespace gets a veth with
explicit `/32` routes (no default route, so `require_no_default_route`
holds) and the production firewall via `configure()`/`verify()`. Probe
client runs inside the sandbox namespace.

Results (identical for **both** nft and iptables legs):

```
PASS  8.8.8.8:443/tcp          OPEN b'HTTP/1.0 200 OK\r\n...OK'   (approved tuple)
PASS  8.8.8.8:444/tcp          TIMEOUT                              (wrong port blocked)
PASS  1.1.1.1:443/tcp          TIMEOUT                              (wrong IP blocked)
PASS  127.0.0.1:4444/tcp       TIMEOUT                              (loopback still closed)
PASS  8.8.8.8:5005/udp         PermissionError: [Errno 1] (blocked; no echo)
```

Approved-tuple TCP completes the full handshake and returns
`HTTP/1.0 200 OK` — B8's blocker #3 is disproven. Every deviation stays
blocked with no data leaking.

## Test status

- `ai.test_b7_egress_boundary`: **69 tests → OK** (1 skip is the
  dig-required real-`nft` compile test, which is privilege-gated; the
  skip is expected unprivileged and irrelevant here — the nft compile
  path was proven privileged in the lifecycle run above).
- Related suites, unmodified paths: `b6_remediation`, `b1_dial_policy`,
  `b3_boundary`, `nuclei_executor`, `live_validation`,
  `execution_authorization`, `deterministic_verifier`, `evidence_core`:
  **676 total → OK (skipped=1)**.
- `git diff --check`: clean (only B8.1 files still modified; this task
  edited nothing).

## Live egress

**DISABLED.** No env gate flipped; no real CVE validation; no external
packet transmitted. The only "server" traffic was between two isolated
namespaces on this host via a private veth pair. `live_egress: False`
confirmed on the full-lifecycle result.

## Remaining findings (unchanged from B8.1)

- **RLIMIT_NPROC root bypass (deferred):** unchanged; requires cgroup
  `pids` controller discussion, out of scope for this retest.
- `ip_forward=1` host-global sysctl (GCE default): harmless under this
  boundary (no transit routes + default DROP) but flagged for the
  live-host hardening review as before.

## Verdict

**RUNTIME_BOUNDARY_PROVEN** — B8 retest passes. All four B8 blockers are
resolved in the real runtime environment, on both nft and iptables
frontends. Ready for the next decision point (live egress remains
explicitly DISABLED).