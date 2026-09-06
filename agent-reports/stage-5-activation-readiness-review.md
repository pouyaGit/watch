# Stage 5 — Activation Readiness Review (Pilot NOT Activated)

## 1. Objective

Close the remaining environment-dependent readiness gaps from the
accepted Stage 4 (PASS WITH LIMITATIONS) and produce a
machine-checkable activation review — still a VALIDATION/READINESS
stage. Outcome is (B): the pilot remains safely CLOSED with exact
remaining UNPROVEN items (10/17 PASS, 0 FAIL, 7 UNPROVEN,
`activation_eligible() == False`). No evidence was manufactured: two
gaps genuinely closed (freshness policy RESOLVED; dial-proof-vs-
actual-dial PROVEN on an isolated fixture); the rest stay UNPROVEN
with executed negative probes. No live target traffic occurred.

## 2. Environment

WSL2 (6.18.33.2-microsoft-standard-WSL2), uid 1000, `CapEff=0`
(fully unprivileged — verified). No `WATCH_TEST_MONGO_URI`/`DB`;
ports 27017/27018 closed; no `mongod`; no `iptables`/`nft`/`ip6tables`
binaries; Docker shim unusable in-distro; cgroup v2 present but
read-only (`mkdir` denied — no delegation). `unshare -Urn`
permitted; no root, no sudo, no separate root-capable validation
environment was provided. Parent netns verified unchanged after
every gated run.

## 3. Mongo validation — UNPROVEN (dedicated server unavailable)

Part A stopped safely at the entry guard: `WATCH_TEST_MONGO_URI`
absent, no server on 27017/27018, no `mongod` to start. Per the
stage rules there was NO fallback to production Mongo (never
contacted: no `.env` read, database `watch` never referenced by any
new code path). Consequences, each recorded UNPROVEN: server-side
index metadata not queried; unique constraints for
authorization/ledger/audit/blob/index not server-verified; all seven
concurrency races unexecuted (the 13 skip-safe tests skip cleanly —
re-verified green-skipped in Stage 5 regressions); failure semantics
not server-exercised; no index names/flags or race winner/loser
counts exist to report. The Stage 3 suite's refusal logic
(URI-gating, `watch`/`admin`/`local`/`config` denylist) re-ran green.

## 4. Network enforcement validation — PARTIAL (FIB proven, packet filter UNPROVEN)

Stage 4 FIB-level results re-verified green in Stage 5 gated runs
(allowed `(A,P)` + peer proof + TCP-only; `(A,P+1)` refused;
`(B,P)`/`(B,P+1)` kernel-`ENETUNREACH` + product refusal; loopback/
RFC1918/link-local/metadata blocked; no default route v4/v6; no
alternate interface; parent unchanged). Honest layer accounting
(§6 of this report's method): address-B blocks are kernel-FIB
proof; namespace-loopback isolation is a real-dial proof;
private/link-local/metadata blocks are harness-guard + B3
`FORBIDDEN_DESTINATION` refusals (no socket created — a true block,
but policy-layer, not kernel-layer). `iptables`/`nftables`
enforcement: UNPROVEN (binaries absent, `CapEff=0`). Proxy absence:
Stage 4 `egress_guard` posture unchanged; no proxy path exists in
the dial path (no proxy env honored, no proxy parameter — B1
structural property, suites green). DNS-alternate-destination:
impossible where no lookup occurs (sabotage-tested Stage 4, green).
Redirect freshness: proven live (readiness executes fresh
resolve→evaluate→policy plus stale-reuse refusal). SYN-DROP:
UNPROVEN (needs a packet filter). Timeout cleanup, namespace
teardown, parent-unchanged: PASS (kill-path test green, ~4 s).

## 5. Resource enforcement — per-limit verdicts (no accounting-only PASS)

Genuinely kernel/runtime-enforced live (Stage 4 scenarios re-run
green in Stage 5): wall-clock/stall timeout (`TRANSPORT_TIMEOUT`
vs hold-open peer), connect-timeout range gating (unit) —
`connect_timeout` live SYN-DROP UNPROVEN; response transport cap
(600 KiB stopped exactly at 512 KiB, `over_cap`); decompression
ratio cap (200 KiB-from-bytes gzip → `DECOMPRESSION_LIMIT`);
request byte cap (16 KiB translator + B3 bound, unit). UNPROVEN
(environment cannot enforce/prove): CPU limit, memory limit,
process-count limit (cgroup read-only, no delegation attempted
rather than faked). No thresholds weakened; all values are the
frozen Stage 3 ceilings. Readiness item stays UNPROVEN overall by
the strict rule.

## 6. Dial-proof validation — PROVEN (isolated full chain)

New `dialproof_chain` harness scenario closes the Stage 4 gap
without touching B1: the fixture ADDRESS TEXT is globally routable
(`8.8.8.8`, admitted by frozen `validate_answers` unmodified) while
the DESTINATION is strictly local (a /32 on `lo` inside the
routeless, peerless test netns — kernel local-table delivery, no
packet can leave). The dial proceeds only after kernel-verified
assertions (foreign netns inode, no v4/v6 default route, fixture in
the local table) through an exact-match chain guard
(`guard_chain_address`: only `8.8.8.8:18081`; high port nothing real
serves). Chain executed live, all green across 3 stable runs:
`chain-resolution` (fresh 5C pin `8.8.8.8` + ALLOWED 5D over
scripted DNS), `chain-egress` (B3 policy on the exact triple),
`chain-peer-proof` (real socket → `getpeername` peer proof →
genuine `DialProof` assembly/verification/egress binding),
`chain-http-exchange` (translated bounded request, wire bytes,
receive within ceilings, decode, body observation),
`chain-evidence-sealed` (sealed via the existing proof-gated 5H
seam — e.g. `ev-cf9123784c5cdc417f25c8c5cd755d3b`, digest
`77952b15…`), `chain-dial-audit` (exactly `8.8.8.8:18081x2` —
machine-checkable; an IPv4-allowlist scan test pins every literal
in the harness). TLS proof fields are nominal for the plaintext
fixture (`no-tls-plaintext`, documented in-scenario); binding force
comes from peer+pin+binding+lineage. Residual risk: a single SYN to
a high port IF all three kernel assertions lied simultaneously —
never observed; kernel would have to be broken.

## 7. Freshness policy — RESOLVED

New deterministic rule in `ai/execution/b3_boundary.py`
(`check_authorization_freshness`, exported): an authorization is
fresh exactly when `issued_at <= now < expires_at`, parsed with the
5B-identical rule (`fromisoformat`, naive read as UTC — the single
documented resolution of timestamp ambiguity, not a second grammar).
Consistent with 5B `_is_live` (expiry exclusive; plus not-yet-valid
refusal, a pure tightening). Wired into `build_egress_policy`
(required keyword-only `now` — deterministic clocks only, no wall-
clock reads) and the pilot gate's `authorization_fresh` item, and
threaded through `require_fresh_scope_for_redirect` (a redirect can
no longer outlive the authorization window). 6 new boundary tests
green: open/closed instants, 1µs margins, naive==aware equivalence,
malformed/inverted windows, gate denial, post-expiry redirect
refusal. Existing fixtures (NOW inside window) unaffected; full
regressions green. This is an explicit, documented tightening per
Part E — not a silent semantic change, and nothing was loosened to
make validation pass.

## 8. Persistence dry-run — UNPROVEN

Part F requires the Part A server; without it the Mongo-backed
Stage 1/2 flow cannot run. The fake-driver Stage 2 dry-run suite
re-ran 39/39 green (behavior unchanged, still UNKNOWN/non-finding
terminus). Durable-record/CAS/sweep-against-persistence proofs await
a dedicated test URI.

## 9. Security review

SSRF/destination-override: exact-match policy + FIB matrix +
chain-audit green; residual = packet-filter layer. DNS rebinding:
no lookup on path (sabotage-proven); scripted answers only.
Host-header: translator forbids `host`; B3 never reads it (suite).
Redirect: fresh-scope live-proven incl. post-expiry refusal.
Private/metadata: triple-layer refusal green. Proxy: DIRECT-ONLY
posture unchanged. Namespace escape: non-persistent userns,
mapped-root `ip` only, parent verified unchanged; no setuid vector.
Egress bypass: FIB proven, nft/iptables outstanding. Stale/drift:
window + hash enforced live. Replay/CAS races: unit-proven;
server-side outstanding. Evidence tampering: hash discipline +
proof-gated seal live-proven (chain). Exhaustion: stall/bytecaps
live; CPU/mem/process outstanding. Orphans: reap + ns-death +
kill-path green (3/3 runs). Credentials: none in fixtures/code;
static errors; prod DB refused by tested guard. No backdoor, test
bypass, env bypass, monkeypatch affecting production, or alternate
activation path was introduced (AST + import-surface reviewed).
Zero risk is not claimed — §16 lists the 7 blockers.

## 10. Exact commands

```bash
python3 -m unittest ai.test_stage1_offline ai.test_stage2_production_reads ai.test_b3_boundary ai.test_b3_mongo_integration ai.test_b3_validation ai.test_pilot_readiness
python3 -m unittest ai.test_execution_authorization ai.test_scope_evaluator ai.test_target_resolver ai.test_evidence_store ai.test_evidence_core ai.test_deterministic_verifier ai.test_finding_pipeline ai.test_legacy_severance_5k ai.test_b1_dial_policy
python3 -m unittest ai.test_http_pinned_executor ai.test_nuclei_executor ai.test_artifact ai.test_artifact_store ai.test_artifact_retrieval ai.test_test_plan_builder ai.test_test_plan_readiness ai.test_hypothesis_testplan ai.test_hypothesis_engine ai.test_xss_verification ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter ai.test_xss_orchestrator ai.test_xss_pipeline ai.test_composite_executor ai.test_nuclei_ready ai.test_target_matcher ai.test_target_intelligence
WATCH_STAGE4_NETNS=1 python3 -m unittest ai.test_b3_validation.GatedValidationTests ai.test_pilot_readiness.GatedReadinessTests
git diff --check
git status --short
```

## 11. Exact test counts

- Stage batch: **131 tests OK** (8 env skips: 5 mongo classes + 3 gated).
  New coverage: B3 boundary 52 (46 + 6 freshness), validation 15
  (12 unit + 3 gated incl. chain), readiness 12 (11 unit + 1 gated).
- Batch 1 (authority chain/B1/evidence/verifier/finding/severance):
  **768/768 OK**. Batch 2 (executors/artifacts/plans/XSS/LLM/targets):
  **976/976 OK**. Combined unit: **1875, 0 failures**.
- Gated (opt-in, real namespaces): **3/3 OK**, stable across 3 runs
  (~12 s; harness ledger 27 PASS / 1 UNPROVEN / 0 FAIL per run).
- `git diff --check`: only pre-existing
  `ai/correlator/version.py` whitespace noise (untouched); all Stage 5
  files verified trailing-whitespace-free by direct scan.

## 12. Skipped tests

5 real-Mongo classes (no URI/server); 3 gated without opt-in
(refusal = UNPROVEN); `timeout-syn-drop` + CPU/mem/process +
server-backed dry run (capability absent). Skips are explicit and
counted; none masks a failure.

## 13. UNPROVEN items

`b2-mongo-authorization`, `b2-ledger`, `b2-audit`,
`b2-evidence-persistence`, `real-mongo-concurrency`,
`resource-enforcement` (subset live-proven, overall strict),
`evidence-path` (seal live-proven via chain; server persistence
outstanding). Plus out-of-matrix: iptables/nft, SYN-DROP, CPU/mem/
process, Part C server dry run. Each names its missing environment,
none simulated.

## 14. Files created

- (Stage 5 deltas inside existing stage files — no new top-level
  test files; new scenario/checks live in the Stage 4 modules by
  design, keeping one harness and one matrix.)
- `agent-reports/stage-5-activation-readiness-review.md` (this report).

## 15. Files modified

- `ai/execution/b3_boundary.py`: +`check_authorization_freshness`
  (+export), required `now` on `build_egress_policy` /
  `require_fresh_scope_for_redirect`, gate freshness wiring.
  Tightening only; no gate weakened, no switch touched.
- `ai/execution/b3_validation.py`: chain fixture constants/guards,
  guarded `_FixtureServer` binds, `dialproof_chain` scenario,
  `CHAIN_CHECK_NAMES`, doc updates.
- `ai/execution/pilot_readiness.py`: item 8 evidence-fed from chain
  checks (was strict-UNPROVEN), `_CHAIN_CHECKS` import.
- `ai/test_b3_boundary.py`: +6 `FreshnessPolicyTests`; `now`
  threading at all build/redirect call sites.
- `ai/test_b3_validation.py`: `ChainGuardTests`, IPv4-allowlist
  hygiene scan, chain names in gated expectations.
- `ai/test_pilot_readiness.py`: gated counts 10/7, chain PASS
  assertion.
- Untouched: `ns/`, `enum/`, `http/`, `crawl/`,
  `nuclei/watch_nuclei_all.py`, legacy verification, systemd units,
  `run-pipeline.sh`, `run-heavy-guarded.sh`, `.env`, secrets, all
  live gates, B1 semantics, 5H/5I/5J. No Git ops beyond read-only
  status/diff; nothing committed/pushed/reset.

## 16. Readiness matrix

```
b1-address-source | PASS | fail-closed w/o transport + frozen allow/deny round-trip executed offline
b2-mongo-authorization | UNPROVEN | server evidence: UNPROVEN; needs dedicated test-URI run
b2-ledger | UNPROVEN | server evidence: UNPROVEN; needs dedicated test-URI run
b2-audit | UNPROVEN | server evidence: UNPROVEN; needs dedicated test-URI run
b2-evidence-persistence | UNPROVEN | server evidence: UNPROVEN; needs dedicated test-URI run
b3-network-namespace | PASS | harness checks green: isolated netns, no inheritance
b3-egress-filtering | PASS | harness checks green: FIB-enforced allowlist matrix
dial-proof-vs-actual-dial | PASS | authz->resolution->scope->egress->socket->proof->http->sealed evidence live
resource-enforcement | UNPROVEN | stall+bytecaps enforced live (3/3); CPU/mem/process-count UNPROVEN
redirect-fresh-scope | PASS | fresh resolve+evaluate+policy executed; stale reuse refused live
scope-drift | PASS | drifted authorization refused live with SCOPE_DRIFT
real-mongo-concurrency | UNPROVEN | server evidence: UNPROVEN; needs dedicated test-URI run
cleanup | PASS | harness checks green: teardown, reap, timeout kill
evidence-path | UNPROVEN | seal path suite-proven (Stage 1/2); server persistence needs test-URI run
deterministic-verification | PASS | pure verifier suite green (Stage 4 regressions)
finding-eligibility-unchanged | PASS | finding+severance suites green; no materialization-path change in Stage 4
live-gates-closed | PASS | LIVE_TRAFFIC/NUCLEI/BROWSER/PILOT all False; pilot config defaults False
SUMMARY | PASS=10 FAIL=0 UNPROVEN=7 | eligible=False
```

## 17. activation_eligible() result

`False` (computed conjunction over the 17 items; 7 UNPROVEN).
No override exists or was used.

## 18. Live-gate values

`LIVE_TRAFFIC_ENABLED = False`, `LIVE_NUCLEI = False`,
`HTTP_PROBE_PILOT_ENABLED = False`, BROWSER execution CLOSED
(`LIVE_BROWSER = False`), pilot config defaults `False`. Verified
post-run; the readiness module exposes no switch-writing API
(AST-tested).

## 19. Final recommendation

Stage 6 must NOT be live execution: 7 blockers remain (dedicated
test Mongo + server dry run; packet-filter + SYN-DROP + cgroup
proofs on a root-capable host). When those convert with genuine
evidence, re-render the matrix and require 17/17 + `eligible() ==
True` before even a separately reviewed controlled probe pilot.
Nuclei/browser stay blocked until their own reviews. What changed
in Stage 5 (freshness tightening, chain proof) alters no activation
posture — the pilot stays CLOSED by computation, not by promise.

## 20. Final status

**PASS WITH LIMITATIONS** (outcome B — safely CLOSED). All
runnable Stage 5 objectives met with real evidence; the 7 UNPROVEN
items are environment-bound, precisely named, and block activation
mechanically. Production readiness is NOT claimed.
