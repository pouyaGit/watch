# Stage 6 — Final Pre-Activation Validation (Pilot NOT Activated)

## 1. Objective

Close the Stage 5 environment blockers (10/17 PASS, 7 UNPROVEN) with
genuine environment evidence and re-render the machine-checkable
readiness matrix — no redesign, no broadened scope, no live target
traffic. Result: **16/17 PASS, 0 FAIL, 1 UNPROVEN**,
`activation_eligible() == False`. The single remaining UNPROVEN
(`resource-enforcement`: CPU/memory/process-count need cgroup
delegation this host cannot grant) blocks activation mechanically.
Outcome (B): safely CLOSED. Nothing was manufactured: the two
concurrency bugs the real server exposed were fixed as product bugs
with regression proof, and every PASS cites executed evidence below.

## 2. Exact environment

WSL2 (6.18.33.2-microsoft-standard-WSL2), uid 1000, `CapEff=0`,
no sudo, no separate root-capable validation env provided.
Provisioned by this stage (tooling download, documented): official
`mongod` 8.0.12 (ubuntu2404 build) extracted to
`/tmp/stage6mongo`, run unprivileged with `--dbpath
/tmp/stage6mongo/data --bind_ip 127.0.0.1 --port 27019` (deliberately
NOT the production 27017), no auth, localhost-only, throwaway data
dir. Test inputs used ONLY as process env for test commands:
`WATCH_TEST_MONGO_URI=mongodb://127.0.0.1:27019`,
`WATCH_TEST_MONGO_DB=watch_stage6_test` (never written to `.env`,
never committed). No `iptables`/`nft` binaries; cgroup v2 present
but read-only (`mkdir` denied; system cgroups untouched per the
rules). `unshare -Urn` permitted. Parent netns verified unchanged
after every gated run.

## 3. Mongo server validation — PROVEN

Dedicated server only (8.0.12, empty at start: only
`admin`/`config`/`local` system DBs). The 16-test skip-safe suite
(`ai.test_b3_mongo_integration`) RAN: green 11/11 consecutive runs
after two genuine findings (see §6/§23). Refusal logic re-verified:
absent URI → skip; `watch`/`admin`/`local`/`config` (via DB var or
URI path) → skip; non-mongo scheme → skip. All test data lives in
`b3t_*` collections inside `watch_stage6_test`, created and dropped
by the suite; post-run the database holds zero non-system
collections (verified).

## 4. Mongo indexes — PROVEN (server metadata)

Queried via `list_indexes()` on collections carrying the declared
sets (created exactly as production wiring must):

- authorization: `_id_` (`_id`, enforced by construction) +
  `b3t_idempotency_key` (`idempotency_key`, unique:true).
- ledger: `_id_` + `b3t_slot` (`slot`, unique:true) +
  `b3t_idempotency_key` (unique:true).
- audit: `_id_` only (`_id` = execution:seq, uniqueness by
  construction — no explicit index document exists, accurately
  recorded, not simulated).
- evidence blob: `_id_` only (`_id` = content hash, by construction).
- evidence index: `_id_` + `b3t_execution_id` (unique:true) +
  `b3t_slot` (unique:true).
- Duplicate-write behavior verified per store: authz re-put and
  key clash → `DuplicateIdempotencyKeyError`; ledger slot clash →
  `ReplayExecutionError` (after the §23 fix); ledger key clash →
  `DuplicateExecutionError`; audit seq clash →
  `AuditPersistenceError` (ordered `records_for` intact); blob
  identical → dedupe `False`, differing-bytes →
  `EVIDENCE_HASH_MISMATCH`; index re-insert → `False`, conflicting
  bindings → `IndexDuplicateError`. No duplicate durable records
  observed anywhere.

## 5. Mongo concurrency — PROVEN (exact counts, no swallowing)

Real thread races (`threading.Barrier`-released workers) with exact
winner/loser/error assertions, stable across 8+ consecutive runs:

- same-key authorization idempotency, 8 workers: 1 winner, 7 losers,
  all `DuplicateIdempotencyKeyError`.
- competing issuance (distinct keys), 8 workers: 8 winners, 0 losers.
- authorization CAS race, 4 workers: 1 winner (version 2), 3 losers,
  all `VersionConflictError`.
- ledger slot race, 8 workers: 1 winner, 7 losers, all
  `ReplayExecutionError` (required the §23 fix; fake driver never
  interleaved this path).
- ledger CAS race on a live row, 4 workers: 1 winner (`STARTED`),
  3 losers, all `InProgressExecutionError` (required the §23 fix;
  flaked 1-in-7 pre-fix with generic `LedgerError`).
- audit sequence race, 6 workers: 1 winner, 5 losers, all
  `AuditPersistenceError`.
- duplicate blob writes, 6 workers: exactly 1 `True`, 5 `False`,
  zero exceptions (idempotent success under concurrency).
- index race, 4 workers (distinct execution/authorization/slot per
  worker — sharing any violates the real unique indexes by design):
  4 winners. (The pre-fix test wrongly shared them and the server
  correctly refused — test bug, fixed; adapter mapping was already
  correct.)
- No swallowed exceptions (every loser asserts its exact domain
  type), no unsafe retry, no `sleep`-papered races.

## 6. Mongo failure semantics — PROVEN

Closed-client operations → `MongoUnavailableError` from issuance
reads and writes (fail closed, static messages, no URI/credential
leak). Driver-failure-injection behavior unchanged and green.
Adapters cache nothing, synthesize nothing, retry nothing unsafe:
every outage surfaces as the typed unavailable error at the seam.

## 7. Persistence dry-run — PASS

New skip-safe `ai/test_stage6_dryrun_mongo.py` (4 tests, green 3/3
runs) injects real-mongo `Stage2Stores` into the unmodified
`run_stage2_dryrun` (`stores=` is the designed seam — "real wiring
later"): end-to-end flow keeps the Stage 1/2 terminus (handoff
accepted, `UNKNOWN`/`POTENTIAL` never `CONFIRMED`, authorization
`CONSUMED`, 5J materialization refused, sweep report clean), with
durable proof on the server — ledger row `SEALED_REF`, ≥2 audit
entries, blob bytes byte-identical to `canonical_envelope_bytes`,
index entry hash-matched. Restart/re-read across a FRESH client:
authz artifact hash, ledger lifecycle, audit count, blob bytes,
index hash all identical. Orphan sweep over real backends:
blob-without-index → `INDEX_MISSING_SEALED` → `run_sweep`
re-indexes `[evidence_id]`, zero quarantines, entry retrievable.
Production-contact guard: test asserts loopback server address,
non-production DB name, `b3t_` collection prefixes, live gates
closed, and `database.db` never imported.

## 8. Network namespace validation — PASS (re-verified)

Stage 4/5 harness results re-verified green in Stage 6 gated runs:
child `net:[inode]` differs every run; only `lo` (+ test veth while
present) visible; veth pair created/verified/deleted in-namespace;
no v4/v6 default route; parent ns unchanged; child always reaped;
hang-scenario SIGKILL→reap path green. Full ledger this stage:
28 checks (21 Stage-4 + 6 chain + 1 syndrop) → 27 PASS / 1 UNPROVEN
(`timeout-syn-drop` firewall variant — see §10) / 0 FAIL, stable
across 3 runs.

## 9. Packet-filter validation — UNPROVEN (no binaries, no privilege)

`iptables`/`nft`/`ip6tables` absent and `CapEff=0`, so genuine
packet-filter rule enforcement is unprovable on this host — recorded
UNPROVEN, not simulated. The Stage 5 FIB proof stands as the
enforced mechanism here (empty route table + single-host fixture
route; unapproved destinations fail in the kernel with
`ENETUNREACH`, dual-observed raw + product). Per the stage rule,
FIB evidence was NOT upgraded into a packet-filter PASS.

## 10. SYN-DROP validation — PROVEN (controlled, firewall-free)

New `syndrop` harness scenario: listener `backlog=1` + 5
never-accepted holders fills the accept queue, so the kernel drops
further SYNs silently (observable DROP: no SYN-ACK, no RST — the
required condition, with no packet filter and no external IP).
Measured dial (3.0 s budget, ≤60 s ceiling): blocks the full
interval (no immediate refusal), fails deterministically with
`TRANSPORT_TIMEOUT` (3.0 s observed), within ceiling, holders +
listener closed, child reaped, parent unchanged. Green 3/3 runs.
This closes the Stage 5 `timeout-syn-drop` gap at the observable
level; a firewall-rule variant remains UNPROVEN per §9.

## 11. CPU enforcement — UNPROVEN

No cgroup delegation (`mkdir` denied) and system-wide cgroups are
explicitly off-limits → cannot create load, cannot observe
throttling/termination. Not marked on values' existence.

## 12. Memory enforcement — UNPROVEN

Same cause as §11. No `memory.max` could be installed for a test
scope; no enforcement observed or claimed.

## 13. Process-count enforcement — UNPROVEN

Same cause as §11 (`pids.max` uninstallable). The harness spawns
only short-lived waited `ip` children plus one reaped validation
child per run (observed, never orphaned) — hygiene, not a limit
proof.

## 14. Dial proof — PROVEN

Stage 5 isolated full chain re-verified green in Stage 6
(`chain-resolution`, `chain-egress`, `chain-peer-proof`,
`chain-http-exchange`, `chain-evidence-sealed` with evidence id +
digest, `chain-dial-audit` exactly `8.8.8.8:18081x2`): fresh
5B/5C/5D lineage over scripted DNS → B3 egress on the exact triple
→ real socket → `getpeername` peer proof → genuine `DialProof`
assemble/verify/egress-bind → bounded HTTP within ceilings →
evidence sealed through the existing proof-gated 5H seam. B1
unchanged; fixture address text B1-admissible, destination
kernel-local with triple runtime assertions.

## 15. Freshness — RESOLVED (unchanged, re-verified)

Stage 5 rule (`issued_at <= now < expires_at`, 5B-identical parsing,
required `now` threading, gate wiring) re-verified: 6 boundary
tests green inside the 52-test B3 suite; readiness executes the
live drift/freshness proofs each render. No semantic drift since
Stage 5.

## 16. Redirect/scope validation — PROVEN (re-verified)

Readiness live-proofs execute every render: fresh
resolve→evaluate→policy succeeds; stale-id reuse refused
(`REDIRECT_REQUIRES_FRESH_SCOPE`); drifted authz refused
(`SCOPE_DRIFT`); post-expiry redirect refused
(`STALE_AUTHORIZATION`). B3 redirect/scope suites green.

## 17. Cleanup — PROVEN (re-verified)

Namespace auto-destroy (never persisted), fixture threads joined,
over-budget child SIGKILLed+reaped, parent ns unchanged, zero
`b3t_*`/test collections left behind (verified empty post-run),
mongod test data confined to the throwaway dbpath.

## 18. Security review

| Threat | Verdict | Concrete evidence |
|---|---|---|
| SSRF / destination override | PROVEN (mech: FIB+policy; packet-filter outstanding §9) | Exact-match policy; matrix + chain-audit green |
| DNS rebinding / alternate DNS | PROVEN | No lookup on path (sabotage-tested); scripted answers only |
| Host header abuse | PROVEN | Translator forbids `host`; B3 never reads it (suite) |
| Redirects | PROVEN | Fresh-scope/drift/expiry refusals executed live |
| Private networks | PROVEN | Triple-layer refusal green (FIB for B, guard+policy for rest) |
| Metadata access | PROVEN | Refused pre-socket + unreachable (169.254.169.254 redialed green) |
| Proxy bypass | PROVEN | DIRECT-ONLY posture; no proxy honored on dial path |
| Namespace escape | PROVEN | Non-persistent userns; parent inode checked every run |
| Egress bypass | UNPROVEN (filter layer) | FIB proven; nft/iptables rules outstanding |
| Stale authz / scope drift | PROVEN | Window + hash enforced live incl. boundaries |
| Replay | PROVEN | Slot→`ReplayExecutionError` under real races (fixed+proven) |
| CAS races | PROVEN | Exact domain errors, 8/8 stable runs, no swallowing |
| Evidence tampering | PROVEN | Hash discipline + proof-gated seal live; server round-trip byte-exact |
| Resource exhaustion | UNPROVEN (partial) | Stall/bytecaps/syndrop live; CPU/mem/pids outstanding |
| Timeout abuse | PROVEN | Bounded budgets expire deterministically; kill-path green |
| Cleanup failure | PROVEN | Reap + ns-death + empty-DB verified |
| Credential leakage | PROVEN | No creds anywhere; static errors; prod DB refused by tested guard |

No FAIL anywhere; no backdoor/bypass/alternate path introduced.

## 19. Exact commands

```bash
python3 -m unittest ai.test_stage1_offline ai.test_stage2_production_reads ai.test_b3_boundary ai.test_b3_mongo_integration ai.test_b3_validation ai.test_pilot_readiness ai.test_stage6_dryrun_mongo
python3 -m unittest ai.test_execution_authorization ai.test_scope_evaluator ai.test_target_resolver ai.test_evidence_store ai.test_evidence_core ai.test_deterministic_verifier ai.test_finding_pipeline ai.test_legacy_severance_5k ai.test_b1_dial_policy
python3 -m unittest ai.test_http_pinned_executor ai.test_nuclei_executor ai.test_artifact ai.test_artifact_store ai.test_artifact_retrieval ai.test_test_plan_builder ai.test_test_plan_readiness ai.test_hypothesis_testplan ai.test_hypothesis_engine ai.test_xss_verification ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter ai.test_xss_orchestrator ai.test_xss_pipeline ai.test_composite_executor ai.test_nuclei_ready ai.test_target_matcher ai.test_target_intelligence
WATCH_TEST_MONGO_URI=mongodb://127.0.0.1:27019 WATCH_TEST_MONGO_DB=watch_stage6_test WATCH_STAGE4_NETNS=1 python3 -m unittest ai.test_b3_mongo_integration ai.test_stage6_dryrun_mongo ai.test_b3_validation.GatedValidationTests ai.test_pilot_readiness.GatedReadinessTests ai.test_pilot_readiness.MongoEvidenceTests
git diff --check
git status --short
```

## 20. Exact test counts

- Stage batch: **133 tests OK** (10 env skips without server/opt-in).
  B3 boundary 52 (46 + 6 freshness), validation 15 unit + chain-guard
  additions, readiness 13 unit, mongo integration 16 (3 always-run
  guards), mongo dry-run 4.
- Batch 1 (authority/B1/evidence/verifier/finding/severance):
  **768/768 OK**. Batch 2 (executors/artifacts/plans/XSS/LLM/targets):
  **976/976 OK**. Combined unit: **1877, 0 failures**.
- Server+gated: **24/24 OK** (16 mongo + 4 dry-run + 2 netns gated
  + 1 readiness gated + 1 mongo-evidence bridge), mongo suites
  additionally 8/8 stable standalone.
- `git diff --check`: only pre-existing
  `ai/correlator/version.py` noise (untouched); all Stage 6 files
  whitespace-clean by direct scan.

## 21. Skipped tests

5 mongo classes + 1 dry-run class without URI; 3 gated without
opt-in (refusal = UNPROVEN). With the Stage 6 env: zero skips in
the 24. Skips explicit, counted, never masking failure.

## 22. UNPROVEN items

Exactly one matrix item: `resource-enforcement` (CPU/memory/
process-count need cgroup delegation; stall/bytecaps/syndrop are
4/4 live). Out-of-matrix: packet-filter rules, firewall-variant
SYN-DROP, system-wide anything (forbidden). Each names its missing
capability; none simulated.

## 23. Files created

- `ai/test_stage6_dryrun_mongo.py` (4 skip-safe server dry-run tests).
- `agent-reports/stage-6-final-pre-activation-validation.md` (this
  report).

## 24. Files modified

- `ai/persistence/mongo_ledger.py`: TWO genuine race-window fixes —
  (a) lost slot race now re-reads and raises `ReplayExecutionError`
  (was uniform `DuplicateExecutionError`, contradicting the ledger
  contract under real concurrency); (b) won-read/lost-replace CAS
  now re-reads and raises `InProgressExecutionError` on live rows
  (was generic `LedgerError`, flaked 1-in-7). Both preserve
  documented semantics (mongo now matches in-memory exactly);
  tightening/classification only, no gate weakened.
- `ai/test_b3_mongo_integration.py`: index-race fixtures made
  constraint-honest (distinct execution/authorization per worker —
  the server correctly refused the shared ones; test bug, not
  product).
- `ai/execution/b3_validation.py`: `syndrop` scenario + `SYNDROP_PORT`
  + doc updates (backlog-full DROP method).
- `ai/execution/pilot_readiness.py`: `mongo_evidence_from_suites()`
  mechanical bridge (+export); `evidence-path` evidence-fed;
  resource evidence 4/4 wording.
- `ai/test_b3_validation.py`: syndrop in gated expectations.
- `ai/test_pilot_readiness.py`: skip-safe bridge test + URI-gated
  all-PASS bridge test.
- Untouched: B1 semantics, B2 semantics (beyond the two race
  classifications), B3 product boundary, 5H/5I/5J, `ns/`, `crawl/`,
  nuclei, legacy verification, systemd units, scripts, `.env`,
  secrets, all live gates. Read-only git only; nothing
  committed/pushed/reset.

## 25. Final readiness matrix

```
b1-address-source | PASS | fail-closed w/o transport + frozen allow/deny round-trip executed offline
b2-mongo-authorization | PASS | server evidence accepted for authz
b2-ledger | PASS | server evidence accepted for ledger
b2-audit | PASS | server evidence accepted for audit
b2-evidence-persistence | PASS | server evidence accepted for blob+index
b3-network-namespace | PASS | harness checks green: isolated netns, no inheritance
b3-egress-filtering | PASS | harness checks green: FIB-enforced allowlist matrix
dial-proof-vs-actual-dial | PASS | authz->resolution->scope->egress->socket->proof->http->sealed evidence live
resource-enforcement | UNPROVEN | stall+bytecaps+syndrop enforced live (4/4); CPU/mem/process-count UNPROVEN
redirect-fresh-scope | PASS | fresh resolve+evaluate+policy executed; stale reuse refused live
scope-drift | PASS | drifted authorization refused live with SCOPE_DRIFT
real-mongo-concurrency | PASS | server evidence accepted for races
cleanup | PASS | harness checks green: teardown, reap, timeout kill
evidence-path | PASS | server evidence accepted for persistence dry-run (durable + reread + sweep)
deterministic-verification | PASS | pure verifier suite green (Stage 4 regressions)
finding-eligibility-unchanged | PASS | finding+severance suites green; no materialization-path change in Stage 4
live-gates-closed | PASS | LIVE_TRAFFIC/NUCLEI/BROWSER/PILOT all False; pilot config defaults False
SUMMARY | PASS=16 FAIL=0 UNPROVEN=1 | eligible=False
```

## 26. activation_eligible()

`False` — computed conjunction, never overridden. One UNPROVEN
remains; 17/17 was not reached, so no activation review is
triggered by this stage.

## 27. Live gate values

`LIVE_TRAFFIC_ENABLED = False`, `LIVE_NUCLEI = False`,
`HTTP_PROBE_PILOT_ENABLED = False`, `LIVE_BROWSER = False`
(all verified post-run; pilot config defaults False; readiness
exposes no switch-writing API).

## 28. Final recommendation

Do NOT propose live traffic: a single, precise blocker remains —
cgroup-delegated CPU/memory/process enforcement on a capable host
(plus, non-blocking, packet-filter rules if FIB+policy is ever
deemed insufficient). Everything else is proven with executed
evidence. The next step, when such a host exists, is a micro-stage:
prove the three cgroup limits, re-render (expect 17/17), and only
then hold the separate activation review. Nuclei/browser stay
blocked under their own reviews regardless.

## 29. Final status

**PASS WITH LIMITATIONS** — 16/17 with the 1 UNPROVEN named,
evidenced, and mechanically blocking (`eligible=False`).
Production readiness is NOT claimed; the pilot was NOT activated.
