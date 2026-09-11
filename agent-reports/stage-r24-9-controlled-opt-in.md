# Stage R24.9 — Controlled Opt-in Scheduler Run

**GO** for opt-in controlled enablement. The **real** R23 scheduler path ran the
R24 discovery pipeline end-to-end with `WATCH_RESEARCH_DISCOVERY=true` for a
single controlled invocation, while the default remained `false`. No project
source was changed for this stage.

---

## 1. Exact command / invocation

A validation-only harness (`/tmp/opencode/r24_9_scheduler_run.py`, **not**
project source) exercised the real scheduler API — no direct
`DiscoveryResearchAgent` call as the primary validation:

```python
config    = SchedulerConfig.from_env(ENV)                 # discovery=true
agent     = research_cli._build_research_agent(config)    # factory path
scheduler = ResearchScheduler(config, agent=agent)        # real scheduler
record    = scheduler.run_once(plan_id=PLAN, force=True,
                               dry_run=False, network=True)
```

`ENV` (process-local only; nothing persisted):

```
WATCH_RESEARCH_ENABLED=true WATCH_RESEARCH_NETWORK=true WATCH_RESEARCH_LLM=true
WATCH_RESEARCH_DISCOVERY=true WATCH_RESEARCH_MAX_PLANS=1 WATCH_RESEARCH_MAX_MINUTES=2
WATCH_RESEARCH_DISCOVERY_MAX_PLANS=1 WATCH_RESEARCH_DISCOVERY_MAX_ROUNDS=1
WATCH_RESEARCH_DISCOVERY_MAX_QUERIES_PER_PLAN=3 WATCH_RESEARCH_DISCOVERY_MAX_DISCOVERED=5
WATCH_RESEARCH_DISCOVERY_MAX_FETCHED=3 WATCH_RESEARCH_DISCOVERY_MAX_BYTES_PER_SOURCE=2000000
WATCH_RESEARCH_DISCOVERY_MAX_BYTES_PER_RUN=4000000 WATCH_RESEARCH_DISCOVERY_MAX_LLM_CALLS=1
WATCH_RESEARCH_DISCOVERY_DEADLINE_SECONDS=120
WATCH_RESEARCH_AGENT_DIR=/tmp/opencode/r24_9_agent
WATCH_RESEARCH_LOCK=/tmp/opencode/r24_9_agent/research.lock
```

## 2. Scheduler path exercised

```
ResearchScheduler.run_once(force=True)
  -> SchedulerConfig (window/lock/deadline/max_plans)
  -> research_cli._build_research_agent(config)      # discovery factory
  -> DiscoveryResearchAgent.run_plans
  -> run_llm_research_loop (R24.6)
  -> QueryBuilder (R24.1) -> ProviderRegistry (R24.2)
  -> R24.3 netguard -> R24.8 HTTPTransport -> public sources
  -> ranking/dedup (R24.4) -> evidence integration (R24.5) -> LLM analysis
  -> storage.store_research_loop + scheduler run record
```

## 3. Configuration before / after

| | before | after |
|---|---|---|
| `SchedulerConfig.from_env({}).discovery` | `False` | `False` |
| `SchedulerConfig.from_env({}).enabled` | `False` | `False` |
| `.env` `WATCH_RESEARCH_DISCOVERY` entries | 0 | 0 |
| `watch-research.service` | inactive | inactive |
| `watch-research.timer` | inactive | inactive |

Process env was supplied only to the harness; no persistent environment change
was left behind.

## 4. Discovery flag state

`discovery=false` → `_build_research_agent` returns the legacy R23
`ResearchAgent`. `discovery=true` → `DiscoveryResearchAgent`. Verified in the
same process (`discovery_false_agent="ResearchAgent"`,
`discovery_true_agent="DiscoveryResearchAgent"`).

## 5. Lock state

- Only the existing scheduler lock is used: `WATCH_RESEARCH_LOCK` →
  `/tmp/opencode/r24_9_agent/research.lock`, created (`lock_created=true`).
- Exactly **1** lock file (`lock_count=1`); no second lock.
- The adapter exposes no `lock_path` and no `run_once` (`false`/`false`) — it
  cannot run its own scheduler.

## 6. Window / force behavior

Configured window `18:00-00:00 Asia/Tehran`. The run occurred outside it
(`in_window=false`); the existing supported `force=True` mechanism was used
(`forced=true`, `skipped=null`). The scheduler window was **not** modified.

## 7. CVE selected

`CVE-2026-1557` (plan `r22-38d26f10681e9a0f`, declared program `dell`). Only CVE
metadata entered discovery; the program label was used solely as a forbidden
token/host.

## 8. Queries

`["CVE-2026-1557", "CVE-2026-1557 advisory", "CVE-2026-1557 vendor"]`
(3/3 allowed; templates `r24-cve-id`, `r24-cve-advisory`, `r24-cve-vendor`).

## 9. Providers

`nvd` and `vendor_advisory` (from the fixed template→provider map).

## 10. Sources discovered / fetched

Discovered **5/5**; fetched **3/3**; relevant 3; evidence **1**.

Discovered URLs: `services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1557`,
`www.cve.org/CVERecord?id=CVE-2026-1557`, `access.redhat.com/search/…`,
`msrc.microsoft.com/update-guide/search…`, `www.drupal.org/search/site/…`.

## 11. Network destinations contacted

Public research only: `services.nvd.nist.gov`, `cve.mitre.org`, `www.cve.org`,
`access.redhat.com`, `msrc.microsoft.com`, `helpx.adobe.com`,
`www.apache.org`, `nodejs.org`, `wordpress.org`, `www.drupal.org`,
`www.nginx.com`, `www.oracle.com`, `www.php.net`, `www.python.org`.

**No** `dell.com` / `indeed.com` / target host/IP; no localhost/RFC1918/
link-local/metadata destination.

## 12. Redirect chains

All fetched sources resolved in a single hop; each chain recorded:
`access.redhat.com…`, `msrc.microsoft.com…`, `services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1557`.
No redirect was followed to a forbidden host.

## 13. Hashes

Trusted `sha256(normalize_text(body))`:
`services.nvd.nist.gov` → `3590199b2b04…`; `access.redhat.com` →
`9e97e3200da1…`; `msrc.microsoft.com` → `4c18f7390251…`.

## 14. Evidence

`de-1ede4c69371d5866` ← source `ds-774180a4cdcfdfbe`
(`services.nvd.nist.gov`, `nvd_cve`/TRUSTED, hash `3590199b2b04…`,
provider `nvd`, query `CVE-2026-1557`, template `r24-cve-id`, redirect chain
`[services.nvd.nist.gov…]`). Generic vendor search pages were **not** evidence
(`content lacks CVE/advisory-specific signal`).

## 15. LLM result

`llm_status="ok"`, model `nvidia/nemotron-3-ultra-550b-a55b:free` (configured),
exactly one call per run. Six supported claims, **all** attributed to the real
evidence/source (`de-1ede4c69371d5866`, `ds-774180a4cdcfdfbe`); no invented
URLs, source ids, evidence ids or hashes; no `VULNERABLE`/`VERIFIED`/`EXPLOITED`/
`FINDING` verdicts; no target information. One earlier R24.8 invocation
fail-softed on a free-model "no choices" with `llm_error` recorded key-free.

## 16. Runtime

Run 1: **69.45 s**; Run 2: **80.52 s** (each ≤ 120 s envelope). Both
`RESEARCH_COMPLETED`, plans 1/1, failures `[]`.

## 17. Budget usage

1 plan (1/1), 1 round (1/1), 3 queries (3/3), 5 discovered (5/5), 3 fetched
(3/3), ≤2 MB/source, ≤4 MB/run, 1 LLM call/run, deadline 120 s. No budget
exceeded (loop `budgets` recorded in the artifact).

## 18. production_finding / public_research_only

`production_finding=false` and `public_research_only=true` on every loop result
and every round.

## 19. Target safety confirmation

No target contact. The program label `dell` appears **only** in the R23
scheduler run record as the plan's declared program (pre-existing R23 storage
behaviour); it is absent from the R24 loop artifact, the sanitized LLM context,
and all evidence. No Nuclei, PoC, browser, verifier, 5B–5J, finding or alert was
invoked; `database/db.py` untouched; no commits/pushes.

## 20. Test counts

| Suite | Tests |
|---|---|
| `tests.test_research_agent` | 92 |
| `tests.test_research_agent_r24_1` | 43 |
| `tests.test_research_agent_r24_2` | 50 |
| `tests.test_research_agent_r24_3` | 80 |
| `tests.test_research_agent_r24_4` | 71 |
| `tests.test_research_agent_r24_5` | 38 |
| `tests.test_research_agent_r24_6` | 49 |
| `tests.test_research_agent_r24_8` | 31 |
| **Combined** | **Ran 454 tests … OK** |

No new R24.9 unit tests were needed (no source defect found; R24.8 already
covers the integration). `git diff --check` → **clean (rc=0)**.

## 21. Netguard verification

Instrumented during the real run: **36** DNS pre-resolutions and **36** netguard
fetches, covering both provider discovery API hosts and fetched source pages
(single `safe_fetch_with_redirects` path for both). Offline property checks:
`10.0.0.5`/`127.0.0.1` → `rejected:private_ip`; `169.254.169.254` →
`rejected:private_ip`; `localhost` → `rejected:host`; `user:pass@` →
`rejected:embedded_credentials`; `https→http` → `rejected:scheme_downgrade`;
`:8443` → `rejected:port`; explicit redirect chain hard-stops at
`MAX_REDIRECTS=3` (`error="redirect_limit"`, 3 hops); same-host redirect
followed (`hops=1`, chain length 2, body present).

## 22. Idempotency result

Two scheduler invocations produced the same deterministic result id
`loop-12f2e459394d3256`. Storage result: **1** loop artifact, **2** run records,
**0** finding/alert artifacts. The second `store_research_loop` did not
overwrite the first (idempotent); no destructive overwrite and no duplicate
authoritative finding (storage is research-only).

## 23. Remaining limitations

1. **Free-model variance** — `nvidia/nemotron-3-ultra-550b-a55b:free`
   intermittently returns "no choices"; fail-soft preserves evidence. A stable
   model is recommended for unattended operation.
2. **Rank vs. fetch budget** — generic vendor search pages share the NVD
   source quality; with the tiny fetch cap they can precede/consume slots before
   NVD (observed in R24.8). The evidence gate still prevents them from becoming
   evidence.
3. **Claim extraction** is a bounded raw-body excerpt for JSON sources.
4. **No mid-plan interrupt** — the loop is bounded by tiny query/fetch/LLM
   budgets, transport timeouts, and a per-plan deadline check.
5. The controlled run used `force=True` outside the window (supported mechanism).
6. `/tmp` artifacts/harness are validation-only and outside the repository.

## 24. GO / NO-GO

- **GO** — the actual R23 scheduler path runs R24 discovery end-to-end when
  opted in, with netguard-validated public-only traffic, bounded budgets,
  deterministic evidence, and preserved safety invariants.
- **Default-off remains required.** `WATCH_RESEARCH_DISCOVERY=false`; the timer
  was not enabled; do not flip the default until the §23 items (notably model
  stability and rank/fetch budgeting) are addressed.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R24.9
- Role: Controlled Opt-in Scheduler Run
