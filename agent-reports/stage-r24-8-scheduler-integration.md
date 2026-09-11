# Stage R24.8 — Autonomous Research Scheduler Integration

**GO** for opt-in controlled enablement. All four R24.7 blockers are fixed; the
existing R23 scheduler/timer now drives the R24 discovery pipeline when
`WATCH_RESEARCH_DISCOVERY=true`, and remains byte-for-byte behaviorally
unchanged (default `false`, no R24 network activity).

No target interaction; `production_finding=False`; `public_research_only=True`
throughout.

---

## 1. Exact files changed

Tracked files (additive; `+125 / −0`):

| File | Change |
|---|---|
| `ai/research_agent/scheduler.py` | `SchedulerConfig` discovery fields + env parsing; `discovery`/`discovery_budget` in `status()`/`preview()`; `_discovery_budget()`. |
| `ai/research_cli.py` | `_build_discovery_agent(config)` factory; `_build_research_agent` returns it when `config.discovery`; discovery line in `agent status`/`dry-run`. |
| `backend/research_agent.py` | exposes `discovery` + `discovery_budget` in the read-only agent status. |
| `systemd/watch-research.service` | explicit `Environment="WATCH_RESEARCH_DISCOVERY=false"`. |

New/untracked R24 modules edited or added:

| File | Change |
|---|---|
| `ai/research_agent/transport.py` | **New** single real bounded HTTP transport adapter. |
| `ai/research_agent/discovery_runner.py` | **New** scheduler adapter + netguard registry/fetcher factories + CVE-metadata loader. |
| `ai/research_agent/providers.py` | NVD canonical host fix. |
| `ai/research_agent/provider_base.py` | `route_through_netguard` flag (provider discovery via netguard). |
| `ai/research_agent/evidence.py` | CVE-content evidence gate (`required_content_tokens`). |
| `ai/research_agent/llm_loop.py` | passes the queried CVE id as the required content token. |
| `tests/test_research_agent_r24_8.py` | **New** 31 tests. |

No atomic rebase: `database/db.py` untouched; R23 `agent.py`/`sources.py`/
`prompts.py`/`storage.py` behavior untouched; no unrelated file modified.

## 2. Exact NVD fix

`ai/research_agent/providers.py`:

```
- NVD_CANONICAL_HOSTS = ("nvd.nist.gov",)
+ NVD_CANONICAL_HOSTS = ("services.nvd.nist.gov",)
```

`https://nvd.nist.gov/rest/json/cves/2.0` returned **HTTP 403** (bot
protection); `https://services.nvd.nist.gov/rest/json/cves/2.0` returns the
CVE-filtered JSON record (**HTTP 200**). Query construction is unchanged:
`https://{host}/rest/json/cves/2.0?cveId={cve_id}`. Regression tests assert the
host is `services.nvd.nist.gov`, the `?cveId=` filter is preserved, and
`//nvd.nist.gov` is never requested.

## 3. Transport design

`ai/research_agent/transport.py` — one adapter, matching the existing
`ProviderTransport` signature (no new abstraction):

- `HTTPTransport(...)` is a callable `(method, url, *, params, headers, timeout, max_bytes)`.
- Injectable low-level `send` so unit tests never touch the network; the default
  `send` lazily imports `httpx` only when invoked.
- **Bounds:** explicit connect (5 s) / read (15 s) / total (20 s) timeouts
  (`httpx.Timeout`); hard body cap (default 2 MB), never streams.
- **No redirect following** (`follow_redirects=False`) — redirects are returned
  to netguard, which walks/validates each hop.
- **No credentials:** `user:pass@host` URLs and `Authorization` / `Cookie` /
  `Set-Cookie` / `Proxy-Authorization` / API-key headers are refused; the only
  header sent is a fixed neutral `User-Agent`.
- Preserves status, content type, body and final URL on the existing
  `ProviderResponse` shape.
- **Fail closed** (returns `None`) on timeout/network/parse errors; never logs
  secrets, auth headers or API keys.

## 4. How provider traffic is routed through netguard

`BoundedHTTPClient` gained `route_through_netguard` (+ `resolver`,
`forbidden_hosts`, `max_redirects`) which is **off by default** (preserving the
R24.2 unit tests' injected-transport semantics). When enabled, `request()` — and
therefore every provider discovery call — delegates to the existing R24.3
`request_via_netguard()` path:

- DNS pre-resolution on provider hosts (`resolve_public_ips`);
- per-hop redirect validation (`validate_hop`), max 3 redirects, no
  https→http downgrade, no non-default port, no embedded credentials;
- localhost / private / link-local / metadata / program-host / allowlist
  rejection at the initial URL and every hop;
- redirect-chain provenance preserved.

`discovery_runner.build_discovery_registry(transport, ...)` constructs the
production client with `route_through_netguard=True`; both provider discovery
and the netguard-backed source-body fetcher share the same transport. No
validation logic was duplicated or weakened.

## 5. Vendor-advisory evidence classification change

`evidence.build_evidence`/`integrate_discovery` accept
`required_content_tokens`. `llm_loop._run_round` supplies the queried
`metadata.cve_id`. A TRUSTED/SEMI_TRUSTED source is now evidence-eligible only
when the fetched content contains the exact CVE token (or another supplied
deterministic advisory token). Generic vendor search pages are recorded as
`RELEVANT_SOURCE`/non-evidence with reason
`content lacks CVE/advisory-specific signal`. Detection-rule advisory
exceptions and all existing R24.4/R24.5 rules are unchanged (the gate is only
active when tokens are supplied).

## 6. Scheduler integration

- New `WATCH_RESEARCH_DISCOVERY` (+ `WATCH_RESEARCH_DISCOVERY_*` envelope vars),
  parsed by `SchedulerConfig.from_env`.
- `_build_research_agent` returns `DiscoveryResearchAgent` when discovery is on,
  otherwise the R23 `ResearchAgent` (unchanged).
- `DiscoveryResearchAgent.run_plans` mirrors the R23 agent contract
  (`plan_id/result_id/cve_id/program/status/evidence/sources`), so the existing
  `ResearchScheduler.run_once` window/lock/deadline/fail-soft loop is reused
  **as-is**.
- **No second scheduler, no second lock, no timer change.** The adapter performs
  no locking; the scheduler holds `WATCH_RESEARCH_LOCK` exactly as before.
- Per-plan metadata comes only from public CVE JSON (`load_cve_metadata`);
  per-plan program is used solely as a forbidden token/host (never an LLM term).

## 7. Default configuration

`WATCH_RESEARCH_DISCOVERY=false` (service and code default). When false: R23
path, zero R24 network activity. Initial envelope (all configurable, safe
defaults):

```
max_plans=1  max_rounds=1  max_queries_per_plan=3  max_discovered=5
max_fetched=3  max_bytes_per_source=2_000_000  max_bytes_per_run=4_000_000
max_llm_calls=1  deadline_seconds=120
```

## 8. Systemd validation

`systemd/watch-research.service` adds only
`Environment="WATCH_RESEARCH_DISCOVERY=false"`. `systemd-analyze verify
systemd/watch-research.service systemd/watch-research.timer` → **clean (rc=0)**.
The timer was not enabled/started; cadence unchanged. No unrelated systemd
warning was touched.

## 9. Exact test counts

| Suite | Tests |
|---|---|
| `tests.test_research_agent` | 92 OK |
| `tests.test_research_agent_r24_1` | 43 OK |
| `tests.test_research_agent_r24_2` | 50 OK |
| `tests.test_research_agent_r24_3` | 80 OK |
| `tests.test_research_agent_r24_4` | 71 OK |
| `tests.test_research_agent_r24_5` | 38 OK |
| `tests.test_research_agent_r24_6` | 49 OK |
| `tests.test_research_agent_r24_8` | 31 OK |
| **Combined** | **Ran 454 tests … OK** |

`git diff --check` → clean.

## 10. Controlled smoke results

One plan (`r22-38d26f10681e9a0f`, CVE-2026-1557), discovery enabled **only** for
the invocation, `--force` (outside the Tehran window), fresh agent dir, ≤120 s.
Run record: `RESEARCH_COMPLETED`, plans 1/1, `forced=true`, `network=true`,
`llm=true`.

Plan-level loop artifact (`RESEARCH_PARTIAL`): discovered **5**, fetched **3**,
relevant **3**, evidence **1**, `production_finding=false`,
`public_research_only=true`.

| Source | Category/Tier | Eligible | Hash (prefix) |
|---|---|---|---|
| `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1557` | nvd_cve / TRUSTED | **yes** | `a056a9616e25…` |
| `https://access.redhat.com/search/?q=…` | vendor_advisory / TRUSTED | no (no CVE signal) | `9e97e3200da1…` |
| `https://msrc.microsoft.com/update-guide/search?…` | vendor_advisory / TRUSTED | no (no CVE signal) | `4c18f7390251…` |
| `https://wordpress.org/search/…` | vendor_advisory / TRUSTED | not fetched (cap) | — |
| `https://www.cve.org/CVERecord?id=CVE-2026-1557` | nvd_cve / TRUSTED | not fetched (cap) | — |

Evidence: `de-425338bb80fe1a92` (NVD record), grounded + hash-verified.
A second invocation with the same envelope produced LLM success; see §12.

## 11. Network destinations contacted

Public research only: `services.nvd.nist.gov`, `access.redhat.com`,
`msrc.microsoft.com`, `www.cve.org` (discovered), `wordpress.org`,
`www.drupal.org` (discovered). **No** `dell.com` / `indeed.com` / target host
was contacted; program tokens (`dell`) were used only to block/reject.

## 12. Redirects

All fetched sources resolved in a **single hop** (no redirects); every chain was
recorded (`redirect_chain == [final_url]`). Netguard's per-hop guard was
exercised in unit tests (private-IP hop, metadata-IP hop rejected; same-host hop
followed).

## 13. Hashes

`sha256(normalize_text(body))` trusted hashes (see §10). Evidence content hash ==
its source hash.

## 14. LLM result

Model (configured, from `.env`): `nvidia/nemotron-3-ultra-550b-a55b:free`.
Exactly one call per run. Across the controlled invocations the free model
succeeded once (attributed claims only) and returned
`OpenRouterProviderError: OpenRouter response has no choices` in others — R24.6
fail-softed to `RESEARCH_PARTIAL`, preserving deterministic evidence and
recording a key-free `llm_error`. No key/header was printed or persisted.

## 15. Safety confirmations

- **No target interaction**; no target URL/host/IP fetched; `dell`/`indeed`
  absent from stored artifacts and from the LLM context.
- **No Nuclei, no PoC, no browser, no verifier, no 5B–5J, no findings, no alerts.**
- `production_finding=False`; `public_research_only=True`.
- Existing R24.6 LLM controls preserved (attribution, forbidden-verdict
  filtering, invented URL/source/evidence rejection, bounded queries/rounds, LLM
  never creates evidence).
- Scheduler remained disabled by default; `WATCH_RESEARCH_DISCOVERY=false`.
- R23 behavior unchanged when discovery is off (suite `test_research_agent` 92 OK).
- No secrets persisted; `database/db.py` untouched; no commits/pushes.

## 16. Remaining limitations

1. **Free-model flakiness** — the configured free model intermittently returns
   "no choices"; fail-soft works, but a paid/stable model is recommended before
   unattended runs.
2. **Source ranking vs. fetch budget** — generic vendor search pages share the
   same `source_quality` as the NVD record; with a small fetch cap the vendor
   pages can consume it before NVD. Consider a tier/category preference or a
   reserved advisory fetch slot.
3. **Claim extraction** for JSON sources is a bounded raw-body excerpt (no
   semantic extraction).
4. **Mid-plan hard timeout** — the loop is bounded by tiny query/fetch/LLM
   budgets, per-call transport timeouts, and a deadline check *before each plan*;
   it cannot interrupt an in-flight plan mid-way.
5. **Idempotent loop storage** — `store_research_loop` does not overwrite an
   existing `<plan>.<rule>.loop.json`; validation runs must use a fresh agent dir
   (or add an explicit overwrite/run-scoped artifact).
6. The NVD `services` endpoint may rate-limit under load (no API key); the
   conservative envelope mitigates this.

## 17. GO / NO-GO

- **GO** for opt-in controlled enablement of R24 discovery via the existing
  scheduler (all R24.7 blockers fixed; 454 tests green; systemd verify clean;
  smoke produced real NVD evidence).
- **NO-GO for enabling by default** — `WATCH_RESEARCH_DISCOVERY` must remain
  `false` until the §16 items (notably model stability and rank/fetch budgeting)
  are addressed.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R24.8
- Role: Autonomous Research Scheduler Integration
