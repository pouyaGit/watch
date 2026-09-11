# Stage R24.7 — Controlled Real Research Validation

**Overall: PARTIAL.**

- **Validation objective: PASS** — the complete R24 public-research pipeline ran
  end-to-end against **real public sources**, produced hash-verified grounded
  evidence, made a real LLM call, and returned a fully-attributed research
  result. No target was contacted.
- **Deploy-as-is: NO-GO** — the shipped provider path has blocking defects
  (see §24): the NVD provider uses a host that returns HTTP 403, no real HTTP
  transport ships for `BoundedHTTPClient`/netguard, and providers bypass R24.3
  netguard for their own API calls.

This stage is a validation only. **No project source was modified.** The
validation harness is throwaway (`/tmp/opencode/r24_7_smoke.py`); only
gitignored R24 storage artifacts were written.

---

## 1. Exact CVE selected

`CVE-2026-1557` — chosen because its metadata and public references are already
in the corpus (`ai_data/research/CVE-2026-1557.cli.json`).

| Metadata | Value |
|---|---|
| CVE | CVE-2026-1557 |
| product | WP Responsive Images (WordPress plugin) |
| component | image_handler.php |
| parameter | src |
| version | <= 1.0 |
| CWE | CWE-22 |
| vulnerability type | Path Traversal |
| public references | 6 persisted URLs (plugins.trac.wordpress.org ×3, wordfence, 2 GitHub PRs) |

Only CVE metadata entered discovery. The reference set is public research
material; no target/program was used.

## 2. Exact smoke-test budget

`LoopBudgets(max_rounds=1, max_queries_per_plan=3, round2_reserve=0,
max_queries_per_run=3, max_discovered=5, max_fetched_per_plan=3,
max_fetched_per_run=3, max_bytes_per_source=2_000_000, max_bytes_per_run=4_000_000,
max_llm_calls_per_plan=1, max_llm_calls_per_run=1)`. Exactly 1 plan, 1 round,
3 discovery queries, ≤5 discovered, ≤3 fetched, ≤4 MB, ≤1 LLM call, ≤120 s.
Round 2 was not run.

## 3. Providers attempted

Leg A used the **shipped real R24.2 registry** (`build_default_registry`) with a
real, bounded, netguard-validated transport. The 3 selected queries map to
providers `nvd` (r24-cve-id) and `vendor_advisory` (r24-cve-advisory,
r24-cve-vendor). Leg B used a supplementary registry that points `nvd` at the
**real working public NVD REST endpoint** (`services.nvd.nist.gov`) to exercise
the downstream pipeline after the shipped-provider defect (no source change).

## 4. Sources discovered

| Leg | Discovered | Fetched | Evidence | Status |
|---|---|---|---|---|
| A (shipped providers) | 5 | 3 | 3 | RESEARCH_COMPLETED |
| B (downstream, real NVD) | 1 | 1 | 1 | RESEARCH_COMPLETED |

Leg A discovered:
`access.redhat.com/…`, `msrc.microsoft.com/…`, `wordpress.org/search/…`
(fetched); `www.cve.org/CVERecord?id=CVE-2026-1557`,
`www.drupal.org/search/site/…` (not fetched — fetch cap reached). All classified
`vendor_advisory`/`TRUSTED` except cve.org (`nvd_cve`/`TRUSTED`).

Leg B discovered: `services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1557`
(`nvd_cve`/`TRUSTED`).

## 5. Sources fetched

Leg A: 3 vendor pages fetched (Red Hat, Microsoft MSRC, WordPress.org).
Leg B: 1 NVD REST JSON record fetched (correct `?cveId=` filter, verified
`totalResults=1`).

## 6. Sources rejected and reasons

No source was rejected by a guard. Two Leg-A sources were not fetched because the
per-plan fetch cap (3) was reached; both were recorded as ineligible with reason
`no trusted content_hash`:
`https://www.cve.org/CVERecord?id=CVE-2026-1557`,
`https://www.drupal.org/search/site/CVE-2026-1557+advisory`.

## 7. Redirect chains

Every fetched source resolved in a single hop (no redirects). Full chains
recorded:
- `access.redhat.com/search/?q=CVE-2026-1557+advisory`
- `msrc.microsoft.com/update-guide/search?query=CVE-2026-1557+advisory`
- `wordpress.org/search/CVE-2026-1557+advisory/`
- `services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1557`

## 8. Final URLs

Identical to the single-hop chains above (all `final_url` preserved; no
downgrade, no embedded credentials, default ports only, ≤3 redirects enforced by
netguard).

## 9. Content hashes (trusted, `sha256(normalize_text(content))`)

| Source | content_hash (prefix) |
|---|---|
| access.redhat.com | `9e97e3200da139da…` |
| msrc.microsoft.com | `4c18f73902519cf1…` |
| wordpress.org | `29c5919eade5ea61…` |
| services.nvd.nist.gov (leg B) | `d2930912972f6baa…` |

## 10. Ranking results

All fetched sources scored `source_quality=0.82` (TRUSTED tier + vendor/NVD
category + exact-CVE/advisory signals). Ranking/dedup ordering was deterministic.

## 11. Dedup results

No duplicates: canonical URLs were distinct, so URL-dedup and content-hash-dedup
collapsed nothing. The NVD record (leg B) produced one canonical source and one
evidence item.

## 12. Evidence generated

- Leg A: 3 grounded evidence items (`de-b94e31d074906856`,
  `de-9fafe3d8c7519e90`, `de-7512c2d4b8be765d`), each traceable to its source and
  trusted hash.
- Leg B: 1 grounded evidence item (`de-08eee9e055c74e57`) from the real NVD JSON
  record; `claim` is a bounded excerpt of the supplied content.

All evidence preserved `source_id`, canonical/final URL, `content_hash`,
category, tier, quality, provider/query/template and redirect chain;
`production_finding=False`.

## 13. LLM call result

Leg B made the single budgeted real OpenRouter call using the configured
`OPENROUTER_MODEL` (`nvidia/nemotron-3-ultra-550b-a55b:free`); no key or header
was printed or persisted.

- Corrected run: `llm_status="ok"`, `RESEARCH_COMPLETED`. Output: summary +
  6 supported claims + 2 inferences + 4 unknowns + 3 gaps + 4 safe suggested
  queries.
- First (harness-bug) run: the provider returned
  `OpenRouterProviderError: OpenRouter response has no choices`; R24.6
  fail-softed to `RESEARCH_PARTIAL` with `llm_error` recorded and deterministic
  evidence preserved. The corrected run succeeded, showing the failure was
  transient/model-side.

## 14. Attribution validation

Every accepted supported claim referenced **real** evidence/source ids
(e.g. `de-08eee9e055c74e57`, `ds-774180a4cdcfdfbe`). An adversarial replay
against the **real Leg-B context** (deterministic, offline) confirmed:

| Adversarial item | Outcome |
|---|---|
| claim citing invented source id | **dropped** (`unknown attribution`) |
| claim citing invented evidence id | **dropped** (`unknown attribution`) |
| claim containing invented URL `https://evil.example/…` | **dropped** (`invented URL`) |
| unsupported claim (no overlap with evidence) | **downgraded to UNKNOWN** |
| claim with `EXPLOITED`/`FINDING` | **dropped** (forbidden verdict) |
| summary with `VULNERABLE`/`VERIFIED` | **cleared** |
| inference citing invented evidence id | **dropped** |

Exactly one well-grounded claim was accepted in the adversarial set.

## 15. Rejected / hallucinated content

In the real LLM run there were no hallucinations. In the adversarial replay:
6 items dropped, 1 downgraded to UNKNOWN, 1 summary cleared. Unsafe suggested
queries (`dell.example.com target`, `https://evil.example/x`, `10.0.0.5`,
`target cookie`) were rejected; the safe `CVE-2026-1557 advisory` was kept.

## 16. Gaps / unknowns (real LLM output)

Gaps: no public PoC/exploit referenced; no vendor advisory/patch linked in the
NVD record; limited code-path detail. Unknowns: patched version beyond 1.0;
exact traversal sequences; in-the-wild exploitation; vendor response timeline.
These were **recorded, not acted on** — round 2 was not executed.

## 17. Exact research status

Leg A: `RESEARCH_COMPLETED` (deterministic; LLM disabled to reserve the single
call). Leg B: `RESEARCH_COMPLETED`. First harness-bug run: `RESEARCH_PARTIAL`
(LLM transient failure). All results `production_finding=False`,
`public_research_only=True`.

## 18. Resource usage / runtime

Corrected run: **72.06 s** total (leg A + leg B), within the 120 s cap; 0 errors.
Network calls: 3 provider queries + up to 3 source fetches (leg A) + 1 provider
query + 1 fetch (leg B) + 1 LLM call. No budget exceeded.

## 19. Storage result

Stored via the existing R24.6 storage (atomic, idempotent) under the gitignored
tree:
- `ai_data/research/agent/r22-38d26f10681e9a0f.r24-loop-1.loop.json` (leg A)
- `ai_data/research/agent/r22-fda96966ea7af4ae.r24-loop-1.loop.json` (leg B)

Each contains round number, queries/provenance, provider failures, counts,
`DiscoveryBlock` (sources/evidence/redirect chains/final URLs/hashes), LLM
analysis, gaps/unknowns, model identifier, rule versions, status and budgets.
Secret scan of the artifacts: **no secrets**. Target-token scan
(`dell`/`indeed`): **none**.

## 20. Pre-run safety checks

| Check | Result |
|---|---|
| `WATCH_RESEARCH_DISCOVERY` set? | **No** (off) |
| Scheduler enabled? | **No** (`SchedulerConfig.enabled=False`) |
| Concurrent systemd timer/service? | **No** — `watch-research.timer` inactive/not-found; no units installed on this host |
| Target URLs/hosts/IPs in context? | **None** — `dell`/`indeed` absent from LLM context and stored artifacts |
| Only public CVE metadata used? | **Yes** |
| Configured provider/model present? | **Yes** (key/model present in `.env`; values not printed) |
| Budget = small smoke budget? | **Yes** |
| `production_finding=False`? | **Yes** |

## 21. Explicit confirmations

- **No target interaction** — only public NVD/vendor/GitHub-adjacent research
  hosts were contacted; `dell.com`/`indeed.com` were never contacted.
- **No target information in the LLM** — program tokens were exclusion filters;
  verified absent from the context.
- **No Nuclei**, **no PoC**, **no browser**, **no 5B–5J**, **no verifier**,
  **no findings**, **no alerts**.
- **`production_finding=False`** throughout.
- **Scheduler remained disabled/off.**
- **R23 unchanged.**
- **No project source modified**; no commit/push/reset.
- **No secrets** printed or persisted.

## 22. All test counts / results

Before the smoke and after the smoke (identical):

| Suite | Result |
|---|---|
| `tests.test_research_agent` | 92 OK |
| `tests.test_research_agent_r24_1` | 43 OK |
| `tests.test_research_agent_r24_2` | 50 OK |
| `tests.test_research_agent_r24_3` | 80 OK |
| `tests.test_research_agent_r24_4` | 71 OK |
| `tests.test_research_agent_r24_5` | 38 OK |
| `tests.test_research_agent_r24_6` | 49 OK |
| **Combined** | **Ran 423 tests … OK** |

`git diff --check` → clean (rc=0).

## 23. Defects / findings discovered (not fixed; reported per instruction)

1. **NVD provider host returns 403.** `NVDProvider` calls
   `https://nvd.nist.gov/rest/json/cves/2.0?cveId=…`, which returns **HTTP 403**
   (bot protection). The working public endpoint is
   `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=…` (**HTTP 200**,
   real record). The shipped provider therefore yields **no NVD source**.
2. **No real HTTP transport ships.** `BoundedHTTPClient` defaults to
   `transport=None` and rejects all calls; `netguard.safe_fetch_with_redirects`
   likewise requires an injected transport. A deployment must wire one (R24.6
   flagged this as a known limitation).
3. **Providers bypass R24.3 netguard.** Providers call
   `self.http.request(...)` (R24.2 `validate_source_url` only), not
   `request_via_netguard(...)`; DNS pre-resolution and per-hop redirect
   validation apply only to the loop's source-body fetcher.
4. **Vendor-advisory source quality.** The vendor provider returns broad vendor
   *search* pages (e.g. `msrc.microsoft.com/update-guide/search`, WordPress
   search) classified `vendor_advisory`/`TRUSTED`; these pages carry no
   CVE-specific advisory text, yet became evidence with generic page-title
   claims (e.g. "Security Update Guide - Microsoft"). This overstates confidence.
5. **Transient LLM free-model failure.** The configured free model once returned
   "no choices"; R24.6 fail-soft handled it correctly. The provider hard-codes
   `response_format={"type":"json_object"}` (pre-existing R23 behaviour), which
   some free models may not support.

## 24. Known limitations

- The validation required a supplementary real NVD URL (defect 1) and a
  validation-only transport (defect 2); a pure shipped-code run yields
  `RESEARCH_BLOCKED`.
- `claim` text for JSON sources is a raw body excerpt (no semantic extraction).
- Evidence grounding is structural (substring/token overlap), not semantic.
- Only 3 of 12 R24.1 templates were exercised (tiny budget); GitHub advisory
  discovery and vendor-specific advisory parsing were not exercised.
- Round 1 only; round-2 gap-directed behaviour validated synthetically in R24.6.

## 25. Recommendation for R24.8

Before scheduler integration:

1. Fix the NVD provider canonical host to `services.nvd.nist.gov` (real defect).
2. Ship a single real, bounded transport adapter and route **both** provider
   discovery and source-body fetching through R24.3 netguard
   (`request_via_netguard`), so DNS/hop validation is universal.
3. Tighten vendor-advisory classification so generic search pages cannot become
   TRUSTED evidence without CVE-specific content.
4. Keep `WATCH_RESEARCH_DISCOVERY=false` by default; wire it through the existing
   R23 scheduler/timer only after (1)–(3), with the smoke budget as the initial
   production envelope.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R24.7
- Role: Controlled Real Research
