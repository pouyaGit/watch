# Stage R24 — Autonomous Research Source Discovery (Phase 1: Scope & Architecture)

Status: **DESIGN / SCOPE ONLY.** No code, tests, systemd, scheduler, provider,
or data was modified. No network research, no target/program contact, no Nuclei,
no PoC, no browser, no LLM invocation, no 5B–5J, no Git operations.

This document specifies the next-generation **public research source discovery**
layer (R24). It is written against the current R23 implementation and the
observed production behavior:

- R23 scheduler is active (hourly systemd timer; exact `18:00–00:00 Asia/Tehran`
  window enforced in the service; outside-window runs are skipped).
- Autonomous runs currently produce `RESEARCH_PARTIAL`, `evidence=0`, `sources=6`.
- R23.1 controlled research proved 2/6 persisted references were fetchable and
  produced grounded evidence. The binding limitation is that R23 **only**
  considers the persisted CVE reference set; it does not independently discover
  additional high-quality public research sources.

---

## 1. Source Discovery — deterministic public source categories

R24 classifies every candidate source into exactly one **category** and one
**trust tier**. Categories and tiers are assigned deterministically from the
discovery provider that produced the result plus the final URL host. A source
never promotes its own tier.

### 1.1 Categories

| Category code | Description | Examples |
|---|---|---|
| `nvd_cve` | NVD / CVE record and derived reference index | nvd.nist.gov, cve.org, cve.mitre.org |
| `vendor_advisory` | Official vendor security advisory | vendor security bulletins, `*.vendor.com/security` |
| `wordfence` | Wordfence Threat Intel | wordfence.com/threat-intel |
| `wpscan` | WPScan vulnerability database | wpscan.com/vulnerability |
| `github_advisory` | GitHub Security Advisories (GHSA) | github.com/advisories, GHSA-* |
| `github_repo` | GitHub repository / code / PR / issue / gist | github.com, raw.githubusercontent.com |
| `detection_rule` | Public detection content | nuclei-templates, crowdsec hub, sigma, yara |
| `exploit_reference` | Public exploit/PoC reference | exploit-db, packetstorm, PoC repos |
| `writeup` | Public research write-up / disclosure | researcher blogs, bug-bounty disclosures |
| `security_blog` | Reputable security news/analysis | vendor-independent security media |
| `generic_search` | Generic search engine result (discovery only) | search-engine result URLs |

### 1.2 Trust tiers

| Tier | Code | Members | May back `EVIDENCE`? |
|---|---|---|---|
| **Tier 1 — trusted** | `TRUSTED` | `nvd_cve`, `vendor_advisory`, `github_advisory` | Yes |
| **Tier 2 — semi-trusted** | `SEMI_TRUSTED` | `wordfence`, `wpscan`, reputable `writeup`/`security_blog` domains (allowlist), `exploit_reference` on authoritative databases | Yes |
| **Tier 3 — discovery-only** | `DISCOVERY_ONLY` | `github_repo` (non-advisory), `detection_rule` | Yes **only** for `detection_rule` whose content is a merged, public rule with an explicit advisory reference; otherwise no |
| **Tier 4 — generic** | `GENERIC` | `generic_search`, unlisted personal blogs, mirrors/aggregators | **No** — may become `RELEVANT_SOURCE`/`INFERENCE` only, or `EVIDENCE` only when a Tier 1/2 source independently corroborates the same claim (the evidence is attributed to the Tier 1/2 source) |

Tier assignment uses the same `classify_source`-style host allowlist as R23
(`ai/research_agent/sources.py`), extended with an explicit
`SOURCE_CATEGORY_BY_DOMAIN` table and a provider-declared category hint that
must agree with the host; a provider hint that disagrees with the host is
downgraded to the host's category (never promoted).

### 1.3 Reused versus new

- Reuse: `ai/research_agent/sources.py::validate_source_url`,
  `classify_source`, `ResearchSourceCollector`; `ai/collectors/discovery.py`
  (GitHub repository/issue search, already implemented but unused by R23);
  `ai/collectors/discovery_fetch.py`; `ai/collectors/reference.py`
  (`ReferenceCollector`, single HTTP primitive);
  `ai/researcher/reference_cache.py::canonicalize_reference_url`;
  `ai/collectors/body_extraction.py` (`normalize_text`, `sha256_text`).
- New: a provider protocol, query builder, SSRF/redirect guard, ranking, and a
  discovery ledger (all under `ai/research_agent/`, no second HTTP client).

---

## 2. Discovery Input

R24 derives **all** seed inputs from deterministic, locally available CVE
metadata and persisted artifacts. There is no free-form or target-derived
input.

### 2.1 Allowed inputs (in priority order)

| Input | Source of truth |
|---|---|
| CVE ID | R22 plan `cve_id` / NVD record |
| affected product | NVD `products` (`ai/collectors/cve.py::_document_from_cve`) |
| affected component | persisted `<CVE>.cli.json` `research.components` |
| affected parameter | persisted `<CVE>.cli.json` `research.parameters` |
| affected version | NVD `affected_versions` + persisted `research.affected_versions` |
| CWE | NVD `cwes` |
| vulnerability type | persisted `research.vulnerability_type` |
| existing references | `<CVE>.references.json` records + `.cli.json` `research.references` |

Only non-empty, length-bounded, sanitized values are used. Duplicate values are
deduplicated deterministically (sorted, case-folded comparison key).

### 2.2 Explicitly forbidden inputs (hard invariant)

The discovery layer **must never** consume, embed, transform, or reflect:

- the program/target URL, host, domain, subdomain, IP, or scope entry;
- any asset inventory / HTTP response / endpoint / parameter *value* observed
  from a target;
- credentials, cookies, headers, or environment secrets;
- anything from 5B–5J.

The program name **may** be loaded only as an exclusion filter (to reject a
discovered host); it is never a query term and never placed in a URL or query
string. A static assertion (R24.1) fails the build if a query contains a
program/asset token, and `validate_source_url(..., program=...)` is re-run on
every discovered URL and every redirect hop.

---

## 3. Search Strategy — deterministic queries

### 3.1 Query-construction contract

1. A fixed, ordered set of **query templates** is rendered from the allowed
   inputs of §2. Templates are total functions of the inputs (no clock, no
   randomness, no model).
2. Each rendered query carries structured provenance:
   `{query_id, template_id, provider, inputs_used[]}`.
3. Each query is **scoped to a provider** and, where the provider supports it,
   to an allowlisted host/`site:` (structured APIs avoid open-web scope
   entirely).
4. Query text is sanitized: strip control characters, collapse whitespace,
   bound to `MAX_QUERY_CHARS = 200`, reject/replace quotes that could alter
   provider syntax, and reject any token that is a program/asset host.

### 3.2 Template set (initial, deterministic)

Exact-token templates (Tier 1–2 providers):

```
"CVE-2026-1557"                                   (cve_id)
"CVE-2026-1557" advisory                          (cve_id)
"CVE-2026-1557" vendor                            (cve_id)
"<product> CVE-2026-1557"                         (product + cve_id)
"<component> CVE-2026-1557"                       (component + cve_id)
"CVE-2026-1557" "<CWE-502>"                       (cve_id + cwe)
"CVE-2026-1557" "<vulnerability_type>"            (cve_id + vuln type)
"<product>" "<version>" advisory                  (product + version)
```

Discovery-oriented templates (Tier 3, optional, not evidence by themselves):

```
"CVE-2026-1557" PoC
"CVE-2026-1557" exploit
"CVE-2026-1557" detection rule
"<product> <component>" nuclei
```

Each template has a fixed tier ceiling: broad PoC/exploit/detection queries can
only yield `DISCOVERY_ONLY`/`GENERIC` sources; they never become Tier 1–2 by
virtue of the query.

### 3.3 Safety properties of query generation

- **No target-host leakage.** Inputs are CVE metadata only (§2); the program
  name/host is excluded from the input set and used only as a rejection filter.
  A runtime assertion checks that no rendered query contains any program host,
  scope entry, or discovered forbidden token.
- **No arbitrary target URLs.** R24 never accepts a URL as input. It only emits
  queries to allowlisted structured providers and only fetches URLs returned by
  those providers, after validation.
- **No search poisoning.** (a) Queries prefer exact-token matching. (b) A
  deterministic relevance gate requires the CVE id (or product+component) to
  appear in the returned title/snippet/path. (c) Tier 4/generic results can
  never become evidence unless corroborated by a Tier 1/2 source. (d) Only
  structured provider APIs are enabled by default; open-web search is opt-in and
  its results are always Tier 4.
- **No unbounded expansion.** Fixed template count, fixed results per query,
  fixed total sources, at most two discovery rounds, and **no recursive link
  crawling** — R24 fetches only the exact discovered result URLs, never links
  found inside a fetched page.

---

## 4. Source Validation — URL and redirect-hop hardening

### 4.1 Pre-fetch URL validation (inherited, unchanged)

Every discovered URL passes `validate_source_url` before it can be fetched,
which already rejects:

- non-`http(s)` schemes; blank host;
- `localhost`, `*.local`, `*.internal` suffixes, loopback;
- RFC1918 (`10/8`, `172.16/12`, `192.168/16`), link-local, reserved,
  multicast, unspecified IP literals;
- cloud metadata hostnames/IPs (`169.254.169.254`, `metadata.google.internal`,
  `instance-data`, …);
- the program/target host (program token matched against DNS labels) and any
  caller-supplied forbidden host.

R24 adds a **fail-closed DNS resolution check** in the same pre-fetch gate:
resolve the host to its A/AAAA records and reject if any resolved address is
private/loopback/link-local/reserved/metadata, or if resolution fails. This
must be implemented in a new neutral `ai/research_agent/netguard.py` (stdlib +
existing deps only) and must **not** import the 5B–5J verification, execution,
scope, or egress packages.

### 4.2 Redirect-hop validation (new — directly addresses the R23.1 limitation)

R23.1 disclosed: "the source layer validates the initial URL before fetching;
the existing `ReferenceCollector` follows redirects and does not re-validate
each redirect hop at runtime." R24 fixes this:

1. R24 fetches with **manual redirect handling** (`follow_redirects=False`),
   not httpx auto-follow. (The R24 fetch wrapper wraps the existing
   `ReferenceCollector`/httpx call pattern; it does not add a second HTTP
   client to the package.)
2. For every hop `current → Location`:
   - resolve `Location` against `current` (RFC 3986 `urljoin`);
   - run the full §4.1 SSRF guard on the hop URL (scheme, host, IP, DNS,
     program/asset/forbidden-host), **at every hop**;
   - reject `http→` / `https→http` scheme downgrade;
   - reject a port change other than implicit default `80`/`443`;
   - reject URL-embedded credentials (`user@host`);
   - reject if the target host is a program/asset host;
   - allow cross-host **only** when the hop passes the SSRF guard; record it.
3. Maximum `MAX_REDIRECTS = 3`. The 4th redirect is a hard stop (the source is
   recorded `REJECTED`/`REDIRECT_LIMIT`).
4. The full hop chain is recorded in provenance
   (`redirect_chain: [url, …]`, `final_url`). Content hashing always uses the
   **final** fetched body; the `source_url` recorded is the final URL, with the
   original discovery URL preserved as `discovered_url`/`via`.
5. A hop that fails validation aborts the fetch for that source only
   (fail-soft), and the source is recorded with a bounded reason code.

The redirect policy is deliberately stricter than the deterministic verifier's
`_check_redirect_safety` (same-registrable-domain). R24 must **not** import that
verifier helper (5B–5J boundary); it implements an independent hop validator
whose only shared dependency is the neutral `validate_source_url` primitive.

**Known residual limitation (disclosed):** string/host validation plus
pre-connect DNS checks reduce, but do not fully eliminate, DNS-rebinding/TOCTOU
risk. The design recommends the existing egress-boundary approach as the
authoritative control at deploy time; R24's in-process checks are defense in
depth, not a substitute.

---

## 5. Source Quality — deterministic ranking

### 5.1 Scoring (proposed; not implemented)

Integers only; no clock, no randomness, ties broken deterministically.

```
TIER_BASE  = { TRUSTED: 100, SEMI_TRUSTED: 70, DISCOVERY_ONLY: 40, GENERIC: 10 }

category_bonus:
  nvd_cve                  +30
  vendor_advisory          +30
  github_advisory          +25
  wpscan / wordfence       +15
  detection_rule           +10
  exploit_reference        +5
  writeup / security_blog   0

signal_bonus (deterministic from URL + fetched title/text):
  CVE id exact in URL or title          +25
  product exact match                   +15
  component exact match                 +10
  CWE exact match                       +10
  affected version match                 +5
  canonical advisory path (GHSA/NVD/ID) +10

penalties:
  known aggregator / mirror             -15
  Tier 4 without corroboration          -20

score = clamp(sum, 0, 200)
source_quality = round(score / 200, 2)        # 0.00 .. 1.00
```

Ordering: `score` desc → tier rank asc → `canonical_url` asc → `source_id` asc.
`source_quality` is stored on each source and used to choose which sources
enter the LLM prompt (bounded slots, highest quality first).

### 5.2 Evidence eligibility gate

A fetched source is evidence-eligible only if:
`content_hash` is present, `source_quality ≥ EVIDENCE_FLOOR = 0.45`, and tier is
`TRUSTED`/`SEMI_TRUSTED` (or `DISCOVERY_ONLY` detection rule with an explicit
advisory reference). Below-floor sources remain `RELEVANT_SOURCE` / `UNKNOWN`.
`GENERIC` sources can never be evidence on their own.

---

## 6. Deduplication

Two-level, deterministic:

1. **Pre-fetch URL canonicalization** (reuse
   `canonicalize_reference_url`, extended for R24 keys): trim, drop fragment,
   drop only tracking params (`utm_*`, `gclid`, `fbclid`), lowercase scheme and
   host, strip default ports, apply the existing deterministic GitHub
   `blob/raw → raw.githubusercontent.com` mapping, and include the
   redirect-resolved `final_url` once known. The key is `canonical_url`.
2. **Post-fetch content hashing**: `sha256(normalize_text(body)[:MAX_DOC_CHARS])`
   (existing trusted-hash function). Identical bodies from different URLs
   collapse into **one** source: the highest-tier / highest-quality URL becomes
   the canonical `source_url`; the others are recorded as
   `aliases`/`discovered_via` (no duplicate evidence).

The discovery ledger keys on `canonical_url` first, then `content_hash` after
fetch, so the same source found by multiple queries/providers is fetched at most
once and yields at most one evidence chain.

---

## 7. Fetch Limits (all hard, all bounded)

| Limit | Proposed default | Env (proposed) |
|---|---|---|
| Discovery queries per plan | 12 | `WATCH_RESEARCH_MAX_QUERIES_PER_PLAN` |
| Discovery queries per run | 40 | `WATCH_RESEARCH_MAX_QUERIES_PER_RUN` |
| Results per query | 10 | `WATCH_RESEARCH_RESULTS_PER_QUERY` |
| Max discovered sources (pre-validation) | 40 | `WATCH_RESEARCH_MAX_DISCOVERED` |
| Max fetched sources per plan | 12 (reuse `MAX_SOURCES`) | `WATCH_RESEARCH_MAX_SOURCES` |
| Max bytes per source | 2,000,000 (reuse `ReferenceCollector.MAX_BYTES`) | — |
| Max total bytes per run | 8,000,000 | `WATCH_RESEARCH_MAX_TOTAL_BYTES` |
| Max redirects per source | 3 | `WATCH_RESEARCH_MAX_REDIRECTS` |
| Request timeout (connect/read) | 20 s total, 10 s connect | `WATCH_RESEARCH_FETCH_TIMEOUT` |
| Discovery wall budget per plan | 120 s | `WATCH_RESEARCH_DISCOVERY_SECONDS` |
| Total discovery runtime per run | 900 s | `WATCH_RESEARCH_MAX_MINUTES` (R23, unchanged) caps the whole run |

All limits are enforced in the discovery loop and are configurable only
downward-safe (a malformed/oversized value clamps to the default). Exceeding a
limit stops discovery cleanly (partial result), never expands.

---

## 8. Evidence Model

A discovered source moves through the lifecycle
`DISCOVERED_SOURCE → FETCHED_SOURCE → RELEVANT_SOURCE → EVIDENCE`, with
`UNKNOWN`/`INFERENCE` as non-source outcomes. Evidence retains **all** of:

| Field | Meaning | Who sets it |
|---|---|---|
| `source_url` | final fetched URL (validated) | source layer |
| `content_hash` | `sha256(normalize_text(body))` — trusted | source layer (never LLM) |
| `source_tier` | `TRUSTED` / `SEMI_TRUSTED` / `DISCOVERY_ONLY` / `GENERIC` | ranking layer (host-derived) |
| `discovery_query` | exact query + `template_id` + provider | discovery layer |
| `extraction_method` | `html_text` / `pdf` / `json_api` / `github_raw` | extractor |
| `claim` | one factual statement | LLM or deterministic extractor, then grounded-checked |
| `quote` | optional short verbatim supporting text | LLM/extractor, bounded, escaped |
| `provenance` | provider, `query_id`, `discovered_at`, `redirect_chain[]`, `final_url`, aliases | deterministic |

`EVIDENCE` is accepted only when `source_url` matches a **supplied, fetched,
hash-verified** source; the hash is copied from the source layer and is rejected
if empty (existing `ResearchAgentEvidence` validator). The LLM can never invent a
URL, hash, evidence item, or target observation: uncited claims, unknown URLs,
and forbidden verdict language are dropped to `UNKNOWN`.

---

## 9. LLM Role

**Allowed**

- summarize fetched public content;
- classify relevance of a fetched source to the CVE;
- extract candidate claims (each must cite a supplied `source_url`);
- identify unknowns;
- suggest additional **public** research queries (returned as structured
  suggestions that are re-validated and re-ranked before any use).

**Forbidden (enforced, not advisory)**

- invent citations, URLs, hashes, or evidence;
- claim the target/program is vulnerable;
- claim exploitation;
- perform target validation or suggest active validation against the program;
- execute commands, fetch URLs, or call any provider/tool;
- decide a production finding (`production_finding` is forced `False`).

Enforcement reuses the R23 mechanisms: bounded prompt, structured JSON parse,
`find_forbidden_terms` scrubbing, hash-by-URL grounding, and schema validators.
Model-suggested queries are treated as untrusted strings and must pass the same
sanitization and target-token rejection as deterministic queries.

---

## 10. Research Loop (bounded, finite)

```
        ┌────────────────────────────────────────────────────────┐
        │ round r = 1 (max ROUNDS = 2)                           │
        │                                                        │
 seed → discover (≤ queries/plan) → rank → validate (SSRF+hops) │
        → fetch (≤ fetched/plan) → extract → analyze (grounded) │
        → identify gaps → emit round-r source/evidence ledger   │
        └───────────────────────────────┬────────────────────────┘
                                        │ gaps AND budget remain?
                                        ▼
                              round 2 (≤ remaining query/source
                              budget, gap-directed queries only)
                                        │
                                        ▼
                                      STOP  (always, after ROUNDS)
```

- `MAX_ROUNDS = 2` hard-coded cap; round 2 consumes a strictly bounded
  remainder of the run budgets and only runs if round 1 produced
  `UNKNOWN`/gap items **and** both query and source budgets remain.
- The loop is per-plan; the R23 scheduler already bounds plans per run and total
  runtime. No loop can extend past the R23 deadline.
- Stop conditions (any): rounds exhausted, query/source/byte budget exhausted,
  discovery time budget expired, R23 run deadline reached.

---

## 11. Output — R24 result schema additions

Additive only; all existing R23 fields, statuses, and validators are preserved.

### 11.1 Lifecycle state

New value set carried per source and per evidence item:

| State | Meaning |
|---|---|
| `DISCOVERED_SOURCE` | found by a provider query, URL-validated, not fetched |
| `FETCHED_SOURCE` | fetched, body extracted, trusted hash computed |
| `RELEVANT_SOURCE` | fetched + passed the deterministic relevance gate, no claim |
| `EVIDENCE` | grounded claim (also present in `evidence[]`) |
| `UNKNOWN` | not established from any supplied source |
| `INFERENCE` | researcher/model reasoning, explicitly not evidence |

### 11.2 Additive fields

`ResearchAgentSource` (additive): `lifecycle`, `tier`, `source_quality`,
`discovery_provider`, `discovery_query`, `discovery_template_id`,
`discovered_url`, `final_url`, `redirect_chain[]`, `aliases[]`,
`extraction_method`.

`ResearchAgentEvidence` (additive): `source_tier`, `discovery_query`,
`discovery_provider`, `extraction_method`, `provenance{}`.

`ResearchAgentResult` (additive): `discovery` block
`{queries_issued, results_returned, discovered, fetched, relevant, evidence,
deduplicated, rejected, by_tier{}, by_category{}, rounds, budget_used{}}`.

Unchanged and always enforced: `production_finding = false`; status vocabulary
`RESEARCH_COMPLETED/PARTIAL/BLOCKED/FAILED`; no `VULNERABLE/VERIFIED/EXPLOITED/
FINDING`; Nuclei candidates `executed=False`, `target_url=None`.

Rule version bumps to `r24-1` for new results; existing `r23-1` result files are
untouched (idempotent store keyed by plan+rule).

---

## 12. Safety Boundary — why R24 cannot become a scanner

| Guarantee | Mechanism |
|---|---|
| No target URLs | Discovery inputs are CVE metadata only; program name is an exclusion filter, never a query term. No API accepts a URL as input. |
| No target-host discovery | `validate_source_url(..., program=…)` + DNS check + forbidden-host set on **every** discovered URL and **every** redirect hop. |
| No HTTP requests to program assets | Same SSRF guard rejects any host whose DNS label matches the program token; generic results are Tier 4 and cannot be fetched unless they pass the guard. |
| No Nuclei | R24 issues zero Nuclei calls; the R23 static no-execution import scan is extended to the new modules; Nuclei candidates stay non-executed schema objects. |
| No browser | No browser/WebDriver import or dependency; static import scan forbids `selenium`/`playwright`/`pyppeteer`. |
| No PoC execution | R24 stores/summarizes text only; no code path executes fetched content; no `subprocess`/`eval`/`exec` on fetched data. |
| No 5B–5J | New modules do not import `ai.execution`, `ai.verification`, `ai.finding`, `ai.resolver`, `ai.authorizer`, `ai.persistence`, `nuclei_runner`, or the B3–B7 egress/scope packages. R24.3 implements its own redirect/DNS guard rather than importing the verifier helper. |
| No production findings/alerts | Schema forces `production_finding=False`; no finding/alert writer is invoked; outputs remain under `ai_data/research/`. |

A dedicated safety test (R24.1) asserts all of the above by static source scan
plus behavioral tests on mocked providers.

---

## 13. Scheduler Integration

R24 **reuses the existing R23 scheduler and systemd timer**. No second timer,
unit, or schedule is created.

- The existing `watch-research.timer` (`OnCalendar=hourly`, `Persistent=true`)
  and `watch-research.service` remain authoritative. The `18:00–00:00
  Asia/Tehran` window, `WATCH_RESEARCH_ENABLED`, `WATCH_RESEARCH_MAX_MINUTES`,
  `WATCH_RESEARCH_MAX_PLANS`, the outer `flock` and in-app `flock(2)` are
  unchanged.
- Discovery executes **inside** the same `ai.research_cli agent run` invocation,
  per selected plan, subject to the same run deadline (`deadline` propagated
  into the discovery loop).
- R24 is gated by a new env flag `WATCH_RESEARCH_DISCOVERY` (default **false**
  for first rollout, then flipped to `true` after R24.7 validation). With it
  false, R23 behavior is byte-for-byte unchanged.
- No systemd or scheduler file is modified by R24.1–R24.6; R24.8 (scheduler
  integration) only wires the flag through existing config/agent plumbing.

---

## 14. Cost Control

Defaults are safe and cheap; all are bounded and fail-closed.

| Budget | Default | Notes |
|---|---|---|
| LLM calls per plan | 1 (≤ 2 with round 2) | discovery summary/extraction only |
| LLM calls per run | 3 | hard cap |
| LLM output tokens | existing provider `OPENROUTER_MAX_TOKENS` | unchanged |
| Search queries per plan | 12 | §7 |
| Search queries per run | 40 | §7 |
| Sources fetched per plan | 12 | reuse `MAX_SOURCES` |
| Bytes per source / per run | 2 MB / 8 MB | §7 |
| Plans per run | existing `WATCH_RESEARCH_MAX_PLANS` (5) | unchanged |
| Total runtime | existing `WATCH_RESEARCH_MAX_MINUTES` (300) | unchanged |
| Discovery wall per plan | 120 s | §7 |
| Concurrency | 1 (serial) | unchanged |

With `WATCH_RESEARCH_DISCOVERY=false` or `WATCH_RESEARCH_LLM=false`, cost is
zero-network-discovery and zero-LLM respectively.

---

## 15. Failure Modes — all fail-soft

| Failure | Behavior |
|---|---|
| Search provider failure (HTTP error/timeout) | provider returns `[]`; `provider_errors{provider, code}` recorded; other providers continue |
| Source 403 / 401 | source `FETCHED_SOURCE`→`FAILED` with bounded reason; not evidence; discovery continues |
| Source 429 | single bounded backoff is **not** added in R24 (avoid retry complexity); mark `RATE_LIMITED`, skip; existing R23 transient handling is unchanged |
| Empty source (no extractable body) | `EMPTY`; no hash; cannot back evidence |
| Redirect failure / hop rejected / > MAX_REDIRECTS | source `REJECTED`/`REDIRECT_LIMIT` with hop index and reason; fail-soft |
| LLM failure / invalid JSON | run stays `RESEARCH_PARTIAL`; explicit unknown; deterministic sources/evidence preserved |
| Malformed content | extractor returns `FAILED`/`EMPTY`; source retained with provenance |
| Duplicate source | collapsed by canonical URL / content hash; counted in `deduplicated` |
| Partial discovery (budget/time exhausted) | return the bounded partial ledger; status `RESEARCH_PARTIAL`; never error |
| Unknown provider / unlisted host | downgraded to `GENERIC`, discovery-only |

A single source or provider failure never aborts a plan; a plan failure never
aborts a run (existing R23 per-plan fail-soft).

---

## 16. Migration — additive, R23 stays functional

1. **Additive modules only.** New code lives under `ai/research_agent/`
   (`providers.py`, `discovery.py`, `netguard.py`, `ranking.py`,
   `queries.py`) plus additive schema fields. No existing function signature is
   changed; R23 call sites are extended, not replaced.
2. **Default-off feature flag.** `WATCH_RESEARCH_DISCOVERY=false` by default:
   the R23 pipeline (`collect_stored` → `fetch_sources` → LLM) runs exactly as
   today; the discovery layer is skipped.
3. **Rule-version isolation.** New results use `r24-1`; `r23-1` result files and
   reports remain valid and are never overwritten (idempotent store keyed by
   plan+rule). Scheduler run records remain compatible (additive counters only).
4. **Schema backward compatibility.** New fields are optional with safe
   defaults; existing `ResearchAgentSource.status` values still map 1:1, so the
   dashboard/API keep working. `backend/research_agent.py` gains optional
   presentation of discovery counters (read-only, fail-soft).
5. **Rollback.** Flipping the flag back to false restores R23 behavior with no
   data migration; no destructive change is made at any point.
6. **Deploy path unchanged.** The same `watch-research.service`/`.timer` and the
   same CLI entrypoint are used; no systemd edit is part of the core rollout.

---

## 17. Implementation Plan

The suggested breakdown is retained (it is the right decomposition); each stage
is independently shippable, default-off, and testable offline.

| Stage | Deliverable | Key tests / exit criteria |
|---|---|---|
| **R24.1 Source Discovery Contract** | New module defining `SourceCategory`, `TrustTier`, `DiscoveredSource` (R24 fields), `DiscoveryQuery`, provider protocol, and the forbidden-input invariant. | Static: no target/program token can enter a query; schema rejects `production_finding`; import-boundary scan. |
| **R24.2 Search Providers** | Allowlisted structured providers: NVD (reuse `CVECollector`), GitHub search (reuse `ReferenceDiscovery`), vendor advisory, Wordfence/WPScan, detection-rule; generic search opt-in/Tier 4. All mocked by default. | Per-provider deterministic query→result mapping; provider failure → `[]`; no open-web search in defaults. |
| **R24.3 URL / Redirect Hardening** | `netguard.py`: pre-fetch DNS-checked SSRF guard + manual redirect-hop validator (max 3, no downgrade/port/credentials, program-host rejection at each hop). | Hop-by-hop rejection tests; redirect-chain provenance; no 5B–5J import; R23.1 gap closed. |
| **R24.4 Source Ranking & Dedup** | Deterministic scoring (§5) + two-level canonicalization/content-hash dedup (§6). | Exact score tables, deterministic tie-breaks, same-source-multi-query collapses to one, evidence floor. |
| **R24.5 Evidence Integration** | Map lifecycle → existing `sources[]`/`evidence[]`/`unknowns[]`; provenance fields; result `discovery` block; keep `production_finding=false`. | Grounded evidence only from hash-verified sources; LLM cannot inject URL/hash; backward-compatible serialization. |
| **R24.6 LLM Research Loop** | Bounded 2-round discover→rank→validate→fetch→extract→analyze→gap loop; model-suggested queries re-sanitized. | Budget/round caps honored; stop conditions; no verdict language; fail-soft LLM. |
| **R24.7 Controlled Real Research** | Report-only controlled run against a known CVE's public sources (no target), measuring discovery yield vs. the current `evidence=0` baseline. | Reproducible, bounded, target-isolated; report artifacts; no target contact. |
| **R24.8 Scheduler Integration** | Wire `WATCH_RESEARCH_DISCOVERY` through existing `SchedulerConfig`/agent construction; no new timer; no systemd edit. | R23 timer unchanged; flag-off equals R23 behavior; flag-on bounded by window/lock/deadline. |

Ordering rationale: contract → providers → hardening → ranking/dedup →
evidence → loop → real validation → scheduler wiring. Hardening (R24.3) precedes
any network-bearing stage (R24.6/R24.7). Each stage leaves `WATCH_RESEARCH_
DISCOVERY=false` until R24.8, so R23 remains authoritative throughout.

---

## Appendix A — Root cause of the current `RESEARCH_PARTIAL / evidence=0 / sources=6`

`ResearchAgent.run_plan` calls `self.sources.collect_stored(cve, references)`
which reads only `ai_data/research/<CVE>.references.json` and the persisted
`.cli.json` `research.references`. For CVE-2026-1557 that is exactly 6 URLs; the
4 WordPress-Trac/Wordfence URLs fail (403/empty) and only the 2 GitHub URLs are
fetchable. R23 has **no** discovery step, so `evidence` can only ever come from
those 6 references — and when only URL-only references exist (or those fail),
the result is honestly `evidence=0`. R24's discovery layer is the missing input,
not a scoring fix.

## Appendix B — Boundary statement

R24 is autonomous **research**, never autonomous **exploitation**. It may read
and reason over public security knowledge; it may not touch, scan, validate,
exploit, or probe any program asset, and it produces no production finding or
alert. All discovery is bounded, deterministic where it touches decisions, and
fail-soft.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R24
- Role: Research Source Discovery Architecture
