# Stage R24.4 — Source Ranking & Dedup

**Status: PASS.**

Implemented deterministic, network-free source ranking and two-level
deduplication as additive R24.4 modules. R23 behavior is unchanged, R24.1/R24.2/
R24.3 are untouched, and `WATCH_RESEARCH_DISCOVERY` remains unset/off. No
scheduler, systemd, timer, database, target, or 5B–5J surface was modified.

---

## 1. Files changed

New only (additive; no existing file modified):

| File | Purpose |
|---|---|
| `ai/research_agent/dedup.py` | URL canonicalization, content-hash reuse, two-level dedup, canonical selection, provenance merge |
| `ai/research_agent/ranking.py` | Deterministic scoring, ordering, evidence-eligibility predicate |
| `tests/test_research_agent_r24_4.py` | 71 focused R24.4 tests |
| `agent-reports/stage-r24-4-ranking-dedup.md` | This report |

`git status --short` shows exactly these as new/untracked (plus the prior D9/R24
working tree). No tracked file was edited. `git diff --check` → clean (rc=0).

---

## 2. Ranking formula (exactly per the R24 scope §5)

```
TIER_BASE = { TRUSTED: 100, SEMI_TRUSTED: 70, DISCOVERY_ONLY: 40, GENERIC: 10 }

category_bonus:
  nvd_cve +30   vendor_advisory +30   github_advisory +25
  wordfence +15 wpscan +15            detection_rule +10
  exploit_reference +5
  writeup / security_blog / github_repo / generic_search +0

signal_bonus:
  exact CVE id +25   product match +15   component match +10
  CWE match +10      version match +5    canonical advisory signal +10

penalties:
  known aggregator/mirror −15
  Tier-4 (GENERIC) without corroboration −20

raw = tier_base + category_bonus + signal_bonus + penalty
score = clamp(raw, 0, 200)
source_quality = round(score / 200, 2)
```

- Signal extraction is deterministic and offline: whole-token CVE/product/
  component/CWE matching over `url` + `final_url` + `title` + `source_type` +
  `discovery_query`; substring version match; advisory signal from category or
  URL markers (`/advisories/`, `/vuln/detail/`, `ghsa-`).
- `ScoreBreakdown` exposes `tier_base`, `category_bonus`, `signal_bonus`,
  `penalty`, `raw_score`, `score`, `source_quality`, `signals`, `penalties`, and
  a `components` map, so every point is auditable/testable.
- The aggregator host table (`AGGREGATOR_HOSTS`) is a fixed, documented set of
  generic mirror domains — **not** a target/program list.
- `corroborated` is an explicit caller flag that only lifts the Tier-4 penalty.

**No program/asset relevance.** Ranking accepts only `CVEResearchMetadata`
(cve_id, product, component, parameter, version, cwe, vulnerability_type,
existing_references). There is no `program`/`target`/`asset`/`target_url` input
or field, so target relevance cannot influence source quality.

---

## 3. Canonicalization rules (`dedup.canonicalize_url`)

Applied deterministically, in order:

1. trim surrounding whitespace;
2. GitHub `blob`/`raw` → `https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>` mapping (`github_raw_url`), only for exact `/blob/` and `/raw/` paths;
3. lowercase scheme and hostname (path case preserved — resource-significant);
4. drop URL-embedded credentials from the netloc;
5. drop the fragment;
6. strip default ports (`:80` http, `:443` https); keep non-default ports;
7. remove only `utm_*`, `gclid`, `fbclid`; preserve every other parameter
   byte-for-byte and order the remainder deterministically (sorted).

No DNS resolution, no fetch, no redirect following. Malformed input never
raises (falls back to the trimmed original; non-string → `""`).

`canonical_url(source)` uses `final_url` (when R24.3 supplied one) else `url`
else `discovered_url`.

---

## 4. URL dedup behavior (Level 1)

`dedup_by_url(sources)` groups by `canonical_url`, merges each group via
`merge_group`, and returns groups sorted by canonical URL ascending. The result
is independent of input order. Single sources pass through unchanged. Same
canonical URL (differing only by case, default port, fragment, or tracking
params) → one source; distinct meaningful URLs stay separate.

---

## 5. Content dedup behavior (Level 2)

`dedup_by_content_hash(sources)` groups only sources that already carry a
trusted `content_hash`; source without a hash are passed through unchanged.
Identical normalized hashes collapse to one source. No body is fetched, read
from disk, or recomputed from a URL.

`content_hash_for(body)` reuses the existing project helpers:
`sha256_text(normalize_text(body)[:MAX_DOC_CHARS])`. `with_content_hash(source,
body)` **does not** recompute an already-present (trusted) hash.

`dedup_discovered_sources(sources)` runs Level 1 then Level 2 and returns a
deterministically sorted list.

---

## 6. Canonical source selection

`choose_canonical(group)` is a pure total order:

1. highest `TrustTier` (rank: TRUSTED < SEMI_TRUSTED < DISCOVERY_ONLY < GENERIC),
2. highest `source_quality`,
3. lowest `canonical_url`,
4. lowest `source_id`.

No timestamps, no discovery order, no provider iteration order. `rank_sources`
uses the same-tier/canonical-url/source-id tie-breaks after score desc.

---

## 7. Evidence eligibility predicate

`is_evidence_eligible(source, *, advisory_reference=None)` is pure and creates/
persists nothing:

- requires a non-empty trusted `content_hash`;
- requires `source_quality >= 0.45` (`EVIDENCE_FLOOR`);
- `TRUSTED` / `SEMI_TRUSTED` → eligible;
- `DISCOVERY_ONLY` + `detection_rule` → eligible **only** with an explicit
  authoritative advisory reference (supplied argument or deterministically
  detected via `authoritative_advisory_reference` — CVE-/GHSA-id or advisory URL
  marker);
- `GENERIC` → never eligible by itself; below-floor sources remain non-evidence.

No evidence object is produced here (deferred to R24.5).

---

## 8. Provenance preservation

`merge_group` preserves:

- **aliases** — every non-canonical URL/alias, canonicalized, deduplicated, and
  `sorted` (deterministic);
- **discovered_via / provenance** — a deterministic `provenance_ledger` of
  `provider=<p>;template=<t>;query=<q>;url=<u>` entries, sorted and deduped,
  appended once to `note` as `discovered_via=...` (idempotent across both dedup
  levels);
- **redirect_chain** — the canonical source's hop order preserved, with unique
  extra hops appended sorted;
- **discovery_provider / discovery_query / discovery_template_id /
  discovered_url / final_url / content_hash / lifecycle** — canonical source's
  values (content_hash falls back to any member's hash).

---

## 9. Determinism & safety of the code

- No clock, no randomness, no `set`/`dict` iteration order leaking into output
  (all aggregates sorted). Shuffled input yields identical ranking/dedup output
  (tested).
- `production_finding` is never set; it stays `False` through ranking and dedup.
- `DiscoveredSource` retains no target/program/asset/endpoint/response/
  credential/cookie/header fields (tested).
- Static import scan: neither new module imports `ai.execution`,
  `ai.verification`, `ai.finding`, `ai.resolver`, `ai.authorizer`,
  `ai.persistence`, `nuclei_runner`, browser automation, `subprocess`, `socket`,
  `httpx`, or `requests`; no `eval`/`exec` call sites.

---

## 10. Explicit confirmation — zero network access

R24.4 performs **no** DNS resolution, **no** HTTP request, **no** socket/DNS
call, **no** URL re-fetch, **no** provider call, and **no** LLM call. It operates
purely on already-materialized `DiscoveredSource` records and already-supplied
`content_hash` values. Verified by (a) AST import scan, (b) text scan for
`urllib.request`/`http.client`/`socket.socket`/eval/exec, and (c) runtime tests
that patch `socket.socket` to raise an assertion during ranking and dedup.

## 11. Explicit confirmation — R23 unchanged

No R23 file was modified (`ai/research_agent/{agent,scheduler,sources,prompts,
storage}.py`, `ai/schemas/research_agent.py`, `ai/research_cli.py`, R23 result
files, `database/db.py`). R23 does not import R24.4. `WATCH_RESEARCH_DISCOVERY`
remains unset (off), so the scheduler executes exactly the R23 path.

## 12. Explicit confirmation — R24.1 / R24.2 / R24.3 preserved

No R24.1/R24.2/R24.3 file was edited. Their suites still pass unchanged
(R24.1 43, R24.2 50, R24.3 80). R24.4 imports and reuses their vocabulary and
helpers (`DiscoveredSource`, `SourceCategory`, `TrustTier`, `Lifecycle`,
`CVEResearchMetadata`, `canonicalize_reference_url`-style canonicalization,
`make_discovered_source`, `netguard`).

## 13. Explicit confirmation — no scheduler/systemd changes

`watch-research.service` and `watch-research.timer` were not touched; no
scheduler defaults were changed; no timer was enabled, started, or reloaded.

## 14. No target interaction / no 5B–5J

No target/program/asset was contacted. No Nuclei, PoC, browser, verifier,
finding, alert, execution, or 5B–5J path was imported or executed.

---

## 15. Tests

New suite `tests/test_research_agent_r24_4.py` — **71 tests, all passing**.
Coverage:

- exact tier base, category bonus, signal bonus, penalty values;
- clamp at 0 and 200; `source_quality`; deterministic scoring;
- no program/asset fields or kwargs;
- deterministic ordering + tier/canonical-url/source-id tie-breaks;
- URL canonicalization (trim, case, fragment, default ports, utm/gclid/fbclid,
  non-tracking preservation, deterministic query order, credentials, GitHub
  blob/raw, malformed input);
- URL dedup (merge vs separate, order independence);
- content dedup (hash merge/separate, unhashed passthrough, trusted-hash reuse,
  content-hash determinism, canonical by tier/quality/url/id, aliases,
  discovered_via/provenance, redirect chain, two-level combined, no-network);
- evidence eligibility matrix;
- schema safety / lifecycle / production_finding;
- import boundary / no network / no eval-exec;
- R23 + R24.1/R24.2/R24.3 compatibility.

Regression (combined):

```
python3 -m unittest \
  tests.test_research_agent \
  tests.test_research_agent_r24_1 \
  tests.test_research_agent_r24_2 \
  tests.test_research_agent_r24_3 \
  tests.test_research_agent_r24_4
→ Ran 336 tests ... OK
```

Per-suite: R23 **92 OK**, R24.1 **43 OK**, R24.2 **50 OK**, R24.3 **80 OK**,
R24.4 **71 OK**. `git diff --check` → clean. No unrelated test was modified.

---

## 16. Known limitations deferred to R24.5+

- **Evidence objects not built here.** R24.4 provides only the eligibility
  predicate; R24.5 must map `RELEVANT_SOURCE`→`EVIDENCE` onto the R23 result/
  evidence schema (additive fields) without changing R23 serialization.
- **`advisory_reference` is caller-supplied or text-detected.** A truly
  authoritative advisory linkage (e.g., a persisted advisory id) should be
  threaded from provenance in R24.5 rather than inferred from URL text.
- **Corroboration** is an explicit flag; automatic cross-source corroboration
  detection belongs to the R24.6 loop.
- **Full aggregation/ingestion integration** (merging discovery + stored
  references into one ranked set and persisting the ledger) is not wired; R24.5+
  owns it.
- **DNS-rebinding/TOCTOU** remains an R24.3/netguard and deploy-time egress
  concern; R24.4 adds no network surface.
- **Aggregator host table** is a fixed documented list; it can be extended
  additively in a later stage if needed.

## 17. Next-stage recommendation

Proceed to **R24.5 — Evidence Integration**: consume ranked, deduplicated
`DiscoveredSource` records, apply `is_evidence_eligible`, and map the lifecycle
(`DISCOVERED_SOURCE → FETCHED_SOURCE → RELEVANT_SOURCE → EVIDENCE`) onto the
existing R23 `sources[]` / `evidence[]` schema additively, with the `discovery`
result block and unchanged `production_finding=False`. Keep
`WATCH_RESEARCH_DISCOVERY` off until R24.6/R24.8.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R24.4
- Role: Source Ranking & Dedup
