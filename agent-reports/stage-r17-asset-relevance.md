# Stage R17 — Deterministic Asset ↔ Vulnerability Relevance

## 1. Objective

Answer, for a researched CVE, "does it appear relevant to assets/programs Watch
already knows, and why?" — using only persisted/local intelligence (R12–R16
vulnerability intelligence plus read-only asset inventory snapshots), with no
active scanning or validation.

The result is RESEARCH RELEVANCE only. It is never called vulnerable,
exploitable, verified, or confirmed.

## 2. Exact files changed

- `ai/knowledge/relevance.py` — **new**. Pure deterministic engine:
  bounded normalization (reusing the existing
  `ai/correlator/technology.py` normalizer), token-based matching, transparent
  scoring, `AssetRecord`/`AssetRelevance` dataclasses,
  `assess_asset_relevance()`, `asset_relevance_projection()`, and read-only
  local loaders (`load_program_definitions`, `assets_from_programs`,
  `assets_from_research_metadata`, `load_asset_snapshot`,
  `derive_technology_hints`).
- `ai/schemas/knowledge.py` — additive `KnowledgeAssetRelevance` model and
  `KnowledgeDocument.asset_relevance` (default `UNKNOWN`; no renames; no
  R12–R16 field or ID changes).
- `ai/research_cli.py` — read-only `relevance` subcommand
  (`--cve`, `--all`, `--assets`, `--json`).
- `ai/test_asset_relevance.py` — **new**, 25 tests.

`ai/knowledge/ingestion.py` and `ai/knowledge/store.py` were intentionally not
changed: assets are not available at ingestion time, so the document field
defaults to `UNKNOWN` and the CLI/engine computes relevance live against a
local asset snapshot. No production database is queried.

## 3. Normalization rules

Bounded and deterministic; no aggressive fuzzy matching, no substring
explosion:

- Reuses `ai/correlator/technology.normalize`: lowercase, trim, drop common
  version suffixes (`:`/`-`/`_`/space + version), collapse non-alphanumerics to
  spaces. So `WP Responsive Images 1.0` and `wp-responsive-images` both become
  `wp responsive images`.
- Each term is capped at 200 characters; at most 256 items per list; inputs are
  normalized and de-duplicated preserving first-seen order.
- Comparisons are **token equality** or **token-subset**, never substring:
  `image` does not match `images` or `image_handler`.
- A curated weak-keyword stopword set (`image`, `file`, `data`, `page`,
  `content`, `wordpress`, …) prevents generic nouns from creating a weak match.
- Existing generic technologies (`php`, `javascript`, `java`, `python`, …) are
  reused from `ai/correlator/technology.GENERIC_TECHNOLOGIES` and never match a
  product/framework identity.

## 4. Matching rules

Strong signals: exact normalized product match (`+50`), exact
plugin/package/module or component match (`+35`), technology/framework match
with explicit aliases (`+20`), component/path relationship via token-subset
(`+20`). Medium: vulnerability-type compatibility (`+10`). Weak: keyword overlap
on non-generic tokens (`+5`).

- Each signal is awarded at most once per asset; a product match suppresses a
  redundant plugin match for the same asset.
- `vulnerability-type compatibility` fires only when the asset already has a
  positive signal and exposes a component/path surface — it reinforces a real
  match and never manufactures one.
- A generic technology alone caps at `+20` (LOW); it can never produce HIGH.
- Cross-CVE isolation: the profile comes from exactly one CVE document; assets
  are independent. Program isolation: `matched_programs` is derived only from
  the assets that actually matched.

## 5. Scoring and classes

Bounded `0–100` (clamped). Thresholds, highest-first:

| Score | Relevance |
|---|---|
| ≥ 70 | `HIGH` |
| ≥ 40 | `MEDIUM` |
| > 0 | `LOW` |
| 0, with asset intelligence present | `NONE` |
| no asset intelligence, or the only possible signal (technology) was never observed | `UNKNOWN` |

Unknown stays unknown; absent information is never scored as negative.

## 6. Explainability

`KnowledgeAssetRelevance` carries: `relevance`, `score`, `reasons[]`,
`matched_assets[]`, `matched_programs[]`, `unknown_factors[]`, `evidence[]`, and
`rule_version` (`"r17-1"`). Every non-NONE result explains what matched, which
asset/program matched, why, and the match strength. `evidence[]` contains
bounded `asset.match` records plus the vulnerability-side R14/R12 evidence
records (component/type/parameter/CWE). Example (synthetic):

```
HIGH 80
reasons: exact product match: wp responsive images; technology match: wordpress; vulnerability type: path traversal
matched assets: shop.example.com
matched programs: x
```

## 7. Real corpus results

Evaluated against the locally persisted program definitions
(`programs/*.json`) plus each CVE's persisted research metadata
(`ai_data/research/<CVE>.cli.json`). No matches were manufactured; missing
per-asset fingerprints are reported as unknowns.

| CVE | priority (R16) | relevance | score | matched programs | reasons | unknowns |
|---|---|---|---:|---|---|---|
| CVE-2026-1557 | CRITICAL_RESEARCH | LOW | 20 | dell; indeed | technology match: wordpress | asset component/path not observed; asset plugin/component not observed |
| CVE-2024-27956 | MEDIUM_RESEARCH | NONE | 0 | – | – | asset technology not observed; asset component/path not observed |
| CVE-2024-42327 | LOW_RESEARCH | NONE | 0 | – | – | asset technology not observed; asset component/path not observed |
| CVE-2024-5376 | LOW_RESEARCH | NONE | 0 | – | – | asset technology not observed; asset component/path not observed |
| CVE-2025-3102 | LOW_RESEARCH | NONE | 0 | – | – | asset technology not observed; asset component/path not observed |
| CVE-2025-4893 | LOW_RESEARCH | NONE | 0 | – | – | asset technology not observed; asset component/path not observed |

CVE-2026-1557 is the only CVE with persisted correlated Watch assets + a
recorded technology (WordPress), so it is LOW (technology-only): the assets are
known to run WordPress and the CVE is a WordPress plugin, but the plugin and
version were not observed on those assets. The others have no local asset
technology inventory and return NONE/UNKNOWN honestly. The corpus was not
edited.

## 8. Test results

- New focused suite `ai.test_asset_relevance`: **25 tests, OK**.
- Consolidated relevant regression pass (28 modules incl. R12 intelligence,
  R14 parameter/component, R15 exploitability, R16 priority, ingestion,
  knowledge store/ingestion, body extraction, KB/XSS e2e, research CLI,
  reports, reference quality/canonicalization/ranker/cache, CVE batch, quality
  parity, ingestion schema/grounding, research pattern, XSS agent/case builder,
  and the mandatory XSS/LLM suites incl. `test_xss_researcher`,
  `test_xss_llm_researcher`, `test_openrouter`): **749 tests, all OK**.
- `py_compile` clean; `git diff --check` clean.

## 9. Adversarial / mandated scenario results

1. exact product match — pass.
2. exact plugin/package match — pass.
3. exact component/path match — pass.
4. normalized name match (`WP Responsive Images 1.0` ↔ `wp-responsive-images`) — pass.
5. technology-only weak match (LOW) — pass.
6. generic `php` does not create HIGH — pass.
7. generic `wordpress` alone does not create HIGH — pass.
8. unrelated product → NONE — pass.
9. unknown asset technology → UNKNOWN — pass.
10. deterministic normalization — pass.
11. bounded matching (200-char terms, 256-item lists) — pass.
12. no substring explosion (`image` ↛ `images`/`image_handler`) — pass.
13. cross-CVE isolation — pass.
14. program isolation — pass.
15. score bounded 0–100 — pass.
16. every positive score has reasons — pass.
17. evidence bounded (≤ 240 chars; bounded count) — pass.
18. repeated computation byte-identical — pass.
19. adversarial/oversized product names are bounded and non-crashing — pass.
20. no network/subprocess (socket/Popen patched to raise) — pass.
21. existing R12–R16 suites remain green — pass.

## 10. Idempotency

`assess_asset_relevance` / `asset_relevance_projection` are pure functions of
their inputs: independent of asset ordering and evidence ordering, and
byte-identical across repeated computation. No timestamps, randomness, or
process state enter the result.

## 11. Security boundary

Pure local deterministic computation:

- no HTTP, DNS, Nuclei, browser, subprocess, active validation, exploit
  execution, 5B–5J, production mutation, alerts, LLM, or external network;
- asserted by test (socket/Popen patched to raise);
- loaders read local JSON only (`programs/*.json`,
  `ai_data/research/<CVE>.cli.json`, optional `--assets` snapshot) and never
  import or query the production MongoDB (`database/db.py`);
- never emits vulnerable/exploitable/verified/confirmed semantics.

## 12. Limitations

- The local asset inventory carries program scopes but no per-asset
  technology/component fingerprints, and only CVE-2026-1557 has persisted
  correlated assets/technologies; most corpus CVEs therefore return
  NONE/UNKNOWN. This is honest, not a matching failure.
- The engine consumes an asset snapshot; wiring the production recon inventory
  would require a later, separately-authorized read-only snapshot step (no
  network is used here).
- Technology hints are derived only from literal token containment of known
  aliases in explicit product wording.
- Version matching and affected/unaffected decisions are out of scope.
- Weak keyword overlap is intentionally weak and stopword-filtered; it can only
  produce LOW.
- `asset_relevance` defaults to `UNKNOWN` on stored documents because assets
  are not available at ingestion; the CLI computes it live.

## 13. Explicit confirmation

- **No network.**
- **No LLM.**
- **No Nuclei.**
- **No active validation.**
- **No production authority chain.**
- **No alerts.**
- **No Git operations** (no add/commit/push).

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R17
- Role: Asset Relevance Intelligence
