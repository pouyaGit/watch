# Stage R30.2 — Observed Component / Plugin / Version / Parameter Inventory

## Status
**IMPLEMENTED (personal bug-bounty research).** R30.2 derives a deterministic,
read-only *observed* inventory from already-persisted Watch recon data and feeds
it into the existing R30.1 matcher as **input only**. No matching rule, score or
subsystem behaviour was changed.

No R17/R18/R25.2/R26.1/R26.2/R26.3/R29.1/R30.1 rule change, no new numeric
score, no LLM, no network, no DNS, no recon/httpx/Nuclei/ffuf/browser, no PoC,
no target contact, no findings/alerts, no sessions/outcomes, no systemd/`.env`,
no Mongo collection, no writes, no fabricated data.

| File | Lines | Purpose |
|---|---:|---|
| `ai/schemas/observed_inventory.py` | 227 | provenance-carrying inventory schema |
| `ai/knowledge/observed_inventory.py` | 578 | pure derivation engine |
| `backend/observed_inventory.py` | 364 | read-only Mongo composition (fail-soft) |
| `tests/test_observed_inventory.py` | 897 | 60 deterministic tests |

Additive edits only: `backend/asset_cve_matching.py` (merge inventory into the
R30.1 input), `ai/research_cli.py` (CLI), `backend/routers/research.py` (API),
`backend/routers/research_pages.py` + `research_lead_detail.html` (UI panel).

## 1. Source discovery

Inspected the current Watch data model (`database/db.py`,
`ai/researcher/target_intelligence.py`, `crawl/watch_param_discovery.py`,
`backend/dashboard.py`, `backend/routers/programs.py`):

| Collection / model | Relevant fields | Persisted meaning |
|---|---|---|
| `Programs` | `program_name, scopes, ooscopes, config` | program membership |
| `Subdomains` | `program_name, subdomain, scope, providers` | target relationship |
| `Http` | `tech` (list of httpx tech-detect labels, e.g. `nginx:1.24.0`) | observed technologies + technology versions |
| `Urls` | `url, path, params, sources` | crawl-level URLs (not needed: URLs are raw target data) |
| `Endpoints` | `path` (already `database.normalize_path`-normalized at write), `params`, `params_from_crawl`, `params_from_x8`, `param_records` (`name/method/location/source`) | paths + parameters with provenance |
| `DnsBruteStatus`, `XssFindings` | — | not inventory sources (XssFindings is legacy) |

Existing deterministic parsing was reused rather than duplicated:
`ai/researcher/target_intelligence.py` already validates and projects
`Http.tech` into `TechnologyObservation(name, observed_version)` and
`Endpoints` into `EndpointObservation(path, params, param_details)` with strict
closed vocabularies. R30.2 calls that public projector
(`project_subdomain`) and aggregates its validated output.

## 2. Database/model findings (explicit answers)

1. **Program technologies** are stored in `database.Http.tech` (httpx
   tech-detect labels). Read-only consumers already exist in
   `backend/dashboard.py` and `ai/researcher/target_intelligence.py`.
2. **Endpoints** are stored in `database.Endpoints` (path-level, normalized at
   write time) and `database.Urls` (crawl-level; a single `path` may carry
   parameters).
3. **`ProgramParams` does NOT exist on the current branch.** There is no such
   model/collection in `database/db.py`. The equivalent persisted parameter
   data is `Endpoints.params`, `params_from_crawl`, `params_from_x8` and the
   canonical `param_records` list (also used by `crawl/watch_param_discovery.py`).
4. **Parameter observations** are persisted in `Endpoints.params*` and
   `Endpoints.param_records` (each record carries `name`, `method` ∈
   {GET, POST, PUT, PATCH}, `location` ∈ {query, body}, `source` ∈ {crawl, x8});
   `Urls.params` is the raw crawl list.
5. **Component / plugin / version observations** are **not** stored in any
   dedicated field. A technology **version** can be embedded in a structured
   `Http.tech` label (`nginx:1.24.0`) and is parsed by the existing
   `_split_technology` logic in `ai/researcher/target_intelligence.py`.
   Components and plugins have **no persisted source**:
   `ai/correlator/plugin_presence.py` only *builds checks* for a known plugin
   name; it never persists an observed plugin.
6. **Without network access**, existing crawl/recon records can provide
   structured **version** evidence (from `Http.tech`) and structured
   **parameter/path** evidence (from `Endpoints`); they cannot provide
   component/plugin evidence because no such field exists.

## 3. Inventory schema (`ai/schemas/observed_inventory.py`)

`ObservedAssetInventory` fields:
`inventory_id, program, technologies, products, components, plugins, versions,
parameters, paths, sources, evidence, generated_from, rule_version,
research_only`.

- Every category is a list of `ObservedItem(value, source, evidence_type)`.
- `evidence_type` closed vocabulary: `EXPLICIT_FIELD, STRUCTURED_ENDPOINT,
  STRUCTURED_PARAMETER, STRUCTURED_TECHNOLOGY, STRUCTURED_COMPONENT`. There is
  **no** `INFERRED` / `GUESSED` / `LLM_DERIVED` value.
- `source` closed vocabulary: `ASSET_INVENTORY, TECHNOLOGY_INVENTORY,
  COMPONENT_INVENTORY, PARAMETER_INVENTORY, ENDPOINT_INVENTORY`.
- `inventory_id = "inv-" + sha256(rule_version + program)[:16]`.
- `rule_version` fixed `r30-2`; `research_only` forced `true`;
  `extra="forbid"`.
- Collections are deduplicated and deterministically ordered; unknown fields
  are rejected.

## 4. Each inventory category

| Category | Source | Emission rule |
|---|---|---|
| **technologies** | `Http.tech` | every validated structured technology label (deduped on the existing normalizer) |
| **products** | explicit persisted product records only | empty when no explicit record; never inferred from a technology |
| **components** | explicit persisted component records only | empty; arbitrary URL path segments are never components |
| **plugins** | explicit persisted plugin records only | empty; `/wp-content/plugins/<slug>/` alone is **not** treated as plugin evidence |
| **versions** | `Http.tech` structured labels only | only when the label really carries a version; never from dates/defaults/package names/URL numbers |
| **parameters** | `Endpoints.params`, `Endpoints.param_records` | union, deduped on the R30.1 parameter normalizer; method/location/source kept as evidence |
| **paths** | `Endpoints.path` | path only (no scheme/host/example_url), deduped |

## 5. Provenance

Every item carries `value`, `source` and `evidence_type`; each inventory also
carries a bounded, sorted `evidence` list of traceable lines, e.g.:

```
technology 'WordPress' from Http.tech
version '1.24.0' from Http.tech technology 'nginx'
path '/user/{id}/profile' from Endpoints.path
parameter 'id' from Endpoints.param_records (method=POST location=body source=x8)
```

`generated_from` holds deterministic record counts
(`http_records, endpoint_records, url_records, subdomain_records,
projected_subdomains, skipped_subdomains`). No evidence string is invented; an
empty source produces an empty category.

## 6. Normalization

- Technologies dedupe on `ai.correlator.technology.normalize` (the same
  vocabulary R30.1 uses; no competing normalizer).
- Versions dedupe on R30.1 `normalize_version`; parameters dedupe on R30.1
  `normalize_parameter` (so `?src` and `src` collapse).
- Paths keep the write-time `database.normalize_path` form; only whitespace is
  trimmed and a leading `/` ensured.
- Values keep the first deterministic observed spelling (e.g. `WordPress`),
  matching R30.1 evidence semantics.

## 7. Privacy handling

- The model has **no** URL / IP / hostname field. `example_url`, `url`,
  `final_url`, `ips`, `subdomain` and `scopes` are never emitted.
- `paths` are path-only (already hostname-free by construction).
- `generated_from` holds counts, not identifiers.
- CLI/UI show categories, not target identifiers; verified by test that the
  full projection contains no `.com`, `http://`, `https://`, `127.0.0.1`,
  `example_url` or known asset host strings.
- R30.1 output continues to use its existing privacy-preserving
  `asset_identifier` (`asset-<sha256…>`), untouched by R30.2.

## 8. R30.1 integration

Preferred architecture implemented:

```
database.db (Http.tech / Endpoints / Subdomains)
        ↓  (read-only, fail-soft, short-timeout client)
backend/observed_inventory  →  ai/knowledge/observed_inventory
        ↓
backend/asset_cve_matching (merges observed values into the matcher input)
        ↓
ai/knowledge/asset_cve_matching.evaluate_inventory()   ← UNCHANGED (r30-1)
        ↓
R30.1 Asset ↔ CVE Match → R26 Opportunity → R29 Hunt Queue
```

`backend/asset_cve_matching.build_matches` now merges the R30.2 inventory value
lists into `observed_products/components/plugins/technologies/versions/
parameters/paths` **after** the existing local evidence (so existing
matched-value spellings are preserved) and calls the same
`evaluate_inventory`. `ai/knowledge/asset_cve_matching.py` was **not touched**;
its `RULE_VERSION` stays `r30-1` and its confidence/blocker semantics are
verified unchanged by test.

Performance/safety: the Mongo reader uses a short-timeout (0.8 s) read-only
client derived from the already-configured mongoengine settings (no credential
is hard-coded), with a cached offline window, so an unreachable database fails
fast and never blocks the existing R26/R29 composition.

## 9. Blocker effects

R30.2 never edits blockers. Evidence flows through R30.1:

```
inventory evidence → R30.1 matcher → resolved / remaining blockers
```

- plugin evidence exists → `plugin_not_observed` may resolve;
- component evidence exists → `component_not_observed` may resolve;
- a known, safely matching version → `version_unknown` may resolve;
- no version evidence → `version_unknown` **remains**;
- unknown blocker codes are preserved.

Verified by test: with injected component + plugin + matching version
evidence, R30.1 resolves `generic_technology_only, plugin_not_observed,
component_not_observed, version_unknown` (state `CONFIRMED`); with no inventory
they all remain (`WEAK`).

## 10. Real corpus results

Run against the current environment (CVE-2026-1557 → dell / indeed):

- The local MongoDB (`127.0.0.1:27017`, configured in `database/db.py`) is
  **not reachable** in this environment (`ServerSelectionTimeoutError`,
  connection refused). Therefore every Mongo-backed R30.2 category is empty:
  `technologies=0, products=0, components=0, plugins=0, versions=0,
  parameters=0, paths=0`.
- The R30.1 technology evidence for these programs still comes from the already
  persisted local research payload metadata (`WordPress`), unchanged from R30.1.
- Resulting match for `CVE-2026-1557 → dell`: `TECHNOLOGY`, confidence
  `MEDIUM`, `asset_match_state = WEAK`, remaining blockers
  `generic_technology_only, plugin_not_observed, component_not_observed,
  version_unknown`; Money Score `[53, 53]`; hunt priority `VERIFY_FIRST`.
- **No upgrade was forced.** This satisfies success criterion F (no stronger
  persisted evidence → remains WEAK/VERIFY_FIRST). Criterion E is demonstrated
  deterministically in tests via injected already-loaded records (the exact
  path a reachable database would use); the mechanism upgrades to `CONFIRMED`
  iff real component/plugin/version evidence is present.

CLI observation (dell):

```
OBSERVED ASSET INVENTORY

dell

TECHNOLOGIES
none

PRODUCTS
none

COMPONENTS
none

PLUGINS
none

VERSIONS
none

PARAMETERS
none

PATHS
0 available records

Sources:
none

Research-only: true

No target testing was performed.
```

## 11. Unavailable categories

- **Components / plugins / products**: `NOT_AVAILABLE_IN_CURRENT_DATA` — no
  persisted field exists in the current data model. R30.2 reports them empty
  instead of inventing evidence.
- **Technologies / versions / parameters / paths**: source exists
  (`Http.tech`, `Endpoints`), but the database is unreachable in this
  environment, so they are empty locally. They are derived automatically when
  `database.db` is reachable; the code path is covered by injected-record
  tests.

## 12. CLI

```
python -m ai.research_cli inventory
python -m ai.research_cli inventory --program dell
python -m ai.research_cli inventory --program dell --json
```

Human output follows the requested shape (`OBSERVED ASSET INVENTORY`, program,
per-category `✓ value` / `none`, `PATHS n available records`, `Sources:`,
`Research-only: true`, `No target testing was performed.`). `--json` emits the
inventory (single program) or `{total, items, rule_version, research_only}`
envelope (all programs). Unknown execution flags exit `2`; no raw target
identifiers appear.

## 13. API

Internal read-only routes (existing auth, no writes), declared before
`/api/research/{cve}`:

| Route | Behavior |
|---|---|
| `GET /api/research/inventory/{program}` | one program's observed inventory (404 when unknown) |
| `GET /api/research/inventory/summary` | counts + programs, r30-2 |

No POST/PUT/DELETE (405/401). No raw target URLs/IPs/hostnames.

## 14. UI

No new page. The existing Lead detail page adds a compact **Observed asset
inventory** panel (r30-2 · raw observed context) with Technology / Product /
Component / Plugin / Version / Parameter rows plus a path-record count. It
shows `none` for empty categories, no secrets and no raw target identifiers,
no charts and no polling.

## 15. Tests (`tests/test_observed_inventory.py`, 60 tests, all OK)

Coverage: technology extraction/dedup/normalization; version extraction and
"never inferred"; parameter extraction with method/location/source provenance,
dedup and `?src` normalization; path extraction/dedup/normalization; explicit
product/component/plugin extraction; plugins/products never inferred from paths
or technologies; provenance vocabulary; closed evidence types (no
INFERRED/GUESSED/LLM_DERIVED); malformed endpoint does not erase the inventory;
missing sources; empty inventory; deterministic `inventory_id`; schema
round-trip/rule-version fix and rejection of bad values; privacy (no host/URL/
example_url); backend real-corpus shape; unknown-program 404; injected-record
composition; R30.1 integration upgrading to `CONFIRMED` and resolving blockers
only through R30.1; no-evidence staying `WEAK`; CLI human/JSON/flags; API auth/
shape/404/no-write/no-target-data; UI panel/no-charts; and safety (no
execution/persistence/credential tokens, no fabrication, no side effects,
R17/R25.1/R26.1/R26.2/R26.3/R29.1/R30.1 unchanged, Money Score unchanged).

Regression run:

- R25.2–R30.2 batch (hunt, action queue, opportunities, workflow, economics
  incl. calibration/API, leads, research API, outcomes, sessions, product
  API/contract/client, product validation, R30.1, R30.2): **957 tests OK**.
- AI knowledge/asset-relevance/parameter-component/exploitability/priority/
  queue/target-intelligence + UI/navigation/dashboard batch: **340 tests**,
  1 pre-existing data-drift failure in
  `tests/test_research_ui.py::test_research_sort_toggle_inverts_order`
  (research-list pagination over grown local data; R30.2 does not touch that
  page or sort path).
- `ai.test_knowledge_store`, `ai.test_xss_researcher`,
  `ai.test_xss_llm_researcher`, `ai.test_openrouter`: **96 tests OK**.
- `python -m unittest tests.test_asset_cve_matching` (R30.1, 79) and
  `tests.test_observed_inventory` (R30.2, 60) both **OK**.

`git diff --check` clean.

## 16. Safety audit

Explicitly verified:

- read-only; `research_only = true` on every schema, CLI/API/UI payload;
- no network / DNS / subprocess / LLM / Nuclei / browser / PoC / target
  interaction; static executable-token scan over all three new modules is empty;
  no hard-coded credentials;
- no findings / alerts / payout prediction / automatic research / outcome
  creation / score adjustment;
- no persistence / Mongo writes / new collection / new `ai_data` artifact;
  static persistence-token scan clean; no filesystem side effects observed;
- no systemd and no `.env` changes;
- R17, R25.1, R26.1, R26.2, R26.3, R29.1 unchanged; Money Score unchanged;
- R30.1 matching semantics unchanged (`ai/knowledge/asset_cve_matching.py`
  untouched; `RULE_VERSION`, confidence precedence and blocker rules asserted);
- no raw target URLs/IPs/hostnames in the schema, CLI, API or UI output.

## 17. Limitations

- Component/plugin/product evidence cannot be derived because no persisted
  source exists; the inventory is honest and empty for those categories.
- Version evidence is derived from `Http.tech` labels and is **not yet
  associated** with a specific component in the R30.1 matcher input (R30.1
  compares observed versions to the CVE affected range as a flat list). A
  reachable database with a versioned, unrelated technology could therefore
  produce a numeric version-range coincidence; the affected-range + component
  combination is still required for HIGH confidence, and VERSION-only remains
  LOW, but this should be tightened in a later stage.
- Local verification of the Mongo path is limited by the database being
  unreachable in this environment; the path is covered by injected-record
  tests, not live data.
- The derived inventory is a snapshot of persisted state; it performs no
  freshness/recon and never fetches anything.
- Subdomain membership follows persisted `Subdomains` rows, with a deterministic
  safety net for row-level `program_name`/`subdomain` pairs; no relationship is
  guessed.
- `get_inventory` returns a per-process 10 s read-only cache; tests expose
  `clear_cache()`.

## 18. Exact next-stage recommendation

**R30.3 — Version↔component association and a genuine component/plugin
observation source (offline).**

1. Associate each observed technology version with its owning technology/name
   in the R30.1 input adapter (or a thin, additive R30.1 adapter), so a
   VERSION signal can only match the component family it belongs to.
2. Only if a real persisted component/plugin observation source is introduced
   (e.g. an existing crawl artifact already structured as component/plugin),
   derive those categories; otherwise keep reporting
   `NOT_AVAILABLE_IN_CURRENT_DATA`. Do not infer plugin/component semantics from
   paths.
3. Re-run the real corpus when `database.db` is reachable to measure whether any
   real CVE/program pair legitimately upgrades from `WEAK`; never force it.
4. Keep all boundaries: research-only, no execution/targets, no new score, no
   R17/R18/R25/R26/R29/R30.1 change.

## Agent / Model
- Model: deepseek-flash (deepseek/deepseek-flash)
- Stage: R30.2
- Role: Observed Asset Inventory
