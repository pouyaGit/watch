# Stage R30.3 — Version ↔ Component Association

Implementation report for the local WSL Watch repository.

- Rule version: `r30-3`
- Action: local implementation only (no deployment, no target interaction)
- Scope: R30 asset↔CVE matching **input** association layer only

## 1. Problem addressed

R30.1 evaluated a CVE version range against *any* observed version. R30.2
collected versions from `database.Http.tech` labels (e.g. `WordPress:6.8.3`)
but flattened them into a plain `versions` list, losing the owning technology.
As a result, a CVE such as

```
WordPress plugin XYZ 1.2.3   (affected: <= 1.2.3)
```

could be evaluated against an unrelated observed technology version such as

```
WordPress 6.8.3
```

because both mention WordPress. When a component/plugin match also existed,
R30.1 combined `VERSION + COMPONENT/PLUGIN` into a strong match, falsely
implying that the affected component was installed at the affected version.

R30.3 associates each observed version with its **explicit owning technology
family** (and its owning component/plugin only when a structured source
establishes it) *before* the R30.1 version evaluation, and adds the explicit
distinction:

- `VERSION_MATCH_WITHIN_SAME_FAMILY`
- `VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION`

The latter can never be promoted into a component/plugin match.

## 2. Exact source of observed version data

The current persisted Watch data model was inspected:
`Programs`, `Subdomains`, `Http.tech`, `Urls`, `Endpoints`,
`Endpoints.params`, `params_from_crawl`, `params_from_x8`, `param_records`.

The only structured persisted source of an observed version is the
`database.Http.tech` tech-detect label. The existing target-intelligence
projector (`ai/researcher/target_intelligence.py`) splits a label such as
`WordPress:6.8.3` into:

- `TechnologyObservation.name = "WordPress"`
- `TechnologyObservation.observed_version = "6.8.3"`

R30.3 reuses that same projection. `collect_version_associations()` emits one
`ObservedVersionAssociation` per versioned technology observation:

```
version           = "6.8.3"        (observed_version)
technology_family = "WordPress"   (the same observation's name)
component         = ""            (unavailable: no structured source)
source            = TECHNOLOGY_INVENTORY
evidence_type     = STRUCTURED_TECHNOLOGY
```

The existing R30.2 flat `versions` list is preserved unchanged for backward
compatibility; the association list is a new additive field.

Other version-like inputs:

- Research payload `metadata.versions` (persisted research metadata) carry no
  technology owner; the backend adapter passes them as
  component/family-unavailable records.
- `backend/asset_cve_matching.py` may receive explicit structured
  `version_records` through dependency injection (tests / future structured
  sources). No such persisted source exists today.

There is **no persisted component/plugin/product version source** anywhere in
the current Watch data model (`Http`, `Endpoints`, `Urls`, `Programs`), so in
real data every derived association reports `component = ""` (unavailable).
Nothing is inferred from URL strings, target hostnames, parameter names,
keyword coincidence, CVE description text or LLM output.

## 3. Component association rules

Pure module: `ai/knowledge/version_component_association.py`
(rule version `r30-3`, no I/O, no network, no LLM, no persistence).

Inputs:

- `cve_families`: CVE products + derived technology hints
  (`backend/asset_cve_matching.build_matches` passes
  `cve_products + profile["technologies"]`)
- `cve_components`, `cve_plugins`, `cve_versions`
- `observed_versions`: `ObservedVersionAssociation` records
- `observed_components`, `observed_plugins`: explicit observed components
  (used only to detect "component present, version absent")

Deterministic classification (reusing R30.1 normalizers/matchers, so matching
semantics stay identical — boundary-safe, alias-aware, never substring):

1. **Component-associated** — the record has an explicit `component` and
   `match_component(cve_components, [component])` or
   `match_plugin(cve_plugins, [component])` hits.
2. **Family-associated** — no component hit, but `technology_family` matches a
   CVE product/technology via `match_product` / `match_technology`.
3. **Family mismatch** — the record has an owner family and the CVE has family
   information, but no family/component matches.
4. **Unknown owner** — no family and no (matching) component.

State precedence (closed vocabulary in `VERSION_ASSOCIATION_STATES`):

| Priority | Condition | State | R30.1 engine receives |
|---|---|---|---|
| 1 | component-associated version satisfies range | `VERSION_MATCH_WITHIN_SAME_FAMILY` | associated versions |
| 2 | family-associated version satisfies range (component-target CVE) | `VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION` | **nothing** |
| 3 | unknown-owner version satisfies range (component-target CVE) | `VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION` | **nothing** |
| 4 | relevant owner exists, range not satisfied | `VERSION_OBSERVED_NO_MATCH` | nothing |
| 5 | only other-family owners | `FAMILY_MISMATCH` | nothing |
| 6 | component observed (or component-associated record), no comparable version | `COMPONENT_ASSOCIATED_VERSION_UNKNOWN` | nothing |
| 7 | version records exist but are uncomparable/unparseable | `VERSION_ASSOCIATION_UNKNOWN` | nothing |
| 8 | no version evidence at all | `NO_VERSION_OBSERVATION` | nothing |
| — | CVE has **no** component/plugin target: family-associated match | `VERSION_MATCH_WITHIN_SAME_FAMILY` | associated versions |
| — | CVE has **no** component/plugin target: unknown-owner match | `VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION` | unknown-owner versions (R30.1 behavior preserved for bare version CVEs) |

Key behavioral rule: for a CVE that targets a component/plugin, a
family-level or unknown-owner version is **withheld** from the R30.1 engine.
The engine therefore cannot produce `VERSION` (which is target-specific) and
cannot combine it with `COMPONENT`/`PLUGIN` into `HIGH`/`CONFIRMED`. The
observation is retained additively as
`version_association_state` / `version_association_evidence` /
`version_association_reason`; it is never discarded and never promoted.

Examples:

- `WordPress + 6.8.3` → `technology_family = "WordPress"`, `component = ""`.
- `WordPress plugin XYZ + 1.2.3` → only when an explicit structured record
  supplies `component = "XYZ"`; otherwise `component = ""` (unavailable).
- `jQuery + 3.7.1` against a WordPress plugin CVE → `FAMILY_MISMATCH`.

## 4. Unavailable-data behavior

- A version without a structured component owner reports
  `component = ""` and `component_available = False`. No component is
  invented from paths (`/wp-content/plugins/...`), hostnames, parameters,
  keywords, CVE text or LLM output.
- A family-level version that satisfies a component/plugin CVE's range is
  reported as `VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION` and is **not**
  passed to the R30.1 version matcher (so `version_unknown` is not falsely
  resolved and no component match is implied).
- An observed component with no observed version yields
  `COMPONENT_ASSOCIATED_VERSION_UNKNOWN`; the R30.1 component match still
  happens (existing semantics), but no version evidence is attached.
- Malformed/empty inputs fail soft: invalid association records are skipped;
  empty inputs yield `NO_VERSION_OBSERVATION`; unparseable versions/ranges
  yield `VERSION_ASSOCIATION_UNKNOWN` or
  `COMPONENT_ASSOCIATED_VERSION_UNKNOWN` deterministically.
- When nothing at all is available, the R30.1 summary is unchanged except for
  the additive association fields.

## 5. Files changed

Changed:

- `ai/schemas/observed_inventory.py`
  - new `ObservedVersionAssociation` model (version + explicit
    `technology_family`/`component` + provenance; `extra="forbid"`),
  - new additive `ObservedAssetInventory.version_associations` field,
  - `VERSION_ASSOCIATION_RULE_VERSION = "r30-3"`.
- `ai/knowledge/observed_inventory.py`
  - new `collect_version_associations(projections, records=())`,
  - new additive `version_records` DI parameter on
    `collect_program_inventory`,
  - association field, evidence lines and source union in
    `collect_program_inventory` / `build_observed_inventory` /
    `build_inventory_summary`,
  - existing collectors and flat `versions` output unchanged.
- `backend/asset_cve_matching.py`
  - `_inventory_values` now also surfaces `version_associations`,
  - new `_version_association_records` adapter (unowned versions are marked
    unowned, never inferred),
  - `build_matches` runs `evaluate_version_association` **before**
    `evaluate_inventory`, passes only `association.engine_versions` as
    `observed_versions`, and attaches the additive
    `version_association_*` summary fields.
- `tests/test_observed_inventory.py`
  - R30.2 integration fixture extended with an explicit association,
  - new regression test: an unassociated version must not resolve the
    `version_unknown` blocker.

Added:

- `ai/knowledge/version_component_association.py` — pure R30.3 association
  engine (639 lines).
- `tests/test_version_component_association.py` — 41 deterministic offline
  tests (750 lines).

Intentionally untouched:

- `ai/knowledge/asset_cve_matching.py` (R30.1 engine, byte-identical),
- `ai/schemas/asset_cve_match.py` (R30.1 schema),
- `backend/observed_inventory.py` (the inventory projection serializes the
  new field automatically; no change needed),
- `database/db.py`, `.env`, systemd/deployment, `ns/`, `crawl/`, Nuclei/CVE,
  R17/R18/R25/R26/R29 code.

## 6. Tests

New test file (41 tests, all passing): `tests/test_version_component_association.py`

Required coverage:

1. Same technology + same component + matching version → association allowed,
   engine yields `CONFIRMED`/`HIGH`.
2. Same technology + different component → no component match, no promotion.
3. Technology version only + CVE for a plugin → component unavailable, not
   inferred; version not passed to the engine.
4. Component present but version absent → component match possible
   (`SUPPORTED`), version match unavailable.
5. Version present but owning component unavailable → version retained with
   `family` recorded, component unavailable.
6. Different technology families → `FAMILY_MISMATCH`, no association.
7. Empty/malformed observations → fail-soft, deterministic.
8. Existing R30.1 tests unchanged and passing.

Additional coverage: collector provenance, paths never create component
ownership, explicit-only component ownership, deterministic builds, closed
state vocabulary, backend adapter integration on the real
`CVE-2026-1557` corpus (mocked inventory: unassociated vs associated),
promotion-blocking, R30.1/R17/R25/R26/R29 canaries, research-only forcing,
no execution/persistence/target-identifier tokens.

Commands and results:

```
python -m unittest tests.test_asset_cve_matching \
                   tests.test_observed_inventory \
                   tests.test_version_component_association -q
Ran 181 tests in 3.146s
OK

python -m unittest ai.test_target_intelligence ai.test_research_cli \
                   tests.test_research_api tests.test_hunt_queue \
                   tests.test_opportunity_action_queue \
                   tests.test_research_leads -q
Ran 242 tests in 495.161s
OK

git diff --check   # clean
```

Three failures in `tests.test_page_render` / `tests.test_research_ui` were
verified to be **pre-existing** (identical failures with R30.3 changes
stashed) and are unrelated to this stage.

## 7. Limitations

- The current Watch data model persists **no structured component/plugin
  version source**. Consequently, in real data every derived association has
  `component = ""` (unavailable), and
  `VERSION_MATCH_WITHIN_SAME_FAMILY` for a plugin/component CVE is only
  reachable when an explicit structured record is injected (as the tests do).
  This is deliberate: representing the component as unavailable rather than
  inferring it.
- CVE family information comes from CVE products plus derived technology
  hints. A CVE without product/technology metadata cannot establish family
  association; its observed versions are treated as unowned and are withheld
  for component/plugin CVEs.
- Alias coverage is intentionally small (it reuses the existing R30.1 alias
  tables); no fuzzy matching is introduced.
- The R30.3 fields are exposed on the asset↔CVE match summary
  (`/api/research/matches/...`, CLI match JSON) only. They are deliberately
  **not** propagated into the R26/R29 additive projection schemas
  (`extra="forbid"`), because R26/R29 must remain unchanged.
- UI/CLI rendering was not changed (not required by R30.3); the new fields are
  additive JSON context.
- Association classification is per CVE/program pair and reuses the R30.1
  normalizers; it is not a vulnerability verdict and does not change any
  existing score.

## 8. Research-only boundary confirmation

- Deterministic, read-only, offline-testable, additive: no new global score,
  no change to any Money/hunt/opportunity score.
- No network, no DNS, no subprocess, no Nuclei, no browser, no PoC/exploit, no
  target interaction, no persistence, no Mongo writes, no new collections.
- No LLM involvement; no credential access; `.env` and `database/db.py`
  untouched; systemd/deployment untouched.
- R17, R18, R25, R26, R29 are unchanged; the R30.1 matching engine
  (`ai/knowledge/asset_cve_matching.py`) and schema are byte-identical
  (not present in `git diff`).
- The distinction between `VERSION_MATCH_WITHIN_SAME_FAMILY` and
  `VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION` is explicit, and the latter
  is never promoted to a component/plugin match.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R30.3
- Role: Asset/CVE Matching Implementation Agent
