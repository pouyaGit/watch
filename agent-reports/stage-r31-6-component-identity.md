# Stage R31.6 — CVE Component/Plugin Identity Resolution

Local WSL implementation. No commit, no push, no VM access, no deployment,
no Mongo writes, no systemd changes.

## Objective

R30.1's matching engine uses conservative normalization (lowercase,
parenthetical-strip, generic `PRODUCT_ALIASES`) to compare CVE-side
component/plugin identities against observed inventory. Real CVE products
appear in several forms that this normalization does not collapse:

| CVE-side raw | R30.1 normalized | Observed identity | R30.1 match? |
|-|-|-|-|
| `WP Responsive Images (WordPress plugin)` | `wp responsive images` | `wp-responsive-images` | yes (alias table) |
| `wordpress_automatic_plugin` | `wordpress automatic plugin` | `wordpress-automatic` | **no** |
| `OttoKit: All-in-One Automation Platform` | `ottokit all in one automation platform` | `wp-ottokit` | **no** |
| `OttoKit` | `ottokit` | `wp-ottokit` | **no** |

R31.6 introduces a small, deterministic, auditable identity-resolution layer
that runs **only on CVE-side identifiers** and feeds the unchanged R30.1
engine the expanded value set it already understands. The resolver never
mutates observed inventory, never invents identities from prose, never
relies on edit distance / Levenshtein / token intersection / substring
matching, and never queries a live target.

## Current Architecture Trace

CVE-side identities enter the pipeline at three points in
`backend/asset_cve_matching.py::build_matches`:

1. `cve_products = _merge_unique(profile.get("products"), extras.get("products"))`
   — `profile["products"]` comes from `ai/knowledge/queue.py::vulnerability_profile`,
   which joins `cve.products` and `research.affected_products`. Real
   payloads include `"WP Responsive Images"`, `"OttoKit: All-in-One
   Automation Platform"`, `"wordpress_automatic_plugin"`, `"Automatic"`.
2. `cve_plugins = _merge_unique(extras.get("plugins"))` — `extras` comes
   from `_research_extras`, which subsets products with `"plugin" in
   product.lower()`. Real values include `"WP Responsive Images (WordPress plugin)"`,
   `"OttoKit: All-in-One Automation Platform"` (substring match).
3. `cve_components = _safe_list(profile.get("components"))` — from the
   document `components` attribute; rarely populated in current payloads.

These three lists are then passed to `ai.knowledge.asset_cve_matching.evaluate_inventory`
which calls `match_product(cve_products, observed_products)`,
`match_plugin(cve_plugins, observed_plugins)` and
`match_component(cve_components, observed_components)`. Each matcher uses
`_exact_pair` with the conservative `normalize_product` / `normalize_plugin`
/ `normalize_component` and the small `PRODUCT_ALIASES` /
`PLUGIN_ALIASES` / `COMPONENT_ALIASES` tables.

Observed identities enter from `backend/observed_inventory.get_inventory`
(via `_inventory_values`) plus `metadata_observed` from the persisted
research payload. Real observed plugin slugs include
`wp-responsive-images`, `wp-ottokit`, `wordpress-automatic`,
`dell-virtual-rack-theme`, etc.

The R30.1 engine itself is `ai/knowledge/asset_cve_matching.py` and is
**untouched** in R31.6.

## Files Changed

| Path | Change | Purpose |
|-|-|-|
| `ai/knowledge/component_identity.py` | new (840 lines) | R31.6 deterministic CVE-side identity resolver |
| `backend/asset_cve_matching.py` | additive | Insert resolver call before R30.1 invocation; record structured identity evidence |
| `tests/test_component_identity.py` | new | 57 tests covering normalization, alias table, negatives, classification, observed matching, determinism, bounds, privacy, backend integration, engine purity |

`ai/knowledge/asset_cve_matching.py` was **not** modified.

## Identity Model

Every CVE-side identity is resolved to a structured `IdentityResolution`
dataclass with the following fields:

| Field | Meaning |
|-|-|
| `raw_identity` | The exact CVE-side string as captured |
| `normalized_identity` | Lowercase, parenthetical-stripped, diacritic-stripped, marketing-trailer-stripped, separator-collapsed form |
| `canonical_identity` | The canonical identity used by the resolver (alias-table entry when matched, else canonical slug from the normalized form) |
| `category` | Closed vocabulary: `PRODUCT`, `COMPONENT`, `PLUGIN`, `TECHNOLOGY`, `UNKNOWN` |
| `resolution_method` | Closed vocabulary: `EXACT_NORMALIZED`, `CANONICAL_SLUG`, `EXPLICIT_ALIAS`, `NO_RESOLUTION` |
| `alias_variants` | Ordered, bounded tuple of normalized variants the resolver treats as equivalent for matching |
| `evidence` | Bounded list of human-readable resolution lines (raw, normalized, canonical, rationale) |

A separate `IdentityEvidence` dataclass records the per-observed match
(`raw_cve_identity`, `canonical_cve_identity`, `observed_identity`,
`observed_normalized`, `category`, `resolution_method`, `evidence`) and is
emitted additively into the per-program match summary under
`identity_resolution`.

## Rules Added

### Normalization (conservative, deterministic)

1. Lowercase + diacritic-strip (NFKD) + parenthetical-strip via
   `\([^)]*\)`.
2. Query/fragment-strip (`?...` and `#...` removed before any further
   processing — guarantees no `Bearer`, `Authorization`, `X-API-Key`,
   `password=` etc. leaks into identity evidence).
3. Marketing-trailer-strip (only when the trailer appears at the tail):
   `All-in-One Automation Platform`, `All-in-One Automation`,
   `Automation Platform`, `WordPress Plugin`, `Wordpress Plugin`,
   `WP Plugin`, `WordPress plugin`, `Wordpress plugin`, `WP plugin`,
   `Plugin`, `plugin`.
4. Trailing-type-suffix-strip: `_plugin`, `-plugin`, `_component`,
   `-component` (only when present at the end of the cleaned string).
5. Leading-`wp-`-strip *only when the remainder is a single token*:
   `wp-ottokit` -> `ottokit`, but `wp-responsive-images` is preserved
   because stripping `wp-` would destroy identity (the observed slug is
   `wp-responsive-images`).
6. Separator-collapse to `-`; leading/trailing `-` removed.

### Canonical-slug generation

`s canonical_slug(raw, normalized, category)` returns a deterministic
slug only when:

* `category in (PLUGIN, COMPONENT, PRODUCT)`;
* `normalized` matches the safe-slug regex
  `^[a-z0-9][a-z0-9.\-]{0,63}$`;
* `normalized` is not a stopword (`the`, `a`, `an`).

Prose multi-token inputs are never concatenated into a slug; they fall
back to the alias-table lookup (or `EXACT_NORMALIZED` if no alias
matches). This is verified by the alias-table tests.

### Explicit alias table (versioned, documented)

The `ALIAS_TABLE` is a tuple of `AliasEntry` records. Each entry carries:

* `canonical`: the resolver's canonical identity.
* `category`: PLUGIN (the only category the resolver currently classifies
  into via alias lookup; PRODUCT is the default for the rest).
* `aliases`: the explicit, ordered, bounded variants.
* `rationale`: short corpus-derived justification (committed as docstring
  evidence so a reviewer can audit why the alias exists).

Current entries:

| Canonical | Category | Aliases | Rationale |
|-|-|-|-|
| `wp-responsive-images` | PLUGIN | `wp-responsive-images`, `wp responsive images`, `wp responsive image`, `wpresponsiveimages` | CVE-2026-1557 `affected_products` includes `"WP Responsive Images (WordPress plugin)"`; observed WordPress plugin slug is `wp-responsive-images`; the current R30.1 alias table already covers this case for the plugin matcher; R31.6 carries it forward at the resolver layer. |
| `wordpress-automatic` | PLUGIN | `wordpress-automatic`, `wordpress_automatic_plugin`, `wordpress automatic`, `automatic` | CVE-2024-27956 lists both `"Automatic"` and `"wordpress_automatic_plugin"` as products; the WordPress plugin directory slug is `wordpress-automatic`. The CVE-side product `"Automatic"` is the post-strip form of `"wordpress_automatic_plugin"`; the observed directory slug `"wordpress-automatic"` is the same identity. |
| `ottokit` | PLUGIN | `ottokit`, `wp-ottokit`, `otto kit` | CVE-2025-3102 lists `"OttoKit: All-in-One Automation Platform"` as product. The marketing trailer is stripped by `normalize_identity`. The observed WordPress plugin directory slug is `wp-ottokit`, which the resolver maps to `ottokit` via the leading-`wp-` strip. |

The alias table is the only source of new alias relationships; the
resolver never invents aliases beyond it. Adding new entries requires
examining current corpus evidence and updating the rationale.

### Negative-collision set

The `negative_alias_pairs()` tuple records the corpus-derived
collisions that must remain distinct:

* `automatic` vs `automatic-login`
* `ottokit` vs `otto`
* `ckeditor` vs `ckfinder`
* `wp-smushit` vs `smush`
* `wordpress` vs `wordpress-automatic`
* `jquery` vs `jquery-ui`

These are exposed read-only and covered by negative tests.

## Known Corpus Cases

| CVE | CVE-side raw form | Observed identity | Before R31.6 | After R31.6 | Resolution deterministic? | Confidence change |
|-|-|-|-|-|-|-|
| CVE-2024-27956 | `wordpress_automatic_plugin` | `wordpress-automatic` (from `/wp-content/plugins/wordpress-automatic/`) | no match (engine normalizes to `wordpress automatic plugin`) | match (canonical `wordpress-automatic`, alias set includes `wordpress automatic`) | yes | MEDIUM (R30.1 PLUGIN match only — no version/component combine) |
| CVE-2024-27956 | `Automatic` (alt product) | `automatic` (from plugin slug) | match via R30.1 (already worked) | match via explicit alias table (canonical `wordpress-automatic`, alias `automatic`) | yes | unchanged |
| CVE-2025-3102 | `OttoKit: All-in-One Automation Platform` | `wp-ottokit` (from plugin slug) | no match (engine normalizes to `ottokit all in one automation platform`) | match (canonical `ottokit`, alias set includes `wp-ottokit`) | yes | MEDIUM (R30.1 PLUGIN match) |
| CVE-2026-1557 | `WP Responsive Images` (cve.products) | `wp-responsive-images` (from plugin slug) | match via existing R30.1 alias table (already worked) | match via resolver alias table (canonical `wp-responsive-images`); resolver now records the resolution in evidence | yes | unchanged (HIGH stays HIGH only with `src` parameter/path support) |
| CVE-2026-1557 | `WP Responsive Images (WordPress plugin)` (research.affected_products) | `wp-responsive-images` | match via R30.1 alias table | match via resolver alias table (canonical `wp-responsive-images`); resolution now recorded in evidence | yes | unchanged |

The resolver never changes R30.1's confidence, blocker resolution, or
research-only status. It only adds identity-resolution evidence rows.

## False-Positive Protection

The alias table is the single most sensitive safety surface in this
module. Protection relies on three layers:

1. **No fuzzy matching.** The resolver uses set-equality only:
   `observed_normalized ∈ resolution.alias_set ∪ {normalized, canonical}`.
   No edit distance, no token intersection, no substring.
2. **Closed vocabulary.** Every category, resolution method, source, and
   alias table field is enumerated; unknown values are rejected by the
   Pydantic schema (`extra="forbid"` in the existing schemas; closed
   tuples in the resolver).
3. **Negative-collision tests.** Six corpus-derived collision pairs are
   pinned by `TestNegativeCollisions` (automatic vs automatic-login,
   otto vs ottokit, ckeditor vs ckfinder, wp-smushit vs smush,
   wordpress vs wordpress-automatic, jquery vs jquery-ui).

Additionally:

* `_leading_wp` is single-token-only (multi-token remainders such as
  `wp-responsive-images` preserve identity).
* `_strip_marketing_trailer` only strips the tail; it never reaches
  inside compound names.
* Query strings and fragments are stripped in `_clean_text` before any
  further processing — credentials, authorization headers, and request
  data can never enter the resolver's output.

## Integration

`backend/asset_cve_matching.py::build_matches` was extended with a single
new step between CVE-side value computation and the R30.1 invocation:

```
cve_products  = _merge_unique(profile.products, extras.products)
cve_plugins   = _merge_unique(extras.plugins)
cve_components= _safe_list(profile.components)
...
identity_resolution = resolve_cve_identities(  # NEW (R31.6)
    cve_products=cve_products,
    cve_plugins=cve_plugins,
    cve_components=cve_components,
)
resolved_products  = expanded_cve_value_set(identity_resolution.resolutions, "PRODUCT")
resolved_plugins   = expanded_cve_value_set(identity_resolution.resolutions, "PLUGIN")
resolved_components= expanded_cve_value_set(identity_resolution.resolutions, "COMPONENT")
if resolved_products:
    cve_products = _merge_unique(cve_products, resolved_products)
... # same for plugins / components
```

The R30.1 engine continues to receive string values; the adapter simply
passes it the expanded value set (canonical + normalized + alias
variants) in addition to the originals.

After `evaluate_inventory` returns, the per-program summary records the
identity-resolution evidence:

```
summary["identity_resolution"] = [
    row.to_dict() for row in identity_matches
][:MAX_IDENTITY_EVIDENCE]
summary["identity_resolution_rule_version"] = IDENTITY_RESOLUTION_RULE_VERSION
```

`identity_matches` is built by `match_observed_identities` which compares
the resolved CVE-side identities against the observed components /
plugins / products and emits one `IdentityEvidence` row per overlap.

### R30.1 engine was not modified

`git diff --stat -- ai/knowledge/asset_cve_matching.py` returns empty.
The R30.1 engine file (`ai/knowledge/asset_cve_matching.py`) is byte
identical to its post-R31.5 state.

## Tests

| Suite | Count | Result |
|-|-|-|
| `tests.test_component_identity` (R31.6) | 57 | OK |
| `tests.test_component_inference` (R31.2) | 53 | OK |
| `tests.test_component_plugin_wiring` (R31.3) | 14 | OK |
| `tests.test_observed_inventory` (R30.2) | 61 | OK |
| `tests.test_asset_cve_matching` (R30.1) | 79 | OK |
| `tests.test_version_component_association` (R30.3) | 41 | OK |
| `tests.test_component_evidence_provenance` (R31.5) | 15 | OK |
| **Total** | **320** | **OK** |

Commands run (local WSL, hermetic Mongo stub via
`mongoengine.connect = lambda *a, **k: None`):

```
PYTHONPATH=/opt/watch ./venv/bin/python -m unittest tests.test_component_identity
PYTHONPATH=/opt/watch ./venv/bin/python -m unittest tests.test_component_inference tests.test_component_plugin_wiring tests.test_observed_inventory tests.test_asset_cve_matching tests.test_version_component_association tests.test_component_evidence_provenance tests.test_component_identity
```

Compile check:

```
./venv/bin/python -c "import sys; sys.path.insert(0, '/opt/watch'); import mongoengine; mongoengine.connect = lambda *a, **k: None; import backend.asset_cve_matching; import ai.knowledge.component_identity"
```

Lint:

```
git diff --check        # clean
git status --short      # 4 files changed (backend adapter, new module, new test) + pre-existing unrelated working-tree noise (D utils.zip, ?? watch.zip, ?? stage-r31-5-planning-audit.md)
```

## Validation

Validation was **offline/synthetic** against:

1. Synthetic identity inputs covering the known corpus cases.
2. Synthetic observed-inventory fixtures (`{"value": ..., "source": ..., "evidence_type": ...}`
   projected via the backend adapter's `_inventory_values` mock).
3. The local CVE research corpus under `ai_data/research/` (read-only
   inspection only — no writes, no I/O against Mongo).

No live Mongo query, no live API call, no live target request was
performed. The known CVE files inspected:

| File | products / affected_products |
|-|-|
| `ai_data/research/CVE-2024-27956.cli.json` | `["Automatic", "wordpress_automatic_plugin"]` |
| `ai_data/research/CVE-2025-3102.cli.json` | `["OttoKit: All-in-One Automation Platform"]` |
| `ai_data/research/CVE-2026-1557.cli.json` | `["WP Responsive Images"]` / `["WP Responsive Images (WordPress plugin)"]` |

Each of these now produces structured identity-resolution evidence rows
that record the raw CVE-side identity, the canonical identity, the
resolution method (`EXPLICIT_ALIAS` for all three), and the observed
identity that was matched.

## Safety / Privacy

* The resolver never logs, persists, or transmits secrets, authorization
  headers, API keys, or query-string parameters.
* `_clean_text` strips `?...` and `#...` before any further processing
  so that credentials and authorization tokens can never enter the
  canonical / normalized / evidence fields.
* Tests `test_no_authorization_headers_or_bearer_tokens_in_evidence` and
  `test_no_url_host_leakage_in_normalized_or_canonical` confirm the
  resolver never emits `Bearer`, `Authorization:`, `X-API-Key`,
  `password=`, `?`, `#`, or similar structures.
* The R30.1 engine never sees secret data because the resolver consumes
  only CVE-side identifiers (product names, affected products) which are
  expected to be free of credentials.

## Working Tree

Pre-existing unrelated working-tree changes that R31.6 does not modify:

* `D utils.zip` (untracked deletion)
* `?? watch.zip` (untracked)
* `?? agent-reports/stage-r31-5-planning-audit.md` (untracked, not in
  R31.6 scope)

R31.6-intentional changes:

* `M backend/asset_cve_matching.py` (additive resolver integration)
* `?? ai/knowledge/component_identity.py` (new module)
* `?? tests/test_component_identity.py` (new test suite)

## Limitations

R31.6 deliberately does not solve the following:

1. **Component identity disambiguation.** The alias table is corpus-derived
   and intentionally narrow. Adding new aliases requires current corpus
   evidence. The resolver will not invent aliases beyond the alias table.
2. **Plugin slug mismatches in the absence of corpus evidence.** A CVE
   that references a WordPress plugin by a slug we have never seen
   (e.g. `akismet` referenced as `"akismet_anti_spam_plugin"`) will
   only resolve if a `AliasEntry` exists for it. The resolver is
   conservative; it will not invent aliases.
3. **Substring / token intersection.** Two distinct strings that share
   a token (e.g. `ckeditor` and `ckfinder`, `wp-smushit` and `smush`)
   remain distinct. The negative-collision tests pin this.
4. **Edit distance / fuzzy matching.** Intentionally out of scope. The
   resolver is bounded by the alias table and the canonical-slug shape.
5. **Marketing trailers beyond the closed list.** The trailer list
   covers the corpus-derived set; novel marketing phrasing requires a
   manual alias-table entry.
6. **Cross-program aliasing.** Each CVE-context resolution is independent;
   the resolver does not maintain a session-wide alias cache. This is
   intentional (deterministic, fail-soft).

## Conclusion

**PASS.** R31.6 introduces a deterministic, auditable, conservative
identity-resolution layer that fixes the known corpus mismatches
(`wordpress_automatic_plugin`, `OttoKit: All-in-One Automation Platform`)
without weakening the R30.1 engine or the R31.5 evidence-provenance gate.
The R30.1 engine is byte-identical to its R31.5 state; the R31.5
evidence-provenance gate is byte-identical to its post-R31.5 state; all
263 R30.1/R30.2/R30.3/R31.2/R31.3/R31.5 tests continue passing; the 57
new R31.6 tests pass; `git diff --check` is clean.

## Agent / Model
- Model: MiniMax-M3
- Stage: R31.6
- Role: coding agent
