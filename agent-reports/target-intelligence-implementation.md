# Read-Only Target Intelligence Projection (Phase 3A) — Implementation Report

## 1. Verdict

**IMPLEMENTED**

A deterministic, read-only Target Intelligence projection over the
Watch recon inventory is implemented in two new modules, proven by
40 focused tests, with every required regression suite passing
unchanged and zero existing files modified.

## 2. Repository Findings

Exact database models discovered in `database/db.py` (mongoengine
`Document`s, all carrying `program_name`; `connect(...)` executes
at import time — the projector therefore never imports it):

- **Programs**: `program_name` (unique), `created_date`,
  `config` (dict), `scopes` / `ooscopes` (registrable-domain
  string lists, e.g. `acme.com`).
- **Subdomains**: `(program_name, subdomain)` unique;
  `scope` is a registrable-domain label string (set to
  `get_domain_name(subdomain)` at write time); `providers` list.
- **Http**: `(program_name, subdomain)` unique; `scope`,
  `ips`, `tech` (raw httpx `-tech-detect` label list, e.g.
  `nginx:1.24.0` — version embedded, no separate version field),
  `title`, `status_code`, `headers` (dict), `url`, `final_url`,
  `favicon`. No confidence field anywhere.
- **LiveSubdomains**: `program_name`, `subdomain`, `scope`,
  `ips`, `cdn` (closed write-time set). NOT projected (liveness
  is DNS-derived volatile state, not target structure; documented
  in §14).
- **Urls**: `(program_name, url)` unique; `subdomain`, `path`,
  `params` (query keys via `urlparse`/`parse_qs` at write time),
  `sources` (e.g. `katana`), `status_code`.
- **Endpoints**: `(program_name, subdomain, path)` unique;
  `path` pre-normalized by `database.normalize_path` at write
  time; `example_url`, `params` / `params_from_crawl` /
  `params_from_x8`, `x8_checked`, `hit_count`, and
  `param_records` (`{name, method, location, source}`).
- **XssFindings**: verdict-bearing rows (`CONFIRMED` /
  `POTENTIAL` / `INCONCLUSIVE`) — deliberately NOT an input:
  findings must never flow back into pre-verification
  intelligence.

Existing conventions reused: `technology.normalize`'s documented
version-suffix shape (`name:version`, `name version`) for
observation parsing; the canonical `param_records` vocabulary
(`crawl/watch_param_discovery.py`: method ∈ {GET,POST,PUT,PATCH},
location ∈ {query,body}, source ∈ {crawl,x8}); stdlib
`urlsplit` parsing as `upsert_url` does; SHA-256 slot-identity
conventions from the pattern contracts. Scope authority stays
with `ai/correlator/scope_policy.py`, which is referenced but
never imported or called.

## 3. Target Intelligence Contract

New schema `ai/schemas/target_intelligence.py`
(`PROJECTION_VERSION = "target_intelligence/v1"`, all models
`extra="forbid"`):

- **TargetIntelligence**: `intelligence_id` (`ti-` + 16 hex),
  `target_key` (64-hex), `program_name`, `subdomain`,
  `scope_snapshot`, `technologies[]`, `http_observations[]`,
  `url_observations[]`, `endpoint_observations[]`,
  `source_refs`, `observed_at` (audit only),
  `snapshot_hash` (64-hex), `projection_version`. No status
  field: projections have no lifecycle; staleness is expressed
  via `snapshot_hash`.
- **ScopeSnapshot**: `program_scopes`, `program_ooscopes`,
  `subdomain_scope` — verbatim inventory strings, documented as
  observed data that grants nothing.
- **TechnologyObservation**: `name`, `observed_version`
  (Phase-2A-shaped token or None), `raw_label` (verbatim),
  `source` (`http_tech`), `record_ref`.
- **HttpObservation**: `record_ref`, `url`, `final_url`,
  `status_code`, `title`, `ips`, `header_names` (names only;
  values stay reachable via `record_ref`).
- **UrlObservation**: `record_ref`, `url`, `scheme`, `host`,
  `path`, `params`, `sources`, `status_code`.
- **ParamDetail** / **EndpointObservation**: closed method /
  location / source vocabularies; `path` (never re-normalized),
  `example_url` (data, never fetched), `params`,
  `param_details`, `hit_count`, `x8_checked`.
- **SourceRefs**: program/subdomain/http/url/endpoint record
  ids for full audit traceability.

The contract contains no `scope_allowed`, `target_affected`,
`verdict`, `command`, `match_score`, `evidence`, or status
field of any kind (asserted over `model_fields` and by
unknown-field rejection tests).

## 4. Projection API

New module `ai/researcher/target_intelligence.py` (stdlib +
schemas only):

```python
@dataclass(frozen=True) ProgramRecord / SubdomainRecord /
  HttpRecord / UrlRecord / EndpointRecord / ParamRecord
  # field-for-field mirrors of the db.py documents +
  # from_document() duck-typed constructors (getattr only)

def project_subdomain(program, subdomain, *, https=(), urls=(),
                      endpoints=()) -> SubdomainProjection
def project_program(program, subdomains, *, https=(), urls=(),
                    endpoints=()) -> ProgramProjection
```

`SubdomainProjection(intelligence, skipped)`,
`ProgramProjection(intelligence, skipped)`; `ProjectionSkip`
carries `missing_relationship` / `malformed_url` /
`invalid_observation` / `invalid_inventory` reasons.
`TargetIntelError(ValueError)` signals projector misuse;
`TypeError` rejects non-record inputs (same boundary style as
Phase 2B). Callers inject plain records — production adapters
use `from_document()` without ever importing `database.db`.

## 5. Source Mapping

| Inventory row.field | TargetIntelligence field |
|---|---|
| Programs.program_name/scopes/ooscopes/_id | `program_name`, `scope_snapshot.program_*`, `source_refs.program_record_id` |
| Subdomains.subdomain/scope/providers/_id | `subdomain`, `scope_snapshot.subdomain_scope`, `source_refs.subdomain_record_id` (providers: write-provenance, no structural content — not projected, documented) |
| Http.tech[] | `technologies[]` (name + parsed version + verbatim raw label) |
| Http.{url,final_url,status_code,title,ips} + header names + _id | `http_observations[]` |
| Urls.{url→scheme/host/path,params,sources,status_code} + _id | `url_observations[]` |
| Endpoints.{path,example_url,params,param_records→param_details,hit_count,x8_checked} + _id | `endpoint_observations[]` |
| row last_update max | `observed_at` (audit only) |

Not mapped (no such data or out of meaning): confidence (DB has
none — never manufactured), LiveSubdomains/CDN, header values,
`config`, `hit_count` beyond preservation, XssFindings.

## 6. Observation Semantics

Every observation is OBSERVED INVENTORY, never ground truth:
`technology=nginx, observed_version=1.24.0, source=http_tech`
records that a banner/detector *said so*, not what is deployed.
Version splitting is observation-preserving (same suffix shape
the existing technology normalizer documents); unparseable
versions fall back to `(whole label, None)` — never guessed,
never compared, never judged (a `0.5.0` next to a `1.24.0`
produces no `affected` output; the schema cannot express it).
Deduplication is exact-canonical-equality only, never fuzzy.
Malformed rows (bad URLs, out-of-vocabulary param records,
newline-carrying labels, missing record ids) are skipped with
reasons while the valid remainder still projects.

## 7. Identity / Determinism

- `target_key` = SHA-256(`program\nsubdomain`) — semantic target
  identity.
- `intelligence_id` = `ti-` + SHA-256(`version\nprogram\n
  subdomain`)[:16] — stable slot identity, invariant across
  inventory change (tested).
- `snapshot_hash` = SHA-256 over canonical (sorted)
  observations + scope + source refs — snapshot identity that
  moves exactly when observed content moves (tested).
- `observed_at` (max source timestamp) is audit-only, excluded
  from both keys.
- All collections sorted (`technologies` by
  name/version/label/ref, urls/endpoints/records
  lexicographically); input permutation and program-level
  subdomain order do not affect output (tested, incl. shuffled
  inputs and reversed subdomain lists). No randomness, LLM,
  network, or process state.

## 8. Scope Boundary

Scope strings travel verbatim into `ScopeSnapshot` and stop
there: the schema has no `execution_allowed` / `scope_allowed`
/ `authorized_target` / `allow_scope` field, its docstring
defines the snapshot as non-authoritative, and tests assert the
serialized intelligence contains none of those keys while still
preserving the observed values (`program_scopes ==
["acme.com"]`). The module never imports the scope policy and
performs no scope decision; future execution must re-resolve
scope through `ai/correlator/scope_policy.py`.

## 9. Security Boundary

- **No LLM** — no provider/model/embedding symbol in the module.
- **No network** — no `requests`/`urllib3`/`httpx`/`socket`
  symbol; full program projection runs with `socket.socket`
  disabled (test). URLs (incl. `https://attacker.example/`
  fixtures) are parsed, preserved as data, never fetched —
  `file://` and schemeless URLs are refused as web targets.
- **No subprocess** — no `subprocess`/`os`/`sys` symbol.
- **No DB writes** — attribute reads only; a write-trap double
  (`save`/`update`/`delete`/`insert`/`upsert`/`reload`/`modify`/
  `objects`) records zero write attempts during projection.
  `database.db` / `mongoengine` / `pymongo` are never imported
  (importing `database.db` would connect to MongoDB).
- **No target matching** — no `PatternStore` / `project_claim` /
  `match_technology` import or reference; no
  pattern-vs-technology comparison exists.
- **No version comparison** — `ai/correlator/version.py` is
  neither imported nor called; versions are inert strings.
- **No finding/verdict authority** — `CONFIRMED`, `VERIFIED`,
  `NOT_VULNERABLE`, `EXPLOITED`, `target_affected`,
  `finding_status`, `evidence` cannot appear (asserted over
  serialized output, incl. hostile tech/title/URL fixtures whose
  payloads remain inert data).
- **Fail closed** — wrong input types (`TypeError`), empty
  names and cross-program subdomain mismatch
  (`TargetIntelError`), malformed observations (skipped with
  reasons, never fabricated).

## 10. Cross-Program Isolation

Attachment uses only the canonical `program_name` (+
`subdomain`) relationship fields every row carries — never
hostname similarity or registrable-domain guessing. Projection
for program A ignores rows owned by program B (tested at both
`project_subdomain` and `project_program` level, asserting B's
strings/ids are absent from A's output). Rows with empty
relationship keys are skipped with `missing_relationship`
reasons rather than guessed into a program (tested); the choice
is documented in the module docstring. Program membership
mismatch between the passed program and subdomain arguments
raises instead of projecting.

## 11. Tests

Exact commands and results (from `/opt/watch`):

```
python3 -m unittest ai.test_target_intelligence
  Ran 40 tests in 0.013s — OK

python3 -m unittest ai.test_research_pattern ai.test_hypothesis_testplan \
  ai.test_pattern_projector ai.test_pattern_store
  Ran 207 tests — OK           (Phases 2A/1/2B/2C unchanged)

python3 -m unittest ai.test_ingestion_schema ai.test_ingestion_grounding \
  ai.test_knowledge_store ai.test_knowledge_ingestion
  Ran 132 tests — OK           (boundary suites unchanged)

python3 -m compileall -q ai   (clean)
```

The 40 new tests cover the full required matrix: schema validity
/ bad ids / unknown+malicious field rejection / authority-field
absence / identity determinism / round-trip (1–7); relationship
preservation, cross-program and cross-subdomain exclusion,
mismatch rejection, orphan-row skips, type rejection, program
isolation (8–11); version-as-observation, versionless labels, no
comparison proof, dedupe, no manufactured confidence, hostile
labels (12–16); HTTP/URL/endpoint projection, malformed URLs,
out-of-vocabulary params, endpoint dedupe, hostile hosts (17–21);
repeat/shuffle/ordering/slot-stability determinism (22–25);
network-disabled run, symbol scan, write trap, unfetched hostile
URLs, inert command strings, scope and verdict authority absence
(26–34); duck-typed document adapter and full round-trip
integration (35–37).

## 12. Files Changed

| File | Action | Why |
|---|---|---|
| `ai/schemas/target_intelligence.py` | CREATED | TI contracts, identity helpers, `PROJECTION_VERSION` |
| `ai/researcher/target_intelligence.py` | CREATED | Inventory records + `project_subdomain` / `project_program` |
| `ai/test_target_intelligence.py` | CREATED (40 tests) | Full §11 matrix |
| `agent-reports/target-intelligence-implementation.md` | CREATED | This report |

No existing file was created, modified, or renamed. No Git
operation was performed.

## 13. Compatibility

Purely additive: no existing module is imported by the new code
except schemas and stdlib (deliberately not `database.db`,
`ai/correlator/*`, pattern store/projector, or any provider).
All Phase 1/2A/2B/2C suites (207 tests) and the
ingestion/grounding/knowledge suites (132 tests) pass
unmodified; `compileall` is clean. The pre-existing
`crawl/watch_param_discovery.py` working-tree state was not
touched or evaluated (out of scope).

## 14. Limitations

1. `LiveSubdomains` (IPs/CDN liveness) is not projected:
   volatile DNS-derived state, not target structure; the matcher
   phase should state explicitly if it needs it.
2. Header values, `config` dicts, `providers` lists, and crawl
   `sources` beyond URL rows are referenced (via record ids),
   not embedded — audit reachability without inventory bloat.
3. `observed_at` is the max source timestamp string, mixing the
   two timestamp formats the DB layer writes (`%Y-%m-%d %H:%M:%S`
   and ISO); audit-only, never identity.
4. No cross-collection snapshot isolation is claimed: MongoDB
   offers no multi-collection transaction here, so a projection
   reflects whatever rows were passed in. Determinism holds per
   input set; callers needing a point-in-time view must gather
   inputs under their own read policy.
5. Version parsing covers the documented `name:version` /
   `name version` label shapes; exotic detector strings fall
   back to version-less observations rather than guessing.
6. No persistence: projection returns typed objects; any future
   snapshot cache needs its own explicit justification.

## 15. Recommended Next Step

The smallest safe next phase is the **deterministic Target
Matcher (read-only relevance join)**: `TargetIntelligence ×
VulnerabilityPattern/AttackPattern → scored (target, pattern)
pairs` using only `technology.normalize`-style alias logic plus
`ai/correlator/version.py` comparison over the observed-version
vs `VersionConstraint` inputs — no hypothesis generation, no
execution, priority inputs restricted to deterministic fields
(CVSS, asset counts) per adversarial-review B4. It consumes
exactly the two Phase 2C/3A outputs and creates the first
relevance signal without adding any new authority.

---

*Phase 3A ends at Existing Watch Recon Inventory → READ-ONLY
Projection → Target Intelligence. No Git operations were
performed; the index is untouched. Report created at
`/opt/watch/agent-reports/target-intelligence-implementation.md`.*
