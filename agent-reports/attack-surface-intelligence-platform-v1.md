# Attack Surface Intelligence Platform v1

## Scope

Transform Watch from a reconnaissance storage system into an **Attack Surface
Intelligence Platform**: turn the raw attack surface Watch already collects
(domains, subdomains, HTTP assets, URLs, endpoints, parameters, technologies)
into prioritized, explainable security-research candidates that specialist
agents can consume.

The platform answers one question deterministically:

> "What should a security researcher investigate next?"

Delivered in this milestone:

- A new `backend/attack_surface/` module (data access, classification,
  scoring, service, queue/lifecycle).
- Deterministic, LLM-free, network-free candidate generation for four research
  categories: `XSS_CANDIDATE`, `IDOR_CANDIDATE`, `SSRF_CANDIDATE`,
  `FILE_UPLOAD_CANDIDATE`.
- A stable JSON API: `GET /api/command/attack-surface`.
- A new **Attack Surface Intelligence** Command Center section (Discovery,
  Candidates, Priority queue).
- Unit tests and this report.

Out of scope and deliberately untouched: the NS/DNS, crawl/parameter
discovery, Nuclei/CVE and `database/` subsystems. No database schema,
collection or credential was added or modified.

## Architecture

```
backend/attack_surface/
    __init__.py     package surface (re-exports the stable API)
    models.py       normalized records + candidate/lifecycle vocabulary
    repository.py   read-only access to existing recon rows
    classifier.py   deterministic category rules (no LLM, no network)
    scorer.py       deterministic, explainable scoring
    service.py      orchestration, payloads, CandidateQueue lifecycle
```

Layering (each layer is independently testable):

```
existing Watch data                       (Http / Urls / Endpoints / Programs)
        │  read-only
        ▼
repository.normalize_records()  ──►  AttackSurfaceRecord  (url, endpoint,
        │                                 parameter, method, technology, source)
        ▼
classifier.classify(record)     ──►  Classification       (category + reasons)
        │
        ▼
scorer.score(record, class.)    ──►  ScoredCandidate       (score, confidence,
        │                                                      reasons)
        ▼
service.build_candidates()      ──►  AttackSurfaceCandidate (lifecycle status)
        │
        ├── build_discovery()        ──►  domains / URLs / endpoints / parameters
        ├── summarize_candidates()   ──►  per-category + per-confidence counts
        ├── build_priority_queue()   ──►  ranked "investigate next" queue
        └── CandidateQueue           ──►  NEW→TRIAGED→ASSIGNED→VERIFYING→
                                          CONFIRMED→REPORTED lifecycle
        ▼
backend/routers/command_center.py ──►  /ui/command + /api/command/attack-surface
```

### Data access (Phase 1)

`repository.py` reuses existing abstractions instead of duplicating databases:

- The existing `ai.researcher.target_intelligence` record converters
  (`HttpRecord`, `UrlRecord`, `EndpointRecord`, `ParamRecord`) mirror the
  `database/db.py` models exactly.
- The existing read-only Mongo accessor
  (`backend.observed_inventory._short_client`, `_database`, `list_programs`)
  provides the short-timeout, fail-soft connection and program discovery.
- Discovery counts are computed **server-side** (`count_documents` /
  `distinct`) so the module never loads an unbounded corpus. Candidate
  generation uses a bounded document sample (endpoints sorted by `hit_count`,
  plus recent URLs and all HTTP technology rows) per program.

Normalized object (per endpoint parameter):

```json
{
  "url": "/api/user?id=",
  "endpoint": "/api/user",
  "parameter": "id",
  "method": "GET",
  "technology": ["WordPress", "nginx"],
  "source": "watch"
}
```

URLs are relative and never fetched; technology versions are stripped to
names only.

### Classification (Phase 2)

Deterministic signal sets (exact + token/prefix/suffix heuristic for signals
of length >= 4; short signals require an exact or whole-token match):

| Category | Parameter signals | Endpoint signals |
|---|---|---|
| `XSS_CANDIDATE` | q, query, search, name, message, input, redirect, return, next | — |
| `IDOR_CANDIDATE` | id, uid, user, user_id, account, profile, object, item | user, users, account, profile, order |
| `SSRF_CANDIDATE` | url, uri, target, callback, webhook, proxy, destination | — |
| `FILE_UPLOAD_CANDIDATE` | upload, file, image, attachment, import | — |

Every match returns the matched signal, whether it was exact or heuristic, and
the category reasons (e.g. "user controlled input name", "reflection
possibility", "object identifier parameter", "resource reference",
"remote resource input", "file handling functionality").

### Scoring (Phase 3)

Explainable additive score, capped at 100. Confidence: `HIGH` >= 80,
`MEDIUM` >= 55, else `LOW`.

| Component | Points |
|---|---|
| base | 30 |
| parameter signal (exact) | 30 |
| parameter signal (heuristic) | 18 |
| endpoint signal | 30 |
| state-changing method (POST/PUT/PATCH/DELETE) | 8 |
| identifier parameter (id / uid / *_id) | 12 |
| technology context | 5 |
| reflection signal (XSS GET) | 5 |

`score()` returns the exact `contributions` that produced the integer score, so
no score is a black box.

### Persistence / queue (Phase 4)

Candidate lifecycle statuses: `NEW`, `TRIAGED`, `ASSIGNED`, `VERIFYING`,
`CONFIRMED`, `REPORTED`. `CandidateQueue` validates transitions against a
fixed transition map, is idempotent on re-add (status preserved) and is
in-memory by default. An explicit `path` opts into a small JSON artifact store
for a future dedicated worker; the Command Center / API path never writes.

### Command Center + API (Phases 5–6)

- UI: a new `ATTACK SURFACE INTELLIGENCE` section on `/ui/command` with
  DISCOVERY (domains, URLs, endpoints, parameters), CANDIDATES (XSS / IDOR /
  SSRF / Upload counts + confidence) and a ranked PRIORITY QUEUE.
- API: `GET /api/command/attack-surface` (optional `?program=`), stable
  schema `{available, rule_version, summary, discovery, candidates,
  priority_queue}`.

## Files Changed

New:

| File | Lines | Purpose |
|---|---|---|
| `backend/attack_surface/__init__.py` | 62 | package surface |
| `backend/attack_surface/models.py` | 262 | records, candidate, lifecycle vocabulary |
| `backend/attack_surface/repository.py` | 565 | read-only normalized access |
| `backend/attack_surface/classifier.py` | 265 | deterministic category rules |
| `backend/attack_surface/scorer.py` | 193 | deterministic explainable scoring |
| `backend/attack_surface/service.py` | 392 | orchestration, payloads, queue |
| `tests/test_attack_surface.py` | 362 | repository, service, lifecycle |
| `tests/test_attack_surface_classifier.py` | 215 | classification + scoring |
| `tests/test_attack_surface_api.py` | 199 | API + Command Center UI |
| `agent-reports/attack-surface-intelligence-platform-v1.md` | — | this report |

Modified:

| File | Change |
|---|---|
| `backend/routers/command_center.py` | read-only `_attack_surface_state()` collector, `attack_surface` in the Command Center payload, `GET /api/command/attack-surface` route |
| `web/templates/command_center.html` | new Attack Surface Intelligence section (Discovery / Candidates / Priority queue) |

No `database/`, `ns/`, `crawl/`, Nuclei or CVE files were modified.

## Data Flow

1. `_attack_surface_state(program)` in the Command Center router calls
   `service.attack_surface_payload(program)` inside a fail-soft wrapper.
2. `service` asks `repository.load_snapshot(program)` for a bounded,
   read-only `AttackSurfaceSnapshot`.
3. `repository` reads existing `Http` / `Urls` / `Endpoints` rows through the
   shared read-only Mongo accessor, computes server-side discovery counts, and
   normalizes the bounded sample into `AttackSurfaceRecord` values.
4. `classifier.classify()` assigns zero or more categories per record;
   `scorer.score()` turns each classification into an explainable score.
5. `service.build_candidates()` produces deterministic
   `AttackSurfaceCandidate` values (stable `asc-…` ids), and
   `build_priority_queue()` ranks them for "investigate next".
6. The same payload is rendered by the Command Center template and returned by
   the JSON API.

Fail-soft everywhere: an unreachable database or malformed row yields an
honest empty/unavailable state (`available: false`, zeroed counters); no value
is invented.

## Tests

New focused suites (62 tests):

```
python3 -m unittest tests.test_attack_surface
python3 -m unittest tests.test_attack_surface_classifier
python3 -m unittest tests.test_attack_surface_api
```

Coverage:

- parameter classification (all four categories, exact + heuristic, negative),
  endpoint classification, multi-category matches;
- scoring, confidence thresholds, contribution sums, determinism, explainability;
- normalization (shape, method/location provenance, params fallback,
  URL-derived records, technology version stripping, malformed-path skip,
  deterministic ordering, honest empty);
- service (candidate construction, deterministic ids, ranked queue, summary,
  stable payload schema, empty payload);
- lifecycle (`NEW→…→REPORTED`, illegal transitions rejected, idempotent add,
  JSON round-trip, no-write default);
- API schema, auth, program filter, empty-data honesty, no-write endpoint,
  Command Center section rendering, forbidden-word absence.

Regression run (218 tests, all passing):

```
tests.test_attack_surface
tests.test_attack_surface_classifier
tests.test_attack_surface_api
tests.test_command_center
tests.test_command_center_intelligence
tests.test_command_center_operations
tests.test_repository_intelligence
ai.test_knowledge_store
ai.test_xss_researcher
ai.test_xss_llm_researcher
ai.test_openrouter
```

`git diff --check` is clean.

## Limitations

- v1 is **deterministic and rule-based**: it produces research *hypotheses*,
  never confirmed vulnerabilities. Classification is name/endpoint-shape based
  and cannot observe actual reflection, authorization or fetch behavior.
- Candidate generation uses a bounded per-program sample (3000 endpoints by
  `hit_count`, 1000 recent URLs, HTTP technology rows). Discovery counts are
  authoritative, but candidate coverage of very large programs is sampled.
- `program=None` loads a bounded number of programs (`DEFAULT_MAX_PROGRAMS`);
  the snapshot is flagged `truncated` when the cap is hit.
- Parameter "numeric identifier" is inferred from the parameter *name*
  (`id`, `uid`, `*_id`), not from observed values.
- The `CandidateQueue` is in-memory unless an explicit path is supplied; v1
  does not persist queue state in production and the Command Center never
  writes. Live queue persistence is intentionally deferred.
- `pytest` is not installed; tests use `unittest`, per `AGENTS.md`.

## Future Specialist Agents

The candidate contract is designed as a consumption surface:

- **XSS agent** consumes `XSS_CANDIDATE` (parameter + reflection signal) to
  plan reflection probes.
- **IDOR agent** consumes `IDOR_CANDIDATE` (object identifier + resource
  endpoint) to plan object-reference tests.
- **SSRF agent** consumes `SSRF_CANDIDATE` (remote resource input) to plan
  out-of-band fetch tests.
- **File-upload agent** consumes `FILE_UPLOAD_CANDIDATE` (file handling
  signals) to plan upload handling tests.

Each candidate carries `id`, `category`, `confidence`, `score`, `endpoint`,
`parameter`, `method`, `reasons`, `status`, `created_at` and source metadata,
so a specialist agent can claim a candidate (`TRIAGED`/`ASSIGNED`), drive it
through `VERIFYING`, and only ever record a confirmed result through the
existing, separate verification authorities. The classifier/scorer never
confirm anything.

## Commit / Push

COMMIT STATUS: committed on `agent/daily-development`
PUSH STATUS: not pushed (push is always manual in this workflow)
READY TO PUSH: YES
