# R68 — Evidence Selection Layer

Date: 2026-09-15
Base commit: `ff8ffe732b47a992f1b81090dfd57227f1e738fe` (R66/R67)
Rule version: `r68-1`

## 1. Implementation

### Evidence schema

A bounded, deterministic evidence catalog is built by Watch before the LLM
call (`evidence_catalog` in `tests/local_e2e/r64_research.py`). Each item is
safe and canonical:

- observation items: `{"id": "E1", "kind": "path", "value": "/x"}`
- derived-signal items: `{"id": "E2", "kind": "derived_signal",
  "signal": "IDOR", "detail": "object_reference=PATH_PARAMETER"}`

Kinds supported: `program`, `snapshot`, `path`, `parameter`, `technology`,
`version`, `record` (all existing canonical context kinds) and
`derived_signal`. Nothing outside the canonical bounded context is added; no
Mongo ids, raw URLs, IPs or credentials are exposed.

### Deterministic evidence ids

- Observation items follow the existing sorted canonical reference index, then
  derived-signal items follow the sorted signal name and sorted details.
- Ids are `E1`, `E2`, ... assigned by position; identical contexts always
  produce identical ids and ordering (no UUIDs, no randomness).
- Budgeted: the catalog is bounded by the existing context bounds (24 items
  per list, 6 refs per collection) and the prompt-size budget.

### Model contract

The prompt now contains `available_evidence` (compact lines, e.g.
`E1 [path] /x`, `E4 [derived_signal] IDOR object_reference=PATH_PARAMETER`)
with explicit rules: select evidence by id; do not reproduce, paraphrase,
translate, combine or modify evidence text; do not invent evidence; signals
are evidence items too; an evidence item never proves a vulnerability; at most
`MAX_LIST_ITEMS` (8) ids per hypothesis.

A hypothesis now returns:

```json
{"title": "...", "category": "...", "priority": "...", "confidence": "...",
 "evidence_refs": ["E1", "E4"], "inference": "...", "why_interesting": "...",
 "missing_evidence": ["..."], "next_safe_action": "..."}
```

The model no longer writes observation refs, facts, sources or derived-signal
details.

### Watch-side resolution

`_resolve_evidence_refs` converts the selection into the canonical R65
representation:

- bounds: more than `MAX_LIST_ITEMS` refs -> `MODEL_OUTPUT_TOO_LARGE`
  (unchanged bound, not increased);
- non-string/empty ref -> `MODEL_OUTPUT_INVALID`;
- unknown id -> `MODEL_OUTPUT_UNGROUNDED` (the model cannot create evidence);
- duplicates are deduplicated deterministically (first occurrence wins);
- catalog kind decides routing: `derived_signal` -> a `watch_derived` signal
  entry; other kinds -> `ref = "kind:value"` plus Watch-computed
  `canonical_fact(ref)`.

### Validation interaction

Resolved evidence is passed through the **unchanged** R65 validators
(`_validate_observations`, `_validate_derived_signals`, category grounding,
confidence/priority caps, unsafe-claim scan, CVE invention check), and the
**unchanged** R66 per-hypothesis acceptance/rejection and global fail-closed
envelope checks still apply. The persisted hypothesis carries resolved
canonical evidence and the safe provenance field `selected_evidence_refs`;
rejected bodies and the evidence catalog are never persisted.

## 2. Tests

- Focused: `tests/local_e2e/test_r64_research.py` — **98 passed, 37 subtests**
  (was 78; +20, including the R67 regression modes below).
- Local suite: `./venv/bin/python -m pytest tests/local_e2e -q
  -p no:cacheprovider` — **240 passed, 63 subtests**.
- Relevant existing suites (`ai/test_openrouter.py`, `ai/test_llm.py`,
  `tests/test_research_priority.py`,
  `tests/test_evidence_confidence_aggregator.py`) — **162 passed**.

Coverage added: deterministic catalog and E1/E2/E3 numbering; catalog traces
back to context; valid selection resolves canonical evidence; unknown evidence
ref; selected ref cannot fabricate a fact; forged evidence text ignored; derived
signal selected separately; duplicate refs deduplicated; evidence limit;
category rules still active; partial acceptance still active; global unsafe
still fails closed; no raw model evidence text trusted; historical R64
artifact untouched.

R67 regression (real R67 failure modes replayed on an R67-like bounded
context):

| R67 failure | R68 behavior |
| --- | --- |
| 16 observations exceeded the limit | selecting > 8 ids -> `MODEL_OUTPUT_TOO_LARGE` |
| combined signal string `api_type=REST, api_versioning=...` | combined string is not a catalog id -> `MODEL_OUTPUT_UNGROUNDED`; selecting the two real ids yields two canonical derived signals |
| canonical fact mismatch (`__cf_chl_f_tk` vs `%5Cu0026__cf_chl_f_tk`) | the model cannot write facts; persisted fact is always `canonical_fact(ref)` |
| session inference without session evidence | still rejected (`MODEL_OUTPUT_UNGROUNDED`) |
| IDOR from derived signal only | still rejected (`MODEL_OUTPUT_UNGROUNDED`) |

## 3. Real fixture run

- Provider: `openrouter` (real, configured; no fake provider)
- Model: `nvidia/nemotron-3-ultra-550b-a55b:free`
- Status: **`COMPLETED_WITH_REJECTIONS`**
- Accepted: 4
  1. IDOR — "Possible IDOR on notification count endpoint via path parameter
     {id}" (MEDIUM/MEDIUM; refs E7, E34)
  2. CVE_RESEARCH — "CVE research for nginx version 1.24.0" (MEDIUM/MEDIUM;
     refs E30, E31)
  3. CVE_RESEARCH — "CVE research for jQuery version 3.5.1" (MEDIUM/MEDIUM;
     refs E29, E33)
  4. RECON — "Unusual endpoint /weird observed; purpose unknown" (LOW/LOW;
     ref E9)
- Rejected: 1 — index 3, `MODEL_OUTPUT_CONFIDENCE_TOO_HIGH` ("REST API
  structure uses path parameters for resource identification")
- Artifact: `ai_data/research/r68/r64-indeed-2ea29240244dcf5b.json`
- One real provider call, no retries; runtime-only 900s timeout accommodation.

## 4. Real Mongo / Indeed run

- Executed: yes
- Program: `indeed` (program isolation: 0 off-program records)
- Snapshot (existing R61 defaults unchanged): subdomains 500,
  live_subdomains 500, http 300, urls 1000, endpoints 1000 (16,500 fetched,
  3,300 selected; all caps reached)
- Evidence items: 81 (78 context refs + 3 derived-signal details)
- Status: **`COMPLETED_WITH_REJECTIONS`**
- Provider/model: `openrouter` / `nvidia/nemotron-3-ultra-550b-a55b:free`
- Artifact: `ai_data/research/r68/r64-indeed-ddd4831a4ecf7077.json`
- Accepted: 2 — both RECON LOW/LOW:
  1. "Possible SAML/OIDC assertion handling via 'assertion' parameter"
     (observation `parameter:assertion`, ref E20; no derived signal)
  2. "File attachment handling via 'attach' and 'attachment' parameters"
     (observations `parameter:attach`, `parameter:attachment`; refs E21, E22)
- Rejected: 4 — 1 `MODEL_OUTPUT_UNGROUNDED` (IDOR without object-reference
  path) and 3 `MODEL_OUTPUT_CONFIDENCE_TOO_HIGH` (brand theming endpoint,
  account flow, Cloudflare Bot Management)

Honest quality classification (the real data produced weak leads):

- Both accepted hypotheses are category RECON at LOW/LOW. Each is grounded in a
  real, canonical parameter observation and framed conditionally with explicit
  missing evidence. Neither demonstrates behavior or a vulnerability.
- 1. `assertion` — **WEAK / LOW-VALUE LEAD** (name-based federation hint; no
  endpoint or token evidence).
- 2. `attach` / `attachment` — **WEAK / LOW-VALUE LEAD** (name-based upload
  hint; no endpoint, validation or storage evidence).

Run attempts (all disclosed):

1. Attempt 1: snapshot OK, provider call failed (`PROVIDER_CALL_FAILED`;
   underlying `OpenRouterProviderError` message not captured at the time).
2. Attempt 2: no provider call; snapshot failed with
   `ServerSelectionTimeoutError` (800 ms server-selection budget).
3. Attempt 3 (final): runtime-only accommodations in the `/tmp` wrapper
   (Mongo server-selection 5 s, provider timeout 900 s; repository unchanged)
   -> `COMPLETED_WITH_REJECTIONS`.

Exact traceability verified after the run: rebuilt context hash
`ddd4831a4ecf7077` equals the artifact hash, and E20/E21/E22 map exactly to
the persisted canonical observations. No rejected hypothesis body appears in
the artifact (only safe rejection titles/codes/reasons).

## 5. Safety

- Mongo writes: **0** (read-only `find`/`find_one` with projections only;
  collection counts identical before and after).
- Target activity: **0** (only the OpenRouter completion calls; no requests to
  Indeed, no crawling, no scanners, no auth/exploit testing).
- `execution_performed=false`, `vulnerability_confirmed=false`,
  `exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
  `human_authority_required=true`, `advisory=true`, `research_only=true`.
- Artifact hygiene: no raw URLs, IPs, Mongo identifiers or credentials; input
  hygiene all false.

## 6. Git

- One local commit: `feat(ai): add evidence selection layer`
  (hash reported in the final task response).
- Files committed: `tests/local_e2e/r64_research.py`,
  `tests/local_e2e/test_r64_research.py`,
  `agent-reports/r68-evidence-selection.md`.
- Unrelated worktree entries untouched: `utils.zip` (pre-existing deletion),
  `watch.zip`, `install.sh`, older untracked reports.
- Push: NO.
