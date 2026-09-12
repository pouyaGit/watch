# Stage D9 — XSS Candidate Semantics & UX Clarification

## Root cause

Persisted XSS research candidates (`ai_data/research/xss/xss-*.json`,
produced deterministically by `ai/researcher/xss_agent.py` from generic KB
documents) contain **no** `program` / `target` / `asset` association at all.
Their schema is: `candidate_id, agent_version, status, query, xss_type,
context, technologies, techniques, source_evidence, vulnerability_pattern,
injection_context, sinks, sources, preconditions, test_idea, confidence,
unknowns, references, disclaimer`. Verified by inspecting all 7 persisted
artifacts: none carries any target key, and no CVE/KB text implies one.

Despite this, the UI rendered every record under the prominent banner
`RESEARCH CANDIDATE — NOT A PRODUCTION FINDING` (detail) /
`RESEARCH CANDIDATES — NOT PRODUCTION FINDINGS` (list) with a `CANDIDATE`
status badge and an `XSS Candidates` dashboard card. A researcher can
reasonably read "candidate" as "XSS found on one of our targets". The
`status = RESEARCH_CANDIDATE` value is a scoring-bucket label (type+context
both matched), not a target claim — but the presentation made it look like
one.

## Current behavior (before)

- `GET /ui/xss/xss-60edf609e21c6b41` → banner
  `RESEARCH CANDIDATE — NOT A PRODUCTION FINDING`, `CANDIDATE` badge, no
  scope/target/validation block.
- `GET /ui/xss` → banner `RESEARCH CANDIDATES — NOT PRODUCTION FINDINGS`,
  no scope column, no Knowledge-Pattern / Target-Candidate split.
- Dashboard + research overview cards → `XSS Candidates` with a status
  breakdown (`research candidate: …`), counting generic KB patterns as
  "candidates".
- API (`/api/xss/candidates*`) exposed no presentation metadata.

## New semantics

New deterministic, presentation-only module `backend/xss_presentation.py`
(stdlib-only; no network/LLM/Nuclei/verifier):

- `KNOWLEDGE_PATTERN` — default. Label
  `KNOWLEDGE PATTERN — NOT TARGET VALIDATED`, scope
  `Generic XSS knowledge pattern`, target `No target associated`,
  `target_association = false`, `validation_state = NOT_TESTED`.
- `TARGET_RESEARCH_CANDIDATE` — only when the persisted artifact literally
  contains a non-empty value under an explicit key (`program, program_id,
  target, target_id, asset, asset_id, target_program, target_asset,
  monitored_program`). Label `TARGET RESEARCH CANDIDATE — NOT VERIFIED`,
  scope `Target-specific research candidate`, target = that exact value
  (never fabricated), `validation_state = NOT_VERIFIED`.
- CVE ids, KB ids/titles, evidence reasons, sinks/sources, query text and
  patterns NEVER count as target association.

Wiring (additive, compatible): `backend/research_data.py` enriches
`_xss_compact`, `get_xss`, `list_xss` (new `presentation_counts` /
`knowledge_patterns` / `target_research_candidates`) and `get_overview`
(new `xss_knowledge_patterns`, `xss_target_candidates`,
`xss_presentation_counts`; existing `xss_candidates`/`xss_by_status` kept).

UI: detail page shows the presentation banner + a `Scope` panel
(Scope / Target / Validation `NOT TESTED` or `NOT VERIFIED`, the
`Generic XSS knowledge pattern / No target associated / Not
target-specific / Not tested` lines for generic records, and the prominent
warning `This record describes reusable security knowledge. It does NOT
indicate an XSS finding on any monitored program.`). List page shows
`KNOWLEDGE PATTERNS — NOT TARGET VALIDATED` plus `Knowledge Patterns` /
`Target Research Candidates` cards and a per-row Scope badge. Dashboard and
research-overview cards relabeled to `Knowledge Patterns` with an explicit
`Target Research Candidates: 0` sub-line. No scoring, R15–R22, verifier,
database (`database/db.py` untouched), network, LLM, Nuclei, browser,
finding or alert behavior was changed.

## Real corpus result

`xss-60edf609e21c6b41` (status `RESEARCH_CANDIDATE`, confidence 0.90,
reflected/html_attribute, 3 KB evidence docs) carries zero explicit target
keys → renders as:

- `KNOWLEDGE PATTERN — NOT TARGET VALIDATED`
- Scope `Generic XSS knowledge pattern`, Target `No target associated`,
  Validation `NOT TESTED`
- warning as above; no `TARGET RESEARCH CANDIDATE` string on the page;
  no program fabricated.
- Corpus-wide: `presentation_counts = {KNOWLEDGE_PATTERN: 7,
  TARGET_RESEARCH_CANDIDATE: 0}`.

## Exact files changed

- `backend/xss_presentation.py` (new): deterministic classifier.
- `backend/research_data.py`: presentation enrichment (compact, detail,
  list counts, overview counts).
- `backend/routers/research_pages.py`: passes presentation counts to
  `xss.html`; retitled page to `XSS Knowledge Patterns`.
- `web/templates/macros.html`: new `xss_presentation_badge` macro.
- `web/templates/xss_detail.html`: presentation banner/badge, Scope panel,
  warning, footer fallback reworded.
- `web/templates/xss.html`: new banner, Knowledge/Target cards, Scope
  column, reworded empty state.
- `web/templates/dashboard.html`: XSS card → Knowledge Patterns +
  target-candidate sub-line.
- `web/templates/research.html`: XSS stat → Knowledge Patterns +
  target-candidate sub-line.
- `tests/test_xss_presentation.py` (new): 12 D9 tests.
- `tests/test_research_ui.py`, `tests/test_research_navigation.py`,
  `tests/test_xss_llm_dashboard.py`: updated stale label assertions to D9
  wording (intent preserved).

## Tests

New `tests/test_xss_presentation.py` covers: real `xss-60edf609e21c6b41`
→ `KNOWLEDGE_PATTERN`; no fabricated program; CVE/KB text never implies a
target; target classification only on explicit association; detail-page
labels (`KNOWLEDGE PATTERN`, `No target associated`, `Not tested`,
`NOT TESTED`, exact warning) and absence of `TARGET RESEARCH CANDIDATE`;
no `VULNERABLE/VERIFIED/EXPLOITED/FINDING` claims (negated disclaimers
excluded); dashboard split cards; API presentation metadata + list counts
(target = 0); hostile KB/program text escaped (explicit program shown only
escaped); no forbidden imports/calls (nuclei/llm/browser/subprocess/
network).

Runs (this environment has no MongoDB; unmocked-`/` tests were given the
same dashboard mocks as sibling suites, which also makes them hermetic):

- `tests.test_xss_presentation` + `tests.test_research_navigation`: 26/26 OK
- `tests.test_research_api`: 29/29 OK
- `tests.test_xss_llm_dashboard`: 14/14 OK
- `tests.test_research_ui` + `tests.test_dashboard_navigation`: 59/60 OK —
  single failure is `test_research_sort_toggle_inverts_order`
  (`/ui/research` title-sort inversion), a pre-existing corpus/sort issue
  in code untouched by this stage.
- `ai.test_knowledge_store` + `ai.test_xss_researcher` +
  `ai.test_xss_llm_researcher` + `ai.test_openrouter`: 96/96 OK
- `git diff --check`: clean (rc=0).

## Security review

- No new data flows: classifier reads only already-persisted dicts; no
  network, subprocess, provider, browser, Nuclei, or verifier invocation
  added (asserted by test).
- No finding/alert/claim created: generic pages contain no affirmative
  `VULNERABLE / VERIFIED / EXPLOITED / FINDING` wording; the only
  `VERIFIED`/`FINDING` tokens are inside `NOT …` disclaimers and the
  pre-existing quarantined LLM panel label.
- Escaping preserved: all persisted strings still render through Jinja
  autoescaping; hostile `<script>`/event-handler payloads (including a
  hostile explicit `program` value) render escaped; presentation strings
  are server-side constants, never derived from untrusted text.
- No target fabrication: `No target associated` is the default; explicit
  values are shown verbatim (clipped to 240 chars) only when literally
  present — and escaped.
- `database/db.py` unmodified; no commits/pushes performed.

## Limitations

- `status = RESEARCH_CANDIDATE` persists in stored JSON and API responses
  (compatibility); the small `CANDIDATE` status badge is still shown next
  to the new `KNOWLEDGE PATTERN` badge. A future stage could rename the
  stored status, but that would change scoring/persistence semantics and
  was out of scope.
- `TARGET_RESEARCH_CANDIDATE` is currently unexercised by real data
  (corpus count 0); its rendering is covered by synthetic-override tests
  only.
- `test_research_sort_toggle_inverts_order` fails independently of this
  stage (research title-sort stability); unmocked-`/` dashboard access
  still requires MongoDB in environments without the new mocks.

## Agent / Model

- Model: muse-spark-1.3-contributor-free
- Stage: D9
- Role: XSS Candidate Semantics and UX
