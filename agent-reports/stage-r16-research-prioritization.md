# Stage R16 — Deterministic Research Prioritization

## 1. Objective

Add an additive, deterministic, explainable **research-priority** layer over the
R12–R15 knowledge intelligence, answering "which vulnerabilities should Watch
investigate first, and why?" It is research attention only — never validation,
exploitation, or a finding/verdict.

The priority is a pure function of persisted intelligence (R15 exploitability
tri-states + CVSS structural metrics, and R12–R14 type/CWE/component/parameter
fields). It is order-independent, idempotent, bounded 0–100, and every point is
explained. Missing values stay `unknown` and never become negative.

## 2. Exact files changed

- `ai/knowledge/intelligence.py` — R16 constants/weights/thresholds,
  `ResearchPriority` dataclass, `summarize_research_priority()`,
  `research_priority_projection()` (+ `_priority_evidence()`). Extends the
  existing engine; no second engine.
- `ai/schemas/knowledge.py` — additive `KnowledgeResearchPriority` and
  `KnowledgeDocument.research_priority` (default `INSUFFICIENT_DATA`).
- `ai/knowledge/ingestion.py` — projects `research_priority` onto synthesis and
  reference documents.
- `ai/knowledge/store.py` — on re-ingest, additively recomputes `exploitability`
  and `research_priority` from the merged evidence, so re-ingest upgrades
  documents created before R15/R16 (still deterministic/idempotent). No existing
  R12–R15 fields are changed.
- `ai/research_cli.py` — `priority` subcommand (`--cve`, `--all`, `--json`),
  read-only.
- `ai/test_research_priority.py` — **new**, 27 tests.

Runtime note (untracked, not source): the six corpus CVEs were re-ingested into
the local JSON KB (`ai_data/knowledge/`) with the sanctioned, offline, idempotent
`kb ingest` so the new CLI reflects current intelligence. The corpus under
`ai_data/research/` was not modified.

## 3. Scoring rules (transparent, bounded)

Score starts at 0; each signal adds an explicit number of points; total is
clamped to `[0, 100]`. Family caps prevent double-counting the same fact.

| Family (cap) | Rule | Points |
|---|---|---|
| Exploit availability (40) | `active_exploitation == true` | +25 |
| | `public_poc == true` | +12 |
| | `exploit_available == true` | +8 |
| Access (30) | `authentication_required == false` | +12 |
| | `privilege_required == false` | +10 |
| | `user_interaction_required == false` | +8 |
| Complexity | `exploit_complexity == low` | +10 |
| | `exploit_complexity == high` | −10 |
| Attack vector | CVSS `AV == N` network | +10 |
| | `AV == A` adjacent | +5 |
| | `AV == L` local | −5 |
| | `AV == P` physical | −10 |
| Research relevance (10) | vulnerability type identified | +3 |
| | affected component identified | +4 |
| | affected parameter identified | +3 |
| | CWE mapped | +2 |

Rules: no point is awarded for an `unknown` value; `unknown` is never a negative
signal. A negative factor (high complexity, local/physical vector) can lower the
score but never below 0 and never by itself produces `INSUFFICIENT_DATA`. No CVSS
score is calculated — only the persisted structural metrics are read.

## 4. Priority thresholds

Evaluated highest-first after clamping:

| Score | Class |
|---|---|
| ≥ 70 | `CRITICAL_RESEARCH` |
| ≥ 50 | `HIGH_RESEARCH` |
| ≥ 30 | `MEDIUM_RESEARCH` |
| 0–29 (with any known signal) | `LOW_RESEARCH` |
| no priority-relevant signal known | `INSUFFICIENT_DATA` |

These are research-attention classes only. They are deliberately not named
`exploitable`, `verified`, `vulnerable`, or `confirmed`.

## 5. Explainability model

`KnowledgeResearchPriority` (and the `ResearchPriority` dataclass) always
contains:

- `priority` — the class above;
- `score` — 0–100;
- `reasons[]` — one human-readable entry per positive rule that fired;
- `negative_factors[]` — e.g. `high exploit complexity`, `local attack vector`;
- `unknown_factors[]` — e.g. `active exploitation status unknown` (preserved,
  never treated as false);
- `evidence[]` — deterministic references to the `IntelligenceEvidence` records
  that back the contributing signals (field/value/rule/source);
- `rule_version` — `"r16-1"`.

No score is ever produced without explanation: a non-zero score always has at
least one reason.

## 6. Real corpus results

Fresh deterministic ingestion (`ai_data/research/`, read-only; no network):

| CVE | score | priority | strongest reasons | negative | unknowns |
|---|---|---:|---|---|---:|
| CVE-2026-1557 | 80 | CRITICAL_RESEARCH | public PoC; exploit availability; no authentication required | – | 0 |
| CVE-2024-27956 | 38 | MEDIUM_RESEARCH | no privileges required; no user interaction; low complexity | – | 4 |
| CVE-2024-42327 | 28 | LOW_RESEARCH | no user interaction; low complexity; network vector | – | 4 |
| CVE-2024-5376 | 28 | LOW_RESEARCH | no user interaction; low complexity; network vector | – | 4 |
| CVE-2025-4893 | 28 | LOW_RESEARCH | no user interaction; low complexity; network vector | – | 4 |
| CVE-2025-3102 | 18 | LOW_RESEARCH | no privileges required; no user interaction; network vector | high exploit complexity | 4 |

The corpus was not edited to influence scores.

## 7. Test results

- New focused suite `ai.test_research_priority`: **27 tests, OK**.
- Consolidated relevant regression pass (27 modules incl. R12 intelligence,
  R14 parameter/component, R15 exploitability, ingestion, knowledge
  store/ingestion, body extraction, KB/XSS e2e, research CLI, reports,
  reference quality/canonicalization/ranker/cache, CVE batch, quality parity,
  ingestion schema/grounding, research pattern, XSS agent/case builder, and the
  mandatory XSS/LLM suites incl. `test_xss_researcher`,
  `test_xss_llm_researcher`, `test_openrouter`): **724 tests, all OK**.
- `py_compile` clean; `git diff --check` clean.

## 8. Adversarial / mandated scenario results

1. public PoC increases priority — pass.
2. active exploitation strongly increases priority (active > PoC > available) — pass.
3. unauthenticated increases priority — pass.
4. no privileges increases priority — pass.
5. no user interaction increases priority — pass.
6. low complexity increases priority — pass.
7. high complexity does not zero out the score — pass.
8. `unknown != false` (unknown adds no points, no negatives, preserved in
   `unknown_factors`) — pass.
9. insufficient evidence → `INSUFFICIENT_DATA`, score 0 — pass.
10. score bounded 0–100 (max family-capped = 100; negative-only clamps to 0) — pass.
11. reasons explain every positive score — pass.
12. unknown factors preserved — pass.
13. deterministic ordering (reversed evidence input → identical output) — pass.
14. repeated computation byte-identical — pass.
15. no cross-CVE contamination (other-CVE wording does not score) — pass.
16. no network/subprocess (socket and Popen patched to raise; pure function) — pass.
17. legacy document compatibility (default projection; re-ingest upgrades) — pass.
18. adversarial exploit-like wording cannot manufacture priority — pass.
19. CVSS structured precedence preserved (structured `UI:N` beats prose) — pass.
20. existing R12–R15 suites remain green — pass.

## 9. Idempotency

- `summarize_research_priority` / `research_priority_projection` return identical
  output for identical input and are independent of evidence ordering.
- `store.ingest` re-ingest remains byte-identical (verified for the R15/R16
  synthetic fixtures and for upgrading a legacy document). Re-ingesting the
  corpus produced `created == []` (identities unchanged) while populating the
  new additive projections.

## 10. Security boundary

R16 is pure local deterministic computation:

- no exploit execution, no Nuclei, no browser, no HTTP, no DNS;
- no active validation, no 5B–5J production authority chain;
- no findings created, no alerts, no production-target mutation;
- no LLM, no network, no subprocess (asserted by test);
- no CVSS score is calculated; only explicit persisted metrics are read.

The only write path used is the pre-existing offline `kb ingest` into the local
JSON KB; the corpus itself is read-only.

## 11. Limitations

- The numeric CVSS base score / severity label is not persisted as a structured
  document field, so R16 prioritizes on persisted structural metrics (AV/AC/PR/UI)
  and tri-states rather than the numeric score. The task forbids calculating a
  score; if numeric severity is wanted as a signal it must first be persisted by
  an upstream stage.
- Thresholds and weights are an explicit policy, not a measured calibration; they
  are centralized constants and easy to tune.
- Priority reflects the freshness of the persisted KB. Documents ingested before
  R15/R16 are upgraded when `kb ingest` is re-run (done for the six corpus CVEs).
- Unlike `KATANA_TIMEOUT`-style tuning there is no runtime configuration for
  weights in this stage (deliberate: deterministic, reviewable constants).
- Priority is research attention only and must not be surfaced as a vulnerability
  verdict.

## 12. Explicit confirmation

- **No network.**
- **No LLM.**
- **No Nuclei.**
- **No active validation.**
- **No production authority chain.**
- **No alerts.**
- **No Git operations** (no add/commit/push).

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R16
- Role: Research Prioritization
