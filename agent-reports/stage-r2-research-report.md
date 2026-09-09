# Stage R2 — Deterministic Read-Only Research Report: Implementation Report

## 1. Implementation summary

Implemented Stage R2: a deterministic, read-only Markdown research report
renderer that consumes ONLY already-persisted local artifacts and produces
`ai_data/reports/<CVE>.md`. No network, no LLM, no Nuclei execution, no
production access, no new infrastructure, no Git operations.

New module `ai/reports/renderer.py` exposes:

- `build_report_for_cve(cve_id, output_path=None, output=None, ...)` —
  loads `<CVE>.cli.json` (required), `<CVE>.references.json` (optional),
  read-only KnowledgeStore contents via `retrieve()`, and optional Nuclei
  `generated/results/findings` artifacts; writes the report atomically
  (temp file + rename). Accepts both `output_path` and `output` keywords
  (the existing `research_cli run_report` passes `output=`).
- `render_report(...)` — pure function rendering Markdown from
  already-loaded artifacts (used by tests and the builder).

The existing CLI command (wired in the prior R1 commit) now works end to
end with zero CLI changes required:

- `python3 -m ai.research_cli report --cve CVE-2026-1557`
- `python3 -m ai.research_cli report --cve CVE-2026-1557 --output <path>`

Report sections (all seven, in order): CVE / Research Summary (table),
Vulnerability (type, endpoint/path, parameter(s), description, persisted
evidence), References (per-record title, URL, source/type, context
availability, content hash), Knowledge Base (read-only readback +
token-overlap relevance, explicitly NOT a KB relationship), Nuclei
(template identity/path/digest, semantic + template validation, decision,
result/finding summaries, trust-boundary banner), Watch Relevance
(persisted fields only, unknowns stated), Limitations (only genuinely
absent items).

## 2. Files changed

Added (no existing file modified):

- `ai/reports/__init__.py` — package export (`ReportError`,
  `build_report_for_cve`, `render_report`).
- `ai/reports/renderer.py` — the renderer (~900 lines with docstrings).
- `ai/test_reports_renderer.py` — 14 focused tests (see section 6).
- `ai_data/reports/CVE-2026-1557.md` — sample output generated via the
  CLI (90 lines).

Modified: none. In particular, production 5B–5J code, `ns/`, `crawl/`,
`database/`, Nuclei/CVE functionality, and `ai/research_cli.py` were
NOT touched (the `report` subcommand and `run_report` already existed).

## 3. CLI usage

```bash
python3 -m ai.research_cli report --cve CVE-2026-1557
python3 -m ai.research_cli report --cve CVE-2026-1557 --output /tmp/r.md
```

Success prints `REPORTED: <CVE>`, `SAVED: <path>`, and the read-only mode
banner. A missing `<CVE>.cli.json` (or malformed CVE id) exits 1 with
`ERROR: ReportError: ...` on stderr — clear and deterministic.

## 4. Report structure

See the sample output `ai_data/reports/CVE-2026-1557.md`: summary table
(CVE, title, CVSS/severity, CWE-22, product, versions, authentication,
public exploit, research status), vulnerability with endpoint
`/wp-content/plugins/wp-responsive-images/image_handler.php` and
parameter `src`, references archive state, KB state, Nuclei evidence
(template digest `sha256:d2d5d8191077e359`, `GOOD_CANDIDATE`, dry-run
verdict), Watch relevance (persisted programs/assets only, applicability
Unknown), and limitations. No raw JSON dumps; single-newline-collapsed
and Markdown-escaped untrusted text; URLs rendered only as `http(s)`
code spans, anything else as `invalid URL:` literals.

## 5. Safety guarantees

- Import surface: only `hashlib`, `json`, `re`, `pathlib`, `typing`
  plus a function-local lazy `ai.knowledge.store.KnowledgeStore`
  import. No `socket`/`urllib`/`requests`/`httpx`/`subprocess`, no
  `ai.llm`/provider, no Nuclei runner, no live-validation, no
  Mongo/pymongo — enforced by a dedicated test that scans top-level
  imports AND renders with `socket`/`urllib.request`/`requests`/
  `subprocess` blocked out of `sys.modules`.
- No timestamps generated at render time (verified: no
  `20xx-xx-xxT` pattern in output); stable ordering everywhere
  (sorted evidence, references by URL, KB by knowledge_id); atomic
  writes; repeated renders are byte-identical (same SHA-256 twice).
- Missing optional artifacts render as "Not available"/"Unknown";
  missing required research JSON raises `ReportError`. No findings
  created, no alerts, no verification/materialization imports.

## 6. Tests and exact counts

Focused R2 suite: `ai.test_reports_renderer` — **14 tests, all pass**
(`venv/bin/python -m unittest ai.test_reports_renderer` → `Ran 14 ...
OK`). Coverage: complete report; missing references archive;
references with/without persisted context; empty KB; populated KB
(match shown, non-match excluded); Nuclei present; Nuclei absent;
missing optional fields; byte-identical determinism; Markdown-injection
resistance; no-network/no-LLM; CLI report command; explicit `--output`;
missing CVE input (both unknown CVE and malformed id).

Regression (venv python): R2 + `test_research_cli` + `test_knowledge_store`
+ `test_xss_researcher` + `test_xss_llm_researcher` + `test_openrouter` —
**109 tests, all pass**.

Full suite `venv/bin/python -m unittest discover -s ai`: 3095 tests,
4 failures + 4 errors + 12 skipped — all pre-existing and unrelated
(loader `ImportError`s from `ai/config.py` shadowing top-level
`config.py` under `-s ai`; tests in `test_http_pinned_executor`,
`test_nuclei_cve_2026_1557_dryrun`, `test_nuclei_offline_prepare`,
`test_stage2_production_reads`). None import `ai.reports`; the change
set adds files only, so it cannot cause them. (System-python runs show
more errors from missing `pymongo`; use the project `venv/`.)

## 7. Sample output path

`ai_data/reports/CVE-2026-1557.md` (90 lines, SHA-256
`1ea6390925aaf25d522cd2bcbae633f8b4b282bff25ed53c4ccf73ac5b92d13b`
at generation time; byte-identical across consecutive renders).

## 8. Known limitations

- No `<CVE>.references.json` archive exists yet in `ai_data/research/`
  (Stage R1 writer exists; no archive has been persisted for any CVE),
  so section 3 currently renders "Not available" for real CVEs.
- The real knowledge store (`ai_data/knowledge/`) does not exist, so
  section 4 renders the empty-store state for real CVEs.
- KB "relevance" is render-time token overlap for presentation only,
  capped at 20 matches; it must not be cited as KB attribution.
- Endpoint/parameter extraction is regex over persisted prose (labeled
  "as stated in persisted research"), not a parser; single-segment
  `/word` mentions are excluded as noise.
- Pre-existing working-tree dirt NOT mine and left untouched:
  `M database/db.py` (Mongo URI/credential edit) and deleted
  `Watch_README_completed.md:Zone.Identifier`. `git diff --check`
  is clean.

## 9. Production 5B–5J / live-validation confirmation

Explicitly confirmed: production 5B–5J and controlled-live-validation
paths were untouched. `git status` shows only the three new R2 paths
(`ai/reports/`, `ai/test_reports_renderer.py`, `ai_data/reports/`);
no file under `ns/`, `crawl/`, `database/`, nuclei/CVE logic,
`ai/live_validation/`, `ai/execution/`, `ai/finding/`, or
`ai/verification/` was modified; the renderer imports none of them.
No commit, no push performed.

```
Report generated:
agent-reports/stage-r2-research-report.md
```
