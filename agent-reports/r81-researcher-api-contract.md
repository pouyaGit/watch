# R81 — Researcher API Contract

Date: 2026-09-16
Base commit: `660688c1390745a76548fdf76f6a36cbf477a95f` (R80)
Rule version: `r81-1` (API/service layer)
**REAL: persisted real case/artifact. SYNTHETIC/OFFLINE: every evidence
package used for API validation (labelled). No evidence was persisted.**

## 1. Existing API architecture inspected

- `api.py` — FastAPI entrypoint: builds the app, wires `APIKeyMiddleware`
  (X-API-Key header or `?api_key=`), mounts `/static`, includes routers from
  `backend/routers/`.
- `backend/routers/*.py` — routers declare full paths (e.g.
  `/api/research/...`), use `Depends(verify_api_key)` and `HTTPException`
  with a `detail` string; request bodies are pydantic `BaseModel`s.
- `backend/deps.py` — shared `verify_api_key` gate and pagination helpers.
- `backend/routers/research.py` — existing read-only research router (includes
  a generic `/api/research/{cve}` route).
- Tests — `from api import app` + `fastapi.testclient.TestClient` with an
  `api_key` query parameter.

R81 follows these conventions instead of creating a parallel app.

## 2. Endpoint contract

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/research/cases` | bounded research case list |
| GET | `/api/research/cases/{case_id}` | R77 workbench for one case |
| POST | `/api/research/cases/{case_id}/evidence` | R80 submission envelope |

All three are behind the existing API-key gate (`verify_api_key` +
global middleware). Registration order places the specific `/api/research/cases`
router before the generic research router so the existing
`/api/research/{cve}` route keeps working (regression-tested).

## 3. List response

`{"rule_version": "r81-1", "total": n, "items": [...]}` where each item is a
bounded summary: `case_id`, `program`, `category`, `gap_id`, `status`,
`readiness`, `decision`, `feedback`, `hypothesis_state`, `next_iteration`,
`human_review_required`, bounded `evidence` (available/missing counts and
available requirement kinds) and `missing_evidence.decision_critical`.
Artifacts are discovered read-only from `ai_data/research/*/*.json`, deduped
by `case_id` in deterministic path order, capped at 32.

## 4. Case detail response

`{"rule_version", "case_id", "program", "case_summary", "workbench", ...}`
where `workbench` is produced by calling the existing
`build_research_workbench` (R77 authority) with the artifact's stages — the
API contains no workbench logic. The response carries `current_state`,
`hypotheses`, `why_interesting`, `what_we_know`, `what_is_missing`,
`what_to_do_next`, `next_steps`, `human_review`, `conflicts`, bounded
`history`, `workflow_actions` and `safety`.

REAL validation on the Indeed artifact:

- status `WAITING_FOR_EVIDENCE`
- WHAT WE KNOW `ENDPOINT_PURPOSE`, `WATCH_SIGNAL`
- WHAT IS MISSING `METHOD_AUTH`, `RESPONSE_BEHAVIOR`
- WHAT TO DO NEXT `PROVIDE_EVIDENCE`, `CONTINUE_RESEARCH`
- `human_review` not required; conflicts 0; safety `NOT_CONFIRMED`

## 5. Evidence submission contract

POST body is exactly the R80 envelope (`submission_version`, `case_ref`,
optional `submitted_by`, `items`); no competing schema. The URL `case_id` is
the binding target: the service rejects a body whose `case_ref` differs
(HTTP 409) before R80 is invoked, and R80 independently binds against the
case's `case_id`. Accepted submissions are fully in-memory: R80 → R74 →
R75 → R76 → R77, returning bounded `submission_status`,
`accepted_external_evidence`, `rejection_codes`,
`accepted_requirement_kinds`, a `provenance` summary (state, record count,
conflict count/kinds, human-review flag), `case_summary` (R76) and the
updated R77 `workbench`. Nothing is written to Mongo or to the artifact.

## 6. Error mapping (bounded, no bodies/stack traces)

| Condition | HTTP | Detail code |
| --- | --- | --- |
| malformed request body (pydantic) | 422 | validation error |
| malformed envelope / unsupported version / no `case_ref` | 400 | `MALFORMED_ENVELOPE`, `UNSUPPORTED_SUBMISSION_VERSION`, `CASE_REF_REQUIRED` |
| unknown case | 404 | `UNKNOWN_CASE` |
| case mismatch | 409 | `CASE_MISMATCH` |
| case state unavailable | 422 | `CASE_STATE_UNAVAILABLE` |
| unknown requirement / hypothesis | 400 | `UNKNOWN_REQUIREMENT_FOR_CASE`, `HYPOTHESIS_NOT_IN_CASE` |
| submitter label not allowed | 400 | `SUBMITTER_NOT_ALLOWED` |
| sensitive evidence | 400 | `SENSITIVE_SUBMISSION_REJECTED` |
| execution content | 400 | `EXECUTION_CONTENT_REJECTED` |
| oversized submission | 413 | `SUBMISSION_TOO_LARGE` |
| unsupported source / duplicate evidence | 200 | delegated R74 codes in `rejection_codes` |
| conflicting evidence | 200 | preserved in `provenance`/`workbench.conflicts`, `resolved=false` |
| internal failure | 500 | `INTERNAL_PROCESSING_FAILURE` (no stack trace) |

`detail` stays a bounded string (`"CODE: message"`), consistent with the
existing routers' string-detail convention.

## 7. Authorization limitation

R81 invents no authentication or authorization. It reuses the existing
API-key gate (`X-API-Key` / `?api_key=`) exactly like the other routers. If
`API_KEY` is unset the app is open by design (pre-existing behavior); R81
does not add roles, identities or per-case access control. The R80
case-binding and safety boundaries remain the substantive guardrails.

## 8. R80 delegation

The API calls `submit_research_evidence` through the service; it never calls
R74 directly. A delegation test mocks the boundary and asserts the service
invokes it once with the resolved case (and that its bounded rejection code
maps to the HTTP error). R80 remains the submission authority.

## 9. R77 reuse

Case detail and post-submission workbenches are both produced by
`build_research_workbench`; a test compares the API response against a direct
R77 call from the same artifact stages (byte-identical). R77 remains the
workbench authority.

## 10. Real case validation (REAL)

`case-indeed-a1-endpoint-behavior` is served from the real R77 artifact with
`WAITING_FOR_EVIDENCE`, the expected know/missing/next values above, and
`REAL_EVIDENCE_NOT_AVAILABLE` remains the R79 status. GET requests leave the
artifact bytes untouched (tested). No real evidence was submitted or
fabricated.

## 11. Synthetic validation (SYNTHETIC/OFFLINE)

All POST tests use in-memory, `NON-REAL/OFFLINE`-labelled packages: valid
partial (→ `ACTIVE`/`PARTIALLY_SUFFICIENT`), complete (→
`READY_FOR_HUMAN_REVIEW`), duplicate (→ `PARTIAL` +
`DUPLICATE_EVIDENCE`), in-package conflict (→ `CONFLICTING` preserved,
`resolved=false`, `CONFLICT_REQUIRES_HUMAN_REVIEW`), plus the negative
matrix in §6. Nothing is persisted and no synthetic result is presented as
real.

## 12. Safety

No target interaction, no HTTP request from Watch to any target, no scanner,
no payload execution, no subprocess/shell, no Mongo writes, no LLM call. The
service module contains no write/network primitives (source-scanned).
Responses preserve `advisory=true`, `research_only=true`,
`execution_performed=false`, `vulnerability_confirmed=false`,
`exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
`human_authority_required=true`.

## 13. Tests

- `tests/test_research_cases_api.py` — **26 passed**: list shape/bounds,
  real case in list, detail R77 workbench and R77 reuse, unknown case,
  malformed body, valid/complete submissions, case mismatch, unknown
  requirement/hypothesis, sensitive (no leak) and execution rejections,
  delegated source/duplicate, preserved conflict, artifact read-only checks,
  R80 delegation mock, error hygiene, route compatibility, auth gate,
  hermetic artifact-root and skip-malformed tests, service source scan.
- `pytest tests/local_e2e -q` — **328 passed, 63 subtests**.
- Adjacent backend/API suites: `tests/test_research_api.py` **29 passed**,
  `tests/test_research_navigation.py` **14 passed**,
  `tests/test_product_api.py` passed, `tests/test_research_workflow.py`
  **32 passed** (2 subtests).
- Pre-existing environment issue (NOT an R81 regression):
  `tests/test_daily_research_workflow.py::TestBackend::test_compare_between_builds`
  hangs when run standalone (it exercises `backend.daily_research` against
  the real database and does not touch the API routers); the rest of that
  suite passes.

## 14. Implementation gaps

None blocking. Two notes:
1. No persistence layer exists for updated cases: POST results are returned
   in-memory by design (mission constraint). A future milestone could persist
   the composed envelope through the existing artifact mechanism.
2. Route ordering: the specific `/api/research/cases` router must stay
   registered before the generic `/api/research/{cve}` route; this is wired
   in `api.py` and regression-tested.

## 15. Files changed

- `backend/research_cases.py` (new service; read-only views + R80/R75/R76/R77
  composition)
- `backend/routers/research_cases.py` (new router)
- `api.py` (+2 lines: import + include_router)
- `tests/test_research_cases_api.py` (new)
- `agent-reports/r81-researcher-api-contract.md` (this report)

No research stage (R65–R80) was modified; `web/` untouched.

## 16. Commit

One local commit: `feat(api): add researcher api contract`
(hash reported in the final task response). No push.
