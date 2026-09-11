# Stage R25.5 — Economic Outcome Capture

## Status
**IMPLEMENTED (append-only, research-only).** A minimal deterministic
outcome-capture layer now records what happened when a researcher acted on an
R25 economic lead. The Money Score is untouched; no calibration is performed
here — this stage only collects the data a future R25.6 calibration stage needs.

No dashboard redesign, no Money Score formula change, no R15–R24 change, no
LLM calls, no exploitation, no Nuclei/browser, no findings/alerts, no payout
prediction, no external contact, no commit/push.

## 1. Implementation summary

```
researcher action
      │
      ▼
UI form (status/time/note only) ─┐
CLI `economics outcome add` ─────┼─► backend/research_outcomes.record_outcome()
API POST /api/research/economics/outcomes ─┘        │
                                                    ▼
                        ai/schemas/research_outcome.py (validation)
                                                    │
                                                    ▼
                        ai/knowledge/research_outcomes.py (append-only JSONL)
                                                    │
                                                    ▼
        list / get / summarize_lead_outcomes / lead_performance / summarize_economic_outcomes
                                                    │
                                                    ▼
                    read-only API/CLI/UI + future R25.6 calibration input
```

- Outcome capture is content-addressed: an identical duplicate submission is
  idempotent and never appends a second line.
- Attribution is fail-closed: a lead must exist in the current R21 projection,
  so an outcome can never be attached to a fabricated CVE/program.
- The Money Score engine (`ai/knowledge/economics.py`) is not imported,
  modified, or consulted by any write path.

## 2. Files changed

New:

| File | Lines | Purpose |
|---|---:|---|
| `ai/schemas/research_outcome.py` | 197 | Outcome schema + deterministic id + whitespace normalization |
| `ai/knowledge/research_outcomes.py` | 279 | Append-only JSONL store with advisory lock |
| `backend/research_outcomes.py` | 323 | Lead attribution, record/list/get/summaries, feedback readiness |
| `tests/test_research_outcomes.py` | 804 | 64 focused offline tests |

Modified (R25.5 additions only; files also carry earlier R25.3/R25.4 wiring):

| File | R25.5 addition |
|---|---|
| `ai/research_cli.py` | `economics outcome add/list/show/summary` (~196 lines) |
| `backend/routers/research.py` | `ResearchOutcomeCreate` + POST/GET outcome routes (~87 lines) |
| `backend/routers/research_pages.py` | Lead outcome summary context + POST form handler (~54 lines) |
| `web/templates/research_lead_detail.html` | RESEARCH OUTCOMES section + manual form (~43 lines) |

Untouched: `ai/knowledge/economics.py`, all R15–R24 modules,
`database/db.py`, systemd, `.env`.

## 3. Schema (`ai/schemas/research_outcome.py`)

```
ResearchOutcome:
  outcome_id          ro-<16 hex>   (content-addressed, deterministic)
  lead_id             rl-<16 hex>   (required, validated)
  cve_id              CVE-…         (required, validated)
  program             ^[A-Za-z0-9._-]{1,128}$  (required)
  status              ACCEPTED | DUPLICATE | REJECTED | NOT_APPLICABLE |
                      WASTED_TIME | IN_PROGRESS
  timestamp           ISO-8601 metadata (assigned at first write)
  researcher_note     whitespace-normalized, <= 2000 chars
  time_spent_minutes  int, 0..100000
  source              MANUAL | IMPORT
  rule_version        fixed "r25-1"
```

Validation rules (all fail-closed):

- unknown status/source rejected; malformed `lead_id`/`cve_id`/`program`
  rejected; negative or absurd time rejected; note bounded *after*
  deterministic normalization (CRLF→LF, per-line trim, collapse blank runs).
- `model_config = ConfigDict(extra="forbid")` — unknown fields are rejected,
  so `payout_amount`, `bounty`, `verified`, `production_finding` etc. can
  never be persisted through this schema.
- `rule_version` is forced to `r25-1` regardless of input.

Deterministic id:

```
outcome_id = "ro-" + sha256(rule_version \n lead_id \n status
                            \n time_spent_minutes \n normalized_note
                            \n source)[:16]
```

`timestamp` is intentionally excluded so an identical duplicate submission maps
to the same id (idempotency). Distinct notes/times produce distinct ids.

## 4. Storage design (`ai/knowledge/research_outcomes.py`)

- **Format:** one JSONL file `ai_data/research/outcomes/outcomes.jsonl`,
  one JSON object per line. Chosen over per-record JSON files because it is
  natively append-only, needs no directory scans for histories, and still
  supports atomic single-line appends.
- **Atomic writes:** `O_APPEND | O_CREAT | O_WRONLY` + `os.fsync` under an
  exclusive `fcntl.flock` on `.outcomes.lock`, serializing
  read-check-append so concurrent writers never interleave a line.
- **Never overwrites:** no update/delete API exists; the file only grows.
  A duplicate id returns the existing record with `created=False`.
- **Fail-closed:** the full `ResearchOutcome` is validated *before* any byte
  is written; a bad record leaves the file untouched.
- **Fail-soft reads:** a malformed line (bad JSON, bad schema) is skipped and
  counted in the list response's `malformed` field; it never breaks listing,
  gets, or summaries and never fabricates a record.
- **No Mongo, no network, no subprocess, no LLM.**

## 5. API / CLI / UI

### API (`backend/routers/research.py`)

| Route | Behavior |
|---|---|
| `POST /api/research/economics/outcomes` | key-gated, validates via pydantic + domain, idempotent, returns `{created, outcome}` (201) |
| `GET /api/research/economics/outcomes` | bounded list with `limit/offset/lead_id/cve/program/status`, `malformed`, `research_only`, `rule_version` |
| `GET /api/research/economics/outcomes/{outcome_id}` | one outcome; malformed id → 400, unknown → 404 |

Declared **before** `/api/research/economics/{lead_id}` so `outcomes` is never
captured as a lead id. Errors reuse `_bad` (400) / 404 conventions; a store
`OSError` maps to 500. No execution, no worker, no external source contact.

### CLI (`ai/research_cli.py`)

```
python -m ai.research_cli economics outcome add \
  --lead-id rl-... --status ACCEPTED --time-minutes 75 --note "Validated and submitted"
python -m ai.research_cli economics outcome list [--lead-id --cve --program --status --limit --offset --json]
python -m ai.research_cli economics outcome show --outcome-id ro-... [--json]
python -m ai.research_cli economics outcome summary [--lead-id] [--json]
```

Argparse defines only lead/status/time/note/source flags; `--payout` (or any
unknown flag) exits 2. The existing `economics` Money queue command is
unchanged.

### UI (existing lead detail page only)

One compact `Research outcomes` panel: attempts, accepted, duplicate,
rejected, not applicable, wasted time, total time, data quality, latest
outcome, and a manual form containing **only** a status select, a time-minutes
number, and a note text field. POST validates and redirects (303) back to the
lead with `outcome_saved=1`; invalid input renders the existing 400 error
page. No payout fields, no charts, no polling, no new page.

## 6. Summaries / feedback readiness

`summarize_lead_outcomes(lead_id)` exposes: attempts, accepted, duplicate,
rejected, not_applicable, wasted_time, in_progress, terminal_attempts,
total_time_spent_minutes, average_time_spent_minutes (terminal outcomes only),
latest_outcome, `outcome_confidence` / `data_quality`
(`NONE` 0, `LOW` 1–2, `MEDIUM` 3–4, `HIGH` 5+ terminal outcomes),
`rule_version`, `research_only`.

`lead_performance(lead_id)` is the deterministic answer to *"How did this lead
perform historically?"* for R25.6: all of the above plus `acceptance_rate`,
`duplicate_rate`, `wasted_rate` (rounded to 4 dp, 0.0 when no terminal
outcomes). It does **not** modify or recompute the Money Score.

`summarize_economic_outcomes()` aggregates globally and returns a bounded
per-lead rollup (`leads`, max 100) plus counts, total/average time, latest
outcome and data quality.

## 7. Test counts

| Suite | Result |
|---|---|
| `tests.test_research_outcomes` (new, R25.5) | **64 tests OK** |
| `tests.test_research_economics` (R25.2 engine) | **91 tests OK** |
| `tests.test_research_economics_projection` (R25.3) | **33 tests OK** |
| `tests.test_research_economics_api` (R25.4) | **21 tests OK** |
| R21/R22 logic classes (leads + execution) | **54 tests OK** |

New-suite coverage: all six statuses; invalid status/source; malformed lead,
CVE, program; negative/absurd/non-integer time; note bounds + whitespace
normalization; unknown/payout/verdict field rejection; deterministic id and
note-normalized id; idempotent duplicate; append-only line counts; fail-closed
bad status (nothing written); malformed-line skip with `malformed` count;
list filters/limit/offset/order; get unknown/malformed; zero-summary for a
fresh store; mixed-status summary math; in-progress excluded from average;
`lead_performance` rates; global summary; API auth/validation/create/list/
detail/404/payout-rejection/route precedence; no Money Score change after
outcome capture; CLI add/list/show/summary/JSON/errors/payout-flag reject;
UI section/form/render/POST/redirect/zero state/invalid status; static
no-execution scans; formula-constant guard.

## 8. Real corpus verification

Before any record was written (verified):

```
$ python3 -m ai.research_cli economics outcome list
RESEARCH OUTCOMES: none recorded

$ python3 -m ai.research_cli economics outcome summary --lead-id rl-af7ecfba1a86fc83
Attempts: 0 | Accepted: 0 | Duplicate: 0 | Rejected: 0
Not applicable: 0 | Wasted time: 0 | Total time: 0 min | Data quality: NONE
```

Both leads (`CVE-2026-1557 → dell`, `CVE-2026-1557 → indeed`) show zero
outcomes; `ai_data/research/outcomes/` does not exist and was not created by
any read. **No outcome was fabricated.** The R25.3 Money queue still reports
`53 / P3_MEDIUM` for both leads.

## 9. Safety verification

- `research_only: true` on every list/summary/performance projection.
- No `production_finding` field exists anywhere in the outcome schema or
  responses (asserted by test).
- No payout/bounty/reward/amount fields exist in the model, the API body, the
  CLI parser, or the form; unknown/payout keys are rejected (422 at the API,
  SystemExit 2 at the CLI).
- No execution path: new modules import no `subprocess`/`socket`/
  `requests`/`httpx`/LLM/Nuclei/browser symbols (static scan on executable
  tokens); the POST handler calls only the append-only store.
- No external network, no LLM, no Mongo; storage is a local JSONL file.
- No R15–R24 modification; `git diff` shows only the R25 presentation files.
- No Money Score formula change: the four `MONEY_W_*` weights and
  `RULE_VERSION = "r25-1"` are asserted unchanged, and an API test confirms
  `build_economics()` is byte-identical before/after an outcome POST.
- All write tests use temporary directories; the real corpus directory is
  untouched. `git diff --check` clean. No commit/push performed.

## 10. Limitations

- **Identical outcomes collapse.** Because the id is content-addressed, two
  genuinely separate attempts with the same status/time/note/source are one
  record. Distinct attempts must differ in note or time; this is the price of
  idempotent duplicate submission.
- **Lead must currently exist.** Attribution resolves through the R21
  snapshot; historical/imported leads no longer in the snapshot are rejected
  (`IMPORT` source does not bypass this yet).
- **Timestamp is first-write metadata** and is excluded from the id, so
  duplicate submissions keep the original timestamp.
- **No edits/deletes** (append-only by design); corrections are new records.
- Summaries read the full JSONL internally (accurate but O(file)); list
  endpoints are capped at 100. Acceptable at current volume.
- **No calibration yet** — outcomes are collected but not used; Money Score
  intentionally unchanged. Rates are only as meaningful as the number of
  terminal outcomes (`data_quality` conveys that).
- UI records are always `source=MANUAL`; `IMPORT` is API/CLI-only.

## 11. Exact next-stage recommendation

**R25.6 — Outcome-Calibrated Money Score (design first, change only with
evidence).** Use `backend.research_outcomes.lead_performance()`:

1. Build an offline, read-only calibration report (score band × terminal
   outcome class, acceptance/duplicate/wasted rates, time spent) and require a
   minimum sample per band before proposing any weight change.
2. If a change is justified, bump `rule_version` (r25-2) and keep the old
   formula reproducible; never silently mutate `r25-1` weights.
3. Expose the calibration report read-only (CLI/API) before it feeds back into
   scoring; no automatic self-tuning.
4. Keep the same boundaries: no LLM in calibration, no payout prediction, no
   execution, no R15–R24 changes.

## Agent / Model
- Model: Miuz Spark (opencode-go/deepseek-v4.1-flash)
- Stage: R25.5
- Role: Economic Outcome Capture
