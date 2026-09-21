# AEC-1 Task T1 — Offline Deterministic Pilot Case Selector

**Status: READY TO PUSH** (uncommitted work in `/opt/watch/.worktrees/watch-agent`, branch workspace of `8d665b1`; production `main` untouched)

- Task: T1 — offline deterministic pilot case selector (first coding task of AEC-1)
- Plan of record: `AEC-1_IMPLEMENTATION_EXECUTION_PLAN.md` §6 (T1), `AEC-1_IMPLEMENTATION_PLAN.md` §7 (pilot selection rules + budget)
- Scope discipline: T1 only. T2 was **not** started. No live module was created.
- Input: the 144 existing research cases in `ai_data/investigations/reports/*.json` (all `WAITING_EVIDENCE`)
- Output: 11 selected cases, 133 excluded cases with explicit reasons, risk category and evidence gap for every case, plus a human approval sheet.

---

## 1. What was created

All paths relative to `/opt/watch/.worktrees/watch-agent`.

| Path | Lines | Role |
|---|---:|---|
| `tests/test_aec_selection.py` | 638 | Test-first suite (45 tests). Written and observed RED before any module existed. |
| `aec/__init__.py` | 160 | Package constants: budget limits, family caps, risk categories, output locations, capability flag `AEC_LIVE_HTTP_ENABLED = False`. |
| `aec/errors.py` | 138 | Closed exclusion-reason vocabulary + `SelectionError`. |
| `aec/models.py` | 368 | `CaseRef`, `EvidenceGap`, `SelectionDecision`, `SelectionResult`. Pure data, no I/O. |
| `aec/selection.py` | 812 | The selector, the renderer and the only writing function (`write_outputs`). |
| `ai_data/aec/scope-snapshot.json` | 27 | **Input** snapshot of in-scope / out-of-scope domains per program (read-only read of `watch.programs`). sha256 `08c1d77013136d79…`. |
| `ai_data/aec/pilot-selection.json` | — | **Output** (runtime, gitignored): full selection. sha256 `af79fa18f192206c…`. |
| `agent-reports/aec-1-pilot-selection.md` | 227 | **Output**: P1 approval sheet. sha256 `52d4cd9006a7a8c3…`. |
| `.gitignore` | +3 | Ignore the runtime selection JSON only; the input snapshot stays tracked and reviewable. |

Additive only: no existing application module was edited except the 3-line `.gitignore` addition.

## 2. What was NOT touched (verified, not assumed)

Byte-identical against production after the work (sha256 compared file by file):

`ai/execution/http_executor.py`, `ai/evidence/builder.py`, `ai/evidence/handoff.py`, `ai/verification/deterministic/gate.py`, `ai/verification/deterministic/pipeline.py`, `ai/verification/verifier.py`, `ai/verification/oracle.py`, `ai/finding/eligibility.py`, `ai/limits/ceilings.py`, `ai/authorizer/service.py`, `ai/authorizer/store.py`, `ai/schemas/execution_authorization.py`, `ai/live_validation/lane.py`, `ai/live_validation/gates.py`, `ai/live_validation/config.py`, `watch_xss_verify.py`, `backend/tasks_registry.py` — **17/17 IDENTICAL**.

- Production repo state unchanged throughout: `HEAD 4eb4c97`, 27 dirty entries (same as before T1).
- `LIVE_TRAFFIC_ENABLED = False` in `ai/execution/http_executor.py:122` (unchanged); `WATCH_AI_LIVE_VALIDATION` still unset.
- No verification gate was changed, relaxed, wrapped or enabled. No network call was made by the selector: `aec/` imports stdlib + `aec` only, and a test asserts the absence of `socket`, `ssl`, `http.client`, `urllib.request`, `subprocess`, `ai.execution`, `ai.authorizer`, `ai.evidence`, `ai.verification` — and that `aec/live_deps.py` / `aec/observation_lane.py` **do not exist**.
- Production was never written to: the pilot artifacts live in the worktree (worktree has no `venv/`, no `.env`; the pilot itself cannot run there — that is intentional).

## 3. Test-first evidence

1. Suite written first: `45 tests` covering every acceptance criterion plus the safety guards.
2. Observed RED: `ModuleNotFoundError: No module named 'aec'` — no module existed.
3. Implemented `aec/`; iterated to GREEN: `Ran 45 tests … OK` (45/45).
4. Three honest corrections while going from RED to GREEN — each one recorded because it changed either the test or the model, never the safety rule:
   - `test_non_pilot_category_is_excluded` used `/accounts/AccountProfile.aspx` and expected `CATEGORY_OUT_OF_PILOT`; the module returned `LOGIN_ENDPOINT`. **The module was right** (auth surfaces are excluded before family/category reasoning); the test fixture was wrong and was changed to a non-auth endpoint.
   - `test_family_cap_is_enforced` originally placed 14 cases on one host; the per-host ceiling (5) binds first, so it could never observe the family cap. Fixture corrected to two hosts.
   - The evidence-gap model originally inferred `present = required − missing`, which **overstated** what the corpus holds. It now reports `missing`, `not_listed_missing` (explicitly *not* a claim of existence), plus `artifacts_collected` / `artifacts_missing` taken from real artifact statuses. This matters: all 144 cases carry `RESPONSE_COMPARISON: MISSING`.
5. Regression: full worktree suite `Ran 7231 tests`. 231 failures + 107 errors exist **pre-existing** in data/UI-dependent modules (`test_asset_cve_matching`, `test_investigations_api`, `test_research_*`, `local_e2e`, …). `test_aec_selection` is not among them and **no production module imports `aec`** (only the new test file does), so T1 cannot influence them. No pre-existing failure was "fixed" to make T1 look green.

## 4. The real selection (144 cases in, 11 out)

Run: `/opt/watch/venv/bin/python3 -m aec.selection --now 2026-09-21T00:00:00Z`
Rule version `aec-selection/v1`. Byte-stable across repeated runs (two consecutive runs → identical sha256).

- Cases considered 144 → **selected 11**, excluded 133
- Hosts: **3** — `hiringlab.indeed.com` (5), `indeedflex.com` (2), `investors.delltechnologies.com` (4)
- Family usage: `IDOR_JSON_RESOURCE` 6/10, `SSRF_OEMBED` 1/6, `XSS_REFLECTED` 4/4
- Worst-case requests: 11 cases × ≤4 = **44 ≤ 60** → 16-request reserve retained

Selected:

1. `hiringlab.indeed.com` `/au/wp-json/wp/v2/pages/{id}` `?id` — IDOR, R1_OBJECT_REFERENCE
2. `hiringlab.indeed.com` `/en-ca/wp-json/wp/v2/pages/{id}` `?id`
3. `hiringlab.indeed.com` `/en-ca/wp-json/wp/v2/posts/{id}` `?id`
4. `hiringlab.indeed.com` `/fr-ca/wp-json/wp/v2/pages/{id}` `?id`
5. `hiringlab.indeed.com` `/fr/wp-json/wp/v2/pages/{id}` `?id`
6. `indeedflex.com` `/wp-json/wp/v2/faq/{id}` `?id`
7. `indeedflex.com` `/es/wp-json/oembed/1.0/embed` `?url` — SSRF, R2_SERVER_FETCH
8. `investors.delltechnologies.com` `/financial-information/sec-filings` `?q` — XSS, R3_REFLECTION
9. `investors.delltechnologies.com` `/node/{id}` `?q`
10. `investors.delltechnologies.com` `/node/{id}/ics` `?Q`
11. `investors.delltechnologies.com` `/node/{id}/pdf` `?Q`

Evidence gap: cases 1–7 need `response difference`; cases 8–11 need `encoding context`. Every collected artifact set is `HTTP_METADATA + TECHNOLOGY_CONTEXT (+ PARAMETER_BEHAVIOR where present)` with `RESPONSE_COMPARISON` still missing — i.e. the pilot's request budget is aimed exactly at the one artifact the corpus cannot produce offline. No case is anywhere near a finding: ladder stays `L0_STORED_OBSERVATION → L3_COMPARATIVE`, ceiling `POTENTIAL`.

Excluded 133, by reason:

- `LOGIN_ENDPOINT` 33 — login / account / SSO / authorization surfaces
- `CATEGORY_OUT_OF_PILOT` 34 — real cases, but outside the three pilot families
- `HOST_BUDGET_FULL` 27 — host already holds its 5-case ceiling
- `UPLOAD_CATEGORY` 16 — file-upload candidates, never in the pilot
- `AUTH_REQUIRED` 12 — session/credential-shaped parameters
- `NON_GET_METHOD` 9 — POST / PATCH / PUT candidates
- `CHALLENGE_TOKEN` 1 — bot-management token (`__cf_chl_f_tk`)
- `FAMILY_CAP_FULL` 1 — XSS family already at 4
- Zero: `BODY_REQUIRED`, `NOT_COMPARABLE`, `OUT_OF_SCOPE_HOST`, `DUPLICATE_ENDPOINT`, `HOST_SET_FULL`, `PILOT_CAP_FULL`

Two reason codes are extensions beyond the ten in the plan, both documented in `aec/errors.py`: `CATEGORY_OUT_OF_PILOT` (needed — most of the corpus is genuinely outside the pilot families) and `FAMILY_CAP_FULL` / `HOST_SET_FULL` / `PILOT_CAP_FULL` (limit enforcement). The vocabulary remains closed and every excluded case carries exactly one code.

## 5. Acceptance criteria

| Criterion | Evidence |
|---|---|
| Deterministic output | Priority key is total (family, confidence, host, endpoint, parameter, case_id); input order has no effect (2 tests); two consecutive real runs produced identical bytes. |
| ≤ 20 selected cases | 11 selected. Guarded by family caps 10/6/4 (sum = 20) **and** `max_cases`, tested independently. |
| Host limits enforced | Per-host cap 5 (test), distinct-host window 3–5 (test), 3 hosts used; `HOST_BUDGET_FULL` / `HOST_SET_FULL` recorded per case. |
| Exclusion reasons explicit | Every case has exactly one outcome (tested); closed vocabulary (tested); reason table in the JSON and in the approval sheet. |
| No writes outside allowed area | `write_outputs` is the only writer, resolves paths and refuses escapes/absolute dirs (test); AST test asserts no other function in `aec/` writes; `git status` shows only the expected 5 paths; production repo unchanged. |
| Tests pass | 45/45 OK. |
| Risk category | Assigned to all 144 cases from the case's own category (R1 object reference 63, R2 server fetch 13, R3 reflection 28, R4 content handling 16, R5 access control 24) — a class, never a severity. |
| Evidence gap | Required / missing / not-listed-missing / collected / missing artifacts, per case, honest about the missing one. |

## 6. Observations the operator should decide on

1. **Host budget starves family diversity.** `hiringlab.indeed.com` holds both the IDOR and the oEmbed candidates; the higher-priority IDOR family consumed all 5 host slots, so **all 27 remaining oEmbed cases there were excluded by `HOST_BUDGET_FULL`** and SSRF ends with a single case. Options: (a) accept 6/1/4 as approved; (b) raise the per-host ceiling (more load on one host — weakens the politeness argument); (c) add a per-host-per-family reservation, which changes the rule → `aec-selection/v2` and a fresh approval. Recommendation: (c) before P2 if family balance matters, as a reviewed v2 — **not** silently tuned now.
2. **Near-duplicates consume the XSS budget.** `/node/{id}`, `/node/{id}/ics`, `/node/{id}/pdf` are three variants of one resource and `?q`/`?Q` differ only in case; they are not exact duplicates, so `DUPLICATE_ENDPOINT` correctly does not fire. Resource-prefix clustering belongs to v2 or to the Skeptic/triage role, not to T1.
3. **3 hosts is the lower bound of the window.** If one host is refused at P2 (authorization or scope), the pilot falls below 3. Keep the selection as-is and treat P2 refusals as a reason to re-select rather than to proceed with two.
4. **Input provenance:** the scope snapshot came from a one-off **read-only** read of `watch.programs`; it is committed as input with its hash, so the selection is reproducible without any database access.
5. **Runner constraint:** the pilot cannot run from the worktree (no `venv/`, no `.env`). AEC-1's live leg will run from production under a per-run flag after the operator merges.

## 7. Reproduce

```bash
cd /opt/watch/.worktrees/watch-agent
/opt/watch/venv/bin/python3 -m unittest tests.test_aec_selection -v
/opt/watch/venv/bin/python3 -m aec.selection --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

## 8. Push

Nothing is committed. Ready to push from the worktree:

```bash
cd /opt/watch/.worktrees/watch-agent
git add aec/ tests/test_aec_selection.py ai_data/aec/ agent-reports/aec-1-pilot-selection.md agent-reports/AEC-1-T1-report.md .gitignore
git commit -m "AEC-1 T1: offline deterministic pilot case selector (aec/, 45 tests, P1 approval sheet)"
```

The operator reviews and merges; `main` is never touched by this work. **T2 was not started.**

**READY TO PUSH**
