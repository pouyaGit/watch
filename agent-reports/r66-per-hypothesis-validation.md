# R66 Per-Hypothesis Validation — Implementation and Run Report

Milestone: R66 (per-hypothesis validation / partial acceptance) on top of the
R65 evidence-grounded pipeline and the first real R65 run findings.
Base commit: `fe6fd978ac098e699cefa5de37913cf1ecb49d0c`.
No push. No Mongo. No architecture redesign.

---

## 1. Exact implementation change

Files changed:

- `tests/local_e2e/r64_research.py` (rule version `r65-1` -> `r66-1`)
- `tests/local_e2e/test_r64_research.py` (regression + safety tests)
- `agent-reports/r66-per-hypothesis-validation.md` (this report)

What changed in the runner:

- `RULE_VERSION = "r66-1"`; added status constants
  (`COMPLETED`, `COMPLETED_WITH_REJECTIONS`, `ERROR`, `SUCCESS_STATUSES`).
- New hypothesis-level rejection codes (reusing the project vocabulary):
  `MODEL_OUTPUT_UNSUPPORTED_CATEGORY`, `MODEL_OUTPUT_CONFIDENCE_TOO_HIGH`,
  `MODEL_OUTPUT_PRIORITY_TOO_HIGH`, `MODEL_OUTPUT_UNSAFE_CLAIM`; the existing
  `MODEL_OUTPUT_UNGROUNDED`, `MODEL_OUTPUT_INVALID`, `MODEL_OUTPUT_TOO_LARGE`
  remain the other hypothesis codes.
- New `_validate_hypothesis(...)`: runs the **existing R65 validation
  functions** (observation grounding, derived-signal checks, category
  grounding, strength caps, bounded text/list, unsafe-claim scan, CVE
  invention) for one hypothesis and raises a `ResearchRunError` with a
  hypothesis-level code on failure. No validation logic was duplicated.
- `_validate_strength` now distinguishes confidence-cap failures
  (`MODEL_OUTPUT_CONFIDENCE_TOO_HIGH`) from priority failures
  (`MODEL_OUTPUT_PRIORITY_TOO_HIGH`); the two checks themselves are unchanged.
- New `_rejection_record(...)` + `_safe_rejection_title(...)`: safe,
  bounded metadata only (`index`, optional safe `title`, `code`, `reason`).
- New `_scan_envelope_unsafe_claims(...)`: the global unsafe scan now runs on
  everything **outside** `hypotheses`; each hypothesis is scanned in isolation.
- `parse_research_response(...)` now validates hypotheses independently,
  collects `accepted` and `rejections`, raises when zero hypotheses survive,
  and returns the accepted research plus a `validation` metadata block.
- `run_research(...)` adds the top-level `validation` block and selects
  `COMPLETED` / `COMPLETED_WITH_REJECTIONS`.
- `_print_result(...)` prints a safe `VALIDATION` section and treats both
  success statuses as success; `main()` persists both success statuses and
  returns exit code 0 for both.
- `persist_result(...)` is unchanged: it persists the envelope, which now
  contains only accepted hypotheses, safe validation/rejection metadata, and
  the safety block.

Envelope extension (top-level, sibling of `research`):

```json
"validation": {
  "accepted_count": 2,
  "rejected_count": 1,
  "rejections": [
    {"index": 1, "title": "...", "code": "MODEL_OUTPUT_CONFIDENCE_TOO_HIGH",
     "reason": "confidence exceeds what the grounded evidence supports"}
  ]
}
```

`index` is the 0-based position of the hypothesis in the model response.

## 2. Global vs hypothesis-level validation

Global (whole response, still fails closed -> `ERROR`):

- malformed JSON / non-object / oversized response;
- top-level schema: missing/empty `summary`, bad `attack_surface`,
  `hypotheses` not a list or above `MAX_HYPOTHESES`;
- unsafe envelope: confirmation/execution language, forbidden truthy keys,
  `confirmation_state` other than `NOT_CONFIRMED`, raw URLs, Mongo ids,
  credentials-like strings in everything outside `hypotheses`;
- invented CVE in `summary` / `attack_surface` (data-hygiene failure);
- zero surviving hypotheses after hypothesis validation.

Hypothesis-level (rejects that hypothesis only):

- schema/enums (`MODEL_OUTPUT_INVALID`, `MODEL_OUTPUT_UNSUPPORTED_CATEGORY`);
- observation grounding, derived-signal grounding, category evidence
  (`MODEL_OUTPUT_UNGROUNDED`);
- confidence cap (`MODEL_OUTPUT_CONFIDENCE_TOO_HIGH`), priority vs confidence
  (`MODEL_OUTPUT_PRIORITY_TOO_HIGH`);
- unsafe/unsupported hypothesis claims, raw URLs/Mongo ids, invented CVE
  (`MODEL_OUTPUT_UNSAFE_CLAIM`).

No R65 rule was weakened or removed: same grounding index, same signal index,
same category rules, same confidence caps, same conditional-claim enforcement.

## 3. Partial-completion semantics

- `COMPLETED` — every hypothesis accepted (`rejected_count == 0`).
- `COMPLETED_WITH_REJECTIONS` — at least one accepted and at least one
  rejected.
- `ERROR` — global failure or zero accepted hypotheses. When all hypotheses
  are rejected, the envelope error code is the first rejection's coarse
  category (`UNSUPPORTED_CATEGORY` -> `MODEL_OUTPUT_INVALID`,
  `CONFIDENCE_TOO_HIGH`/`PRIORITY_TOO_HIGH` -> `MODEL_OUTPUT_UNGROUNDED`,
  `UNSAFE_CLAIM` -> `MODEL_OUTPUT_UNSAFE`), so existing callers keep the R65
  error contract.
- A model response with an empty `hypotheses` list remains `COMPLETED` with an
  empty accepted list (pre-existing behavior, covered by the existing test
  `test_empty_context_runs_safely`); the rule in this milestone targets
  "nothing survived validation", not "model proposed nothing".
- Persistence: both success statuses persist; rejected hypothesis bodies, raw
  model output, unpaid strings, credentials, URLs, IPs and Mongo ids are never
  persisted. Rejection titles are emitted only when they pass the same safety
  scan (otherwise the field is `""`).

## 4. R65 regression result (the captured real response)

The exact R65 captured model response (real provider, request
`gen-1789478857-XbfcaQq1DuVCCP6by0Kn`) is embedded in the test suite as
`R65_CAPTURED_RESPONSE` and is content-identical to the capture.

- H1 IDOR MEDIUM/MEDIUM — grounded observation + `watch_derived` IDOR signal
  -> **ACCEPT**
- H2 RECON LOW priority / HIGH confidence from structural-only evidence
  -> **REJECT** (`MODEL_OUTPUT_CONFIDENCE_TOO_HIGH`)
- H3 CVE_RESEARCH LOW/UNKNOWN, technology + version observations -> **ACCEPT**

Result: `COMPLETED_WITH_REJECTIONS`, `accepted_count = 2`,
`rejected_count = 1`, rejection `index = 1`, rejected body absent from the
result and from the persisted file. The R65 confidence cap that rejected H2
was not modified.

## 5. Test counts

- Focused: `tests/local_e2e/test_r64_research.py` — **78 passed, 37 subtests**
  (was 65; 13 new regression tests).
- Full local suite: `./venv/bin/python -m pytest tests/local_e2e -q
  -p no:cacheprovider` — **220 passed, 63 subtests**.
- Relevant adjacent pure suites (`ai/test_openrouter.py`, `ai/test_llm.py`,
  `tests/test_research_priority.py`,
  `tests/test_evidence_confidence_aggregator.py`) — **162 passed**.

New coverage includes all 15 required safety regressions: one invalid
hypothesis does not kill valid ones; rejected hypothesis absent from persisted
research; safe minimal rejection metadata; two valid + one invalid; all invalid
-> ERROR; malformed top-level -> ERROR; global unsafe -> ERROR; global
data-hygiene -> ERROR; each R65 rule still enforced; deterministic ordering of
accepted list and rejection records; no raw model output persisted; historical
R64 artifact untouched.

## 6. Real OpenRouter run

One real provider call (fixture source, bounded sample):

| Item | Value |
| --- | --- |
| Provider | `openrouter` (real configured provider; no fake) |
| Model | `nvidia/nemotron-3-ultra-550b-a55b:free` |
| Request id | `gen-1789480494-jbQbUL3TlzrjLavz7YfH` |
| Status | **`COMPLETED_WITH_REJECTIONS`** |
| Artifact | `ai_data/research/r66/r64-indeed-2ea29240244dcf5b.json` |
| Accepted | 2 |
| Rejected | 1 |

Accepted hypotheses:

1. IDOR — "Potential IDOR on notifications count endpoint via path parameter",
   priority MEDIUM / confidence MEDIUM; observation
   `path:/notifications/api/{id}/getNotificationsCount`; derived signal
   `IDOR object_reference=PATH_PARAMETER`.
2. CVE_RESEARCH — "Technology stack version exposure for CVE research",
   priority LOW / confidence LOW; observations `technology:nginx`,
   `technology:jQuery`, `version:1.24.0`, `version:3.5.1`.

Rejected hypothesis (metadata only; body not persisted):

- index 1, title "REST API structure reconnaissance",
  code `MODEL_OUTPUT_CONFIDENCE_TOO_HIGH`, reason "confidence exceeds what the
  grounded evidence supports". Cause: the hypothesis discussed `/weird` as
  possibly "non-standard or legacy endpoints", so the unchanged R65
  debug/legacy topic cap applies (LOW) while it stated MEDIUM.

Runtime note: the free model again exceeded the provider's fixed 60s timeout,
so the run used the prior runtime-only accommodation — the same module
`main()`, same args, same real provider, client timeout raised to 900s via a
temporary `/tmp/opencode/r66_live_run.py` wrapper (no repository timeout
change). One provider call was made; the raw response is preserved at
`/tmp/opencode/r66_raw_model_output.txt` for audit and is free of URLs, IPs,
Mongo ids, and CVE ids. Persistence was directed to `ai_data/research/r66/`
because the default path would overwrite the historical R64 artifact.

## 7. Mongo

**NOT accessed.** No `--source mongo`, no real MongoDB query; the fixture path
uses the in-memory `tests.local_e2e.fake_mongo` client only.

## 8. Safety status

Envelope safety block: `advisory=true`, `research_only=true`,
`execution_performed=false`, `vulnerability_confirmed=false`,
`exploit_authorized=false`, `human_authority_required=true`,
`confirmation_state=NOT_CONFIRMED`. Input hygiene all false; artifact contains
no raw URLs, IPs, Mongo ids, credentials, or invented CVEs; the rejected
hypothesis body is absent from the artifact and from the CLI output.

## 9. Git status

Before commit:

```text
 M tests/local_e2e/r64_research.py
 M tests/local_e2e/test_r64_research.py
 D utils.zip
?? watch.zip
?? install.sh
?? agent-reports/... (older reports, untracked)
```

`utils.zip`, `watch.zip`, `install.sh`, and the older reports are pre-existing
worktree entries and are **not** staged. Historical R64 artifact SHA-256
`055335aad86dda872eb59b11229146ef2b3ad3d67a3eb7e152f4cc6496651191` verified
unchanged after the run.

## 10. Commit

One local commit with only the intended R66 files:

- message: `feat(ai): add per-hypothesis research validation`
- hash: reported in the final task response.

No push.
