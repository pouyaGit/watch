# R65 — Evidence-Grounded Security Research

- **Date:** 2026-09-15
- **Repository:** `/opt/watch`
- **Parent HEAD:** `2f9b6f7` (R64 first real security research run)
- **Task type:** Additive hardening of the R64 research logic only. No provider,
  orchestration, database or R61/R62/R63 change. No push.
- **No new real LLM run was performed in this task.** The real provider remains
  explicitly opt-in.

---

## 1. Exact Problem Found in R64

Audit of the first real persisted result
(`ai_data/research/r64/r64-indeed-2ea29240244dcf5b.json`) showed the model can
present generic security knowledge and name-based inference as if it were
observed evidence:

| Old hypothesis | Problem |
|---|---|
| `{id}` → IDOR | Structural basis real, but HIGH confidence/priority from a path pattern + a derived signal. |
| `continue` → open redirect | Mechanism, `/auth` association and MEDIUM confidence inferred from a parameter name. |
| `sid` → JWT | Category and session-fixation mechanism inferred from a name; no token/algorithm evidence. |
| `/weird` → debug/deprecated | MEDIUM/MEDIUM from an unusual endpoint name; interpretive claims listed as observations. |
| `client`/`co` → SSRF | Correctly conditional — the desired behavior to preserve. |
| versions → CVE research | Hedged and LOW/UNKNOWN, but echoed a spurious version (`3` from `HTTP/3`). |

Root cause: `supporting_observations` accepted arbitrary model text; nothing
required observations to exist in the context, and derived Watch signals could
be listed alongside raw facts as if independent.

---

## 2. Evidence Model

`tests/local_e2e/r64_research.py` now emits and validates this hypothesis
contract (rule version `r65-1`):

```json
{
  "title": "...", "category": "...", "priority": "...", "confidence": "...",
  "evidence": {
    "observations": [
      {"ref": "path:/notifications/api/{id}/getNotificationsCount",
       "fact": "observed path /notifications/api/{id}/getNotificationsCount",
       "source": "context"}
    ],
    "derived_signals": [
      {"signal": "IDOR", "detail": "object_reference=PATH_PARAMETER",
       "source": "watch_derived"}
    ]
  },
  "inference": "...",
  "why_interesting": "...",
  "missing_evidence": ["..."],
  "next_safe_action": "..."
}
```

Raw `supporting_observations` is gone; the parser projects only the new shape
(unknown extra keys cannot leak into the result). The prompt explains the
distinction between observation, derived signal, inference, hypothesis,
evidence needed, and confirmed vulnerability (never allowed).

---

## 3. Observation Grounding

- `evidence_index(research_context, intelligence_context)` builds canonical
  observation references from the bounded contexts only:
  `program:<p>`, `snapshot:<rule>`, `path:<p>`, `parameter:<p>`,
  `technology:<t>`, `version:<v>`, `record:<record_ref>`.
- The exact ref list is included in the prompt data as
  `available_observation_refs` (prompt budget unchanged: 12,000 chars; fixture
  yields 33 refs).
- The validator requires for every observation:
  - `ref` present in the index (exact match, no semantic similarity);
  - `source == "context"`;
  - `fact` matching the canonical fact for the ref (normalized comparison;
    the bare value is also accepted);
  - no `signal:` refs (signals must be declared as derived).
- Consequences: `"The continue parameter is definitely an open redirect"`,
  `"sid is a JWT"` and `"/weird is a debug endpoint"` can no longer be
  submitted as observations — they fail with `MODEL_OUTPUT_UNGROUNDED`.
- Every emitted observation is therefore traceable to the actual context.

---

## 4. Derived-Signal Separation

- Derived signals live only under `evidence.derived_signals` with
  `source == "watch_derived"`.
- The signal category must exist in `intelligence_context.specialist_signals`
  and, when a detail is given, it must exactly match one of the context's
  `key=value` pairs (e.g. `object_reference=PATH_PARAMETER`,
  `api_type=REST`).
- Signal refs in the observation list are rejected, so `path {id}` and the
  `IDOR/PATH_PARAMETER` classification cannot be counted as two independent
  raw observations; the relatedness is explicit.

---

## 5. Category-Specific Validation

Enforced before any hypothesis is accepted:

| Category | Requirement |
|---|---|
| IDOR | object-reference path observation (`{id}`/`{uuid}`/`{hash}`) AND (IDOR signal or parameter observation) |
| JWT | token/algorithm observation kinds or a JWT signal (absent in current contexts → rejected) |
| XSS / SQLI | their Watch-derived signal (absent in current contexts → rejected) |
| SSRF | SSRF signal or URL/host evidence; otherwise only explicitly conditional wording and LOW/UNKNOWN confidence |
| CVE_RESEARCH | at least one technology AND one version observation; CVE ids only from the context (unchanged) |
| RECON | at least one grounded observation (structural surface) |
| redirect topic | observed redirect/location evidence required; a parameter name is not enough |
| session topic | observed session/cookie/token evidence required; a parameter name is not enough |

---

## 6. Confidence / Priority Hardening

Small deterministic rules, no numeric scoring:

- Confidence vocabulary unchanged: `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
- Base cap: `MEDIUM` for structural observations; `HIGH` only with a
  corroborating non-structural ref kind (response/authorization/redirect/
  session/token/algorithm/header/error/status — none exist in current bounded
  contexts, so HIGH is unreachable today by design).
- Caps: parameter-only support → `LOW`; debug/deprecated topic → `LOW`;
  conditional-only SSRF → `LOW`.
- Priority: `HIGH` requires confidence `HIGH`; `MEDIUM` requires at least
  `MEDIUM`; `LOW` any.
- Declared confidence above the cap, or priority above the declared
  confidence, fails closed with `MODEL_OUTPUT_UNGROUNDED`.
- The prompt instructs the model to prefer lower confidence and fewer
  hypotheses when evidence is weak.

Result: `{id}` → IDOR can pass at MEDIUM but not HIGH; `continue` → redirect
and `sid` → JWT cannot pass at all; `/weird` can pass as a LOW RECON note about
an endpoint with unknown purpose; conditional SSRF passes at LOW.

---

## 7. Vulnerability-Claim Hardening

Added to the existing confirmation/execution patterns:

- unconditional terms: `vulnerable`, `exploitable` rejected unless a
  conditional marker (`may`, `might`, `could`, `possibly`, `potentially`,
  `whether`, `if`, `appears`, `suggests`, `unclear`, `unknown`, `not`,
  `no evidence`, `not observed`) appears in a bounded window around them;
- unconditional phrases rejected: `can be exploited`, `allows an attacker`,
  `allow an attacker`, `permits an attacker`, `leads to exploitation`,
  `allows exploitation`.

`"may be vulnerable"` and `"could be exploited"` pass; `"is vulnerable to"`,
`"can be exploited"` and `"allows an attacker"` fail closed. All previous
confirmation/execution-pattern and truthy-flag checks remain.

---

## 8. Regression Tests

New/updated focused tests in `tests/local_e2e/test_r64_research.py`:

- observation grounding: unknown ref, fact/ref mismatch, signal-as-observation,
  wrong source, missing observations; the three mandated cases
  (`continue` open redirect, `sid` JWT, `/weird` debug endpoint as observations);
- derived signals: valid accepted, unknown signal, wrong source, bad detail;
- categories: JWT without evidence rejected; IDOR object-ref required;
  conditional SSRF accepted, unconditional SSRF rejected; redirect/session
  from parameter names rejected; unusual endpoint allowed at LOW; CVE requires
  technology+version (and invented CVE ids still rejected);
- strength: IDOR HIGH rejected / MEDIUM accepted; parameter-only support does
  not reach MEDIUM; HIGH priority without HIGH confidence rejected; MEDIUM
  priority requires MEDIUM confidence;
- claims: unconditional variants rejected, conditional wording accepted,
  confirmation/execution/truthy-flag/URL/CVE checks preserved;
- schema/malformed: missing evidence block, malformed responses, oversized
  response/list/summary, unsupported enums, code fences;
- historical R64 artifact (read-only, historical evidence): the named
  problematic statements are classified `UNGROUNDED` / `DERIVED_SIGNAL`, the
  old research block is rejected by the new schema, and the old artifact still
  uses the old shape (not presented as R65 output). The artifact test skips
  when the gitignored local file is absent.
- safety/determinism/persistence/hygiene/provider-gate/CLI-preflight tests
  updated to the new schema.

---

## 9. Test Counts

```text
./venv/bin/python -m pytest tests/local_e2e/test_r64_research.py -q -p no:cacheprovider
65 passed, 26 subtests passed in 3.10s

./venv/bin/python -m pytest tests/local_e2e -q -p no:cacheprovider
207 passed, 52 subtests passed in 4.35s

python -m unittest ai.test_openrouter ................................... 33 OK
pytest tests/test_security_research_workflow.py \
       tests/test_bug_bounty_copilot.py \
       tests/test_bug_bounty_copilot_safety.py .......................... 142 passed
pytest tests/test_hunt_priority.py tests/test_component_plugin_wiring.py 60 passed
```

All tests are offline; no fake provider outside tests; no live Mongo tests.

---

## 10. Real Provider / Mongo

- **Real OpenRouter was NOT used in this task.** No live provider call was
  made; the real path is still opt-in via `WATCH_R64_LIVE=1` and is unchanged.
  No new real research artifact was produced.
- **MongoDB was not accessed.** Fixture-only, in-memory.
- The historical artifact was opened read-only and is unchanged
  (`ai_data/research/r64/r64-indeed-2ea29240244dcf5b.json`, 7462 bytes).

Manual command for the next real run (same as before):

```bash
WATCH_R64_LIVE=1 ./venv/bin/python -m tests.local_e2e.r64_research \
    --source fixture --program indeed
```

---

## 11. Files Changed

Modified:

- `tests/local_e2e/r64_research.py` — evidence schema, prompt, grounding,
  derived-signal separation, category rules, confidence/priority caps,
  unconditional-claim hardening, CLI rendering (rule version `r65-1`).
- `tests/local_e2e/test_r64_research.py` — tests updated to the R65 schema.

Created:

- `agent-reports/r65-evidence-grounded-research.md`.

Untouched: R59/R60/R61/R62/R63, `backend/`, `ai/`, `database/`, `crawl/`,
`ns/`, provider layer, persisted R64 artifact, `utils.zip`, `watch.zip`,
`install.sh`, older audit reports.

---

## 12. Safety Status

`safety` block unchanged and asserted: `advisory=true`, `research_only=true`,
`execution_performed=false`, `vulnerability_confirmed=false`,
`exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
`human_authority_required=true`. No target activity; no Mongo; no network; no
secrets in output; bounded contexts and prompt unchanged in bounds.

---

## 13. Git Status

Before commit:

```text
$ git status --short
 M tests/local_e2e/r64_research.py
 M tests/local_e2e/test_r64_research.py
 D utils.zip
?? watch.zip
?? install.sh
?? agent-reports/... (older reports)
```

`utils.zip`, `watch.zip`, `install.sh` and the older reports are not staged.

---

## 14. Commit

One local commit with only the intended R65 files:

- message: `feat(ai): add evidence-grounded research validation`
- hash: reported in the final task response.

No push.
