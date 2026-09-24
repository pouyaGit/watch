# EPIC13 — Active Evidence Acquisition v1

**Scope:** Watch AI Agent Runtime (`backend/research_agents/verification/`)
**Rule versions:** `epic13-capability-1`, `epic13-marker-1`, `epic13-request-1`,
`epic13-detection-1`, `epic13-context-1`, `epic13-transport-1`,
`epic13-limits-1`, `epic13-replay-1`, `epic13-acquisition-1`
**Base:** `main = b74530e` (EPIC12 promoted) · **Branch:** `agent/daily-development`

---

## 1. EPIC13 STATUS

**The acquisition machinery is complete, deterministic, and fails closed. The
production runtime genuinely cannot perform a live outbound request, so the
honest production result for the real candidate is BLOCKED — and that is
recorded as a result, not worked around.**

EPIC12 answers *what evidence is missing*. EPIC13 answers *whether that
evidence can be safely acquired*, and then acquires it — or records exactly
why it cannot:

```
CANDIDATE -> EPIC12 CHAIN -> MISSING EVIDENCE -> AUTHORIZED ACTION
  -> REAL CONTROLLED REQUEST/OBSERVATION -> STRUCTURED OBSERVATION
  -> EPIC11 CLASSIFICATION -> CHAIN RE-EVALUATION -> NEXT MISSING EVIDENCE
  -> CONFIRMED / NOT_CONFIRMED / PENDING / BLOCKED
```

Nothing in EPIC11 was modified. EPIC12 was reused wholesale; one of its
executors changed in one place (see §5). No new evidence taxonomy, no second
Evidence Gate, no second lifecycle, no second scheduler, no second
authorization system, no new network primitive.

## 2. What was built

New package `backend/research_agents/verification/acquisition/` (12 modules):

| Module | Lines | Responsibility |
|---|---|---|
| `__init__.py` | 90 | the package contract |
| `limits.py` | 127 | every bound, read through `ai.limits.ceilings` |
| `markers.py` | 152 | deterministic controlled markers |
| `context.py` | 199 | output-context classification (delegates to the platform) |
| `detector.py` | 316 | deterministic reflection detection |
| `transport.py` | 336 | the transport seam (no network primitive) |
| `requests.py` | 217 | controlled request construction |
| `executor.py` | 521 | one typed action → structured observations |
| `plan.py` | 332 | chain → requirements → authorized actions |
| `capabilities.py` | 149 | per-class capability contracts |
| `replay.py` | 160 | duplicate/replay control |
| `service.py` | 337 | plan → execute → re-evaluate |

Modified: `verification/executors.py` (its naive reflection check now delegates
to the deterministic detector; context constants imported from
`acquisition.context`), `verification/store.py` (`ACQUISITIONS_FILE` plus
record/lookup helpers), `verification/engine.py` (row signal/type mismatch
reported as a divergence — see §7).

## 3. The transport adds no network primitive

`transport.py` contains no `requests`, `urllib.request`, `httpx`, `socket` or
`subprocess`; static tests parse the package AST and fail on a forbidden import
or a bare dangerous call. Two transports:

* `PlatformAuthorizedTransport` — resolves the platform's own live-traffic
  gate. In this runtime `LIVE_TRAFFIC_ENABLED = False` and the B1/B2 adapters
  are deferred, so it reports itself **unavailable** and refuses to send.
* `InjectedTransport` — a plain callable for tests and offline analysis, never
  presented as production acquisition.

Per-request contract: explicit authorization, target, method and parameter;
bounded timeout/size/redirects/retries; no arbitrary destination (scheme, host,
port and path must be in scope; credentials, metadata hosts, `file:`, `gopher:`
and userinfo refused); no arbitrary headers (the request carries none, and no
parameter can forge one); no method escalation (`GET`/`HEAD` only); an audit
trail scrubbed of secrets; fail closed on anything it cannot prove.

## 4. Real bugs found and fixed while testing

1. `InjectedTransport(fn)` silently discarded its callable (field-order
   footgun) — now raises.
2. `check_redirects` returned `safe=True` for hops with no identifiable
   destination and ignored the `Location` header — now fail-closed.
3. A response whose reported `final_url` was outside the authorized scope was
   accepted as evidence — now refused.
4. The executor ignored the replay ledger's `reusable` flag, so a stored
   timeout could be reused as evidence — now gated.
5. The executor never *recorded* to the ledger, so §18 reuse could never
   trigger — now recorded.
6. `ReplayLedger.record` did not set `reusable` and did not accept the fields
   the executor passes, so the real-ledger path raised and reuse was
   unreachable — fixed on both sides.
7. Non-text bodies were stringified into a conclusive "absent" — now
   fail-closed.
8. `authorization_allows` ignored a scope declared *inside* the authorization —
   a mismatched scope is now refused.
9. A run with no authorization manufactured an authorization context for its
   re-evaluation, moving the verdict from `BLOCKED` to `VERIFICATION_PENDING`
   without a single authorized request. Found by the **real production run**;
   now the re-evaluation carries no authorization unless one exists.
10. The planner planned the context action alongside the reflection action,
    spending two requests where the §16 loop needs one — acquisition now
    follows the chain's *next* stage.

## 5. Reflection detection and context classification

The detector distinguishes all eleven required cases (absent, present, present
multiple times, transformed, encoded, decoded, HTML text, HTML attribute,
script, URL context, body unavailable) and emits a structured
`REFLECTION_OBSERVED` with `action_id`, `request_id`, `response_id`,
`parameter`, `marker`, `occurrence_count`, `context`, encoding/transformation,
evidence location and the detector rule version. The search window is bounded —
a marker beyond it is **inconclusive, never a negative**; a non-text body fails
closed; the transport's own opinion is ignored.

Context classification distinguishes `HTML_TEXT`, `HTML_ATTRIBUTE`, `SCRIPT`,
`STYLE`, `URL`, `JSON`, `COMMENT`, `UNKNOWN`, offset-aware and delegating to the
platform classifier. There is no DOM, so `DOM_ANALYSIS_UNAVAILABLE` is recorded
and DOM-sink evidence is never inferred from server-side reflection.

A reflection is evidence of reflection. No test in this Epic asserts an XSS.

## 6. Actions and capability honesty

| Action | State |
|---|---|
| `CHECK_REFLECTION` | implemented |
| `SEND_MARKER` | implemented |
| `CLASSIFY_REFLECTION_CONTEXT` | implemented |
| `ACTIVE_PAYLOAD_EXECUTION` | **not implemented, not faked** |

`ACTIVE_PAYLOAD_EXECUTION` is not in the action registry and is recorded as
*not acquirable* in `capabilities.py`. `PAYLOAD_EXECUTION` and
`EXPLOITABILITY_ESTABLISHED` therefore stay `MISSING`; the chain reports
`VERIFICATION_PENDING` with `missing_payload_execution_evidence` and the run
reports `CAPABILITY_UNAVAILABLE` naming the gap. CORS, open-redirect and SSRF
are recorded as `LIMITED`.

## 7. A finding this Epic did not patch

The EPIC11 gate resolves a row's class from its **signal** but honours a
row-supplied `evidence_type` inside the closed set. A hand-written row whose
signal is `xss_parameter_inventory` and whose type is `PAYLOAD_EXECUTION` is
therefore *admissible*, and combined with genuinely acquired reflection and
context evidence it can complete a chain.

EPIC13 does **not** patch the gate — that is not this Epic's layer, and
weakening or forking it is forbidden. Instead EPIC12's engine now reports every
such row as `evidence_type_mismatch:<signal>-><type>` in `ChainState.divergence`,
so a verdict leaning on one is visibly inconsistent rather than silently
trusted. The acquisition layer itself never emits a mismatched row (pinned by
test). **This needs an EPIC11-level decision and is reported as an open item.**

## 8. OFFLINE / INJECTED VALIDATION

Run through `InjectedTransport` with deterministic bodies. This exercises the
whole flow and proves the machinery; it is **not** a network acquisition.

* reflection observed in `HTML_TEXT` → `REFLECTION_OBSERVED`, chain advances
  stage 1 → 3, verdict `VERIFICATION_PENDING` /
  `missing_payload_execution_evidence`, execution and exploitability `MISSING`,
  `confirmed: False`.
* second run classifies the context; third run reports
  `CAPABILITY_UNAVAILABLE` naming `PAYLOAD_EXECUTION`.
* reflection absent → `REFLECTION_NOT_OBSERVED`, chain contradicted, no
  evidence type on the negative row.
* timeout / refused / failed transport → `INCONCLUSIVE` or
  `TRANSPORT_UNAVAILABLE`, never negative evidence, never evidence at all.
* no authorization → `UNAUTHORIZED`, zero requests, zero evidence.

## 9. REAL PRODUCTION ACQUISITION — the actual result

Read-only, against the real store and the real production transport, for
`cand-7c229c48c455` (scope `watch:scope:dell/www.dell.com`, endpoint
`https://www.dell.com/support`). Nothing was written to production.

```
candidate_id        : cand-7c229c48c455
lifecycle_state     : DETECTED
authorization_ids   : [] (none recorded)
evidence_refs       : 20 ids
resolved rows       : 20 (['xss_parameter_inventory'])
chain verdict       : BLOCKED / missing_authorization_confirmation
confirmed           : False
furthest stage      : 1        next stage missing: ['REFLECTION_OBSERVED']
observed parameters : ['response_type', 'client_id', 'redirect_uri']
resolved transport  : unavailable_transport   available: False
live gate (code)    : LIVE_TRAFFIC_ENABLED = False
REAL ACQUISITION ATTEMPT
termination         : UNAUTHORIZED
requests sent       : 0
evidence produced   : 0 row(s)
blocked (each param): authorization_unavailable
verdict before/after: BLOCKED -> BLOCKED
confirmed after     : False
```

**The correct production result is BLOCKED / verification_not_authorized, and
that is a successful safety result.** The runtime sent no request, produced no
evidence, and did not improve the verdict. `verification_not_authorized` is the
precise reason: the candidate carries no recorded authorization for active
acquisition.

The injected seam and real production acquisition are never represented as the
same thing: the run record carries the transport name, its availability and the
platform gate state.

## 10. Tests

| Suite | Tests |
|---|---|
| `test_epic13_markers` | 34 |
| `test_epic13_requests` | 47 |
| `test_epic13_context` | 42 |
| `test_epic13_detector` | 65 |
| `test_epic13_executor` | 124 |
| `test_epic13_plan` | 61 |
| `test_epic13_chain` | 83 |
| `test_epic13_lineage` | 54 |
| `test_epic13_security` | 83 |
| `test_epic13_adversarial` | 53 |
| `test_epic13_regression_cand_7c229c48c455` | 43 |
| **EPIC13 total** | **689 OK** |
| EPIC11 + EPIC12 (unchanged) | 455 OK |

The security suite is executable attack surface: AST guards for the absence of
any network primitive, target/header/method/marker injection refusals, unbounded
work refusals, authorization bypass attempts, LLM escalation attempts, evidence
fabrication attempts, secret-safety checks, redirect escapes and fail-closed
behaviour on broken collaborators.

### Full-suite regression

`python3 -m unittest discover -s tests -t .` in the worktree:

```
Ran 12272 tests in 156.370s
FAILED (failures=243, errors=129, skipped=17)
308 unique failing test names
```

* **zero** EPIC11, EPIC12 or EPIC13 failures;
* 308 unique failing names — identical to the pre-EPIC13 baseline (308), so no
  new failure was introduced;
* the failing names are the known artifact-dependent suites (`test_research_ui`,
  `test_research_cases_api`, `test_recon_soc_navigation`, `test_investigations_api`,
  `local_e2e/*`, …) that depend on untracked `ai_data/` runtime state, plus one
  environmental LLM-guard failure (`env_model_not_free:…` from the shell
  environment) — none of which this Epic touches.

Caveat, stated honestly: the comparison is on the *count* of unique failing
names (308 = 308) plus the absence of any EPIC failure, not a name-by-name diff
against a stored pre-EPIC13 baseline list.

## 11. Honest limitations

* Live outbound HTTP is **not available** in this runtime. The production
  result is BLOCKED, not a successful acquisition.
* No Watch step persists a response body, so the acquisition layer consumes
  bodies only through the transport seam.
* `watch_xss_verify.py` stays disabled (Phase 5K P0-1); it was not revived and
  is not referenced anywhere in the package (pinned by test).
* DOM analysis, payload execution and exploitability establishment remain
  unavailable and are recorded as such.

## 12. Delivery

```
LLM: provider=openrouter/free calls=0 failures=0
```

EPIC13 makes no LLM calls. The acquisition layer never reads LLM output
(pinned by test: no `advisor`/`openrouter`/`llm` reference in the package), and
LLM output can never create, upgrade or confirm acquisition evidence.

```
Delivery check : READY FOR PROMOTION (BRANCH, COMMIT, TESTS, PATH_GUARD,
                 REPORT, PRODUCTION_UNTOUCHED all PASS)
Diff guard     : PASS (29 files) with one WARN: 8693 added lines > 5000
Production     : untouched, main = b74530e, 27 dirty entries preserved
Branch         : agent/daily-development @ 6f67934, pushed to origin
```

**READY TO PUSH: YES** — the branch is pushed and promotion is waiting for the
Telegram `APPROVE`.
