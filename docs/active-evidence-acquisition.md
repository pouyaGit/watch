# Active Evidence Acquisition (EPIC13)

EPIC12 answers *what evidence is missing*. EPIC13 answers *whether that
evidence can be safely acquired* — and then acquires it, or records why it
cannot.

The whole layer lives in one package:

```
backend/research_agents/verification/acquisition/
    __init__.py     the package contract and the flow it implements
    limits.py       every bound, read through the platform's own ceilings
    markers.py      deterministic controlled markers
    context.py      deterministic output-context classification
    detector.py     deterministic reflection detection
    requests.py     controlled request construction
    transport.py    the transport seam (adds no network primitive)
    executor.py     one typed action -> structured observations
    plan.py         chain -> requirements -> authorized actions
    capabilities.py per-class acquisition capability contracts
    replay.py       duplicate and replay control
    service.py      plan -> execute -> re-evaluate
```

## The flow

```
CANDIDATE
  -> EPIC12 VERIFICATION CHAIN          (what is missing, and why)
  -> MISSING EVIDENCE                   (one named evidence type)
  -> SELECT AUTHORIZED ACQUISITION ACTION
  -> EXECUTE A REAL CONTROLLED REQUEST / OBSERVATION
  -> STRUCTURED OBSERVATION             (REFLECTION_OBSERVED, ...)
  -> EPIC11 EVIDENCE CLASSIFICATION     (unchanged, authoritative)
  -> CHAIN RE-EVALUATION                (EPIC12 engine)
  -> NEXT MISSING EVIDENCE
  -> CONFIRMED / NOT_CONFIRMED / PENDING / BLOCKED
```

One run acquires the **next** missing item, not every missing item. That is
what keeps the layer from becoming a scanner: each action has a reason, a
budget, and an authorization reference, and the chain decides what comes next.

## What was reused, and what was not

| Concern | Reused | New |
|---|---|---|
| Evidence taxonomy, stages, gate | EPIC11 `finding/integrity/*` | — |
| Chain, engine, typed actions, observations, store, budget, loop, advisor, projection | EPIC12 `verification/*` | — |
| Bounds | `ai.limits.ceilings.CEILINGS` (read-through, never widened) | `limits.py` |
| Redaction | `ai.evidence.scrubber` | — |
| Location classification | `ai.verification.deterministic.http` | `context.py` (delegates) |
| HTTP execution | the platform's own transport seam | `transport.py` (no primitive) |
| Reflection detection | — | `detector.py` |
| Markers, request construction, replay control, capability contracts | — | `markers.py`, `requests.py`, `replay.py`, `capabilities.py` |

EPIC11 was **not modified**. EPIC12's `executors.py` was modified in exactly
one place: its naive `if marker in text` reflection check now delegates to the
deterministic detector, and its context constants come from `context.py`.

## The transport adds no network primitive

`transport.py` contains no `requests`, no `urllib.request`, no `httpx`, no
`socket`, no `subprocess`. This is enforced by static tests that parse the
package's AST and fail on a forbidden import or a bare dangerous call.

Two transports exist:

* `PlatformAuthorizedTransport` — resolves the platform's own live-traffic
  gate. In this runtime the gate is closed (`LIVE_TRAFFIC_ENABLED = False`,
  the B1/B2 adapters are deferred, and no code path sets it `True`), so it
  reports itself **unavailable** and refuses to send. A closed gate is a
  result, not an error: the acquisition terminates `TRANSPORT_UNAVAILABLE`.
* `InjectedTransport` — a plain callable used by tests and offline analysis.
  It is never presented as production acquisition.

The transport contract, enforced per request:

* explicit authorization, target, method and parameter;
* bounded timeout, response size, redirects, retries;
* no arbitrary destination — scheme, host, port and path must stay in the
  authorized scope, and credentials, metadata endpoints, `file:`, `gopher:`
  and userinfo are refused;
* no arbitrary headers — the built request carries none, and no header value
  can be forged through a parameter;
* no arbitrary method escalation — `GET`/`HEAD` only, and a parameter observed
  over `GET` can never be probed with another method;
* an audit trail, scrubbed of secrets;
* fail closed on anything it cannot prove.

## Markers

A marker is derived from the action it belongs to, is unique per action, is
inert (`HERMES_REFLECT_<12 hex>`), is persisted with the action, and is
bounded. It cannot contain a payload alphabet: `<`, `>`, `"`, `'`, `&`, `=`,
`?`, `#`, `%`, `/`, whitespace and control characters are refused, so a marker
can never be a request-injection vector or an exploit payload. A static marker
is never reused across actions.

## Reflection detection

The detector is deterministic and never upgrades ambiguity. It distinguishes
all eleven required cases — absent, present, present multiple times,
transformed, encoded, decoded, in HTML text, in an HTML attribute, in script,
in URL context, and body-unavailable — and emits a structured
`REFLECTION_OBSERVED` carrying `action_id`, `request_id`, `response_id`,
`parameter`, `marker`, `occurrence_count`, `context`, encoding/transformation,
evidence location and the detector rule version.

Rules that matter:

* the search window is bounded; a marker beyond it is **inconclusive**, never
  a negative;
* a non-text body fails closed;
* an occurrence is not a vulnerability: a reflection is evidence of
  reflection, and nothing more;
* the transport's own opinion is ignored — only the bytes the detector read
  can produce evidence.

## Context classification

Eight classes are distinguished: `HTML_TEXT`, `HTML_ATTRIBUTE`, `SCRIPT`,
`STYLE`, `URL`, `JSON`, `COMMENT`, `UNKNOWN`. Classification is deterministic
and offset-aware, and it delegates to the platform's own classifier so the two
cannot drift.

There is no DOM in this runtime, so DOM analysis is recorded as
`DOM_ANALYSIS_UNAVAILABLE` and DOM-sink evidence is never inferred from
server-side reflection.

## Acquisition actions

| Action | State |
|---|---|
| `CHECK_REFLECTION` | implemented |
| `SEND_MARKER` | implemented |
| `CLASSIFY_REFLECTION_CONTEXT` | implemented |
| `ACTIVE_PAYLOAD_EXECUTION` | **not implemented, not faked** |

`ACTIVE_PAYLOAD_EXECUTION` is not an action, is not in the action registry, and
is recorded as *not acquirable* in the capability contracts. The XSS chain's
`PAYLOAD_EXECUTION` and `EXPLOITABILITY_ESTABLISHED` stages therefore stay
`MISSING`: the chain reports `VERIFICATION_PENDING` with
`missing_payload_execution_evidence`, and the run reports
`CAPABILITY_UNAVAILABLE` naming the gap. That is the honest result.

## Replay and duplicate control

A fingerprint over the action's target, parameter, method, marker and
authorization is recorded with its result. A repeat probe of the same
parameter is refused unless the recorded result is reusable **and** the entry
is still inside its TTL. A timeout is never reusable. Repeating a run cannot
manufacture evidence, which is why promotion-by-repetition is impossible.

## Capability honesty

`capabilities.py` states, per vulnerability class, what acquisition is
available, limited or not implemented, together with the evidence types it can
and cannot produce and the limitation text. CORS, open-redirect and SSRF are
recorded as `LIMITED`; payload execution as `NOT_IMPLEMENTED`.

## Offline validation vs real production acquisition

These are two different things and are never conflated:

* **OFFLINE / INJECTED VALIDATION** — `InjectedTransport` supplies a
  deterministic response. This exercises the whole flow end to end and proves
  the machinery, but it is not a network acquisition.
* **REAL PRODUCTION ACQUISITION** — the transport is resolved from the
  production environment. In this runtime that resolves to
  `PlatformAuthorizedTransport`, which is unavailable, so the honest result is
  `BLOCKED` / `TRANSPORT_UNAVAILABLE` (and `UNAUTHORIZED` when no
  authorization is recorded for the target).

The run record carries the transport's name, its availability and the platform
gate state, so the two can always be told apart after the fact.

## Safety properties pinned by tests

* no new network primitive, no dynamic execution, no shell;
* no acquisition without an authorization reference, a scope and a budget;
* no out-of-scope target, hop, or final URL;
* no credential, cookie or secret in a plan, outcome, ledger or persisted row;
* no evidence without a response, a marker and an action;
* no fabricated positive: a negative never carries an evidence type or a
  marker match;
* a failed, refused or timed-out transport is never negative evidence;
* a row whose declared evidence type disagrees with its own signal is
  surfaced as a divergence, never presented as clean evidence.
