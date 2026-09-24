# Multi-Class Verification (EPIC16)

EPIC11–15 made XSS verification evidence-first: an alert is only confirmed when
real authorized observation, authoritative classification, valid provenance,
the required evidence and the EPIC11 gate all agree. EPIC16 extends the same
discipline to the other classes the platform hunts — and, where the runtime
cannot prove something, says so instead of guessing.

Nothing about the authoritative layers changed:

| layer | still authoritative for |
| --- | --- |
| EPIC11 | the evidence taxonomy and the claim gate |
| EPIC12 | verification chains, actions and the verification engine |
| EPIC13 | active evidence acquisition |
| EPIC14 | evidence provenance and the declared-vs-authoritative boundary |
| EPIC15 | deep DOM verification |

EPIC16 adds one shared specialist framework, deterministic per-class
classifiers, one trusted producer and class contracts. It creates no second
taxonomy, gate, lifecycle, authorization model, scheduler or provenance
system.

## Capability matrix

| class | capability | evidence | active verification | confirmation | limitations |
| --- | --- | --- | --- | --- | --- |
| **XSS** | IMPLEMENTED | reflection, output context, DOM sink, negative | yes (EPIC13), bounded and authorized | EPIC11 gate + EPIC15 deep lane | unchanged by EPIC16 |
| **CORS** | LIMITED | controlled-origin observation, ACAO/ACAC classification, negative | **no** — no live lane can set `Origin` | unreachable here: needs browser-relevant exploitability | an ACAO value is never automatically exploitable; `*` cannot carry credentials; ACAO reflection alone is a configuration observation |
| **OPEN_REDIRECT** | LIMITED | redirect input, Location observation, target classification, negative | **no** — no live lane can supply a controlled destination | unreachable here: the terminal off-site destination is never followed | a redirect parameter is not an open redirect; a 302 alone never confirms; only a controlled destination becoming the target counts |
| **SSRF** | LIMITED | destination-policy decision, negative | **no** — needs a controlled callback the runtime does not have | unreachable here | no internal, loopback, metadata, non-http(s), non-standard-port or out-of-scope target is ever probed; a URL parameter is not SSRF; without server-side request evidence there is no SSRF claim |
| **IDOR / BOLA** | NOT_IMPLEMENTED | object-reference observation only | **no** — `CHECK_OBJECT_ACCESS` refuses | unreachable (contract only) | no second authorized identity, no identity switching, no object-ownership semantics exist in this runtime |
| **CVE_RESEARCH** | LIMITED (research only) | product, version, applicability evidence, negative | not applicable | **never** — the class contract declares no confirmation claim | a CVE match is not vulnerability confirmation; applicability is not exploitability |

Classes with no chain at all — SQLI, COMMAND_INJECTION, SSTI, AUTH_BYPASS,
OAUTH, JWT — report `NOT_IMPLEMENTED` and produce no observations.

## What "LIMITED" means precisely

A LIMITED class has its **deterministic classification lane implemented**: it
can read a recorded response header, a recorded `Location` value, a
destination, or a product/version pair, classify it against the class's
contract, and produce EPIC11-classified observations with an auditable
provenance stamp. What it cannot do in this runtime is the *active* half:
sending a controlled `Origin`, supplying a controlled redirect destination, or
observing a server-side request. Those actions stay unimplemented and their
specs say why.

A LIMITED class therefore **cannot be confirmed here** — and the code says so
rather than degrading the gate. The strongest reachable CORS state, for
example, is `PENDING` with the reason
`final_stage_capability_unavailable:EXPLOITABILITY_ESTABLISHED`.

## Class states that are never merged

* **CORS** — ACAO absent / wildcard / exact origin / reflected arbitrary
  origin / `null` origin / origin list / malformed, plus credentialed behaviour
  and sensitive-response availability. `Access-Control-Allow-Origin: *` is
  never automatically exploitable, and a wildcard can never carry credentials.
* **Open redirect** — no Location / parameter ignored / relative only /
  same origin / destination normalized / external accepted / external out of
  scope / unsafe scheme. Only a controlled destination actually controlling the
  target reaches the acceptance stage.
* **SSRF** — policy decision only, with the refusal reason preserved
  (loopback, RFC1918, link-local, metadata by address *and* name, `file://`,
  `gopher://`, `ftp://`, arbitrary ports, out-of-scope hosts, trailing-dot and
  rebinding-shaped names).
* **IDOR/BOLA** — capability answer only: the run names the missing second
  identity, identity switching and ownership semantics and performs nothing.
* **CVE research** — product unknown / version unknown / ambiguous /
  not affected / applicability confirmed / unresolved. `confirmatory` is
  always false.

## Cross-class evidence contamination

EPIC16 registers a **class scope** for class-specific signals. When a contract
is evaluated, rows whose signal belongs to another class are **quarantined**
(recorded as auditable `cross_class_evidence` entries) and never contribute to
the claim — mirroring EPIC14's declared-vs-authoritative mismatch rule. The
confirmation-capable generic signals (`payload_execution`,
`exploitability_established`, `impact_established`) are XSS-owned, so no other
class can satisfy an XSS confirmation stage by reusing a type name.

## Outcomes

Every class run ends in exactly one state, and the distinction is preserved:

| state | meaning |
| --- | --- |
| `CONFIRMED_ELIGIBLE` | the EPIC11 gate confirmed the claim |
| `NOT_CONFIRMED` | the check ran and the observation is negative |
| `PENDING` | the observation is positive but the contract needs more evidence |
| `NOT_TESTED` | no material, or the run was refused as unsafe |
| `BLOCKED` | authorization is missing |
| `INCONCLUSIVE` | bounded run could not decide (research chains) |
| `CAPABILITY_UNAVAILABLE` | the required lane does not exist here |

`NOT_TESTED`, `BLOCKED`, `NOT_CONFIRMED` and `INCONCLUSIVE` are never
collapsed into one another.

## Operating the classes

```python
from backend.research_agents.verification.specialists import (
    verify_class, project_class_verification, capability_matrix)

result = verify_class("CORS", candidate_id="cand-x", scope_ref=scope,
                      authorization=authz,
                      material={"origin": controlled_origin(),
                                "response_headers": headers,
                                "credentials_relevant": True})
print(result.outcome, result.chain_state["verdict"], result.confirmed)
print(project_class_verification(result))   # the SOC/analyst view
```

Material is always **recorded** material. The classification lane opens no
socket: the deterministic executor consumes it from the action context, checks
the authorization first, and refuses when the class capability or the material
is absent.

## Production reality

A read-only pass over the production runtime store finds real XSS candidates
and real CVE-research candidates, and **no** CORS, open-redirect, SSRF or
IDOR candidate at all; none of the classes has a recorded authorization. The
honest production result for the new classes is therefore
`NO_AUTHORIZED_LIVE_CANDIDATE`, and the mandatory XSS regression candidate
`cand-7c229c48c455` stays `BLOCKED` / not confirmed with
`PARAMETER_OBSERVED` evidence only.
