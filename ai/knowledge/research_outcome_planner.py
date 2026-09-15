"""Stage R70 deterministic research outcome and action planner (pure engine).

Consumes the accepted hypotheses of one validated R65/R66 research artifact
and derives the bounded research outcome for each hypothesis plus a ranked,
correlated, category-aware action plan:

    Observed evidence -> hypothesis -> evidence gap -> ranked research action

It answers the human-researcher question:

    "What should be investigated next, why does it matter, what evidence is
     missing, and when should the hypothesis stay unconfirmed?"

This is a **planning signal only, and it is plan-only**. It never executes an
action, never contacts a target, never scans, never crawls, never calls an
LLM, never touches Mongo and never renders a probability, exploitability,
severity or CVSS judgement. It contains no payloads, exploit strings, scanner
commands or request bodies. The recommended action is an advisory, offline
review step over existing evidence, not a vulnerability claim.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no target interaction, no Mongo, no persistence, no execution.
- Deterministic and explainable: outcomes, grouping, ranking and summary are
  pure functions of the accepted hypotheses; every score is a bounded sum of
  documented factor points (no probabilities, no magic numbers).
- Closed vocabularies: categories, gap ids, evidence states and safety flags
  are closed sets; no free-form generated instructions exist.
- Additive and read-only: inputs are never mutated; every result is a new
  dict with rule version ``r70-1``.
- Every action forces ``confirmation_state = NOT_CONFIRMED`` and carries an
  explicit safe stopping condition.
"""

from __future__ import annotations

from typing import Mapping, Sequence

RULE_VERSION = "r70-1"

MAX_ACTIONS = 8
MAX_ACTION_HYPOTHESES = 8
MAX_TEXT_CHARS = 320
MAX_OUTCOME_EVIDENCE = 4
MAX_MISSING_EVIDENCE = 6

CATEGORY_ORDER: tuple[str, ...] = (
    "XSS",
    "SSRF",
    "SQLI",
    "IDOR",
    "JWT",
    "OAUTH",
    "RECON",
    "CVE_RESEARCH",
)

CORROBORATING_REF_KINDS: frozenset[str] = frozenset(
    {
        "response",
        "authorization",
        "redirect",
        "session",
        "token",
        "algorithm",
        "header",
        "error",
        "status",
    }
)

EVIDENCE_STATES: tuple[str, ...] = (
    "CORROBORATED",
    "STRUCTURE_AND_SIGNAL",
    "STRUCTURAL_ONLY",
    "DERIVED_ONLY",
    "NONE",
)

#: Bounded, documented factor points. These are qualitative research-ordering
#: points, never probabilities, severity or exploitability.
PRIORITY_POINTS: dict[str, int] = {
    "HIGH": 30,
    "MEDIUM": 20,
    "LOW": 10,
}
CONFIDENCE_POINTS: dict[str, int] = {
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "UNKNOWN": 0,
}
EVIDENCE_COMPLETENESS_POINTS: dict[str, int] = {
    "CORROBORATED": 15,
    "STRUCTURE_AND_SIGNAL": 5,
    "STRUCTURAL_ONLY": 2,
    "DERIVED_ONLY": 0,
    "NONE": 0,
}
#: Information gain tiers: a missing behavior gap discriminates more than a
#: missing mapping, which discriminates more than a missing structural detail.
INFORMATION_GAIN_POINTS: dict[str, int] = {
    "OBJECT_AUTHORIZATION": 20,
    "SERVER_SIDE_FETCH": 20,
    "REFLECTION_CONTEXT": 20,
    "QUERY_BEHAVIOR": 20,
    "TOKEN_VALIDATION": 20,
    "OAUTH_FLOW_ARTIFACTS": 20,
    "COMPONENT_MAPPING": 15,
    "ENDPOINT_BEHAVIOR": 10,
    "ADDITIONAL_EVIDENCE": 10,
}
CORRELATION_COVERAGE_POINTS_PER_HYPOTHESIS = 2
CORRELATION_COVERAGE_MAX_HYPOTHESES = 4

SAFETY_BLOCK: dict = {
    "advisory": True,
    "research_only": True,
    "execution_performed": False,
    "vulnerability_confirmed": False,
    "exploit_authorized": False,
    "confirmation_state": "NOT_CONFIRMED",
    "human_authority_required": True,
}

_GAP_SPECS: dict[str, dict] = {
    "OBJECT_AUTHORIZATION": {
        "category": "IDOR",
        "evidence_gap": (
            "object identity plus authorization/ownership behavior evidence"
        ),
        "objective": (
            "Determine whether the referenced object is authorization-scoped "
            "per principal."
        ),
        "recommended_action": (
            "Review stored records for the affected surface to establish "
            "whether the same object reference is associated with different "
            "authorization outcomes for different authorized principals."
        ),
        "expected_evidence": (
            "Stored responses showing whether the same object reference is "
            "reachable across distinct authorized principals or ownership "
            "bindings."
        ),
        "reason": (
            "authorization and ownership evidence is the gap most likely to "
            "distinguish a structural object reference from a real "
            "access-control finding."
        ),
        "stopping_condition": (
            "If no object-ownership or authorization evidence exists in "
            "stored records, keep the hypothesis unconfirmed and record the "
            "gap."
        ),
    },
    "SERVER_SIDE_FETCH": {
        "category": "SSRF",
        "evidence_gap": (
            "server-side fetch behavior plus controlled-destination evidence"
        ),
        "objective": (
            "Determine whether the observed input influences server-side "
            "request behavior."
        ),
        "recommended_action": (
            "Review stored response and error records for the affected "
            "surface to establish whether any server-side fetch, callback or "
            "internal-network indicator is observable."
        ),
        "expected_evidence": (
            "Stored evidence of a server-side fetch, callback, redirect "
            "handling or internal-network indicator tied to the input."
        ),
        "reason": (
            "An input name is not fetch behavior; only server-side request "
            "evidence can separate reachability from actual influence."
        ),
        "stopping_condition": (
            "If no server-side fetch indicator exists in stored records, "
            "keep the hypothesis unconfirmed and record the gap."
        ),
    },
    "REFLECTION_CONTEXT": {
        "category": "XSS",
        "evidence_gap": "reflection plus execution-context evidence",
        "objective": (
            "Determine whether the observed input reaches an executable "
            "response context."
        ),
        "recommended_action": (
            "Review stored response bodies for the affected input to "
            "establish whether it is reflected and what encoding context it "
            "lands in."
        ),
        "expected_evidence": (
            "Stored response evidence showing the input reflected into a "
            "specific context together with the encoding applied."
        ),
        "reason": (
            "Parameter presence and generic reflection are not execution "
            "context; only stored response evidence can distinguish them."
        ),
        "stopping_condition": (
            "If no reflection or context evidence exists in stored records, "
            "keep the hypothesis unconfirmed and record the gap."
        ),
    },
    "QUERY_BEHAVIOR": {
        "category": "SQLI",
        "evidence_gap": (
            "input influence plus database/query behavior evidence"
        ),
        "objective": (
            "Determine whether the observed input influences database query "
            "behavior."
        ),
        "recommended_action": (
            "Review stored response and error records for the affected "
            "surface to establish whether parameter-dependent database "
            "behavior is observable."
        ),
        "expected_evidence": (
            "Stored database error, timing or response differences tied to "
            "the input."
        ),
        "reason": (
            "Parameter presence is not query influence; only stored database "
            "behavior evidence can separate the two."
        ),
        "stopping_condition": (
            "If no database behavior evidence exists in stored records, keep "
            "the hypothesis unconfirmed and record the gap."
        ),
    },
    "TOKEN_VALIDATION": {
        "category": "JWT",
        "evidence_gap": (
            "actual JWT structure/token evidence plus validation "
            "characteristics"
        ),
        "objective": (
            "Determine whether real JWT artifacts with validation-relevant "
            "characteristics exist."
        ),
        "recommended_action": (
            "Review stored header, cookie and response records for actual "
            "token artifacts, their structure and any algorithm/claim "
            "metadata before treating the surface as JWT-related."
        ),
        "expected_evidence": (
            "Observed token structure, claims and algorithm or validation "
            "metadata in stored records."
        ),
        "reason": (
            "Token-shaped names are not JWTs; only observed token artifacts "
            "can support a JWT hypothesis."
        ),
        "stopping_condition": (
            "If no token artifact exists in stored records, keep the "
            "hypothesis unconfirmed and record the gap."
        ),
    },
    "OAUTH_FLOW_ARTIFACTS": {
        "category": "OAUTH",
        "evidence_gap": (
            "actual OAuth/OIDC flow artifact plus redirect/token/state "
            "evidence"
        ),
        "objective": (
            "Determine whether real OAuth/OIDC flow artifacts are present "
            "and how redirect/state/token handling is expressed."
        ),
        "recommended_action": (
            "Review stored request records for authorize, token, "
            "redirect_uri, state, nonce or assertion artifacts before "
            "treating the surface as an OAuth/OIDC flow."
        ),
        "expected_evidence": (
            "Observed authorize/token/redirect_uri/state artifacts and their "
            "handling in stored requests."
        ),
        "reason": (
            "Generic auth parameters are not OAuth; only observed flow "
            "artifacts can support a flow hypothesis."
        ),
        "stopping_condition": (
            "If no OAuth/OIDC artifact exists in stored records, keep the "
            "hypothesis unconfirmed and record the gap."
        ),
    },
    "COMPONENT_MAPPING": {
        "category": "CVE_RESEARCH",
        "evidence_gap": (
            "technology plus exact version plus component-mapping plus "
            "applicability evidence"
        ),
        "objective": (
            "Determine the exact component-version mapping and whether it "
            "warrants offline CVE applicability review."
        ),
        "recommended_action": (
            "Correlate stored technology and version evidence to establish "
            "which component each version belongs to, then consult offline "
            "CVE references for that mapping."
        ),
        "expected_evidence": (
            "An observed technology-to-version association suitable for "
            "offline CVE correlation."
        ),
        "reason": (
            "An unassociated version string is not a component version and "
            "cannot be correlated with CVE data."
        ),
        "stopping_condition": (
            "If the component-version mapping cannot be established from "
            "stored evidence, keep the version observation unmapped."
        ),
    },
    "ENDPOINT_BEHAVIOR": {
        "category": "RECON",
        "evidence_gap": (
            "endpoint purpose, behavior, authentication or response evidence"
        ),
        "objective": (
            "Determine the purpose, authentication requirement and response "
            "behavior of the observed surface."
        ),
        "recommended_action": (
            "Review stored request/response records for the affected path to "
            "establish its method, authentication requirement and response "
            "behavior."
        ),
        "expected_evidence": (
            "Observed method, authentication requirement and response "
            "schema for the path."
        ),
        "reason": (
            "Endpoint names do not prove purpose or behavior; only stored "
            "request/response evidence can support a structural lead."
        ),
        "stopping_condition": (
            "If no method/authentication/response evidence exists in stored "
            "records, keep the observation structural."
        ),
    },
    "ADDITIONAL_EVIDENCE": {
        "category": "",
        "evidence_gap": "additional evidence tied to the stated uncertainty",
        "objective": (
            "Determine what additional evidence would distinguish the "
            "structural observation from a supported research lead."
        ),
        "recommended_action": (
            "Review stored records for evidence that directly addresses the "
            "hypothesis missing-evidence list."
        ),
        "expected_evidence": (
            "Stored evidence that directly addresses the stated missing "
            "evidence."
        ),
        "reason": (
            "The hypothesis currently rests on structural or derived "
            "support; targeted evidence is required before it can progress."
        ),
        "stopping_condition": (
            "If no relevant evidence exists in stored records, keep the "
            "hypothesis unconfirmed and record the gap."
        ),
    },
}

CATEGORY_GAPS: dict[str, str] = {
    "IDOR": "OBJECT_AUTHORIZATION",
    "SSRF": "SERVER_SIDE_FETCH",
    "XSS": "REFLECTION_CONTEXT",
    "SQLI": "QUERY_BEHAVIOR",
    "JWT": "TOKEN_VALIDATION",
    "OAUTH": "OAUTH_FLOW_ARTIFACTS",
    "CVE_RESEARCH": "COMPONENT_MAPPING",
    "RECON": "ENDPOINT_BEHAVIOR",
}

_ALLOWED_PRIORITIES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW")
_ALLOWED_CONFIDENCE: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW", "UNKNOWN")


class ResearchOutcomeError(ValueError):
    """Deterministic, secret-free R70 planning failure."""


def _text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    text = str(value if value is not None else "")
    text = " ".join(text.split())
    return text[:limit]


def _upper(value: object) -> str:
    return _text(value, 64).upper()


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_strings(value: object, limit: int, item_limit: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _text(item, item_limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _observation_kinds(hypothesis: Mapping) -> set[str]:
    evidence = hypothesis.get("evidence")
    if not isinstance(evidence, Mapping):
        return set()
    kinds: set[str] = set()
    for observation in evidence.get("observations") or ():
        if isinstance(observation, Mapping):
            ref = _text(observation.get("ref"), 512)
            kind = ref.partition(":")[0]
            if kind:
                kinds.add(kind)
    return kinds


def evidence_state_of(hypothesis: Mapping) -> str:
    """Closed-vocabulary evidence state for one hypothesis."""

    evidence = hypothesis.get("evidence")
    observations = (
        list(evidence.get("observations") or ())
        if isinstance(evidence, Mapping)
        else []
    )
    derived = (
        list(evidence.get("derived_signals") or ())
        if isinstance(evidence, Mapping)
        else []
    )
    if _observation_kinds(hypothesis) & CORROBORATING_REF_KINDS:
        return "CORROBORATED"
    if observations and derived:
        return "STRUCTURE_AND_SIGNAL"
    if observations:
        return "STRUCTURAL_ONLY"
    if derived:
        return "DERIVED_ONLY"
    return "NONE"


def gap_id_for(category: object) -> str:
    """Category-aware evidence gap id (generic fallback for unknown)."""

    return CATEGORY_GAPS.get(_upper(category), "ADDITIONAL_EVIDENCE")


def build_research_outcomes(hypotheses: object = None) -> list[dict]:
    """One bounded research outcome per accepted hypothesis (input order)."""

    outcomes: list[dict] = []
    for position, hypothesis in enumerate(_mapping_items(hypotheses), start=1):
        evidence = hypothesis.get("evidence")
        if not isinstance(evidence, Mapping):
            evidence = {}
        category = _upper(hypothesis.get("category"))
        priority = _upper(hypothesis.get("priority"))
        confidence = _upper(hypothesis.get("confidence"))
        if priority not in _ALLOWED_PRIORITIES:
            priority = "LOW"
        if confidence not in _ALLOWED_CONFIDENCE:
            confidence = "UNKNOWN"
        gap_id = gap_id_for(category)
        spec = _GAP_SPECS[gap_id]
        observations = []
        for observation in evidence.get("observations") or ():
            if not isinstance(observation, Mapping):
                continue
            ref = _text(observation.get("ref"), 512)
            if not ref:
                continue
            observations.append(
                {"ref": ref, "fact": _text(observation.get("fact"), 512)}
            )
            if len(observations) >= MAX_OUTCOME_EVIDENCE:
                break
        derived = []
        for signal in evidence.get("derived_signals") or ():
            if not isinstance(signal, Mapping):
                continue
            name = _upper(signal.get("signal"))
            if not name:
                continue
            derived.append(
                {
                    "signal": name,
                    "detail": _text(signal.get("detail"), 512),
                }
            )
            if len(derived) >= MAX_OUTCOME_EVIDENCE:
                break
        outcomes.append(
            {
                "hypothesis_ref": f"H{position}",
                "title": _text(hypothesis.get("title"), 160),
                "category": category,
                "priority": priority,
                "confidence": confidence,
                "evidence_state": evidence_state_of(hypothesis),
                "current_evidence": {
                    "observations": observations,
                    "derived_signals": derived,
                    "selected_evidence_refs": _bounded_strings(
                        hypothesis.get("selected_evidence_refs"),
                        MAX_OUTCOME_EVIDENCE,
                        16,
                    ),
                },
                "hypothesis_missing_evidence": _bounded_strings(
                    hypothesis.get("missing_evidence"),
                    MAX_MISSING_EVIDENCE,
                    160,
                ),
                "gap_id": gap_id,
                "evidence_gap": spec["evidence_gap"],
                "research_objective": spec["objective"],
                "recommended_next_action": spec["recommended_action"],
                "expected_evidence": spec["expected_evidence"],
                "reason_for_action": spec["reason"],
                "safe_stopping_condition": spec["stopping_condition"],
                "advisory": True,
                "research_only": True,
                "confirmation_state": "NOT_CONFIRMED",
            }
        )
    return outcomes


def _max_state(members: Sequence[Mapping], key: str, points: Mapping) -> str:
    best = ""
    best_points = -1
    for member in members:
        value = _upper(member.get(key))
        score = points.get(value, -1)
        if score > best_points:
            best = value
            best_points = score
    return best


def build_research_actions(outcomes: object = None) -> list[dict]:
    """Correlate outcomes with the same evidence gap into bounded actions."""

    groups: dict[str, list[dict]] = {}
    for outcome in _mapping_items(outcomes):
        gap_id = _text(outcome.get("gap_id"), 64) or "ADDITIONAL_EVIDENCE"
        groups.setdefault(gap_id, []).append(dict(outcome))

    actions: list[dict] = []
    for gap_id, members in groups.items():
        spec = _GAP_SPECS.get(gap_id, _GAP_SPECS["ADDITIONAL_EVIDENCE"])
        priority = _max_state(members, "priority", PRIORITY_POINTS) or "LOW"
        confidence = _max_state(members, "confidence", CONFIDENCE_POINTS)
        states = sorted(
            {_text(member.get("evidence_state"), 32) for member in members}
        )
        completeness = max(
            EVIDENCE_COMPLETENESS_POINTS.get(state, 0) for state in states
        )
        correlated = min(len(members), CORRELATION_COVERAGE_MAX_HYPOTHESES)
        factors = {
            "priority": PRIORITY_POINTS.get(priority, 0),
            "confidence": CONFIDENCE_POINTS.get(confidence, 0),
            "evidence_completeness": completeness,
            "information_gain": INFORMATION_GAIN_POINTS.get(gap_id, 10),
            "correlation_coverage": (
                correlated * CORRELATION_COVERAGE_POINTS_PER_HYPOTHESIS
            ),
        }
        category = _upper(members[0].get("category")) or spec["category"]
        actions.append(
            {
                "action_id": "",
                "gap_id": gap_id,
                "category": category,
                "objective": spec["objective"],
                "recommended_action": spec["recommended_action"],
                "expected_evidence": spec["expected_evidence"],
                "reason": spec["reason"],
                "stopping_condition": spec["stopping_condition"],
                "hypothesis_refs": [
                    _text(member.get("hypothesis_ref"), 16)
                    for member in members[:MAX_ACTION_HYPOTHESES]
                ],
                "hypothesis_titles": [
                    _text(member.get("title"), 160)
                    for member in members[:MAX_ACTION_HYPOTHESES]
                ],
                "hypothesis_count": len(members),
                "evidence_states": states,
                "priority": priority,
                "confidence": confidence,
                "score": {
                    "total": sum(factors.values()),
                    "factors": factors,
                },
                "safety": dict(SAFETY_BLOCK),
                "research_only": True,
            }
        )
    return actions


def _category_rank(category: str) -> int:
    return (
        CATEGORY_ORDER.index(category)
        if category in CATEGORY_ORDER
        else len(CATEGORY_ORDER)
    )


def rank_research_actions(actions: object = None) -> list[dict]:
    """Deterministic ranking: score desc, category order, gap id."""

    ranked = [dict(action) for action in _mapping_items(actions)]
    ranked.sort(
        key=lambda action: (
            -int((action.get("score") or {}).get("total", 0)),
            _category_rank(_upper(action.get("category"))),
            _text(action.get("gap_id"), 64),
        )
    )
    return ranked


def summarize_research_actions(actions: object = None) -> dict:
    """Bounded plan summary (counts, bands, top action)."""

    ranked = [action for action in _mapping_items(actions)]
    bands = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for action in ranked:
        band = _upper(action.get("priority"))
        if band in bands:
            bands[band] += 1
    top = ranked[0] if ranked else {}
    return {
        "rule_version": RULE_VERSION,
        "action_count": len(ranked),
        "covered_hypotheses": sum(
            int(action.get("hypothesis_count") or 0) for action in ranked
        ),
        "priority_bands": bands,
        "top_action_id": _text(top.get("action_id"), 16),
        "top_action_objective": _text(top.get("objective")),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def plan_research_actions(
    hypotheses: object = None, *, limit: int = MAX_ACTIONS
) -> dict:
    """Build, correlate, rank and bound the R70 research action plan."""

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ResearchOutcomeError("limit must be an integer")
    if limit < 0:
        raise ResearchOutcomeError("limit must be >= 0")

    outcomes = build_research_outcomes(hypotheses)
    actions = rank_research_actions(build_research_actions(outcomes))
    limited = actions[:limit]
    for position, action in enumerate(limited, start=1):
        action["action_id"] = f"A{position}"
    return {
        "rule_version": RULE_VERSION,
        "outcomes": outcomes,
        "actions": limited,
        "summary": summarize_research_actions(limited),
        "safety": dict(SAFETY_BLOCK),
        "research_only": True,
    }


__all__ = [
    "RULE_VERSION",
    "MAX_ACTIONS",
    "MAX_ACTION_HYPOTHESES",
    "MAX_TEXT_CHARS",
    "CATEGORY_ORDER",
    "CATEGORY_GAPS",
    "EVIDENCE_STATES",
    "SAFETY_BLOCK",
    "PRIORITY_POINTS",
    "CONFIDENCE_POINTS",
    "EVIDENCE_COMPLETENESS_POINTS",
    "INFORMATION_GAIN_POINTS",
    "ResearchOutcomeError",
    "evidence_state_of",
    "gap_id_for",
    "build_research_outcomes",
    "build_research_actions",
    "rank_research_actions",
    "summarize_research_actions",
    "plan_research_actions",
]
