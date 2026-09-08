"""Deterministic TestPlan Builder (Phase 4B).

Converts ONE bound Hypothesis into ONE structured TestPlan
describing intended future testing::

    Hypothesis
            +
    optional bound match / pattern / target-intelligence context
            |
            v
    TestPlan (TEST INTENT ONLY, normally PROPOSED)

The builder is PURE and DETERMINISTIC:

- NO LLM calls, NO embeddings, NO model routers.
- NO network access (a request spec is DATA and is never sent).
- NO subprocess execution, NO browser/Nuclei invocation.
- NO database reads or writes (batch resolvers are
  caller-provided, read-only, dependency-injected callables).
- NO scope decisions (``ai/correlator/scope_policy.py`` is never
  imported or called; scope strings travel as observed,
  descriptive data only).
- NO payload generation, NO artifact generation, NO template
  generation, NO findings, NO verdicts, NO evidence collection.

A TestPlan describing an HTTP test does NOT perform an HTTP
request. A TestPlan describing Nuclei does NOT invoke Nuclei. A
TestPlan describing browser verification does NOT launch a
browser. Category, execution type, and verifier are selected ONLY
from deterministic structured facts (hypothesis type, pattern
facts, match criteria) using the existing closed TestPlan enums;
when no safe selection exists the builder returns UNSUPPORTED
instead of guessing. There is no generic-execution escape hatch.

Priority/execution authority (adversarial-review B4): the builder
never reads pattern interpretation, severity, CVSS, urgency
prose, or instruction-shaped text, and TestPlans carry no
priority signal for scheduling. The future executor MUST
re-resolve the canonical target and scope immediately before any
action; this artifact is never authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal

from ai.schemas.hypothesis import Hypothesis, ResearchProvenance
from ai.schemas.hypothesis import TargetRef as HypothesisTargetRef
from ai.schemas.research_pattern import (
    AttackPattern,
    VulnerabilityPattern,
)
from ai.schemas.target_intelligence import TargetIntelligence
from ai.schemas.target_match import TargetPatternMatch
from ai.schemas.test_plan import (
    HttpRequestSpec,
    TestPlan,
    build_test_plan,
)

Pattern = VulnerabilityPattern | AttackPattern

PlanOutcome = Literal["CREATED", "UNSUPPORTED", "REJECTED"]


@dataclass(frozen=True)
class PlanResult:
    """Deterministic outcome of one hypothesis → plan evaluation.

    ``CREATED`` carries the TestPlan; ``UNSUPPORTED`` marks a
    hypothesis for which no safe category/execution/verifier
    triple can be derived (never guessed); ``REJECTED`` marks a
    binding failure (identity mismatch, unverifiable binding, or
    non-PROPOSED lifecycle). ``reason`` is deterministic text;
    ``hypothesis_id`` identifies the evaluated hypothesis.
    """

    outcome: PlanOutcome
    plan: TestPlan | None
    reason: str
    hypothesis_id: str


# ------------------------------------------------------------------
# Closed derivation tables (structured facts only)
# ------------------------------------------------------------------

#: Preconditions are fixed templates keyed by closed match
#: criteria. No prose interpolation: hostile research text cannot
#: reach them.
_PRECONDITION_TEMPLATES = {
    "product": "product identity matched: research product "
    "observed in target technology inventory",
    "version": "version condition matched: observed version "
    "satisfied the research version constraint",
    "technology_context": "technology context matched: research "
    "technology context observed in target inventory",
    "path": "endpoint matched: research path observed in target "
    "inventory",
    "method": "method matched: research method observed for the "
    "target path",
    "parameter": "parameter matched: research parameter observed "
    "in target inventory",
    "parameter_location": "parameter location matched: research "
    "parameter location observed in target inventory",
}

_REQUIRED_EVIDENCE = (
    "recorded HTTP response status line and headers for the "
    "specified request",
    "response content preserved unmodified for verifier evaluation",
)


def _check_inputs(
    hypothesis: object,
    match: object,
    pattern: object,
    target_intelligence: object,
) -> None:
    if not isinstance(hypothesis, Hypothesis):
        raise TypeError(
            "build_test_plan_from_hypothesis accepts only "
            "Hypothesis, not "
            f"{type(hypothesis).__name__}; raw dicts are never "
            "coerced"
        )
    if match is not None and not isinstance(match, TargetPatternMatch):
        raise TypeError(
            "match must be TargetPatternMatch or None, not "
            f"{type(match).__name__}"
        )
    if pattern is not None and not isinstance(
        pattern, (VulnerabilityPattern, AttackPattern)
    ):
        raise TypeError(
            "pattern must be VulnerabilityPattern, AttackPattern, "
            f"or None, not {type(pattern).__name__}"
        )
    if target_intelligence is not None and not isinstance(
        target_intelligence, TargetIntelligence
    ):
        raise TypeError(
            "target_intelligence must be TargetIntelligence or "
            f"None, not {type(target_intelligence).__name__}"
        )


def _check_bindings(
    hypothesis: Hypothesis,
    match: TargetPatternMatch | None,
    pattern: Pattern | None,
    target: TargetIntelligence | None,
) -> str | None:
    """Return a rejection reason, or None when bindings hold."""

    if hypothesis.status != "PROPOSED":
        return (
            f"hypothesis status {hypothesis.status!r} is not "
            "PROPOSED; plans are built only from live proposals"
        )
    if not hypothesis.pattern_id:
        return "hypothesis carries no pattern binding"
    if match is not None:
        if hypothesis.match_id is None:
            return (
                "hypothesis carries no match binding, so a "
                "supplied match cannot be verified against it"
            )
        if hypothesis.match_id != match.match_id:
            return (
                "hypothesis/match mismatch: hypothesis binds "
                f"{hypothesis.match_id!r} but match is "
                f"{match.match_id!r}"
            )
        if hypothesis.pattern_id != match.pattern_id:
            return (
                "hypothesis/match pattern disagreement: "
                f"{hypothesis.pattern_id!r} != "
                f"{match.pattern_id!r}"
            )
    if pattern is not None:
        if hypothesis.pattern_id != pattern.pattern_id:
            return (
                "hypothesis/pattern mismatch: hypothesis binds "
                f"{hypothesis.pattern_id!r} but pattern is "
                f"{pattern.pattern_id!r}"
            )
        if match is not None and (
            (match.pattern_type == "vulnerability")
            != isinstance(pattern, VulnerabilityPattern)
        ):
            return (
                "match/pattern type disagreement: "
                f"{match.pattern_type!r} match bound to "
                f"{type(pattern).__name__}"
            )
    if target is not None:
        if hypothesis.snapshot_hash is None:
            return (
                "hypothesis carries no snapshot binding, so a "
                "supplied target snapshot cannot be verified "
                "against it"
            )
        if hypothesis.snapshot_hash != target.snapshot_hash:
            return (
                "hypothesis/snapshot mismatch: hypothesis binds "
                "a different target observation state"
            )
        if (
            hypothesis.target.program_name != target.program_name
            or hypothesis.target.subdomain != target.subdomain
        ):
            return (
                "hypothesis/target identity mismatch: program or "
                "subdomain disagree; identity is never inferred"
            )
        if match is not None and (
            match.target_key != target.target_key
            or match.snapshot_hash != target.snapshot_hash
        ):
            return (
                "match/target disagreement: match and target "
                "intelligence describe different observations"
            )
    return None


def _derive_triple(
    hypothesis: Hypothesis,
    pattern: Pattern | None,
) -> tuple[str, str, str] | None:
    """Derive (category, execution, verifier) or None if unsafe.

    Rules use only the closed hypothesis type, the closed pattern
    kind, structured pattern facts, and the descriptive endpoint.
    Severity/CVSS/urgency/prose are never consulted. Technique
    selection requires the bound AttackPattern's structured
    technique label to carry an explicit XSS token; anything else
    is UNSUPPORTED rather than guessed.
    """

    htype = hypothesis.hypothesis_type
    if htype == "vulnerability_relevance":
        if pattern is not None:
            has_ids = bool(
                isinstance(pattern, VulnerabilityPattern)
                and pattern.facts.vulnerability_ids
            )
        else:
            has_ids = hypothesis.pattern_kind in ("cve", "ghsa")
        if has_ids:
            return ("nuclei_cve", "nuclei_scan", "nuclei_verifier")
        if hypothesis.target.endpoint:
            return ("http_probe", "http_probe", "http_matcher")
        return ("http_probe", "http_probe", "manual_review")
    if htype == "technique_relevance":
        if pattern is None or not isinstance(
            pattern, AttackPattern
        ):
            return None
        technique = pattern.facts.technique.casefold()
        if "xss" not in technique:
            return None
        if "reflect" in technique:
            return ("xss_reflected", "http_verification",
                    "xss_verifier")
        if "dom" in technique:
            return ("xss_dom", "browser_verification",
                    "xss_verifier")
        if "stored" in technique:
            return ("xss_stored", "browser_verification",
                    "xss_verifier")
        return ("xss_generic", "http_verification", "xss_verifier")
    return None


def _request_path(hypothesis: Hypothesis) -> str:
    endpoint = hypothesis.target.endpoint
    if (
        endpoint
        and endpoint.startswith("/")
        and "\n" not in endpoint
        and "\r" not in endpoint
    ):
        return endpoint
    return "/"


def _request_method(
    path: str, pattern: Pattern | None
) -> str:
    if pattern is not None and isinstance(
        pattern, VulnerabilityPattern
    ):
        methods = {
            entry.method
            for entry in pattern.facts.attack_surface
            if entry.method
            and (not entry.path or entry.path == path)
        }
        if len(methods) == 1:
            only = next(iter(methods))
            if only is not None:
                return only
    return "GET"


def _request_params(
    path: str,
    pattern: Pattern | None,
    target: TargetIntelligence | None,
) -> dict[str, str]:
    """Query parameter NAMES (empty values) from structured facts.

    A name is included only when the pattern surface declares it
    for this path with a query (or unspecified) location AND the
    target inventory observes it. Values are always empty: the
    builder invents no payloads, tokens, or secrets.
    """

    if pattern is None or target is None:
        return {}
    if not isinstance(pattern, VulnerabilityPattern):
        return {}
    observed: set[str] = set()
    for item in target.endpoint_observations:
        if item.path == path:
            observed.update(item.params)
            observed.update(
                detail.name for detail in item.param_details
            )
    for item in target.url_observations:
        if item.path == path:
            observed.update(item.params)
    names = sorted(
        {
            entry.parameter
            for entry in pattern.facts.attack_surface
            if entry.parameter
            and (not entry.path or entry.path == path)
            and entry.parameter_location
            in (None, "query")
            and entry.parameter in observed
        }
    )
    return {name: "" for name in names}


def _build_objective(hypothesis: Hypothesis) -> str:
    return (
        f"Test whether the observed target "
        f"{hypothesis.target.program_name}/"
        f"{hypothesis.target.subdomain} satisfies the "
        f"deterministic conditions associated with hypothesis "
        f"{hypothesis.hypothesis_id} "
        f"({hypothesis.hypothesis_type}). This is test intent "
        f"only: it does not assert vulnerability, scope "
        f"authorization, or execution authorization."
    )


def _build_expected_behavior(
    hypothesis: Hypothesis,
    method: str,
    path: str,
    pattern: Pattern | None,
) -> str:
    if pattern is not None:
        observables = (
            len(pattern.facts.observables)
            if isinstance(pattern, VulnerabilityPattern)
            else len(pattern.facts.expected_observables)
        )
        anchor = (
            f"the {observables} structured observable "
            f"expectation(s) of pattern {pattern.pattern_id}"
        )
    else:
        anchor = (
            "the structured observable expectations of the "
            "bound pattern"
        )
    return (
        f"Future verification should evaluate the recorded "
        f"response for {method} {path} against {anchor}; no "
        f"vulnerability outcome is asserted and no finding is "
        f"produced."
    )


def _build_preconditions(
    match: TargetPatternMatch | None,
) -> list[str]:
    if match is None:
        return []
    return sorted(
        {
            _PRECONDITION_TEMPLATES[criterion]
            for criterion in match.matched_criteria
            if criterion in _PRECONDITION_TEMPLATES
        }
    )


def build_test_plan_from_hypothesis(
    hypothesis: object,
    *,
    match: object = None,
    pattern: object = None,
    target_intelligence: object = None,
) -> PlanResult:
    """Build one TestPlan from one Hypothesis plus optional context.

    Pure function: no lookup, no network, no LLM, no subprocess,
    no database. Wrong Python types fail closed with TypeError.
    Binding failures yield REJECTED; underivable
    category/execution/verifier triples yield UNSUPPORTED; only
    fully bound, safely derivable inputs yield a CREATED
    PROPOSED TestPlan that remains test intent only.
    """

    _check_inputs(hypothesis, match, pattern, target_intelligence)
    assert isinstance(hypothesis, Hypothesis)
    assert match is None or isinstance(match, TargetPatternMatch)
    assert pattern is None or isinstance(
        pattern, (VulnerabilityPattern, AttackPattern)
    )
    assert target_intelligence is None or isinstance(
        target_intelligence, TargetIntelligence
    )

    rejection = _check_bindings(
        hypothesis, match, pattern, target_intelligence
    )
    if rejection is not None:
        return PlanResult(
            outcome="REJECTED",
            plan=None,
            reason=rejection,
            hypothesis_id=hypothesis.hypothesis_id,
        )

    triple = _derive_triple(hypothesis, pattern)
    if triple is None:
        return PlanResult(
            outcome="UNSUPPORTED",
            plan=None,
            reason=(
                f"no safe category/execution/verifier derivation "
                f"for hypothesis type "
                f"{hypothesis.hypothesis_type!r} with the "
                "available structured context; refusing to guess"
            ),
            hypothesis_id=hypothesis.hypothesis_id,
        )
    test_category, execution_type, verifier_type = triple

    path = _request_path(hypothesis)
    method = _request_method(path, pattern)
    try:
        request_spec = HttpRequestSpec(
            method=method,  # type: ignore[arg-type]
            path=path,
            query_params=_request_params(path, pattern,
                                         target_intelligence),
            headers={},
            body=None,
        )
    except Exception:
        request_spec = HttpRequestSpec()

    target = HypothesisTargetRef.model_validate(
        hypothesis.target.model_dump(mode="json")
    )
    provenance = ResearchProvenance.model_validate(
        hypothesis.provenance.model_dump(mode="json")
    )
    plan = build_test_plan(
        hypothesis_id=hypothesis.hypothesis_id,
        target=target,
        test_category=test_category,
        objective=_build_objective(hypothesis),
        execution_type=execution_type,
        verifier_type=verifier_type,
        provenance=provenance,
        request_spec=request_spec,
        preconditions=_build_preconditions(match),
        expected_behavior=_build_expected_behavior(
            hypothesis, request_spec.method, request_spec.path,
            pattern,
        ),
        required_evidence=list(_REQUIRED_EVIDENCE),
        artifact_ref=None,
        match_id=hypothesis.match_id,
        snapshot_hash=hypothesis.snapshot_hash,
    )
    return PlanResult(
        outcome="CREATED",
        plan=plan,
        reason=(
            f"test plan {plan.test_plan_id} created for "
            f"hypothesis {hypothesis.hypothesis_id} as "
            f"{test_category}/{execution_type}/{verifier_type}; "
            f"intent only, never authorization"
        ),
        hypothesis_id=hypothesis.hypothesis_id,
    )


def build_test_plans_from_hypotheses(
    hypotheses: object,
    *,
    match_resolver: Callable[[str], object] | None = None,
    pattern_resolver: Callable[[str], object] | None = None,
    target_resolver: Callable[[str], object] | None = None,
) -> tuple[PlanResult, ...]:
    """Build plans for a batch of hypotheses via optional resolvers.

    Resolvers are read-only DI callables keyed by ``match_id``,
    ``pattern_id``, and ``snapshot_hash`` respectively; every
    resolved object is re-validated through the single-build
    binding gates. Omitted resolvers mean hypothesis-only mode.
    Each hypothesis is evaluated independently (no ranking, no
    merging); results deduplicate by ``hypothesis_id`` (first
    wins) and sort by ``hypothesis_id``. One bad record never
    affects another. NOT a scheduler.
    """

    if not isinstance(hypotheses, (list, tuple)):
        raise TypeError(
            "build_test_plans_from_hypotheses accepts a list or "
            f"tuple of hypotheses, not {type(hypotheses).__name__}"
        )
    for name, resolver in (
        ("match_resolver", match_resolver),
        ("pattern_resolver", pattern_resolver),
        ("target_resolver", target_resolver),
    ):
        if resolver is not None and not callable(resolver):
            raise TypeError(f"{name} must be callable or None")

    seen: set[str] = set()
    results: list[PlanResult] = []
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, Hypothesis):
            raise TypeError(
                "batch elements must be Hypothesis, not "
                f"{type(hypothesis).__name__}"
            )
        if hypothesis.hypothesis_id in seen:
            continue
        seen.add(hypothesis.hypothesis_id)
        match = (
            match_resolver(hypothesis.match_id)
            if match_resolver is not None
            and hypothesis.match_id is not None
            else None
        )
        pattern = (
            pattern_resolver(hypothesis.pattern_id)
            if pattern_resolver is not None
            else None
        )
        target = (
            target_resolver(hypothesis.snapshot_hash)
            if target_resolver is not None
            and hypothesis.snapshot_hash is not None
            else None
        )
        if (
            (match_resolver is not None
             and hypothesis.match_id is not None
             and match is None)
            or (pattern_resolver is not None and pattern is None)
            or (target_resolver is not None
                and hypothesis.snapshot_hash is not None
                and target is None)
        ):
            results.append(
                PlanResult(
                    outcome="REJECTED",
                    plan=None,
                    reason=(
                        "unresolvable bound reference for "
                        f"hypothesis {hypothesis.hypothesis_id}; "
                        "the builder performs no lookup of its own"
                    ),
                    hypothesis_id=hypothesis.hypothesis_id,
                )
            )
            continue
        try:
            results.append(
                build_test_plan_from_hypothesis(
                    hypothesis,
                    match=match,
                    pattern=pattern,
                    target_intelligence=target,
                )
            )
        except TypeError as exc:
            results.append(
                PlanResult(
                    outcome="REJECTED",
                    plan=None,
                    reason=(
                        "resolver returned unusable object: "
                        f"{exc}"
                    ),
                    hypothesis_id=hypothesis.hypothesis_id,
                )
            )
    results.sort(key=lambda item: item.hypothesis_id)
    return tuple(results)


__all__ = [
    "Pattern",
    "PlanOutcome",
    "PlanResult",
    "build_test_plan_from_hypothesis",
    "build_test_plans_from_hypotheses",
]
