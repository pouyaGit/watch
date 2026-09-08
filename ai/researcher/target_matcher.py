"""Deterministic Target Matcher (Phase 3B).

Joins research patterns with target intelligence into READ-ONLY
relevance statements::

    VulnerabilityPattern / AttackPattern
                +
            TargetIntelligence
                |
                v
        TargetPatternMatch (RELEVANCE ONLY)

The matcher is PURE and DETERMINISTIC:

- NO LLM calls, NO embeddings, NO semantic similarity.
- NO network access (a URL is data and is never fetched).
- NO subprocess, NO database reads or writes.
- NO scope decisions (``ai/correlator/scope_policy.py`` remains the
  sole scope authority and is never imported or called here).
- NO findings, verdicts, evidence, or execution plans.

MATCH != VULNERABLE. A MATCH states only that the deterministic
research-side criteria are satisfied by the observed target
inventory. Neither input is ground truth about current
vulnerability status.

Currently matchable fields (only criteria represented on BOTH
sides are compared; everything else is UNKNOWN, never guessed):

- VulnerabilityPattern.products (vendor/product/aliases/cpe)
  <-> TargetIntelligence.technologies, via the existing
  ``ai/correlator/technology.py::match_technology`` (exact
  normalized identity, explicit aliases, token equality,
  vendor+product, CPE fallback; generic-technology blocklist and
  no-substring rules inherited unchanged). No second product
  algorithm exists here.
- VulnerabilityPattern.version_constraints (EXACT, LOWER_BOUND,
  UPPER_BOUND, RANGE, FIXED, UNKNOWN with inclusive/exclusive
  bounds) <-> TechnologyObservation.observed_version, via the
  ``ai/correlator/version.py::evaluate_version_constraint``
  authority. Inclusivity is honored exactly; unrepresentable or
  unparseable conditions yield INCONCLUSIVE, never a guess.
- VulnerabilityPattern.attack_surface (path, method, parameter,
  parameter_location) <-> endpoint/url observations, via exact
  deterministic equality. ``parameter_location`` values outside
  the target-side ``{query, body}`` vocabulary are UNKNOWN
  (unrepresentable, never coerced).
- AttackPattern.technology_context <-> technologies, via the same
  ``match_technology`` rule (technique labels are the product
  side). Technique, sink, precondition, and observable content
  has no target-side representation and stays UNKNOWN, so an
  attack pattern can reach at most PARTIAL_MATCH.

Explicitly NOT matched (kept UNKNOWN when present, never
compared, never matched against execution evidence):

- required_conditions, observables / expected_observables
  (expectations, never evidence), technique, sink_characteristics,
  preconditions, severity/CVSS, titles/descriptions.

Priority / B4 rule: pattern ``interpretation``, ``reported_severity``,
``cvss_*``, and any model-shaped metadata are never read and cannot
influence matching or scoring. The score derives ONLY from the
deterministic criteria counts.

Result identity binds the observation snapshot: a match is a
statement about one (pattern, target, snapshot) triple. Any future
execution stage must re-resolve the current target, current scope,
and current inventory before acting; this result grants nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ai.correlator.technology import match_technology
from ai.correlator.version import evaluate_version_constraint
from ai.schemas.research_pattern import (
    AttackPattern,
    VulnerabilityPattern,
)
from ai.schemas.target_intelligence import TargetIntelligence
from ai.schemas.target_match import (
    MATCHER_VERSION,
    TargetPatternMatch,
    deterministic_score_for,
    match_id_for,
)

Pattern = VulnerabilityPattern | AttackPattern

_TARGET_LOCATIONS = frozenset({"query", "body"})


class TargetMatchError(ValueError):
    """Deterministic, testable matcher misuse signal."""


@dataclass(frozen=True)
class CriterionOutcome:
    """Per-criterion deterministic evaluation."""

    matched: tuple[str, ...] = ()
    unmatched: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()
    details: tuple[str, ...] = ()


@dataclass
class _Evaluation:
    matched: list[str] = field(default_factory=list)
    unmatched: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    def as_outcome(self) -> CriterionOutcome:
        return CriterionOutcome(
            matched=tuple(sorted(set(self.matched))),
            unmatched=tuple(
                sorted(set(self.unmatched) - set(self.matched))
            ),
            unknown=tuple(
                sorted(
                    set(self.unknown)
                    - set(self.matched)
                    - set(self.unmatched)
                )
            ),
            details=tuple(sorted(set(self.details))),
        )


def _check_inputs(pattern: object, target: object) -> None:
    if not isinstance(pattern, (VulnerabilityPattern, AttackPattern)):
        raise TypeError(
            "match_pattern_to_target accepts only "
            "VulnerabilityPattern or AttackPattern, not "
            f"{type(pattern).__name__}; raw dicts are never coerced"
        )
    if not isinstance(target, TargetIntelligence):
        raise TypeError(
            "match_pattern_to_target accepts only "
            f"TargetIntelligence, not {type(target).__name__}"
        )


def _evaluate_product(
    pattern: VulnerabilityPattern,
    target: TargetIntelligence,
) -> tuple[_Evaluation, list[tuple[str, str | None]]]:
    """Match pattern products against observed technologies.

    Returns the evaluation plus the (product_label, observed_version)
    pairs behind every product match (the version-candidate set).
    Aliases are alternative names for the same product; any alias
    match counts as a product match.
    """

    evaluation = _Evaluation()
    candidates: list[tuple[str, str | None]] = []
    if not pattern.facts.products:
        return evaluation, candidates
    found = False
    for product in pattern.facts.products:
        names = [product.product, *product.aliases]
        cpes = [product.cpe] if product.cpe else None
        for name in names:
            for tech in target.technologies:
                result = match_technology(
                    technology=tech.raw_label,
                    vendor=product.vendor,
                    product=name,
                    cpes=cpes,
                )
                if result is not None:
                    found = True
                    candidates.append((name, tech.observed_version))
                    evaluation.details.append(
                        f"product {name!r} ~ technology "
                        f"{tech.raw_label!r} "
                        f"({result.match_type})"
                    )
    # Deduplicate candidates deterministically.
    candidates = sorted(set(candidates))
    if found:
        evaluation.matched.append("product")
    else:
        evaluation.unmatched.append("product")
    return evaluation, candidates


def _evaluate_version(
    pattern: VulnerabilityPattern,
    candidates: list[tuple[str, str | None]],
    *,
    product_matched: bool,
    product_present: bool,
) -> _Evaluation:
    """Evaluate version constraints against matched observations.

    Only observed versions of technologies that matched the pattern
    product are candidates. Without a product anchor (pattern
    carries version constraints but no products) the version
    criterion is UNKNOWN: a version match without product identity
    must never become relevance.
    """

    evaluation = _Evaluation()
    constraints = pattern.facts.version_constraints
    if not constraints:
        return evaluation
    if not product_present or not product_matched:
        evaluation.unknown.append("version")
        evaluation.details.append(
            "version constraints present but no anchored product "
            "match; version relevance is unknown"
        )
        return evaluation
    observed = sorted(
        {version for _, version in candidates if version}
    )
    if not observed:
        evaluation.unknown.append("version")
        evaluation.details.append(
            "matched technology carries no observed version"
        )
        return evaluation
    saw_inconclusive = False
    for constraint in constraints:
        for detected in observed:
            result = evaluate_version_constraint(
                detected,
                constraint_kind=constraint.constraint_kind,
                version=constraint.version,
                upper_version=constraint.upper_version,
                lower_inclusive=constraint.lower_inclusive,
                upper_inclusive=constraint.upper_inclusive,
            )
            if result.status == "MATCH":
                evaluation.matched.append("version")
                evaluation.details.append(
                    f"version {detected!r} satisfies "
                    f"{constraint.constraint_kind} "
                    f"{constraint.version!r}"
                )
            elif result.status == "INCONCLUSIVE":
                saw_inconclusive = True
                evaluation.details.append(
                    f"version {detected!r} vs "
                    f"{constraint.constraint_kind}: {result.reason}"
                )
            else:
                evaluation.details.append(
                    f"version {detected!r} outside "
                    f"{constraint.constraint_kind} "
                    f"{constraint.version!r}: {result.reason}"
                )
    if "version" in evaluation.matched:
        return evaluation
    if saw_inconclusive:
        evaluation.unknown.append("version")
    else:
        evaluation.unmatched.append("version")
    return evaluation


def _evaluate_surface(
    pattern: VulnerabilityPattern,
    target: TargetIntelligence,
) -> _Evaluation:
    """Compare attack-surface fields against endpoint/url inventory.

    Each of path/method/parameter/parameter_location is evaluated
    only when at least one surface entry specifies it; otherwise
    the criterion is not applicable and stays out of every list.
    All comparisons are exact deterministic equality.
    """

    evaluation = _Evaluation()
    surface = pattern.facts.attack_surface
    if not surface:
        return evaluation

    target_paths = sorted(
        {item.path for item in target.endpoint_observations}
        | {item.path for item in target.url_observations}
    )
    methods_by_path: dict[str, set[str]] = {}
    for item in target.endpoint_observations:
        observed = methods_by_path.setdefault(item.path, set())
        for detail in item.param_details:
            observed.add(detail.method)
    all_methods = sorted(
        {method for methods in methods_by_path.values() for method in methods}
    )
    target_params = sorted(
        {item for item in target.endpoint_observations for item in item.params}
        | {
            detail.name
            for item in target.endpoint_observations
            for detail in item.param_details
        }
        | {item for item in target.url_observations for item in item.params}
    )
    details_by_param: dict[str, set[str]] = {}
    for item in target.endpoint_observations:
        for detail in item.param_details:
            details_by_param.setdefault(detail.name, set()).add(
                detail.location
            )

    paths = sorted({entry.path for entry in surface if entry.path})
    if paths:
        if any(path in target_paths for path in paths):
            evaluation.matched.append("path")
            evaluation.details.append(
                "path observed in target inventory: "
                + ",".join(
                    sorted(f"{path!r}" for path in paths if path in target_paths)
                )
            )
        elif not target_paths:
            evaluation.unknown.append("path")
            evaluation.details.append(
                "pattern specifies paths but the target exposes "
                "no observed paths"
            )
        else:
            evaluation.unmatched.append("path")

    methods = sorted(
        {entry.method for entry in surface if entry.method}
    )
    if methods:
        if not all_methods:
            evaluation.unknown.append("method")
            evaluation.details.append(
                "pattern specifies methods but the target exposes "
                "no observed methods"
            )
        else:
            hit = False
            for entry in surface:
                if not entry.method:
                    continue
                if entry.path:
                    observed = methods_by_path.get(entry.path, set())
                    if entry.method in observed:
                        hit = True
                elif entry.method in all_methods:
                    hit = True
            if hit:
                evaluation.matched.append("method")
                evaluation.details.append(
                    "method observed in target inventory"
                )
            else:
                evaluation.unmatched.append("method")

    parameters = sorted(
        {entry.parameter for entry in surface if entry.parameter}
    )
    if parameters:
        if any(param in target_params for param in parameters):
            evaluation.matched.append("parameter")
            evaluation.details.append(
                "parameter observed in target inventory: "
                + ",".join(
                    sorted(
                        f"{param!r}"
                        for param in parameters
                        if param in target_params
                    )
                )
            )
        elif not target.endpoint_observations and not target.url_observations:
            evaluation.unknown.append("parameter")
            evaluation.details.append(
                "pattern specifies parameters but the target "
                "exposes no observed endpoints or urls"
            )
        else:
            evaluation.unmatched.append("parameter")

    locations = sorted(
        {
            entry.parameter_location
            for entry in surface
            if entry.parameter_location
        }
    )
    if locations:
        representable = [loc for loc in locations if loc in _TARGET_LOCATIONS]
        if not representable:
            evaluation.unknown.append("parameter_location")
            evaluation.details.append(
                "pattern parameter locations have no target-side "
                "representation (target vocabulary is query/body)"
            )
        elif not details_by_param:
            evaluation.unknown.append("parameter_location")
            evaluation.details.append(
                "pattern specifies parameter locations but the "
                "target exposes no parameter provenance"
            )
        else:
            hit = False
            for entry in surface:
                location = entry.parameter_location
                if location not in _TARGET_LOCATIONS:
                    continue
                if entry.parameter:
                    if location in details_by_param.get(
                        entry.parameter, set()
                    ):
                        hit = True
                elif any(
                    location in known
                    for known in details_by_param.values()
                ):
                    hit = True
            if hit:
                evaluation.matched.append("parameter_location")
                evaluation.details.append(
                    "parameter location observed in target inventory"
                )
            else:
                evaluation.unmatched.append("parameter_location")

    return evaluation


def _evaluate_technology_context(
    pattern: AttackPattern,
    target: TargetIntelligence,
) -> _Evaluation:
    """Match attack technique context against observed technologies."""

    evaluation = _Evaluation()
    labels = sorted(set(pattern.facts.technology_context))
    if not labels:
        return evaluation
    if not target.technologies:
        evaluation.unknown.append("technology_context")
        evaluation.details.append(
            "attack pattern names technology context but the "
            "target exposes no observed technologies"
        )
        return evaluation
    found = False
    for label in labels:
        for tech in target.technologies:
            result = match_technology(
                technology=tech.raw_label,
                vendor="",
                product=label,
            )
            if result is not None:
                found = True
                evaluation.details.append(
                    f"technology context {label!r} ~ technology "
                    f"{tech.raw_label!r} ({result.match_type})"
                )
    if found:
        evaluation.matched.append("technology_context")
    else:
        evaluation.unmatched.append("technology_context")
    return evaluation


def _unmatchable_markers(pattern: Pattern) -> _Evaluation:
    """Record present-but-unrepresentable research content as UNKNOWN.

    Technique, sink, precondition, observable, and required-condition
    content has no deterministic target-side representation. When
    present it is documented as unknown uncertainty rather than
    silently dropped or guessed.
    """

    evaluation = _Evaluation()
    if isinstance(pattern, VulnerabilityPattern):
        if pattern.facts.required_conditions:
            evaluation.unknown.append("required_condition")
        if pattern.facts.observables:
            evaluation.unknown.append("observable")
    else:
        evaluation.unknown.append("technique")
        if pattern.facts.sink_characteristics:
            evaluation.unknown.append("sink_characteristic")
        if pattern.facts.preconditions:
            evaluation.unknown.append("precondition")
        if pattern.facts.expected_observables:
            evaluation.unknown.append("expected_observable")
    if "technique" in evaluation.unknown:
        evaluation.details.append(
            "technique relevance is not determined; technique "
            "content has no target-side representation"
        )
    return evaluation


def _decide_kind(
    *,
    matched: list[str],
    unmatched: list[str],
    unknown: list[str],
) -> str:
    """Closed match-kind decision table (deterministic order)."""

    if "product" in unmatched:
        return "NO_MATCH"
    if "version" in unmatched:
        return "NO_MATCH"
    if not matched:
        if unmatched:
            return "NO_MATCH"
        return "INCONCLUSIVE"
    if not unmatched and not unknown:
        return "MATCH"
    if "version" in unknown and all(
        criterion in ("product",) for criterion in matched
    ):
        # Product matched but the decisive version criterion cannot
        # be evaluated and no other relevance signal exists.
        return "INCONCLUSIVE"
    return "PARTIAL_MATCH"


def _build_explanation(
    *,
    match_kind: str,
    matched: list[str],
    unmatched: list[str],
    unknown: list[str],
    details: list[str],
    pattern: Pattern,
    target: TargetIntelligence,
) -> str:
    if isinstance(pattern, VulnerabilityPattern):
        research = sorted(pattern.facts.vulnerability_ids) or sorted(
            product.product for product in pattern.facts.products
        )
    else:
        research = [pattern.facts.technique]
    parts = [
        f"match_kind={match_kind}",
        f"matched={matched}",
        f"unmatched={unmatched}",
        f"unknown={unknown}",
        f"research={research}",
        f"target={target.program_name}/{target.subdomain}",
        "relevance only, not a vulnerability verdict",
    ]
    parts.extend(f"detail: {detail}" for detail in sorted(details))
    explanation = "; ".join(parts)
    return explanation[:4096]


def match_pattern_to_target(
    pattern: object,
    target: object,
) -> TargetPatternMatch:
    """Deterministically match one pattern to one target.

    Pure function of the two typed inputs: no database lookup, no
    network, no LLM, no subprocess. Each pattern produces an
    independent result; nothing is inferred across patterns or
    across targets. The result binds the target's observation
    snapshot and must be re-evaluated against fresh inventory
    before any future use.
    """

    _check_inputs(pattern, target)
    assert isinstance(
        pattern, (VulnerabilityPattern, AttackPattern)
    )
    assert isinstance(target, TargetIntelligence)
    if not target.program_name or not target.subdomain:
        raise TargetMatchError(
            "target identity (program_name/subdomain) is required"
        )

    evaluation = _Evaluation()
    if isinstance(pattern, VulnerabilityPattern):
        product_eval, candidates = _evaluate_product(pattern, target)
        evaluation.matched.extend(product_eval.matched)
        evaluation.unmatched.extend(product_eval.unmatched)
        evaluation.unknown.extend(product_eval.unknown)
        evaluation.details.extend(product_eval.details)
        version_eval = _evaluate_version(
            pattern,
            candidates,
            product_matched="product" in product_eval.matched,
            product_present=bool(pattern.facts.products),
        )
        evaluation.matched.extend(version_eval.matched)
        evaluation.unmatched.extend(version_eval.unmatched)
        evaluation.unknown.extend(version_eval.unknown)
        evaluation.details.extend(version_eval.details)
        surface_eval = _evaluate_surface(pattern, target)
        evaluation.matched.extend(surface_eval.matched)
        evaluation.unmatched.extend(surface_eval.unmatched)
        evaluation.unknown.extend(surface_eval.unknown)
        evaluation.details.extend(surface_eval.details)
    else:
        context_eval = _evaluate_technology_context(pattern, target)
        evaluation.matched.extend(context_eval.matched)
        evaluation.unmatched.extend(context_eval.unmatched)
        evaluation.unknown.extend(context_eval.unknown)
        evaluation.details.extend(context_eval.details)
    markers = _unmatchable_markers(pattern)
    evaluation.unknown.extend(markers.unknown)
    evaluation.details.extend(markers.details)

    outcome = evaluation.as_outcome()
    matched = list(outcome.matched)
    unmatched = list(outcome.unmatched)
    unknown = list(outcome.unknown)
    match_kind = _decide_kind(
        matched=matched, unmatched=unmatched, unknown=unknown
    )
    score = deterministic_score_for(
        matched=len(matched),
        unmatched=len(unmatched),
        unknown=len(unknown),
    )
    pattern_type = (
        "vulnerability"
        if isinstance(pattern, VulnerabilityPattern)
        else "attack"
    )
    explanation = _build_explanation(
        match_kind=match_kind,
        matched=matched,
        unmatched=unmatched,
        unknown=unknown,
        details=list(outcome.details),
        pattern=pattern,
        target=target,
    )
    return TargetPatternMatch(
        match_id=match_id_for(
            pattern_id=pattern.pattern_id,
            target_key=target.target_key,
            snapshot_hash=target.snapshot_hash,
            matched_criteria=matched,
            unmatched_criteria=unmatched,
            unknown_criteria=unknown,
        ),
        pattern_id=pattern.pattern_id,
        pattern_type=pattern_type,
        target_key=target.target_key,
        snapshot_hash=target.snapshot_hash,
        program_name=target.program_name,
        subdomain=target.subdomain,
        match_kind=match_kind,
        matched_criteria=matched,  # type: ignore[list-item]
        unmatched_criteria=unmatched,  # type: ignore[list-item]
        unknown_criteria=unknown,  # type: ignore[list-item]
        deterministic_score=score,
        explanation=explanation,
        matcher_version=MATCHER_VERSION,
    )


def match_patterns_to_target(
    patterns: object,
    target: object,
) -> list[TargetPatternMatch]:
    """Match independent patterns to one target, ordered by id.

    Each pattern is evaluated independently: no pattern influences
    another, no global score is produced, and input order does not
    affect the output.
    """

    if not isinstance(patterns, (list, tuple)):
        raise TypeError(
            "match_patterns_to_target accepts a list or tuple of "
            f"patterns, not {type(patterns).__name__}"
        )
    results = [
        match_pattern_to_target(pattern, target) for pattern in patterns
    ]
    return sorted(results, key=lambda item: item.pattern_id)


__all__ = [
    "Pattern",
    "CriterionOutcome",
    "TargetMatchError",
    "match_pattern_to_target",
    "match_patterns_to_target",
]
