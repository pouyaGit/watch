"""Deterministic Hypothesis Engine (Phase 4A).

Converts eligible deterministic relevance matches into Phase 1
Hypothesis objects::

    TargetPatternMatch
            +
    bound Research Pattern (VulnerabilityPattern / AttackPattern)
            +
    bound Target Intelligence snapshot
            |
            v
    Hypothesis (RELEVANCE PROPOSAL ONLY)

The engine is PURE and DETERMINISTIC:

- NO LLM calls, NO embeddings, NO model routers.
- NO network access.
- NO subprocess execution.
- NO database reads or writes (batch resolvers are
  caller-provided, read-only, dependency-injected callables).
- NO scope decisions (``ai/correlator/scope_policy.py`` is never
  imported or called; scope strings are copied as observed,
  descriptive data only).
- NO TestPlans, NO execution, NO findings, NO verdicts.

The engine NEVER claims the target is vulnerable. It creates a
structured research hypothesis stating that a specific pattern is
relevant enough to a specific target snapshot to be considered
for future testing. Every Hypothesis it emits:

- is deterministic (same inputs → same identity),
- is content-bound (pattern id + match id + snapshot hash in the
  idempotency basis),
- is idempotent (repeats and reorderings converge),
- preserves provenance verbatim (never manufactures IDs),
- is target-bound and snapshot-bound (stale snapshots cannot
  collide),
- stays PROPOSED, non-authoritative, and non-executable.

Priority (adversarial-review B4): untrusted research text MUST NOT
control priority or execution. The engine sets the neutral
``priority=0.0`` with a deterministic neutral basis on every
Hypothesis; pattern interpretation, severity, CVSS, urgency prose,
and instruction-shaped text are never read and cannot influence
any field. Priority is NOT execution authority.

Target re-resolution invariant: the emitted Hypothesis records the
observation snapshot it was built against
(``technology_snapshot``, ``snapshot_hash``, ``observed_at``).
Any future executor MUST re-resolve the canonical target, current
scope, and current inventory before acting; this artifact grants
nothing and its ``scope`` field is descriptive inventory data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Sequence

from ai.schemas.hypothesis import (
    Hypothesis,
    ResearchProvenance,
    TargetRef,
    build_hypothesis,
)
from ai.schemas.research_pattern import (
    AttackPattern,
    VulnerabilityPattern,
)
from ai.schemas.target_intelligence import TargetIntelligence
from ai.schemas.target_match import TargetPatternMatch

Pattern = VulnerabilityPattern | AttackPattern

EngineOutcome = Literal["CREATED", "SKIPPED", "REJECTED"]

#: Match kinds eligible for hypothesis creation. A MATCH does NOT
#: mean vulnerable; a PARTIAL_MATCH does NOT mean vulnerable. Both
#: mean only that deterministic relevance evidence exists.
ELIGIBLE_MATCH_KINDS = frozenset({"MATCH", "PARTIAL_MATCH"})

#: Neutral priority: relevance is not execution priority.
NEUTRAL_PRIORITY = 0.0
NEUTRAL_PRIORITY_BASIS = (
    "deterministic-neutral: match relevance is not execution "
    "priority and grants no scope or execution authorization"
)


@dataclass(frozen=True)
class EngineResult:
    """Deterministic outcome of one match → hypothesis evaluation.

    ``CREATED`` carries the Hypothesis; ``SKIPPED`` marks a
    legitimate ineligible match (NO_MATCH / INCONCLUSIVE) that must
    never silently become a hypothesis; ``REJECTED`` marks a
    binding failure (pattern/target mismatch, unresolvable
    reference). ``reason`` is deterministic text; ``match_id`` is
    the evaluated match ("" when the input itself was unusable).
    """

    outcome: EngineOutcome
    hypothesis: Hypothesis | None
    reason: str
    match_id: str


def _pattern_kind_for(pattern: Pattern) -> str:
    """Closed PatternKind derived from structured facts only.

    AttackPattern → "technique". VulnerabilityPattern → "cve" when
    any identifier is CVE-shaped, "ghsa" when any is GHSA-shaped,
    else "knowledge_claim" (research-derived, the honest default
    for product-anchored patterns). Severity/CVSS/urgency prose is
    never consulted.
    """

    if isinstance(pattern, AttackPattern):
        return "technique"
    identifiers = pattern.facts.vulnerability_ids
    if any(item.startswith("CVE-") for item in identifiers):
        return "cve"
    if any(item.startswith("GHSA-") for item in identifiers):
        return "ghsa"
    return "knowledge_claim"


def _hypothesis_type_for(pattern: Pattern) -> str:
    """Closed HypothesisType derived from the pattern contract."""

    if isinstance(pattern, AttackPattern):
        return "technique_relevance"
    return "vulnerability_relevance"


def _endpoint_for(pattern: Pattern, target: TargetIntelligence) -> str:
    """Descriptive matched endpoint, or "" when none matched.

    The smallest sorted pattern surface path observed in the
    target inventory. Deterministic; descriptive only — executors
    re-resolve targets before acting.
    """

    if not isinstance(pattern, VulnerabilityPattern):
        return ""
    target_paths = {
        item.path for item in target.endpoint_observations
    } | {item.path for item in target.url_observations}
    matched = sorted(
        {
            entry.path
            for entry in pattern.facts.attack_surface
            if entry.path and entry.path in target_paths
        }
    )
    return matched[0] if matched else ""


def _build_statement(
    *,
    match_kind: str,
    match_id: str,
    pattern_id: str,
    program_name: str,
    subdomain: str,
    snapshot_hash: str,
    matched: Sequence[str],
    unmatched: Sequence[str],
    unknown: Sequence[str],
) -> str:
    """Deterministic relevance statement from structured fields only.

    Uses IDs, the closed match kind, and criteria lists. Free-form
    pattern prose (titles, technique labels, rationale) is NEVER
    interpolated, so hostile research text cannot smuggle verdict
    or command language into the statement. Every input is
    schema-constrained (regex IDs, single-line names, closed
    criteria), so the statement is single-line by construction.
    """

    return (
        f"Research pattern {pattern_id} shows {match_kind} "
        f"relevance to target {program_name}/{subdomain} at "
        f"snapshot {snapshot_hash} (match {match_id}); matched "
        f"criteria: {sorted(matched)}; unmatched criteria: "
        f"{sorted(unmatched)}; unknown criteria: "
        f"{sorted(unknown)}. This is a relevance hypothesis "
        f"only: it does not assert the target is affected and "
        f"grants no scope or execution authorization. Any "
        f"future testing must re-resolve the canonical target "
        f"and scope."
    )


def build_hypothesis_from_match(
    match: object,
    pattern: object,
    target_intelligence: object,
) -> EngineResult:
    """Build one Hypothesis from one bound match triple.

    Pure function: no lookup, no network, no LLM, no subprocess,
    no database. Wrong Python types fail closed with TypeError
    (raw dicts/strings/IDs are never coerced). Binding failures
    yield REJECTED; ineligible match kinds yield SKIPPED; only
    MATCH/PARTIAL_MATCH with fully consistent bindings yields
    CREATED.
    """

    if not isinstance(match, TargetPatternMatch):
        raise TypeError(
            "build_hypothesis_from_match accepts only "
            "TargetPatternMatch, not "
            f"{type(match).__name__}; raw dicts are never coerced"
        )
    if not isinstance(
        pattern, (VulnerabilityPattern, AttackPattern)
    ):
        raise TypeError(
            "build_hypothesis_from_match accepts only "
            "VulnerabilityPattern or AttackPattern, not "
            f"{type(pattern).__name__}"
        )
    if not isinstance(target_intelligence, TargetIntelligence):
        raise TypeError(
            "build_hypothesis_from_match accepts only "
            "TargetIntelligence, not "
            f"{type(target_intelligence).__name__}"
        )

    target = target_intelligence

    if match.pattern_id != pattern.pattern_id:
        return EngineResult(
            outcome="REJECTED",
            hypothesis=None,
            reason=(
                "pattern binding mismatch: match references "
                f"{match.pattern_id!r} but pattern is "
                f"{pattern.pattern_id!r}; substitution is forbidden"
            ),
            match_id=match.match_id,
        )

    expected_type = (
        VulnerabilityPattern
        if match.pattern_type == "vulnerability"
        else AttackPattern
    )
    if not isinstance(pattern, expected_type):
        return EngineResult(
            outcome="REJECTED",
            hypothesis=None,
            reason=(
                f"pattern type mismatch: {match.pattern_type!r} "
                "match requires "
                f"{expected_type.__name__}, not "
                f"{type(pattern).__name__}"
            ),
            match_id=match.match_id,
        )

    for field in (
        "target_key",
        "snapshot_hash",
        "program_name",
        "subdomain",
    ):
        if getattr(match, field) != getattr(target, field):
            return EngineResult(
                outcome="REJECTED",
                hypothesis=None,
                reason=(
                    f"target binding mismatch on {field!r}: match "
                    "and target intelligence disagree; target "
                    "identity is never inferred"
                ),
                match_id=match.match_id,
            )
    if not target.program_name or not target.subdomain:
        return EngineResult(
            outcome="REJECTED",
            hypothesis=None,
            reason="target identity (program_name/subdomain) "
            "is required",
            match_id=match.match_id,
        )

    if match.match_kind not in ELIGIBLE_MATCH_KINDS:
        return EngineResult(
            outcome="SKIPPED",
            hypothesis=None,
            reason=(
                f"match kind {match.match_kind!r} is not eligible; "
                "only MATCH and PARTIAL_MATCH may become "
                "hypotheses, and neither asserts vulnerability"
            ),
            match_id=match.match_id,
        )

    hypothesis_type = _hypothesis_type_for(pattern)
    pattern_kind = _pattern_kind_for(pattern)
    statement = _build_statement(
        match_kind=match.match_kind,
        match_id=match.match_id,
        pattern_id=pattern.pattern_id,
        program_name=target.program_name,
        subdomain=target.subdomain,
        snapshot_hash=target.snapshot_hash,
        matched=list(match.matched_criteria),
        unmatched=list(match.unmatched_criteria),
        unknown=list(match.unknown_criteria),
    )
    target_ref = TargetRef(
        program_name=target.program_name,
        subdomain=target.subdomain,
        scope=target.scope_snapshot.subdomain_scope,
        endpoint=_endpoint_for(pattern, target),
        technology_snapshot=sorted(
            {tech.raw_label for tech in target.technologies}
        ),
        observed_at=target.observed_at,
    )
    provenance = ResearchProvenance.model_validate(
        pattern.provenance.model_dump(mode="json")
    )
    hypothesis = build_hypothesis(
        target=target_ref,
        hypothesis_type=hypothesis_type,
        statement=statement,
        pattern_kind=pattern_kind,
        pattern_id=pattern.pattern_id,
        provenance=provenance,
        priority=NEUTRAL_PRIORITY,
        priority_basis=(
            f"{NEUTRAL_PRIORITY_BASIS}; "
            f"match_kind={match.match_kind}"
        ),
        match_id=match.match_id,
        snapshot_hash=target.snapshot_hash,
    )
    return EngineResult(
        outcome="CREATED",
        hypothesis=hypothesis,
        reason=(
            f"hypothesis {hypothesis.hypothesis_id} created from "
            f"{match.match_kind} match {match.match_id}"
        ),
        match_id=match.match_id,
    )


def build_hypotheses_from_matches(
    matches: object,
    pattern_resolver: object,
    target_resolver: object,
) -> tuple[EngineResult, ...]:
    """Build hypotheses for a batch of matches via read-only resolvers.

    ``pattern_resolver(pattern_id)`` returns the bound pattern or
    None; ``target_resolver(target_key)`` returns the bound
    TargetIntelligence or None. Resolvers are never called with
    anything but string IDs and their results are re-validated by
    the single-match binding checks, so a hostile or stale
    resolver cannot smuggle a substitution past the engine.

    Each match is evaluated independently: no cross-match
    inference, no global ranking, no priority escalation, no
    target merging. Results are deduplicated by match_id (first
    occurrence wins) and sorted by match_id. One bad record
    yields its own SKIPPED/REJECTED entry and never affects
    another. This is NOT a scheduler: outputs are unordered
    proposals, one per eligible match.
    """

    if not isinstance(matches, (list, tuple)):
        raise TypeError(
            "build_hypotheses_from_matches accepts a list or "
            f"tuple of matches, not {type(matches).__name__}"
        )
    if not callable(pattern_resolver) or not callable(
        target_resolver
    ):
        raise TypeError(
            "resolvers must be callable read-only lookups"
        )

    seen: set[str] = set()
    results: list[EngineResult] = []
    for match in matches:
        if not isinstance(match, TargetPatternMatch):
            raise TypeError(
                "batch elements must be TargetPatternMatch, not "
                f"{type(match).__name__}"
            )
        if match.match_id in seen:
            continue
        seen.add(match.match_id)
        pattern = pattern_resolver(match.pattern_id)  # type: ignore[operator]
        target = target_resolver(match.target_key)  # type: ignore[operator]
        if pattern is None or target is None:
            missing = (
                "pattern"
                if pattern is None
                else "target intelligence"
            )
            results.append(
                EngineResult(
                    outcome="REJECTED",
                    hypothesis=None,
                    reason=(
                        f"unresolvable {missing} reference for "
                        f"match {match.match_id}; the engine "
                        "performs no lookup of its own"
                    ),
                    match_id=match.match_id,
                )
            )
            continue
        try:
            results.append(
                build_hypothesis_from_match(match, pattern, target)
            )
        except TypeError as exc:
            results.append(
                EngineResult(
                    outcome="REJECTED",
                    hypothesis=None,
                    reason=f"resolver returned unusable object: {exc}",
                    match_id=match.match_id,
                )
            )
    results.sort(key=lambda item: item.match_id)
    return tuple(results)


__all__ = [
    "Pattern",
    "ELIGIBLE_MATCH_KINDS",
    "EngineOutcome",
    "EngineResult",
    "NEUTRAL_PRIORITY",
    "NEUTRAL_PRIORITY_BASIS",
    "build_hypotheses_from_matches",
    "build_hypothesis_from_match",
]
