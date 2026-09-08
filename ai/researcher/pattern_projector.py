"""Deterministic Pattern Projector (Phase 2B).

Converts already validated, grounded research claims into normalized
research patterns (:class:`VulnerabilityPattern` /
:class:`AttackPattern` from ``ai/schemas/research_pattern.py``).

The projector is a PURE, DETERMINISTIC transformation:

- NO LLM calls.
- NO network access.
- NO subprocess execution.
- NO target-applicability, scope, finding, or verdict decisions.

Input trust boundary
---------------------

The projector accepts ONLY :class:`GroundedClaim` objects. A
``GroundedClaim`` wraps one of the repository's existing validated
claim types -- :class:`ai.schemas.ingestion.ExtractedClaim` or
:class:`ai.schemas.knowledge.KnowledgeSourceClaims` -- together with
the stable provenance IDs assigned by the existing grounding/store
boundary (``clm-...``, ``kb-...``, ``src-...``, full content hashes).

Raw research text (``ResearchItem.text`` / ``SourceDocument.content``)
can NEVER become pattern facts: :func:`project_claim` raises
``TypeError`` for anything that is not a ``GroundedClaim``.

Trust classification is PRESERVED, never created: only claims whose
upstream evidence class already marks them as grounded (``EXPLICIT``
or ``STRONGLY_IMPLIED`` for :class:`ExtractedClaim`;
``PRIMARY``/``HIGH_CONFIDENCE``/``SECONDARY`` for
:class:`KnowledgeSourceClaims`) can be wrapped. ``MODEL_INFERENCE``
/ ``UNVERIFIED`` / ``UNKNOWN`` claims are rejected at the
``GroundedClaim`` boundary. Model reasoning (``rationale``,
``confidence``) is preserved ONLY in ``Pattern.interpretation``
(audit-only, identity-excluded) and can never reach ``facts``.

Claim -> Pattern mapping (actual repository fields only)
--------------------------------------------------------

``ExtractedClaim`` / ``KnowledgeSourceClaims`` carry NO
``cve_id``/``product``/``affected_version``/``endpoint``/``parameter``/
``sink``/``preconditions`` fields, so the corresponding mappings from
the task brief are explicitly UNSUPPORTED (see ``UNMAPPED_FIELDS``).
The supported mapping is:

- ``claim.technologies`` -> ``VulnerabilityFacts.products`` (one
  :class:`ProductIdentity` per distinct technology) and
  ``AttackFacts.technology_context``.
- ``claim.techniques`` -> ``AttackFacts.technique`` (one
  :class:`AttackPattern` per distinct technique label).
- ``claim.contexts`` -> ``AttackFacts.sink_characteristics``.
- ``claim.payload_patterns`` -> ``AttackFacts.input_characteristics``.
- ``claim.verification_patterns`` -> ``expected_observables`` /
  ``observables`` (``observation_kind="behavior"`` expectations,
  never evidence).
- ``claim.title`` / ``claim.summary`` -> pattern ``title`` /
  ``description`` (display prose only, identity-excluded).
- ``claim.rationale`` / ``claim.confidence`` ->
  ``Pattern.interpretation`` (audit-only).
- ``claim.xss_types`` / ``claim.wafs`` / ``claim.tags`` /
  ``claim.evidence_class`` -> ``interpretation.classification_hints``
  (grounded-but-unprojectable metadata preserved audit-only so it is
  neither silently discarded nor escalated into facts).
- wrapper ``claim_id`` / ``knowledge_id`` / ``source_id`` /
  ``research_hash`` -> ``ResearchProvenance``.

Unsupported (documented, never guessed): vulnerability identifiers
(CVE/GHSA/CWE), version constraints, attack-surface endpoints/paths/
methods/parameters, required conditions/preconditions, severity/CVSS.

Projection is conservative: a pattern is produced ONLY when the
structured claim content satisfies the Phase 2A contract minimums
(VP: >= 1 product; AP: technique + >= 1 sink characteristic or
expected observable). Anything else is skipped with a structured
reason. Pattern validation failures fail closed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Literal, Sequence, Union

from pydantic import ValidationError

from ai.ingestion.grounding import contains_forbidden
from ai.schemas.hypothesis import ResearchProvenance
from ai.schemas.ingestion import ExtractedClaim
from ai.schemas.knowledge import KnowledgeSourceClaims
from ai.schemas.research_pattern import (
    AttackPattern,
    ModelInterpretation,
    ObservableCharacteristic,
    ProductIdentity,
    VulnerabilityPattern,
    build_attack_pattern,
    build_vulnerability_pattern,
)

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

#: Claim fields from the task brief that do NOT exist on the actual
#: repository claim types and are therefore never projected. Listed
#: explicitly so the gap is auditable instead of silently ignored.
UNMAPPED_FIELDS: tuple[str, ...] = (
    "cve_id",
    "affected_version",
    "endpoint",
    "parameter",
    "observation",
    "sink",
    "preconditions",
)

#: Evidence classes of ExtractedClaim that already crossed the
#: grounding boundary (MODEL_INFERENCE claims are quarantined by
#: ai/ingestion/agent.py and never become trusted knowledge).
_TRUSTED_EVIDENCE_CLASSES: frozenset[str] = frozenset(
    {"EXPLICIT", "STRONGLY_IMPLIED"}
)

#: Evidence qualities of KnowledgeSourceClaims that correspond to
#: grounded claims (MODEL_INFERENCE projects to UNVERIFIED).
_TRUSTED_EVIDENCE_QUALITIES: frozenset[str] = frozenset(
    {"PRIMARY", "HIGH_CONFIDENCE", "SECONDARY"}
)

_CLM_ID_RE = re.compile(r"^clm-[0-9a-f]{16}$")
_KB_ID_RE = re.compile(r"^kb-[0-9a-f]{16}$")
_SRC_ID_RE = re.compile(r"^src-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SkipReason = Literal[
    "ungrounded_evidence_class",
    "missing_provenance",
    "insufficient_information",
    "validation_failed",
    "forbidden_content",
    "unsupported_claim",
]

Pattern = Union[VulnerabilityPattern, AttackPattern]


# ------------------------------------------------------------------
# Input: GroundedClaim
# ------------------------------------------------------------------


def _check_id(value: str | None, pattern: re.Pattern[str], name: str) -> None:
    if value is None:
        return
    if not pattern.match(value):
        raise ValueError(f"invalid {name}: {value!r}")


@dataclass(frozen=True)
class GroundedClaim:
    """One already validated/grounded claim plus its stable provenance.

    Wraps the repository's EXISTING claim types without duplicating
    them: ``claim`` is either an :class:`ExtractedClaim` that passed
    the ingestion grounding boundary or a :class:`KnowledgeSourceClaims`
    read back from the :class:`KnowledgeStore` (which stamps the stable
    ``claim_id``). The wrapper only adds the provenance IDs assigned
    by that boundary; it performs no grounding itself.

    Construction fails closed: ungrounded evidence classes, malformed
    IDs, and claims without supporting evidence snippets (for the
    :class:`ExtractedClaim` form) raise ``ValueError``.
    """

    claim: ExtractedClaim | KnowledgeSourceClaims
    claim_id: str
    knowledge_id: str | None = None
    source_id: str | None = None
    research_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(
            self.claim, (ExtractedClaim, KnowledgeSourceClaims)
        ):
            raise TypeError(
                "GroundedClaim.claim must be an ExtractedClaim or "
                f"KnowledgeSourceClaims, not {type(self.claim).__name__}; "
                "raw research text can never be projected"
            )
        if not _CLM_ID_RE.match(self.claim_id or ""):
            raise ValueError(
                f"invalid claim_id: {self.claim_id!r}; patterns must "
                "cite a stable grounded claim"
            )
        _check_id(self.knowledge_id, _KB_ID_RE, "knowledge_id")
        _check_id(self.source_id, _SRC_ID_RE, "source_id")
        _check_id(self.research_hash, _SHA256_RE, "research_hash")

        if isinstance(self.claim, ExtractedClaim):
            if (
                self.claim.evidence_class
                not in _TRUSTED_EVIDENCE_CLASSES
            ):
                raise ValueError(
                    f"evidence_class={self.claim.evidence_class!r} is "
                    "not grounded; MODEL_INFERENCE claims are "
                    "quarantined and can never be projected"
                )
            if not self.claim.evidence_snippets:
                raise ValueError(
                    "ExtractedClaim without evidence_snippets is "
                    "not grounded and can never be projected"
                )
        else:
            if (
                self.claim.evidence_quality
                not in _TRUSTED_EVIDENCE_QUALITIES
            ):
                raise ValueError(
                    "evidence_quality="
                    f"{self.claim.evidence_quality!r} is not grounded; "
                    "UNVERIFIED/UNKNOWN claims can never be projected"
                )

    def fingerprint(self) -> str:
        """Deterministic, order-independent identity of this input."""

        payload = {
            "claim": self.claim.model_dump(mode="json"),
            "claim_id": self.claim_id,
            "knowledge_id": self.knowledge_id,
            "research_hash": self.research_hash,
            "source_id": self.source_id,
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------
# Result types
# ------------------------------------------------------------------


@dataclass(frozen=True)
class ProjectionSkip:
    """One claim (or claim group) that produced no pattern, and why."""

    claim_id: str
    reason: SkipReason
    detail: str


@dataclass(frozen=True)
class ProjectionResult:
    """Deterministic outcome of projecting a batch of grounded claims."""

    patterns: tuple[Pattern, ...] = field(default_factory=tuple)
    skipped: tuple[ProjectionSkip, ...] = field(default_factory=tuple)


# ------------------------------------------------------------------
# Normalization helpers (deterministic, order-independent)
# ------------------------------------------------------------------


def _collapse_whitespace(value: str) -> str:
    return " ".join(value.split())


def _dedupe_labels(
    values: Sequence[str], *, strict: bool = True
) -> list[str]:
    """Clean, dedupe (case-insensitively), and sort label strings.

    Strict mode (default, used for every ``facts`` input) fails
    closed on embedded newlines: they are rejected, never silently
    normalized away. Non-strict mode (audit-only interpretation
    hints) drops newline-carrying values instead of killing the
    whole pattern over display metadata.
    """

    best: dict[str, str] = {}
    for raw in values:
        if not isinstance(raw, str):
            continue
        if "\n" in raw or "\r" in raw:
            if strict:
                raise ValueError(
                    f"label contains a forbidden newline: {raw!r}"
                )
            continue
        cleaned = _collapse_whitespace(raw)
        if not cleaned:
            continue
        key = cleaned.casefold()
        if key not in best or cleaned < best[key]:
            best[key] = cleaned
    return sorted(best.values())


def _is_safe_label(value: str) -> bool:
    """Reject newlines and executable payload constructs (fail closed)."""

    if "\n" in value or "\r" in value:
        return False
    if len(value) > 256:
        return False
    return not contains_forbidden(value)


def _claim_text(claim: ExtractedClaim | KnowledgeSourceClaims) -> tuple[
    list[str], list[str], list[str], list[str], list[str], list[str]
]:
    """Return (technologies, techniques, contexts, payloads, verifs, tags)."""

    return (
        list(claim.technologies),
        list(claim.techniques),
        list(claim.contexts),
        list(claim.payload_patterns),
        list(claim.verification_patterns),
        list(claim.tags),
    )


def _provenance_for(grounded: GroundedClaim) -> ResearchProvenance:
    return ResearchProvenance(
        knowledge_ids=(
            [grounded.knowledge_id] if grounded.knowledge_id else []
        ),
        source_ids=([grounded.source_id] if grounded.source_id else []),
        claim_ids=[grounded.claim_id],
        research_hashes=(
            [grounded.research_hash] if grounded.research_hash else []
        ),
    )


def _interpretation_for(
    grounded: GroundedClaim,
) -> ModelInterpretation:
    """Preserve model reasoning and unprojectable metadata audit-only.

    ``rationale``/``confidence`` are model-side content and stay in
    ``interpretation``. Grounded-but-unprojectable fields
    (``xss_types``/``wafs``/``tags``/``evidence_class``) are kept as
    classification hints so they are not silently discarded -- while
    remaining identity-excluded and unreachable from ``facts``.
    """

    claim = grounded.claim
    hints: list[str] = []
    if isinstance(claim, ExtractedClaim):
        hints.append(f"evidence_class:{claim.evidence_class}")
    else:
        hints.append(
            f"evidence_quality:{claim.evidence_quality}"
        )
    for value in _dedupe_labels(list(claim.xss_types), strict=False):
        hints.append(f"xss_type:{value}")
    for value in _dedupe_labels(list(claim.wafs), strict=False):
        hints.append(f"waf:{value}")
    for value in _dedupe_labels(list(claim.tags), strict=False):
        hints.append(f"tag:{value}")
    hints = sorted(set(hints))
    # Hints are audit-only: drop (never escalate) anything the fact
    # validators would reject instead of failing the whole pattern.
    hints = [
        hint
        for hint in hints
        if len(hint) <= 256 and _is_safe_label(hint)
    ]

    rationale = ""
    if isinstance(claim, ExtractedClaim) and claim.rationale:
        rationale = _collapse_whitespace(claim.rationale)[:2048]

    return ModelInterpretation(
        classification_hints=hints,
        rationale=rationale,
        confidence=float(claim.confidence),
    )


def _title_description(
    claim: ExtractedClaim | KnowledgeSourceClaims,
    fallback_title: str,
    fallback_description: str,
) -> tuple[str, str]:
    title = (
        claim.title
        if claim.title and claim.title.strip()
        else fallback_title
    )
    description = (
        claim.summary
        if claim.summary and claim.summary.strip()
        else fallback_description
    )
    # Display prose only (identity-excluded): fail closed on
    # newlines and executable constructs, truncate deterministically
    # on length.
    for text in (title, description):
        if "\n" in text or "\r" in text:
            raise ValueError(
                "claim title/summary contains a forbidden newline"
            )
        if contains_forbidden(text):
            raise ValueError(
                "claim title/summary contains forbidden content"
            )
    title = _collapse_whitespace(title)
    description = _collapse_whitespace(description)
    return title[:2048], description[:2048]


# ------------------------------------------------------------------
# Single-claim projection
# ------------------------------------------------------------------


def _project_vulnerability(
    grounded: GroundedClaim,
    technologies: list[str],
    verification_labels: list[str],
) -> VulnerabilityPattern | None:
    """Build a VulnerabilityPattern or return None (insufficient)."""

    if not technologies:
        return None
    for technology in technologies:
        if not _is_safe_label(technology):
            raise ValueError(
                f"unsafe technology label: {technology!r}"
            )
    products = [
        ProductIdentity(product=technology)
        for technology in technologies
    ]

    observables = []
    for label in verification_labels:
        if not _is_safe_label(label):
            raise ValueError(
                f"unsafe verification label: {label!r}"
            )
        observables.append(
            ObservableCharacteristic(
                observation_kind="behavior",
                description=label,
            )
        )

    claim = grounded.claim
    fallback_title = (
        f"Vulnerability pattern: {technologies[0]}"
        if len(technologies) == 1
        else f"Vulnerability pattern: {len(technologies)} products"
    )
    title, description = _title_description(
        claim,
        fallback_title,
        f"Research-derived vulnerability pattern projected from "
        f"grounded claim {grounded.claim_id}.",
    )
    return build_vulnerability_pattern(
        pattern_kind="PRODUCT_VULNERABILITY",
        title=title,
        description=description,
        facts={
            "products": products,
            "observables": observables,
        },
        provenance=_provenance_for(grounded),
        interpretation=_interpretation_for(grounded),
    )


def _project_attacks(
    grounded: GroundedClaim,
    techniques: list[str],
    technologies: list[str],
    contexts: list[str],
    payload_labels: list[str],
    verification_labels: list[str],
) -> list[AttackPattern]:
    """Build one AttackPattern per distinct technique label."""

    patterns: list[AttackPattern] = []
    for technique in techniques:
        if not _is_safe_label(technique):
            raise ValueError(
                f"unsafe technique label: {technique!r}"
            )
        for label in (
            list(contexts)
            + list(payload_labels)
            + list(verification_labels)
            + list(technologies)
        ):
            if not _is_safe_label(label):
                raise ValueError(f"unsafe attack label: {label!r}")
        if not (contexts or verification_labels):
            # Phase 2A contract: technique alone is not projectable.
            continue
        claim = grounded.claim
        title, description = _title_description(
            claim,
            f"Attack technique: {technique}",
            f"Reusable attack technique {technique!r} projected from "
            f"grounded claim {grounded.claim_id}.",
        )
        patterns.append(
            build_attack_pattern(
                pattern_kind="TECHNIQUE",
                title=title,
                description=description,
                facts={
                    "technique": technique,
                    "input_characteristics": list(payload_labels),
                    "sink_characteristics": list(contexts),
                    "expected_observables": [
                        {
                            "observation_kind": "behavior",
                            "description": label,
                        }
                        for label in verification_labels
                    ],
                    "technology_context": list(technologies),
                },
                provenance=_provenance_for(grounded),
                interpretation=_interpretation_for(grounded),
            )
        )
    return patterns


def project_claim(claim: object) -> list[Pattern]:
    """Project one grounded claim to 0+ normalized patterns.

    Returns a (possibly empty) list of typed pattern objects built
    through the Phase 2A factories. An empty list means the claim
    was safely skipped (insufficient information); a
    :class:`ValueError` means the claim carried forbidden content or
    failed pattern validation (fail closed). Anything that is not a
    :class:`GroundedClaim` raises ``TypeError`` -- raw research text
    can never become a pattern.
    """

    if not isinstance(claim, GroundedClaim):
        raise TypeError(
            "project_claim accepts only GroundedClaim objects, not "
            f"{type(claim).__name__}; raw research text must first "
            "cross the ingestion grounding boundary"
        )
    grounded = claim
    (
        technologies_raw,
        techniques_raw,
        contexts_raw,
        payloads_raw,
        verifs_raw,
        _tags,
    ) = _claim_text(grounded.claim)

    technologies = _dedupe_labels(technologies_raw)
    techniques = _dedupe_labels(techniques_raw)
    contexts = _dedupe_labels(contexts_raw)
    payloads = _dedupe_labels(payloads_raw)
    verifs = _dedupe_labels(verifs_raw)

    patterns: list[Pattern] = []
    vulnerability = _project_vulnerability(
        grounded, technologies, verifs
    )
    if vulnerability is not None:
        patterns.append(vulnerability)
    patterns.extend(
        _project_attacks(
            grounded,
            techniques,
            technologies,
            contexts,
            payloads,
            verifs,
        )
    )
    return sorted(patterns, key=lambda item: item.pattern_id)


# ------------------------------------------------------------------
# Multi-claim projection (deterministic merge)
# ------------------------------------------------------------------


def _merge_group(
    representative: Pattern, claim_ids: list[str], grounded_by_id: dict
) -> Pattern:
    """Rebuild one pattern over the union provenance (deterministic)."""

    provenance = ResearchProvenance(
        knowledge_ids=sorted(
            {
                known
                for cid in claim_ids
                for known in (
                    [grounded_by_id[cid].knowledge_id]
                    if grounded_by_id[cid].knowledge_id
                    else []
                )
            }
        ),
        source_ids=sorted(
            {
                known
                for cid in claim_ids
                for known in (
                    [grounded_by_id[cid].source_id]
                    if grounded_by_id[cid].source_id
                    else []
                )
            }
        ),
        claim_ids=sorted(set(claim_ids)),
        research_hashes=sorted(
            {
                known
                for cid in claim_ids
                for known in (
                    [grounded_by_id[cid].research_hash]
                    if grounded_by_id[cid].research_hash
                    else []
                )
            }
        ),
    )
    # Interpretation merge is deterministic and audit-only
    # (identity-excluded): union of hints, joined rationales,
    # maximum self-reported confidence.
    hints = sorted(
        {
            hint
            for cid in claim_ids
            for hint in _interpretation_for(
                grounded_by_id[cid]
            ).classification_hints
        }
    )
    rationales = sorted(
        {
            _interpretation_for(
                grounded_by_id[cid]
            ).rationale.strip()
            for cid in claim_ids
            if _interpretation_for(
                grounded_by_id[cid]
            ).rationale.strip()
        }
    )
    confidence = max(
        float(grounded_by_id[cid].claim.confidence)
        for cid in claim_ids
    )
    interpretation = ModelInterpretation(
        classification_hints=hints[:256],
        rationale=" | ".join(rationales)[:2048],
        confidence=confidence,
    )
    if isinstance(representative, VulnerabilityPattern):
        return build_vulnerability_pattern(
            pattern_kind=representative.pattern_kind,
            title=representative.title,
            description=representative.description,
            facts=representative.facts,
            provenance=provenance,
            interpretation=interpretation,
        )
    return build_attack_pattern(
        pattern_kind=representative.pattern_kind,
        title=representative.title,
        description=representative.description,
        facts=representative.facts,
        provenance=provenance,
        interpretation=interpretation,
    )


def project_claims(claims: Sequence[object]) -> ProjectionResult:
    """Project a batch of grounded claims to normalized patterns.

    Deterministic: input order does not affect the output. Claims
    describing the same semantic pattern (equal ``semantic_key``)
    are merged into one pattern over the union provenance;
    duplicate claims collapse to a single provenance entry. One bad
    claim never poisons valid independent patterns: it is recorded
    in ``skipped`` with a structured reason while the rest of the
    batch still projects.
    """

    for item in claims:
        if not isinstance(item, GroundedClaim):
            raise TypeError(
                "project_claims accepts only GroundedClaim objects, "
                f"not {type(item).__name__}"
            )
    ordered = sorted(claims, key=lambda item: item.fingerprint())  # type: ignore[union-attr]
    grounded_by_id: dict[str, GroundedClaim] = {
        item.claim_id: item for item in ordered  # type: ignore[union-attr]
    }

    by_semantic: dict[str, Pattern] = {}
    semantic_claims: dict[str, list[str]] = {}
    skipped: list[ProjectionSkip] = []

    for grounded in ordered:  # type: ignore[union-attr]
        try:
            projected = project_claim(grounded)
        except ValueError as exc:
            reason: SkipReason = (
                "forbidden_content"
                if "unsafe" in str(exc) or "forbidden" in str(exc)
                else "validation_failed"
            )
            skipped.append(
                ProjectionSkip(
                    claim_id=grounded.claim_id,
                    reason=reason,
                    detail=str(exc),
                )
            )
            continue
        if not projected:
            skipped.append(
                ProjectionSkip(
                    claim_id=grounded.claim_id,
                    reason="insufficient_information",
                    detail=(
                        "claim carries no projectable combination: "
                        "VulnerabilityPattern needs >= 1 technology; "
                        "AttackPattern needs a technique plus a sink "
                        "characteristic or expected observable"
                    ),
                )
            )
            continue
        for pattern in projected:
            existing = by_semantic.get(pattern.semantic_key)
            if existing is None:
                by_semantic[pattern.semantic_key] = pattern
                semantic_claims[pattern.semantic_key] = [
                    grounded.claim_id
                ]
            else:
                semantic_claims[pattern.semantic_key].append(
                    grounded.claim_id
                )

    merged: list[Pattern] = []
    for semantic_key in sorted(by_semantic):
        representative = by_semantic[semantic_key]
        claim_ids = sorted(set(semantic_claims[semantic_key]))
        if len(claim_ids) == 1:
            merged.append(representative)
        else:
            try:
                merged.append(
                    _merge_group(
                        representative, claim_ids, grounded_by_id
                    )
                )
            except (ValidationError, ValueError) as exc:
                skipped.append(
                    ProjectionSkip(
                        claim_id=claim_ids[0],
                        reason="validation_failed",
                        detail=f"merge failed: {exc}",
                    )
                )
    merged.sort(key=lambda item: item.pattern_id)
    skipped.sort(key=lambda item: (item.claim_id, item.reason))
    return ProjectionResult(
        patterns=tuple(merged), skipped=tuple(skipped)
    )


__all__ = [
    "Pattern",
    "ProjectionResult",
    "ProjectionSkip",
    "GroundedClaim",
    "SkipReason",
    "UNMAPPED_FIELDS",
    "project_claim",
    "project_claims",
]
