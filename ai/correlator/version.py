from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version


@dataclass
class VersionMatch:
    status: str
    detected_version: str | None
    matched_version: str | None
    reason: str


def extract_version(technology: str) -> str | None:
    """
    Extract a version from technology names such as:

        Nginx:1.30.4
        PHP:5.6.40
        jQuery:3.7.1
        Drupal:10
        IIS:10.0
    """

    if not technology:
        return None

    # First handle common colon format:
    # Technology:1.2.3
    match = re.search(
        r":\s*v?(\d+(?:\.\d+){0,3}(?:[-+._][0-9A-Za-z.-]+)?)$",
        technology,
    )

    if match:
        return match.group(1)

    # Generic fallback for embedded versions.
    match = re.search(
        r"\bv?(\d+\.\d+(?:\.\d+){0,2}(?:[-+._][0-9A-Za-z.-]+)?)\b",
        technology,
    )

    if match:
        return match.group(1)

    return None


def normalize_version(value: str) -> Version | None:
    if not value:
        return None

    value = value.strip()

    try:
        return Version(value)
    except InvalidVersion:
        return None


@dataclass
class ConstraintEvaluation:
    status: str
    reason: str


def evaluate_version_constraint(
    detected_version: str | None,
    *,
    constraint_kind: str,
    version: str | None = None,
    upper_version: str | None = None,
    lower_inclusive: bool = True,
    upper_inclusive: bool = False,
) -> ConstraintEvaluation:
    """
    Evaluate one Phase 2A VersionConstraint against one observed
    version token.

    Pure and deterministic. Reuses normalize_version as the sole
    parsing authority; compare_version is untouched. Returned
    status is one of:

        MATCH        -- observed version deterministically satisfies
                        the research-side constraint.
        MISMATCH     -- observed version deterministically falls
                        outside the constraint.
        INCONCLUSIVE -- either side is missing/unparseable, the
                        constraint kind carries no bound (UNKNOWN),
                        or the semantics cannot decide relevance
                        without guessing (FIXED with an older
                        observed version: the fixed release is known
                        but the affected lower bound is not).

    FIXED semantics: ``version`` is the release research claims
    fixed the issue. An observed version at or newer than the fix
    is deterministically outside relevance (MISMATCH); an older
    observed version is INCONCLUSIVE, never MATCH, because the
    affected range below the fix is unstated.

    MATCH here means only "the version criterion is satisfied". It
    is NOT a vulnerability verdict.
    """

    if constraint_kind == "UNKNOWN":
        return ConstraintEvaluation(
            status="INCONCLUSIVE",
            reason=(
                "Research states no usable version constraint "
                "(UNKNOWN)."
            ),
        )

    if not detected_version:
        return ConstraintEvaluation(
            status="INCONCLUSIVE",
            reason="No version was observed for the technology.",
        )

    detected = normalize_version(detected_version)

    if detected is None:
        return ConstraintEvaluation(
            status="INCONCLUSIVE",
            reason="Observed version could not be parsed.",
        )

    if constraint_kind == "EXACT":
        bound = normalize_version(version or "")

        if bound is None:
            return ConstraintEvaluation(
                status="INCONCLUSIVE",
                reason="EXACT constraint carries no usable version.",
            )

        if detected == bound:
            return ConstraintEvaluation(
                status="MATCH",
                reason=(
                    "Observed version exactly matches the "
                    "research-side affected version."
                ),
            )

        return ConstraintEvaluation(
            status="MISMATCH",
            reason=(
                "Observed version does not equal the "
                "research-side affected version."
            ),
        )

    if constraint_kind == "LOWER_BOUND":
        # ``version`` is the lower bound; no upper bound exists.
        lower = normalize_version(version or "") if version else None

        if lower is None:
            return ConstraintEvaluation(
                status="INCONCLUSIVE",
                reason=(
                    "LOWER_BOUND constraint carries no usable "
                    "lower bound."
                ),
            )

        if lower_inclusive:
            if detected < lower:
                return ConstraintEvaluation(
                    status="MISMATCH",
                    reason=(
                        "Observed version is below the "
                        "research-side lower bound."
                    ),
                )
        elif detected <= lower:
            return ConstraintEvaluation(
                status="MISMATCH",
                reason=(
                    "Observed version is at or below the "
                    "exclusive research-side lower bound."
                ),
            )

        return ConstraintEvaluation(
            status="MATCH",
            reason=(
                "Observed version satisfies the research-side "
                "lower bound."
            ),
        )

    if constraint_kind == "UPPER_BOUND":
        # ``version`` is the upper bound; no lower bound exists.
        upper = normalize_version(version or "") if version else None

        if upper is None:
            return ConstraintEvaluation(
                status="INCONCLUSIVE",
                reason=(
                    "UPPER_BOUND constraint carries no usable "
                    "upper bound."
                ),
            )

        if upper_inclusive:
            if detected > upper:
                return ConstraintEvaluation(
                    status="MISMATCH",
                    reason=(
                        "Observed version is above the "
                        "inclusive research-side upper bound."
                    ),
                )
        elif detected >= upper:
            return ConstraintEvaluation(
                status="MISMATCH",
                reason=(
                    "Observed version is at or above the "
                    "exclusive research-side upper bound."
                ),
            )

        return ConstraintEvaluation(
            status="MATCH",
            reason=(
                "Observed version satisfies the research-side "
                "upper bound."
            ),
        )

    if constraint_kind == "RANGE":
        # ``version`` is the lower bound, ``upper_version`` the
        # upper bound.
        lower = normalize_version(version or "") if version else None
        upper = (
            normalize_version(upper_version or "")
            if upper_version
            else None
        )

        if lower is None or upper is None:
            return ConstraintEvaluation(
                status="INCONCLUSIVE",
                reason=(
                    "RANGE constraint carries no usable "
                    "lower/upper bound pair."
                ),
            )

        if lower_inclusive:
            if detected < lower:
                return ConstraintEvaluation(
                    status="MISMATCH",
                    reason=(
                        "Observed version is below the "
                        "research-side lower bound."
                    ),
                )
        elif detected <= lower:
            return ConstraintEvaluation(
                status="MISMATCH",
                reason=(
                    "Observed version is at or below the "
                    "exclusive research-side lower bound."
                ),
            )

        if upper_inclusive:
            if detected > upper:
                return ConstraintEvaluation(
                    status="MISMATCH",
                    reason=(
                        "Observed version is above the "
                        "inclusive research-side upper bound."
                    ),
                )
        elif detected >= upper:
            return ConstraintEvaluation(
                status="MISMATCH",
                reason=(
                    "Observed version is at or above the "
                    "exclusive research-side upper bound."
                ),
            )

        return ConstraintEvaluation(
            status="MATCH",
            reason=(
                "Observed version satisfies the research-side "
                "version bounds."
            ),
        )

    if constraint_kind == "FIXED":
        fixed = normalize_version(version or "")

        if fixed is None:
            return ConstraintEvaluation(
                status="INCONCLUSIVE",
                reason="FIXED constraint carries no usable version.",
            )

        if detected >= fixed:
            return ConstraintEvaluation(
                status="MISMATCH",
                reason=(
                    "Observed version is at or newer than the "
                    "research-side fixed version."
                ),
            )

        return ConstraintEvaluation(
            status="INCONCLUSIVE",
            reason=(
                "Observed version predates the research-side fixed "
                "version, but the affected lower bound is unstated; "
                "relevance cannot be decided without guessing."
            ),
        )

    return ConstraintEvaluation(
        status="INCONCLUSIVE",
        reason=f"Unknown constraint kind: {constraint_kind}.",
    )


def compare_version(
    detected_version: str | None,
    affected_versions: list,
) -> VersionMatch:

    if not detected_version:
        return VersionMatch(
            status="UNKNOWN",
            detected_version=None,
            matched_version=None,
            reason="No version was detected for the technology.",
        )

    detected = normalize_version(detected_version)

    if detected is None:
        return VersionMatch(
            status="UNKNOWN",
            detected_version=detected_version,
            matched_version=None,
            reason="Detected version could not be parsed.",
        )

    affected_seen = False

    for affected in affected_versions:
        if affected.status and affected.status != "affected":
            continue

        affected_seen = True

        version = normalize_version(
            affected.version
        )

        less_than = normalize_version(
            affected.less_than
        )

        # Exact affected version.
        if version and not less_than:
            if detected == version:
                return VersionMatch(
                    status="AFFECTED",
                    detected_version=detected_version,
                    matched_version=affected.version,
                    reason=(
                        "Detected version exactly matches an "
                        "explicitly affected version."
                    ),
                )

            continue

        # Range:
        # version <= detected < less_than
        if version and less_than:
            if version <= detected < less_than:
                return VersionMatch(
                    status="AFFECTED",
                    detected_version=detected_version,
                    matched_version=affected.version,
                    reason=(
                        f"Detected version is within the affected "
                        f"range {affected.version} <= version < "
                        f"{affected.less_than}."
                    ),
                )

    if affected_seen:
        return VersionMatch(
            status="NOT_AFFECTED",
            detected_version=detected_version,
            matched_version=None,
            reason=(
                "Detected version does not match any known "
                "affected version/range."
            ),
        )

    return VersionMatch(
        status="UNKNOWN",
        detected_version=detected_version,
        matched_version=None,
        reason="No usable affected version information was available.",
    )