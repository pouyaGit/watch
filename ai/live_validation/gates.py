"""CVE identity + template provenance gates (Phase 5K-live).

Hard-scoped to CVE-2026-1557 only. The template is pinned in code
with a deterministic canonical digest. Arbitrary template paths are
rejected; the lane never accepts template path arguments.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ai.researcher.nuclei_artifact_validator import (
    NucleiFixture,
    NucleiMatcher,
    NucleiTemplateContent,
    canonical_template_bytes,
    validate_nuclei_safety,
    validate_nuclei_specificity,
)
from ai.schemas.artifact import content_hash_for_bytes

# ------------------------------------------------------------------
# Hard scope
# ------------------------------------------------------------------

HARD_SCOPE_CVE_ID = "CVE-2026-1557"

# ------------------------------------------------------------------
# Pinned template for CVE-2026-1557
# ------------------------------------------------------------------


def _build_pinned_template() -> NucleiTemplateContent:
    """Canonical template content for CVE-2026-1557 (frozen)."""
    return NucleiTemplateContent(
        template_id="CVE-2026-1557",
        method="GET",
        path="/wp-content/plugins/wp-responsive-images/image_handler.php",
        headers={},
        query_params={"src": "/wp-config.php"},
        body=None,
        matchers=[
            NucleiMatcher(
                matcher_type="dsl",
                values=["status_code==200 || status_code==403"],
                part="status",
            ),
            NucleiMatcher(
                matcher_type="word",
                values=["DB_NAME", "DB_PASSWORD"],
                part="body",
            ),
        ],
    )


PINNED_TEMPLATE: NucleiTemplateContent = _build_pinned_template()
PINNED_TEMPLATE_BYTES: bytes = canonical_template_bytes(PINNED_TEMPLATE)
PINNED_TEMPLATE_DIGEST: str = content_hash_for_bytes(PINNED_TEMPLATE_BYTES)


def _build_fixtures() -> tuple[NucleiFixture, NucleiFixture]:
    """Deterministic fixtures for specificity validation."""
    benign = NucleiFixture(
        fixture_kind="benign",
        status=500,
        body="hello welcome to the error page",
    )
    vulnerable = NucleiFixture(
        fixture_kind="vulnerable",
        status=403,
        body=(
            "<?php define('DB_NAME', 'wordpressdb'); "
            "define('DB_PASSWORD', 'secret123'); ?>"
        ),
    )
    return benign, vulnerable


FIXTURES: tuple[NucleiFixture, NucleiFixture] = _build_fixtures()


@dataclass(frozen=True)
class PinnedCveCandidate:
    """Resolved pinned candidate for a hard-scoped CVE."""

    cve_id: str
    template: NucleiTemplateContent
    canonical_bytes: bytes
    digest: str
    fixtures: tuple[NucleiFixture, NucleiFixture]


def resolve_pinned_candidate(cve_id: str) -> PinnedCveCandidate:
    """Resolve the pinned candidate for a CVE-identity gate check.

    Only CVE-2026-1557 is supported. Arbitrary templates are rejected.
    Returns the pinned candidate; raises ValueError on unsupported CVE.
    """
    if cve_id != HARD_SCOPE_CVE_ID:
        raise ValueError(
            f"CVE identity mismatch: expected {HARD_SCOPE_CVE_ID}, "
            f"got {cve_id!r}; only the pinned CVE is supported"
        )
    return PinnedCveCandidate(
        cve_id=cve_id,
        template=PINNED_TEMPLATE,
        canonical_bytes=PINNED_TEMPLATE_BYTES,
        digest=PINNED_TEMPLATE_DIGEST,
        fixtures=FIXTURES,
    )


def validate_template_safety(candidate: PinnedCveCandidate) -> tuple[bool, tuple[str, ...]]:
    """Run deterministic safety + specificity validation on pinned template.

    Returns (passed, reasons). Fail closed.
    """
    safety_errors = validate_nuclei_safety(candidate.template)
    if safety_errors:
        return False, tuple(safety_errors)
    spec = validate_nuclei_specificity(candidate.template, list(candidate.fixtures))
    if not spec.passed:
        return False, spec.reasons
    return True, ("safety+specificity passed",)
