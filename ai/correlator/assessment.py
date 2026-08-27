from __future__ import annotations

from dataclasses import dataclass

from ai.correlator.candidates import (
    product_matches_ecosystem,
    technology_matches_product,
)
from ai.correlator.technology import match_technology
from ai.correlator.version import (
    compare_version,
    extract_version,
)
from ai.schemas.http import HTTPAsset
from ai.schemas.source import ResearchDocument


@dataclass
class CVEAssessment:
    cve_id: str
    program_name: str
    subdomain: str

    technology: str
    product_match: str
    version_status: str

    detected_version: str | None
    confidence: float

    reason: str


def assess_asset(
    asset: HTTPAsset,
    cve: ResearchDocument,
) -> list[CVEAssessment]:

    results = []

    for technology in asset.tech:

        # ==================================================
        # 1. Normal/exact technology matching
        # ==================================================

        technology_match = match_technology(
            technology=technology,
            vendor=" ".join(cve.vendor),
            product=" ".join(cve.products),
            cpes=cve.cpes,
        )

        if technology_match is not None:

            detected_version = extract_version(
                technology
            )

            version_result = compare_version(
                detected_version,
                cve.affected_versions,
            )

            # ----------------------------------------------
            # Exact product + affected version
            # ----------------------------------------------

            if version_result.status == "AFFECTED":

                results.append(
                    CVEAssessment(
                        cve_id=cve.title,
                        program_name=asset.program_name,
                        subdomain=asset.subdomain,
                        technology=technology,
                        product_match=(
                            technology_match.match_type
                        ),
                        version_status=(
                            version_result.status
                        ),
                        detected_version=(
                            detected_version
                        ),
                        confidence=(
                            technology_match.confidence
                        ),
                        reason=(
                            version_result.reason
                        ),
                    )
                )

                continue

            # ----------------------------------------------
            # Exact product but version unknown
            # ----------------------------------------------

            if version_result.status == "UNKNOWN":

                results.append(
                    CVEAssessment(
                        cve_id=cve.title,
                        program_name=asset.program_name,
                        subdomain=asset.subdomain,
                        technology=technology,
                        product_match=(
                            technology_match.match_type
                        ),
                        version_status="UNKNOWN",
                        detected_version=(
                            detected_version
                        ),
                        confidence=(
                            technology_match.confidence
                            * 0.5
                        ),
                        reason=(
                            "Technology matched the CVE "
                            "product, but no usable "
                            "affected-version evidence was "
                            "available for the detected asset."
                        ),
                    )
                )

                continue

        # ==================================================
        # 2. Ecosystem matching
        #
        # Example:
        #     CVE product = WP Responsive Images
        #     asset tech  = WordPress
        #
        # This establishes relevance only.
        # It does NOT establish plugin presence or
        # vulnerability.
        # ==================================================

        ecosystem_match = any(
            product_matches_ecosystem(
                technology=technology,
                product=product,
            )
            for product in cve.products
        )

        if not ecosystem_match:
            continue

        detected_version = extract_version(
            technology
        )

        results.append(
            CVEAssessment(
                cve_id=cve.title,
                program_name=asset.program_name,
                subdomain=asset.subdomain,
                technology=technology,
                product_match="ecosystem",
                version_status="UNKNOWN",
                detected_version=detected_version,
                confidence=0.25,
                reason=(
                    f"Asset technology '{technology}' "
                    f"matches the '{cve.products[0] if cve.products else 'unknown'}' "
                    "product ecosystem, but specific product/plugin "
                    "presence and affected version have not been "
                    "verified."
                ),
            )
        )

    return results