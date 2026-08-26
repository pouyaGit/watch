from __future__ import annotations

from dataclasses import dataclass

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

        technology_match = match_technology(
            technology=technology,
            vendor=" ".join(cve.vendor),
            product=" ".join(cve.products),
            cpes=cve.cpes,
        )

        if technology_match is None:
            continue

        detected_version = extract_version(
            technology
        )

        version_result = compare_version(
            detected_version,
            cve.affected_versions,
        )

        # Product match + affected version.
        if version_result.status == "AFFECTED":
            confidence = technology_match.confidence

            results.append(
                CVEAssessment(
                    cve_id=cve.title,
                    program_name=asset.program_name,
                    subdomain=asset.subdomain,
                    technology=technology,
                    product_match=technology_match.match_type,
                    version_status=version_result.status,
                    detected_version=detected_version,
                    confidence=confidence,
                    reason=version_result.reason,
                )
            )

            continue

        # Product match but no version evidence.
        if version_result.status == "UNKNOWN":
            results.append(
                CVEAssessment(
                    cve_id=cve.title,
                    program_name=asset.program_name,
                    subdomain=asset.subdomain,
                    technology=technology,
                    product_match=technology_match.match_type,
                    version_status="UNKNOWN",
                    detected_version=detected_version,
                    confidence=technology_match.confidence * 0.5,
                    reason=(
                        "Technology matched the CVE product, "
                        "but no usable affected-version evidence "
                        "was available for the detected asset."
                    ),
                )
            )

    return results