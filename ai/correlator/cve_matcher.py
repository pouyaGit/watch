from __future__ import annotations

from ai.correlator.technology import match_technology
from ai.schemas.http import HTTPAsset
from ai.schemas.source import ResearchDocument


def find_matches(
    asset: HTTPAsset,
    cve: ResearchDocument,
) -> list:
    """
    Find technology-based matches between one HTTP asset
    and one CVE.

    This stage intentionally does NOT perform version matching.
    """

    matches = []

    for technology in asset.tech:
        result = match_technology(
            technology=technology,
            vendor=" ".join(cve.vendor),
            product=" ".join(cve.products),
            cpes=cve.cpes,
        )

        if result is None:
            continue

        matches.append(
            {
                "cve_id": cve.title,
                "program_name": asset.program_name,
                "subdomain": asset.subdomain,
                "scope": asset.scope,
                "technology": technology,
                "vendor": cve.vendor,
                "products": cve.products,
                "cpes": cve.cpes,
                "match_type": result.match_type,
                "confidence": result.confidence,
            }
        )

    return matches