from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ai.schemas.source import ResearchDocument


@dataclass
class ResearchCandidate:
    cve_id: str
    cvss_score: float | None

    vendor: list[str]
    products: list[str]

    programs: list[str]
    assets: list[str]

    technologies: list[str]

    affected_asset_count: int
    unknown_version_count: int

    priority_score: float


def build_shortlist(
    cves: list[ResearchDocument],
    assessments: list,
    limit: int = 10,
) -> list[ResearchCandidate]:

    cve_by_id = {
        cve.title: cve
        for cve in cves
    }

    grouped = defaultdict(list)

    for assessment in assessments:
        grouped[assessment.cve_id].append(
            assessment
        )

    candidates = []

    for cve_id, items in grouped.items():
        cve = cve_by_id.get(cve_id)

        if cve is None:
            continue

        programs = sorted(
            {
                item.program_name
                for item in items
            }
        )

        assets = sorted(
            {
                item.subdomain
                for item in items
            }
        )

        technologies = sorted(
            {
                item.technology
                for item in items
            }
        )

        unknown_versions = sum(
            1
            for item in items
            if item.version_status == "UNKNOWN"
        )

        affected_versions = sum(
            1
            for item in items
            if item.version_status == "AFFECTED"
        )

        # --------------------------------------------------
        # Priority scoring
        # --------------------------------------------------

        score = 0.0

        # CVSS is the primary signal.
        if cve.cvss_score is not None:
            score += cve.cvss_score * 8

        # Confirmed affected version is extremely valuable.
        score += affected_versions * 40

        # Unknown version still deserves investigation.
        score += unknown_versions * 4

        # More assets provide extra evidence, but with
        # diminishing importance.
        score += min(len(assets), 10)

        # Multiple programs are useful.
        if len(programs) > 1:
            score += 8

        candidates.append(
            ResearchCandidate(
                cve_id=cve_id,
                cvss_score=cve.cvss_score,
                vendor=cve.vendor,
                products=cve.products,
                programs=programs,
                assets=assets,
                technologies=technologies,
                affected_asset_count=len(assets),
                unknown_version_count=unknown_versions,
                priority_score=score,
            )
        )

    candidates.sort(
        key=lambda item: item.priority_score,
        reverse=True,
    )

    return candidates[:limit]