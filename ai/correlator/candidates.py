from __future__ import annotations

from ai.correlator.index import TechnologyIndex
from ai.correlator.technology import normalize
from ai.schemas.http import HTTPAsset
from ai.schemas.source import ResearchDocument


# Explicit technology aliases.
#
# This is intentionally small at first.
# We will expand it based on real Watch data instead of
# creating a huge guessed mapping.
TECHNOLOGY_ALIASES = {
    "nginx": {
        "nginx",
    },
    "wordpress": {
        "wordpress",
    },
    "apache http server": {
        "apache http server",
        "apache",
    },
    "next js": {
        "next js",
    },
}


def technology_matches_product(
    technology: str,
    product: str,
) -> bool:
    tech = normalize(technology)
    prod = normalize(product)

    if not tech or not prod:
        return False

    # Exact normalized match.
    if tech == prod:
        return True

    # Explicit aliases only.
    aliases = TECHNOLOGY_ALIASES.get(tech)

    if aliases and prod in aliases:
        return True

    return False


def candidate_assets(
    cve: ResearchDocument,
    index: TechnologyIndex,
) -> list[HTTPAsset]:

    candidates: list[HTTPAsset] = []
    seen: set[str] = set()

    for product in cve.products:
        product_norm = normalize(product)

        if not product_norm:
            continue

        # Exact index lookup first.
        assets = index.get(product_norm)

        for asset in assets:
            key = (
                f"{asset.program_name}:"
                f"{asset.subdomain}"
            )

            if key in seen:
                continue

            # Re-check identity. This prevents a future index
            # expansion from silently creating false positives.
            if any(
                technology_matches_product(
                    technology,
                    product,
                )
                for technology in asset.tech
            ):
                seen.add(key)
                candidates.append(asset)

    return candidates