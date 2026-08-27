from __future__ import annotations

from ai.correlator.index import TechnologyIndex
from ai.correlator.technology import normalize
from ai.schemas.http import HTTPAsset
from ai.schemas.source import ResearchDocument


# ------------------------------------------------------------
# Explicit technology aliases.
#
# These are exact/family-level relationships that we trust.
# ------------------------------------------------------------

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


# ------------------------------------------------------------
# Product ecosystem mapping.
#
# IMPORTANT:
# This does NOT mean the product is installed.
# It only means the product belongs to the ecosystem.
#
# Example:
#
# WP Responsive Images
#       ↓
# WordPress ecosystem
#       ↓
# WordPress asset = candidate
#
# Vulnerability/version status remains UNKNOWN until verified.
# ------------------------------------------------------------

PRODUCT_ECOSYSTEMS = {
    "wordpress": {
        "wordpress",
    },

    "wp responsive images": {
        "wordpress",
    },

    "woocommerce": {
        "wordpress",
    },

    "yoast seo": {
        "wordpress",
    },

    "elementor": {
        "wordpress",
    },

    "wordfence": {
        "wordpress",
    },
}


def technology_matches_product(
    technology: str,
    product: str,
) -> bool:

    tech = normalize(
        technology
    )

    prod = normalize(
        product
    )

    if not tech or not prod:
        return False

    # --------------------------------------------------------
    # Exact normalized match
    # --------------------------------------------------------

    if tech == prod:
        return True

    # --------------------------------------------------------
    # Explicit technology aliases
    # --------------------------------------------------------

    aliases = TECHNOLOGY_ALIASES.get(
        tech
    )

    if aliases and prod in aliases:
        return True

    return False


def product_matches_ecosystem(
    technology: str,
    product: str,
) -> bool:

    tech = normalize(
        technology
    )

    prod = normalize(
        product
    )

    if not tech or not prod:
        return False

    ecosystems = PRODUCT_ECOSYSTEMS.get(
        prod
    )

    if not ecosystems:
        return False

    return tech in {
        normalize(item)
        for item in ecosystems
    }


def candidate_assets(
    cve: ResearchDocument,
    index: TechnologyIndex,
) -> list[HTTPAsset]:

    candidates: list[HTTPAsset] = []

    seen: set[str] = set()

    for product in cve.products:

        product_norm = normalize(
            product
        )

        if not product_norm:
            continue

        # ----------------------------------------------------
        # Strategy 1:
        # Exact product lookup
        # ----------------------------------------------------

        assets = index.get(
            product_norm
        )

        for asset in assets:

            key = (
                f"{asset.program_name}:"
                f"{asset.subdomain}"
            )

            if key in seen:
                continue

            if any(
                technology_matches_product(
                    technology,
                    product,
                )
                for technology in asset.tech
            ):
                seen.add(key)
                candidates.append(
                    asset
                )

        # ----------------------------------------------------
        # Strategy 2:
        # Ecosystem lookup
        #
        # Example:
        # WP Responsive Images -> WordPress
        # ----------------------------------------------------

        ecosystems = PRODUCT_ECOSYSTEMS.get(
            product_norm,
            set(),
        )

        for ecosystem in ecosystems:

            ecosystem_norm = normalize(
                ecosystem
            )

            assets = index.get(
                ecosystem_norm
            )

            for asset in assets:

                key = (
                    f"{asset.program_name}:"
                    f"{asset.subdomain}"
                )

                if key in seen:
                    continue

                if any(
                    product_matches_ecosystem(
                        technology,
                        product,
                    )
                    for technology in asset.tech
                ):
                    seen.add(key)
                    candidates.append(
                        asset
                    )

    return candidates