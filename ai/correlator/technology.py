from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class TechnologyMatch:
    technology: str
    vendor: str
    product: str
    match_type: str
    confidence: float


INVALID_VALUES = {
    "",
    "n/a",
    "na",
    "n a",
    "unknown",
    "none",
    "null",
    "-",
}


# Technologies that are too generic to be used as a product identity.
#
# Example:
#   Watch: Python
#   CVE product: GitPython
#
# These must NOT match.
GENERIC_TECHNOLOGIES = {
    "java",
    "python",
    "php",
    "node js",
    "javascript",
    "react",
    "vue js",
}


# Explicit aliases only.
#
# We intentionally keep this small.
# A new alias should be added only when we are confident
# that the two names represent the same product/family.
TECHNOLOGY_ALIASES = {
    "nginx": {
        "nginx",
    },

    "apache http server": {
        "apache",
        "apache http server",
    },

    "oracle weblogic server": {
        "weblogic",
        "oracle weblogic server",
    },

    "wordpress": {
        "wordpress",
    },

    "mysql": {
        "mysql",
    },

    "next js": {
        "next js",
    },
}


def normalize(value: str) -> str:
    """
    Normalize technology/vendor/product names.

    Examples:

        Nginx:1.30.4
            -> nginx

        Microsoft ASP.NET:4.0.30319
            -> microsoft asp net

        Next.js
            -> next js
    """

    if not value:
        return ""

    value = value.lower().strip()

    # Remove common version suffixes.
    #
    # Examples:
    #   nginx:1.30.4
    #   php:5.6.40
    #   jquery:3.7.1
    value = re.sub(
        r"[:/_\-\s]+v?\d+(?:\.\d+){0,3}(?:[-+._][0-9a-z.-]+)?$",
        "",
        value,
    )

    # Normalize separators.
    value = re.sub(
        r"[^a-z0-9]+",
        " ",
        value,
    )

    return " ".join(value.split())


def is_valid(value: str | None) -> bool:
    """
    Return True only for meaningful identifiers.
    """

    if not value:
        return False

    normalized = normalize(value)

    return normalized not in INVALID_VALUES


def normalize_tokens(value: str) -> set[str]:
    """
    Convert a normalized identifier into tokens.
    """

    normalized = normalize(value)

    if not normalized:
        return set()

    return set(normalized.split())


def normalize_cpe(
    cpe: str,
) -> tuple[str | None, str | None]:
    """
    Extract vendor/product from a CPE 2.3 string.

    Example:

        cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*

    Returns:

        ("nginx", "nginx")
    """

    if not cpe:
        return None, None

    if not cpe.startswith("cpe:2.3:"):
        return None, None

    parts = cpe.split(":")

    if len(parts) < 5:
        return None, None

    vendor = normalize(parts[3])
    product = normalize(parts[4])

    if not vendor:
        vendor = None

    if not product:
        product = None

    return vendor, product


def _build_match(
    technology: str,
    vendor: str,
    product: str,
    match_type: str,
    confidence: float,
) -> TechnologyMatch:
    return TechnologyMatch(
        technology=technology,
        vendor=vendor,
        product=product,
        match_type=match_type,
        confidence=confidence,
    )


def match_technology(
    technology: str,
    vendor: str,
    product: str,
    cpes: list[str] | None = None,
) -> TechnologyMatch | None:
    """
    Conservative deterministic product correlation.

    Important:
    - No arbitrary substring matching.
    - Generic technologies do not match arbitrary packages.
    - n/a / unknown identifiers are ignored.
    - CPE is used as a strong fallback.
    """

    tech_norm = normalize(technology)
    vendor_norm = normalize(vendor)
    product_norm = normalize(product)

    if not tech_norm:
        return None

    if not is_valid(product_norm):
        return None

    if not is_valid(vendor_norm):
        vendor_norm = ""

    # --------------------------------------------------
    # 1. Exact normalized product identity
    # --------------------------------------------------

    if tech_norm == product_norm:
        return _build_match(
            technology=technology,
            vendor=vendor,
            product=product,
            match_type="exact_identity",
            confidence=0.98,
        )

    # --------------------------------------------------
    # 2. Generic technologies
    #
    # Do NOT allow:
    #   Python -> GitPython
    #   PHP -> phpMyFAQ
    #   Java -> rabbitmq-java-client
    # --------------------------------------------------

    if tech_norm in GENERIC_TECHNOLOGIES:
        return None

    # --------------------------------------------------
    # 3. Explicit aliases
    #
    # Only aliases we explicitly trust are accepted.
    # --------------------------------------------------

    aliases = TECHNOLOGY_ALIASES.get(tech_norm, set())

    if product_norm in aliases:
        return _build_match(
            technology=technology,
            vendor=vendor,
            product=product,
            match_type="strong_alias",
            confidence=0.93,
        )

    # --------------------------------------------------
    # 4. Token equality
    #
    # Example:
    #
    #   Apache HTTP Server
    #   apache http server
    #
    # This is different from substring matching.
    # --------------------------------------------------

    tech_tokens = normalize_tokens(technology)
    product_tokens = normalize_tokens(product)

    if (
        tech_tokens
        and product_tokens
        and tech_tokens == product_tokens
    ):
        return _build_match(
            technology=technology,
            vendor=vendor,
            product=product,
            match_type="token_exact",
            confidence=0.96,
        )

    # --------------------------------------------------
    # 5. Vendor + product exact identity
    #
    # Both sides must contribute.
    #
    # We DO NOT use OR here.
    # --------------------------------------------------

    if vendor_norm and product_norm:
        vendor_tokens = normalize_tokens(vendor)
        product_tokens = normalize_tokens(product)
        tech_tokens = normalize_tokens(technology)

        if (
            vendor_tokens
            and product_tokens
            and vendor_tokens.issubset(tech_tokens)
            and product_tokens.issubset(tech_tokens)
        ):
            return _build_match(
                technology=technology,
                vendor=vendor,
                product=product,
                match_type="vendor_product",
                confidence=0.90,
            )

    # --------------------------------------------------
    # 6. CPE fallback
    #
    # CPE is strong evidence.
    #
    # But again, no arbitrary substring matching.
    # --------------------------------------------------

    technology_vendor = None
    technology_product = tech_norm

    for cpe in cpes or []:
        cpe_vendor, cpe_product = normalize_cpe(cpe)

        if not cpe_product:
            continue

        # Exact product identity from CPE.
        if cpe_product == technology_product:
            return _build_match(
                technology=technology,
                vendor=vendor,
                product=product,
                match_type="cpe_product",
                confidence=0.97,
            )

        # If the technology has an explicit vendor component,
        # require vendor/product consistency.
        if (
            vendor_norm
            and cpe_vendor
            and vendor_norm == cpe_vendor
            and cpe_product == technology_product
        ):
            return _build_match(
                technology=technology,
                vendor=vendor,
                product=product,
                match_type="cpe_vendor_product",
                confidence=0.98,
            )

    # No reliable deterministic match.
    return None