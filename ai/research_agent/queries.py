"""Stage R24.1 — deterministic discovery query construction primitives.

Contract-only. This module builds :class:`DiscoveryQuery` objects from
deterministic CVE research metadata. It performs **no** network request, calls
no provider, and supports no model-generated queries yet.

Safety properties implemented here:

- Inputs are strictly CVE research metadata (:class:`CVEResearchMetadata`). Its
  fields are the only allowed inputs; program/target/asset fields simply do not
  exist on the structure, so they cannot be passed to the builder.
- Query text is sanitized deterministically: control characters removed,
  whitespace collapsed, provider-syntax-altering quotes removed, bounded to
  ``MAX_QUERY_CHARS`` (200) and each input value bounded to
  ``MAX_VALUE_CHARS``. No randomness, no clock, no timestamps.
- The forbidden-input invariant rejects a query whenever any supplied
  program/asset host/token is present in the rendered query.
- Queries are emitted in a fixed template order with deduplicated, sorted
  provenance, so the whole result is a total, deterministic function of the
  inputs.

Import boundary: standard library + the R24.1 discovery contract only. No
network, no subprocess, no target-validation, no 5B–5J import.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Callable, Iterable

from ai.research_agent.discovery_contract import (
    DiscoveryQuery,
    SearchProvider,
    query_id_for,
    assert_no_forbidden_input,
)

__all__ = [
    "MAX_QUERY_CHARS",
    "MAX_VALUE_CHARS",
    "TEMPLATE_CVE_ID",
    "TEMPLATE_CVE_ADVISORY",
    "TEMPLATE_CVE_VENDOR",
    "TEMPLATE_PRODUCT_CVE",
    "TEMPLATE_COMPONENT_CVE",
    "TEMPLATE_CVE_CWE",
    "TEMPLATE_CVE_VULN_TYPE",
    "TEMPLATE_PRODUCT_VERSION",
    "TEMPLATE_CVE_POC",
    "TEMPLATE_CVE_EXPLOIT",
    "TEMPLATE_CVE_DETECTION",
    "TEMPLATE_PRODUCT_COMPONENT_NUCLEI",
    "QUERY_TEMPLATE_IDS",
    "sanitize_query",
    "normalize_cve_id",
    "CVEResearchMetadata",
    "QueryBuilder",
]

# Fixed template ids (R24 scope §3.2 initial, deterministic template set).
TEMPLATE_CVE_ID = "r24-cve-id"
TEMPLATE_CVE_ADVISORY = "r24-cve-advisory"
TEMPLATE_CVE_VENDOR = "r24-cve-vendor"
TEMPLATE_PRODUCT_CVE = "r24-product-cve"
TEMPLATE_COMPONENT_CVE = "r24-component-cve"
TEMPLATE_CVE_CWE = "r24-cve-cwe"
TEMPLATE_CVE_VULN_TYPE = "r24-cve-vuln-type"
TEMPLATE_PRODUCT_VERSION = "r24-product-version"
TEMPLATE_CVE_POC = "r24-cve-poc"
TEMPLATE_CVE_EXPLOIT = "r24-cve-exploit"
TEMPLATE_CVE_DETECTION = "r24-cve-detection"
TEMPLATE_PRODUCT_COMPONENT_NUCLEI = "r24-product-component-nuclei"

QUERY_TEMPLATE_IDS: tuple[str, ...] = (
    TEMPLATE_CVE_ID,
    TEMPLATE_CVE_ADVISORY,
    TEMPLATE_CVE_VENDOR,
    TEMPLATE_PRODUCT_CVE,
    TEMPLATE_COMPONENT_CVE,
    TEMPLATE_CVE_CWE,
    TEMPLATE_CVE_VULN_TYPE,
    TEMPLATE_PRODUCT_VERSION,
    TEMPLATE_CVE_POC,
    TEMPLATE_CVE_EXPLOIT,
    TEMPLATE_CVE_DETECTION,
    TEMPLATE_PRODUCT_COMPONENT_NUCLEI,
)

# Bounds (R24 scope §3.1: MAX_QUERY_CHARS = 200; inputs individually bounded).
MAX_QUERY_CHARS = 200
MAX_VALUE_CHARS = 64

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_WS_RE = re.compile(r"\s+")
_DANGEROUS_RE = re.compile(r"""["'\\]""")
_CVE_RE = re.compile(r"^CVE-\d{4,}-\d+$")


def sanitize_query(text: object) -> str:
    """Deterministically sanitize one query/input string.

    - removes control characters
    - removes quotes/backslash that could alter provider syntax
    - collapses whitespace
    - truncates to ``MAX_QUERY_CHARS``
    """
    s = str(text or "")
    s = _DANGEROUS_RE.sub(" ", s)
    s = _CONTROL_RE.sub(" ", s)
    s = _WS_RE.sub(" ", s).strip()
    return s[:MAX_QUERY_CHARS]


def normalize_cve_id(value: object) -> str:
    """Normalize a CVE id to ``CVE-\\d{4,}-\\d+`` or return ``""`` when invalid."""
    s = sanitize_query(value).upper().replace(" ", "")
    return s if _CVE_RE.match(s) else ""


@dataclass(frozen=True)
class CVEResearchMetadata:
    """Strictly CVE research metadata (the only accepted builder input).

    Deliberately has **no** program / target / asset / target-URL / host / IP /
    endpoint / response / credentials / cookies / headers fields — those are not
    representable, so they are rejected structurally.
    """

    cve_id: str = ""
    product: str = ""
    component: str = ""
    parameter: str = ""
    version: str = ""
    cwe: str = ""
    vulnerability_type: str = ""
    existing_references: tuple[str, ...] = ()


@dataclass(frozen=True)
class _QueryTemplate:
    template_id: str
    provider: SearchProvider
    required: tuple[str, ...]
    render: Callable[[object], str]


# Fixed, ordered template table (order defines deterministic emission order).
_TEMPLATES: tuple[_QueryTemplate, ...] = (
    _QueryTemplate(
        TEMPLATE_CVE_ID,
        SearchProvider.NVD,
        ("cve_id",),
        lambda m: m.cve_id,
    ),
    _QueryTemplate(
        TEMPLATE_CVE_ADVISORY,
        SearchProvider.VENDOR_ADVISORY,
        ("cve_id",),
        lambda m: f"{m.cve_id} advisory",
    ),
    _QueryTemplate(
        TEMPLATE_CVE_VENDOR,
        SearchProvider.VENDOR_ADVISORY,
        ("cve_id",),
        lambda m: f"{m.cve_id} vendor",
    ),
    _QueryTemplate(
        TEMPLATE_PRODUCT_CVE,
        SearchProvider.NVD,
        ("product", "cve_id"),
        lambda m: f"{m.product} {m.cve_id}",
    ),
    _QueryTemplate(
        TEMPLATE_COMPONENT_CVE,
        SearchProvider.NVD,
        ("component", "cve_id"),
        lambda m: f"{m.component} {m.cve_id}",
    ),
    _QueryTemplate(
        TEMPLATE_CVE_CWE,
        SearchProvider.NVD,
        ("cve_id", "cwe"),
        lambda m: f"{m.cve_id} {m.cwe}",
    ),
    _QueryTemplate(
        TEMPLATE_CVE_VULN_TYPE,
        SearchProvider.NVD,
        ("cve_id", "vulnerability_type"),
        lambda m: f"{m.cve_id} {m.vulnerability_type}",
    ),
    _QueryTemplate(
        TEMPLATE_PRODUCT_VERSION,
        SearchProvider.VENDOR_ADVISORY,
        ("product", "version"),
        lambda m: f"{m.product} {m.version} advisory",
    ),
    _QueryTemplate(
        TEMPLATE_CVE_POC,
        SearchProvider.GITHUB_SEARCH,
        ("cve_id",),
        lambda m: f"{m.cve_id} PoC",
    ),
    _QueryTemplate(
        TEMPLATE_CVE_EXPLOIT,
        SearchProvider.GITHUB_SEARCH,
        ("cve_id",),
        lambda m: f"{m.cve_id} exploit",
    ),
    _QueryTemplate(
        TEMPLATE_CVE_DETECTION,
        SearchProvider.DETECTION_RULE,
        ("cve_id",),
        lambda m: f"{m.cve_id} detection rule",
    ),
    _QueryTemplate(
        TEMPLATE_PRODUCT_COMPONENT_NUCLEI,
        SearchProvider.DETECTION_RULE,
        ("product", "component"),
        lambda m: f"{m.product} {m.component} nuclei",
    ),
)
class QueryBuilder:
    """Deterministic discovery query builder (contract only, no I/O).

    Accepts only :class:`CVEResearchMetadata`. ``forbidden_tokens`` are used
    exclusively as a rejection filter (never as a query term) — the program name
    / asset host is never placed into a query.
    """

    def __init__(
        self,
        *,
        forbidden_tokens: Iterable[str] = (),
        max_query_chars: int = MAX_QUERY_CHARS,
    ) -> None:
        self._forbidden: tuple[str, ...] = tuple(sorted(str(t or "") for t in forbidden_tokens))
        self._max_query_chars = max(int(max_query_chars), 1)

    @property
    def forbidden_tokens(self) -> tuple[str, ...]:
        """Read-only view of the rejection filter (never emitted into queries)."""
        return self._forbidden

    @staticmethod
    def _norm(value: object) -> str:
        return sanitize_query(value)[:MAX_VALUE_CHARS]

    @staticmethod
    def _clean(
        metadata: CVEResearchMetadata,
    ) -> dict[str, object]:
        cve_id = normalize_cve_id(metadata.cve_id)
        return {
            "cve_id": cve_id,
            "product": QueryBuilder._norm(metadata.product),
            "component": QueryBuilder._norm(metadata.component),
            "parameter": QueryBuilder._norm(metadata.parameter),
            "version": QueryBuilder._norm(metadata.version),
            "cwe": QueryBuilder._norm(metadata.cwe),
            "vulnerability_type": QueryBuilder._norm(metadata.vulnerability_type),
            "existing_references": tuple(
                dict.fromkeys(
                    QueryBuilder._norm(r) for r in metadata.existing_references if r
                )
            ),
        }

    def build_queries(self, metadata: CVEResearchMetadata) -> list[DiscoveryQuery]:
        """Render the fixed template set into deterministic queries.

        Raises :class:`ForbiddenInputError` if any rendered query contains a
        forbidden program/asset token (the hard invariant).
        """
        clean = self._clean(metadata)
        m = SimpleNamespace(**clean)
        out: list[DiscoveryQuery] = []
        seen: set[str] = set()
        for tpl in _TEMPLATES:
            if any(not clean.get(k) for k in tpl.required):
                continue
            rendered = sanitize_query(tpl.render(m))[: self._max_query_chars]
            if not rendered:
                continue
            # Hard invariant: never emit a query that leaks a program/asset token.
            assert_no_forbidden_input(rendered, self._forbidden)
            inputs_used = sorted({str(clean[k]) for k in tpl.required})
            query = DiscoveryQuery(
                query_id=query_id_for(
                    tpl.template_id, tpl.provider.value, rendered, inputs_used
                ),
                template_id=tpl.template_id,
                provider=tpl.provider.value,
                query=rendered,
                inputs_used=inputs_used,
            )
            if query.query_id in seen:
                continue
            seen.add(query.query_id)
            out.append(query)
        return out