"""Deterministic degraded research fallback (research-only, fail-soft).

When the LLM provider is transiently unavailable (HTTP 402/429/5xx,
timeout/network), the CVE must NOT be dropped. Instead a conservative
:class:`ResearchResult` is built from already-available deterministic
CVE/NVD/reference material only.

Provenance rules (never violated):

- Deterministic/NVD/reference-derived facts stay in ``summary``,
  ``affected_products``, ``affected_versions``, ``references`` and
  ``CONFIRMED:``/``SECONDARY:`` evidence items.
- LLM-derived research is absent: ``root_cause`` is None,
  ``detection_ideas``/``attack_requirements``/``impact`` are empty.
- Unavailable LLM analysis is explicit: ``nuclei_reason`` and evidence
  state the LLM did not complete; ``llm_status="unavailable"`` is
  recorded on the payload (outside the ``ResearchResult`` schema).
- Never invented: exploitability, affected assets, active
  exploitation, HTTP signatures, Nuclei payloads, or product versions
  not supported by source material.
- Never authoritative: ``nuclei_candidate=False``,
  ``public_exploit=None``, ``actively_exploited=None``,
  ``bug_bounty_relevance=0``, ``severity=None``.
"""

from __future__ import annotations

from ai.schemas.research import stringify_affected_version
from ai.schemas.research import ResearchResult


def _truncate(text: str, limit: int = 1200) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "…"


def build_degraded_research(
    cve_id: str,
    *,
    llm_error: str,
    description: str = "",
    vendor: list[str] | None = None,
    products: list[str] | None = None,
    affected_versions: list[str] | None = None,
    references: list[str] | None = None,
) -> ResearchResult:
    """Build the safest possible degraded ResearchResult.

    All inputs must be deterministic source material (NVD/reference).
    Nothing is inferred beyond what the caller supplies.
    """
    cve_id = (cve_id or "").strip().upper() or "UNKNOWN-CVE"
    vendor = list(vendor or [])
    products = list(products or [])
    references = list((references or [])[:20])
    versions = [str(v) for v in (affected_versions or []) if str(v).strip()]

    nvd_note = _truncate(description) or "NVD description unavailable."
    summary = (
        "Degraded deterministic research: the LLM provider was "
        "unavailable, so no LLM analysis was performed. "
        "This result contains ONLY NVD/reference-derived facts. "
        f"NVD description for {cve_id}: {nvd_note}"
    )
    evidence: list[str] = [
        f"NOT OBSERVED: LLM analysis unavailable ({llm_error}). "
        "No LLM-derived conclusions are present in this result.",
        f"SECONDARY: NVD/reference-derived facts only for {cve_id}; "
        "exploitability, affected assets, active exploitation, HTTP "
        "signatures, and Nuclei payloads were NOT established.",
    ]
    if vendor or products:
        evidence.append(
            "CONFIRMED: NVD-reported vendor/product metadata: "
            f"vendor={vendor or 'unknown'} products={products or 'unknown'}."
        )
    if references:
        evidence.append(
            f"SECONDARY: {len(references)} NVD reference URL(s) recorded "
            "without fetching conclusions."
        )

    return ResearchResult(
        title=f"{cve_id} (degraded deterministic research — LLM unavailable)",
        summary=summary,
        vulnerability_type=None,
        severity=None,
        cve_ids=[cve_id],
        affected_products=products,
        affected_versions=versions,
        attack_requirements=[],
        root_cause=None,
        impact=[],
        public_exploit=None,
        actively_exploited=None,
        bug_bounty_relevance=0,
        detection_ideas=[],
        nuclei_candidate=False,
        nuclei_reason=(
            "LLM unavailable: deterministic fallback claims no Nuclei "
            f"candidacy. ({llm_error})"
        ),
        references=references,
        evidence=evidence,
    )


def build_degraded_research_from_document(
    document,
    *,
    llm_error: str,
) -> ResearchResult:
    """Build degraded research from a deterministic CVE document."""
    versions: list[str] = []
    for version in getattr(document, "affected_versions", []) or []:
        if isinstance(version, str):
            text = version.strip()
        else:
            try:
                text = stringify_affected_version(
                    version.model_dump()
                    if hasattr(version, "model_dump")
                    else version
                )
            except Exception:
                text = str(version)
        if text.strip():
            versions.append(text.strip())

    return build_degraded_research(
        document.title,
        llm_error=llm_error,
        description=getattr(document, "content", "") or "",
        vendor=list(getattr(document, "vendor", []) or []),
        products=list(getattr(document, "products", []) or []),
        affected_versions=versions,
        references=list(getattr(document, "references", []) or []),
    )


def degraded_payload_fields(
    research: ResearchResult,
    *,
    llm_error: str,
    cve_id: str,
    vendor: list[str] | None = None,
    products: list[str] | None = None,
    cvss_score=None,
    cvss_vector: str | None = None,
) -> dict:
    """Wrap a degraded ResearchResult in CLI-payload conventions."""
    data = research.model_dump()
    # Provenance markers live OUTSIDE the ResearchResult schema so
    # ``ResearchResult(**payload["research"])`` keeps validating.
    data["llm_status"] = "unavailable"
    data["llm_error"] = llm_error
    return {
        "research_status": "completed_degraded",
        "llm_status": "unavailable",
        "llm_error": llm_error,
        "authoritative": False,
        "research_only": True,
        "provenance": {
            "deterministic": ["nvd", "reference"],
            "llm": "unavailable",
            "authoritative": False,
        },
        "cve": {
            "id": cve_id,
            "vendor": list(vendor or []),
            "products": list(products or []),
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
        },
        "research": data,
    }
