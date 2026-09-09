"""Deterministic research-to-knowledge ingestion (Stage R4).

Converts already-persisted research/reference artifacts into
:class:`KnowledgeDocument` objects and stores them via the existing
:class:`KnowledgeStore.ingest` API:

- ``ai_data/research/<CVE>.cli.json`` → one synthesis document,
- ``ai_data/research/<CVE>.references.json`` → one document per record.

Local-only, deterministic, no network, no LLM, no subprocess, no
Nuclei, no production verification, no finding materialization, no
alerting. Only explicitly present fields are copied; missing fields
are never invented (``UNKNOWN`` / ``0.0`` / ``None`` defaults, and the
CVE is carried in tags + prose because ``KnowledgeDocument`` has no
dedicated CVE field).

Idempotency comes from content addressing: identity is
``sha256(content)`` (``knowledge_id = kb-<16>``), so rerunning over
identical input converges with no duplicates. ``store.ingest`` merges
re-ingested provenance deterministically.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RESEARCH_DIR = Path("ai_data/research")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

# Tag namespace carrying the CVE id (KnowledgeDocument has no CVE field).
CVE_TAG_PREFIX = "cve:"


class ResearchIngestionError(ValueError):
    """Raised for malformed input or unreadable persisted artifacts."""


@dataclass
class ResearchIngestionResult:
    """Outcome of one ingestion pass (deterministic ordering)."""

    cve_id: str
    knowledge_ids: list[str] = field(default_factory=list)
    created: list[str] = field(default_factory=list)
    existing: list[str] = field(default_factory=list)
    documents: list[Any] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    dry_run: bool = False


def _intelligence_document_fields(
    cve_id: str,
    payload: dict[str, Any],
    records: list[dict[str, Any]],
    artifact_url: str | None,
    product_terms: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Map deterministic extraction onto document/provenance fields.

    Stage R12 keeps the compatibility projection identity-safe:
    only fields present in the persisted top-level document, its
    claims, aggregate, and projection are populated, and all values
    remain verbatim strings from explicit evidence.
    """

    from ai.knowledge.intelligence import extract_research_intelligence

    intelligence = extract_research_intelligence(
        cve_id,
        payload if isinstance(payload, dict) else {},
        records,
        product_terms=product_terms,
    )
    evidence = [
        {
            "field": item.field,
            "value": item.value,
            "source_artifact": item.source_artifact,
            "source_url": item.source_url,
            "source_type": item.source_type,
            "evidence": item.evidence,
            "rule_id": item.rule_id,
            "rule_version": item.rule_version,
        }
        for item in intelligence.evidence
    ]
    return {
        "vulnerability_types": list(intelligence.vulnerability_types),
        "cwes": list(intelligence.cwes),
        "xss_types": list(intelligence.xss_types),
        "contexts": list(intelligence.contexts),
        "parameters": list(intelligence.parameters),
        "intelligence_evidence": evidence,
        "provenance": [
            {
                "source_url": artifact_url or f"local://{cve_id}.cli.json",
                "source_type": "research",
                "claims": [
                    {
                        "vulnerability_types": list(
                            intelligence.vulnerability_types
                        ),
                        "cwes": list(intelligence.cwes),
                        "xss_types": list(intelligence.xss_types),
                        "contexts": list(intelligence.contexts),
                        "parameters": list(intelligence.parameters),
                        "tags": sorted(
                            {
                                f"{CVE_TAG_PREFIX}{cve_id}",
                                "research",
                                "deterministic-intelligence",
                            }
                        ),
                    }
                ],
            }
        ],
    }


def _validate_cve_id(cve_id: str) -> str:
    normalized = (cve_id or "").strip()
    if not CVE_RE.match(normalized):
        raise ResearchIngestionError(f"invalid CVE id: {cve_id!r}")
    return normalized


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        raise ResearchIngestionError(
            f"invalid JSON artifact: {path}: {exc}"
        ) from exc


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _content_lines(parts: list[tuple[str, Any]]) -> str:
    """Deterministic content builder: fixed-order labeled sections."""
    lines: list[str] = []
    for label, value in parts:
        if value is None:
            continue
        if isinstance(value, list):
            items = _as_list(value)
            if not items:
                continue
            lines.append(f"{label}:")
            lines.extend(f"- {item}" for item in items)
        else:
            text = str(value).strip()
            if text:
                lines.append(f"{label}: {text}")
    return "\n".join(lines).strip()


def build_research_document(cve_id: str, payload: dict, artifact: Path) -> Any:
    """Build the CVE synthesis document (pure; explicit fields only)."""
    from ai.schemas.knowledge import KnowledgeDocument

    cve = payload.get("cve", {}) if isinstance(payload.get("cve"), dict) else {}
    metadata = (
        payload.get("metadata", {})
        if isinstance(payload.get("metadata"), dict)
        else {}
    )
    research = (
        payload.get("research", {})
        if isinstance(payload.get("research"), dict)
        else {}
    )

    title = _first_text(research.get("title")) or f"Research synthesis: {cve_id}"
    substantive = (
        _as_list(cve.get("vendor"))
        + _as_list(cve.get("products"))
        + _as_list(research.get("affected_products"))
        + _as_list(research.get("affected_versions"))
        + _as_list(research.get("attack_requirements"))
        + _as_list(research.get("impact"))
        + _as_list(research.get("evidence"))
        + _as_list(research.get("references"))
        + _as_list(metadata.get("technologies"))
    )
    substantive_text = _first_text(
        research.get("title"),
        research.get("summary"),
        research.get("vulnerability_type"),
        research.get("severity"),
        research.get("root_cause"),
        cve.get("cvss_score"),
        cve.get("cvss_vector"),
    )
    if not substantive and not substantive_text:
        raise ResearchIngestionError(
            f"research payload carries no usable fields: {artifact}"
        )
    content = _content_lines(
        [
            ("Title", _first_text(research.get("title"))),
            ("CVE", cve_id),
            ("Vendor", "; ".join(_as_list(cve.get("vendor"))) or None),
            ("Products", "; ".join(_as_list(cve.get("products"))) or None),
            (
                "CVSS",
                (
                    f"{cve.get('cvss_score')} {cve.get('cvss_vector') or ''}".strip()
                    if cve.get("cvss_score") is not None
                    or cve.get("cvss_vector") is not None
                    else None
                ),
            ),
            ("Severity", _first_text(research.get("severity"))),
            ("Vulnerability type", _first_text(research.get("vulnerability_type"))),
            (
                "Affected products",
                _as_list(research.get("affected_products")) or None,
            ),
            (
                "Affected versions",
                _as_list(research.get("affected_versions")) or None,
            ),
            ("Summary", _first_text(research.get("summary"))),
            ("Root cause", _first_text(research.get("root_cause"))),
            ("Attack requirements", _as_list(research.get("attack_requirements")) or None),
            ("Impact", _as_list(research.get("impact")) or None),
            ("Evidence", _as_list(research.get("evidence")) or None),
            (
                "Public exploit",
                (
                    str(bool(research.get("public_exploit")))
                    if "public_exploit" in research
                    else None
                ),
            ),
            ("References", _as_list(research.get("references")) or None),
        ]
    )
    if not content:
        raise ResearchIngestionError(
            f"research payload carries no usable fields: {artifact}"
        )

    return KnowledgeDocument.model_validate(
        {
            "knowledge_id": "ingest-placeholder",
            "title": title,
            # Synthesis provenance: the local artifact itself. Never
            # invent a remote source URL for derived content.
            "source_url": f"local://{artifact.as_posix()}",
            "source_type": "research",
            "technologies": sorted(set(_as_list(metadata.get("technologies")))),
            "content": content,
            "summary": _first_text(research.get("summary")),
            "tags": sorted({f"{CVE_TAG_PREFIX}{cve_id}", "research"}),
            **_intelligence_document_fields(
                cve_id,
                payload,
                [],
                f"local://{Path(artifact).as_posix()}",
            ),
        }
    )


def build_reference_documents(
    cve_id: str, archive: dict, product_terms: tuple[str, ...] | None = None
) -> list[Any]:
    """Build one document per reference record (pure; explicit fields only)."""
    from ai.schemas.knowledge import KnowledgeDocument

    records = archive.get("records", [])
    if not isinstance(records, list):
        raise ResearchIngestionError("references archive records is not a list")
    documents = []
    for record in sorted(
        (r for r in records if isinstance(r, dict)),
        key=lambda r: str(r.get("source_url") or ""),
    ):
        url = _first_text(record.get("source_url"))
        if not url:
            continue  # no source identity → no provenance → skip
        chunks = _as_list(record.get("context_chunks"))
        body_parts: list[str] = []
        title = _first_text(record.get("title"))
        if title:
            body_parts.append(title)
        # Stage R13: the normalized extracted body (when present) is
        # part of the persisted reference evidence. It is appended
        # after the title and before context chunks so document
        # identity remains a pure function of the archive record.
        body = _first_text(record.get("body"))
        if body:
            body_parts.append(body)
        body_parts.extend(chunks)
        content_hash = _first_text(record.get("content_hash"))
        if content_hash:
            body_parts.append(f"Reference content hash: {content_hash}")
        content = "\n".join(body_parts).strip()
        if not content:
            continue
        record_provenance = [
            {
                "source_url": url,
                "source_type": _first_text(record.get("source_type"))
                or "reference",
                "title": title,
                "claims": [
                    {
                        "title": title,
                        "tags": sorted(
                            {
                                f"{CVE_TAG_PREFIX}{cve_id}",
                                "reference",
                                "deterministic-intelligence",
                            }
                        ),
                    }
                ],
            }
        ]
        documents.append(
            KnowledgeDocument.model_validate(
                {
                    "knowledge_id": "ingest-placeholder",
                    "title": title or f"Reference: {url}",
                    "source_url": url,
                    "source_type": _first_text(record.get("source_type")) or "reference",
                    "content": content,
                    "summary": title,
                    "tags": sorted({f"{CVE_TAG_PREFIX}{cve_id}", "reference"}),
                    **_reference_intelligence_fields(
                        cve_id, record, product_terms
                    ),
                }
            )
        )
    return documents


def _reference_intelligence_fields(
    cve_id: str,
    record: dict[str, Any],
    product_terms: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Attach per-record intelligence plus explicit URL provenance."""

    url = _first_text(record.get("source_url")) or ""
    source_type = _first_text(record.get("source_type")) or "reference"
    title = _first_text(record.get("title"))
    intelligence_fields = _intelligence_document_fields(
        cve_id, {}, [record], url, product_terms
    )
    record_provenance = [
        {
            "source_url": url,
            "source_type": source_type,
            "title": title,
            "claims": [
                {
                    "title": title,
                    "tags": sorted(
                        {
                            f"{CVE_TAG_PREFIX}{cve_id}",
                            "reference",
                            "deterministic-intelligence",
                        }
                    ),
                }
            ],
        }
    ]
    return {
        **intelligence_fields,
        "provenance": [
            *record_provenance,
            *intelligence_fields["provenance"],
        ],
    }


def _store_documents(
    documents: list[Any], store: Any, *, dry_run: bool, cve_id: str
) -> ResearchIngestionResult:
    result = ResearchIngestionResult(cve_id=cve_id, dry_run=dry_run)
    for document in documents:
        # Identity preview without writing (read-only presence check).
        from ai.knowledge.store import content_hash

        digest = content_hash(document.content)
        knowledge_id = f"kb-{digest[:16]}"
        if dry_run:
            already = store.get_by_hash(digest) is not None
            result.knowledge_ids.append(knowledge_id)
            result.documents.append(
                document.model_copy(
                    update={"content_hash": digest, "knowledge_id": knowledge_id}
                )
            )
            (result.existing if already else result.created).append(knowledge_id)
            continue
        stored, created = store.ingest(document)
        result.knowledge_ids.append(stored.knowledge_id)
        result.documents.append(stored)
        (result.created if created else result.existing).append(stored.knowledge_id)
    # Deterministic ordering everywhere.
    result.knowledge_ids.sort()
    result.created.sort()
    result.existing.sort()
    result.documents.sort(key=lambda d: str(d.knowledge_id))
    return result


def ingest_cve_research(
    cve_id: str,
    store: Any,
    research_dir: str | Path = RESEARCH_DIR,
    *,
    dry_run: bool = False,
) -> ResearchIngestionResult:
    """Ingest ``<CVE>.cli.json`` (+ archive when present) into the store."""
    cve = _validate_cve_id(cve_id)
    research_dir_p = Path(research_dir)
    path = research_dir_p / f"{cve}.cli.json"
    if not path.exists():
        raise ResearchIngestionError(f"missing CVE research JSON: {path}")
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ResearchIngestionError(
            f"invalid CVE research JSON (not an object): {path}"
        )

    documents = [build_research_document(cve, payload, path)]
    notes: list[str] = []
    from ai.knowledge.intelligence import product_terms_from_payload

    product_terms = product_terms_from_payload(payload)
    archive_path = research_dir_p / f"{cve}.references.json"
    if archive_path.exists():
        archive = _read_json(archive_path)
        if not isinstance(archive, dict):
            raise ResearchIngestionError(
                f"invalid references archive (not an object): {archive_path}"
            )
        ref_docs = build_reference_documents(cve, archive, product_terms)
        documents.extend(ref_docs)
        notes.append(f"references: {len(ref_docs)} document(s) from {archive_path.name}")
    else:
        notes.append(f"references: archive not present ({archive_path.name})")

    result = _store_documents(documents, store, dry_run=dry_run, cve_id=cve)
    result.notes.extend(notes)
    return result


def ingest_reference_archive(
    cve_id: str,
    store: Any,
    research_dir: str | Path = RESEARCH_DIR,
    *,
    dry_run: bool = False,
) -> ResearchIngestionResult:
    """Ingest only ``<CVE>.references.json`` into the store."""
    cve = _validate_cve_id(cve_id)
    research_dir_p = Path(research_dir)
    archive_path = research_dir_p / f"{cve}.references.json"
    if not archive_path.exists():
        raise ResearchIngestionError(
            f"missing references archive: {archive_path}"
        )
    archive = _read_json(archive_path)
    if not isinstance(archive, dict):
        raise ResearchIngestionError(
            f"invalid references archive (not an object): {archive_path}"
        )
    documents = build_reference_documents(cve, archive)
    result = _store_documents(documents, store, dry_run=dry_run, cve_id=cve)
    result.notes.append(
        f"references: {len(documents)} document(s) from {archive_path.name}"
    )
    return result


def ingest_research(
    cve_id: str,
    store: Any,
    research_dir: str | Path = RESEARCH_DIR,
    *,
    dry_run: bool = False,
    references_only: bool = False,
) -> ResearchIngestionResult:
    """Small umbrella API over the CVE + reference ingestion passes."""
    if references_only:
        return ingest_reference_archive(
            cve_id, store, research_dir, dry_run=dry_run
        )
    return ingest_cve_research(cve_id, store, research_dir, dry_run=dry_run)
