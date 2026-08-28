from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

from ai.schemas.knowledge import (
    KnowledgeAggregate,
    KnowledgeAttributedValue,
    KnowledgeConfidenceAttribution,
    KnowledgeDocument,
    KnowledgeProvenance,
    KnowledgeSourceClaims,
)


class KnowledgeStoreIntegrityError(ValueError):
    """Raised when persisted knowledge-store state is inconsistent."""


class KnowledgeIdCollisionError(KnowledgeStoreIntegrityError):
    """Raised when one short knowledge ID identifies multiple hashes."""


def content_hash(content: str) -> str:
    """Return the canonical SHA-256 key for UTF-8 document content."""

    return hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()


def _knowledge_id(document_hash: str) -> str:
    return f"kb-{document_hash[:16]}"


def _normalize_source_type(value: str) -> str:
    return " ".join(value.lower().split())


def canonicalize_source_url(value: str) -> str:
    """Canonicalize source identity without relying on mutable metadata."""

    parsed = urlsplit(value.strip())
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port

    netloc = hostname
    if port and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        netloc = f"{hostname}:{port}"

    return urlunsplit(
        (scheme, netloc, parsed.path or "/", parsed.query, "")
    )


def source_id(source_type: str, source_url: str) -> str:
    identity = (
        f"{_normalize_source_type(source_type)}\n"
        f"{canonicalize_source_url(source_url)}"
    )
    return "src-" + hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:16]


def _claim_id(claim: KnowledgeSourceClaims) -> str:
    payload = claim.model_dump(exclude={"claim_id"}, mode="json")
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "clm-" + hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()[:16]


def _normalize_metadata(value: str) -> str:
    """Normalize metadata for deterministic exact matching only."""

    return " ".join(
        re.sub(
            r"[^a-z0-9]+",
            " ",
            value.lower(),
        ).split()
    )


def _normalize_values(
    values: Iterable[str] | None,
) -> set[str]:
    return {
        normalized
        for value in values or []
        if value
        if (normalized := _normalize_metadata(value))
    }


class KnowledgeStore:
    """
    Small local JSON knowledge store.

    Content hashes are canonical deduplication keys. Knowledge IDs are stable
    short identifiers derived from those hashes. The store is intentionally
    metadata-only: it provides no network access, full-text search, semantic
    search, embeddings, or model inference.
    """

    def __init__(
        self,
        root_dir: str | Path = "ai_data/knowledge",
    ):
        self.root_dir = Path(root_dir)
        self.documents_dir = self.root_dir / "documents"
        self.index_path = self.root_dir / "index.json"

    def _document_path(
        self,
        document_hash: str,
    ) -> Path:
        return self.documents_dir / f"{document_hash}.json"

    def _read_json(
        self,
        path: Path,
    ) -> dict:
        try:
            return json.loads(
                path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"Invalid knowledge-store JSON: {path}"
            ) from exc

    def _write_json_atomic(
        self,
        path: Path,
        payload: dict,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

        temp_path = path.with_suffix(
            f"{path.suffix}.tmp"
        )

        temp_path.write_text(
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        temp_path.replace(path)

    def _load_index(self) -> dict:
        if not self.index_path.exists():
            return {
                "documents": {},
                "version": 1,
            }

        index = self._read_json(self.index_path)

        if not isinstance(index, dict):
            raise ValueError(
                "Knowledge-store index must be a JSON object."
            )

        documents = index.get("documents")

        if not isinstance(documents, dict):
            raise ValueError(
                "Knowledge-store index has no valid documents map."
            )

        return index

    def _save_index(
        self,
        index: dict,
    ) -> None:
        documents = index.get("documents", {})

        ordered_documents = {
            key: documents[key]
            for key in sorted(documents)
        }

        self._write_json_atomic(
            self.index_path,
            {
                "documents": ordered_documents,
                "version": 1,
            },
        )

    def _load_document(
        self,
        document_hash: str,
    ) -> KnowledgeDocument | None:
        path = self._document_path(document_hash)

        if not path.exists():
            return None

        payload = self._read_json(path)

        try:
            document = KnowledgeDocument.model_validate(payload)
        except ValueError as exc:
            raise ValueError(
                f"Invalid knowledge document: {path}"
            ) from exc

        calculated_hash = content_hash(document.content)

        if document.content_hash != calculated_hash:
            raise KnowledgeStoreIntegrityError(
                "Knowledge document content_hash does not match its content: "
                f"{path}"
            )

        if calculated_hash != document_hash:
            raise KnowledgeStoreIntegrityError(
                f"Knowledge document hash does not match filename: {path}"
            )

        if document.knowledge_id != _knowledge_id(calculated_hash):
            raise KnowledgeStoreIntegrityError(
                "Knowledge document knowledge_id does not match its "
                f"content hash: {path}"
            )

        if document.schema_version >= 2:
            expected_aggregate = self._build_aggregate(
                self._normalized_provenance(document)
            )
            if (
                document.aggregate.model_dump(mode="json")
                != expected_aggregate.model_dump(mode="json")
            ):
                raise KnowledgeStoreIntegrityError(
                    "Knowledge document aggregate does not match "
                    f"source claims: {path}"
                )

        return document

    def _validate_index_entry(
        self,
        document_hash: str,
        entry: dict,
        document: KnowledgeDocument,
    ) -> None:
        if not isinstance(entry, dict):
            raise KnowledgeStoreIntegrityError(
                "Knowledge-store index entry must be a JSON object: "
                f"{document_hash}"
            )

        expected_path = str(
            self._document_path(document_hash).relative_to(
                self.root_dir
            )
        )

        if entry.get("knowledge_id") != document.knowledge_id:
            raise KnowledgeStoreIntegrityError(
                "Knowledge-store index knowledge_id does not match "
                f"document: {document_hash}"
            )

        if entry.get("path") != expected_path:
            raise KnowledgeStoreIntegrityError(
                "Knowledge-store index path does not match document: "
                f"{document_hash}"
            )

        if document.content_hash != document_hash:
            raise KnowledgeStoreIntegrityError(
                "Knowledge-store index hash does not match document: "
                f"{document_hash}"
            )

    def _validated_document_from_index(
        self,
        document_hash: str,
        index: dict,
    ) -> KnowledgeDocument | None:
        document = self._load_document(document_hash)
        entry = index["documents"].get(document_hash)

        if document is None:
            if entry is not None:
                raise KnowledgeStoreIntegrityError(
                    "Knowledge-store index references a missing document: "
                    f"{document_hash}"
                )
            return None

        if entry is None:
            raise KnowledgeStoreIntegrityError(
                "Knowledge-store document is missing an index entry: "
                f"{document_hash}"
            )

        self._validate_index_entry(
            document_hash,
            entry,
            document,
        )

        return document

    def _ensure_short_id_is_unique(
        self,
        knowledge_id: str,
        document_hash: str,
        index: dict,
    ) -> None:
        for indexed_hash, entry in index["documents"].items():
            if (
                isinstance(entry, dict)
                and entry.get("knowledge_id") == knowledge_id
                and indexed_hash != document_hash
            ):
                raise KnowledgeIdCollisionError(
                    "Short knowledge_id collision for "
                    f"{knowledge_id}: {indexed_hash} and {document_hash}"
                )

        if not self.documents_dir.exists():
            return

        for path in sorted(self.documents_dir.glob("*.json")):
            indexed_hash = path.stem

            if indexed_hash == document_hash:
                continue

            stored = self._load_document(indexed_hash)

            if (
                stored is not None
                and stored.knowledge_id == knowledge_id
            ):
                raise KnowledgeIdCollisionError(
                    "Short knowledge_id collision for "
                    f"{knowledge_id}: {indexed_hash} and {document_hash}"
                )

    def _legacy_claim(
        self,
        document: KnowledgeDocument,
    ) -> KnowledgeSourceClaims:
        claim = KnowledgeSourceClaims(
            title=document.title,
            summary=document.summary,
            technologies=document.technologies,
            xss_types=document.xss_types,
            contexts=document.contexts,
            wafs=document.wafs,
            techniques=document.techniques,
            payload_patterns=document.payload_patterns,
            verification_patterns=document.verification_patterns,
            evidence_quality=document.evidence_quality,
            confidence=document.confidence,
            tags=document.tags,
        )
        return claim.model_copy(update={"claim_id": _claim_id(claim)})

    def _normalized_provenance(
        self,
        document: KnowledgeDocument,
    ) -> list[KnowledgeProvenance]:
        sources = list(document.provenance)

        # A v1 document has only top-level claims. Existing secondary legacy
        # provenance records retain their source identity but receive no
        # invented claims.
        if document.schema_version < 2 or not sources:
            sources.append(
                KnowledgeProvenance(
                    source_url=document.source_url,
                    source_type=document.source_type,
                    published_at=document.published_at,
                    ingested_at=document.indexed_at,
                    title=document.title,
                    claims=[self._legacy_claim(document)],
                )
            )

        normalized = {}

        for source in sources:
            stable_source_id = source_id(
                source.source_type,
                source.source_url,
            )
            claims = []

            for claim in source.claims:
                claims.append(
                    claim.model_copy(
                        update={"claim_id": _claim_id(claim)}
                    )
                )

            existing = normalized.get(stable_source_id)

            if existing is None:
                normalized[stable_source_id] = KnowledgeProvenance(
                    source_id=stable_source_id,
                    source_url=canonicalize_source_url(source.source_url),
                    source_type=_normalize_source_type(source.source_type),
                    published_at=source.published_at,
                    ingested_at=source.ingested_at,
                    title=source.title,
                    claims=claims,
                )
                continue

            merged_claims = {
                claim.claim_id: claim
                for claim in [*existing.claims, *claims]
            }
            normalized[stable_source_id] = existing.model_copy(
                update={
                    "published_at": min(
                        value
                        for value in [
                            existing.published_at,
                            source.published_at,
                        ]
                        if value is not None
                    ) if (
                        existing.published_at or source.published_at
                    ) else None,
                    "ingested_at": min(
                        value
                        for value in [
                            existing.ingested_at,
                            source.ingested_at,
                        ]
                        if value is not None
                    ) if (
                        existing.ingested_at or source.ingested_at
                    ) else None,
                    "title": min(
                        value
                        for value in [existing.title, source.title]
                        if value is not None
                    ) if (existing.title or source.title) else None,
                    "claims": [
                        merged_claims[key]
                        for key in sorted(merged_claims)
                    ],
                }
            )

        return [normalized[key] for key in sorted(normalized)]

    def _merged_provenance(
        self,
        existing: KnowledgeDocument | None,
        incoming: KnowledgeDocument,
    ) -> list[KnowledgeProvenance]:
        documents = [incoming]
        if existing is not None:
            documents.insert(0, existing)

        merged = KnowledgeDocument.model_construct(
            schema_version=2,
            provenance=[
                source
                for document in documents
                for source in self._normalized_provenance(document)
            ]
        )
        return self._normalized_provenance(
            merged.model_copy(update={"schema_version": 2})
        )

    def _aggregate_values(
        self,
        provenance: list[KnowledgeProvenance],
        field: str,
    ) -> list[KnowledgeAttributedValue]:
        values = {}

        for source in provenance:
            for claim in source.claims:
                for value in getattr(claim, field):
                    normalized = _normalize_metadata(value)
                    if not normalized:
                        continue
                    values.setdefault(normalized, {"values": set(), "sources": set()})
                    values[normalized]["values"].add(value)
                    values[normalized]["sources"].add(source.source_id)

        return [
            KnowledgeAttributedValue(
                value=sorted(values[key]["values"])[0],
                source_ids=sorted(values[key]["sources"]),
            )
            for key in sorted(values)
        ]

    def _aggregate_optional_values(
        self,
        provenance: list[KnowledgeProvenance],
        field: str,
    ) -> list[KnowledgeAttributedValue]:
        values = {}

        for source in provenance:
            for claim in source.claims:
                value = getattr(claim, field)
                if not value:
                    continue
                normalized = _normalize_metadata(value)
                if not normalized:
                    continue
                values.setdefault(normalized, {"values": set(), "sources": set()})
                values[normalized]["values"].add(value)
                values[normalized]["sources"].add(source.source_id)

        return [
            KnowledgeAttributedValue(
                value=sorted(values[key]["values"])[0],
                source_ids=sorted(values[key]["sources"]),
            )
            for key in sorted(values)
        ]

    def _build_aggregate(
        self,
        provenance: list[KnowledgeProvenance],
    ) -> KnowledgeAggregate:
        confidence = []
        for source in provenance:
            for claim in source.claims:
                confidence.append(
                    KnowledgeConfidenceAttribution(
                        source_id=source.source_id,
                        claim_id=claim.claim_id,
                        evidence_quality=claim.evidence_quality,
                        confidence=claim.confidence,
                    )
                )

        return KnowledgeAggregate(
            titles=self._aggregate_optional_values(provenance, "title"),
            summaries=self._aggregate_optional_values(provenance, "summary"),
            technologies=self._aggregate_values(provenance, "technologies"),
            xss_types=self._aggregate_values(provenance, "xss_types"),
            contexts=self._aggregate_values(provenance, "contexts"),
            wafs=self._aggregate_values(provenance, "wafs"),
            techniques=self._aggregate_values(provenance, "techniques"),
            payload_patterns=self._aggregate_values(
                provenance, "payload_patterns"
            ),
            verification_patterns=self._aggregate_values(
                provenance, "verification_patterns"
            ),
            tags=self._aggregate_values(provenance, "tags"),
            source_confidence=sorted(
                confidence,
                key=lambda item: (item.source_id, item.claim_id),
            ),
        )

    def _compatibility_projection(
        self,
        document: KnowledgeDocument,
        provenance: list[KnowledgeProvenance],
        aggregate: KnowledgeAggregate,
    ) -> dict:
        primary = provenance[0] if provenance else None
        primary_claim = primary.claims[0] if primary and primary.claims else None
        values = lambda items: [item.value for item in items]

        return {
            "schema_version": 2,
            "title": (primary_claim.title if primary_claim and primary_claim.title else document.title),
            "source_url": primary.source_url if primary else document.source_url,
            "source_type": primary.source_type if primary else document.source_type,
            "published_at": primary.published_at if primary else document.published_at,
            "summary": primary_claim.summary if primary_claim else document.summary,
            "technologies": values(aggregate.technologies),
            "xss_types": values(aggregate.xss_types),
            "contexts": values(aggregate.contexts),
            "wafs": values(aggregate.wafs),
            "techniques": values(aggregate.techniques),
            "payload_patterns": values(aggregate.payload_patterns),
            "verification_patterns": values(aggregate.verification_patterns),
            "tags": values(aggregate.tags),
            "evidence_quality": primary_claim.evidence_quality if primary_claim else document.evidence_quality,
            "confidence": primary_claim.confidence if primary_claim else document.confidence,
            "provenance": provenance,
            "aggregate": aggregate,
        }

    def ingest(
        self,
        document: KnowledgeDocument,
    ) -> tuple[KnowledgeDocument, bool]:
        """
        Persist a document and return ``(stored_document, created)``.

        Identical content is represented by one record. Re-ingestion merges
        unique provenance records while retaining the first document's
        top-level metadata and content.
        """

        document_hash = content_hash(document.content)
        knowledge_id = _knowledge_id(document_hash)
        index = self._load_index()
        existing = self._validated_document_from_index(
            document_hash,
            index,
        )

        self._ensure_short_id_is_unique(
            knowledge_id,
            document_hash,
            index,
        )

        if existing is not None:
            provenance = self._merged_provenance(existing, document)
            aggregate = self._build_aggregate(provenance)
            stored = existing.model_copy(
                update={
                    **self._compatibility_projection(
                        existing,
                        provenance,
                        aggregate,
                    ),
                    "indexed_at": min(
                        existing.indexed_at,
                        document.indexed_at,
                    ),
                }
            )
            created = False
        else:
            provenance = self._merged_provenance(None, document)
            aggregate = self._build_aggregate(provenance)
            stored = document.model_copy(
                update={
                    "content_hash": document_hash,
                    "knowledge_id": knowledge_id,
                    **self._compatibility_projection(
                        document,
                        provenance,
                        aggregate,
                    ),
                }
            )
            created = True

        self._write_json_atomic(
            self._document_path(document_hash),
            stored.model_dump(mode="json"),
        )

        index["documents"][document_hash] = {
            "knowledge_id": knowledge_id,
            "path": str(
                self._document_path(document_hash).relative_to(
                    self.root_dir
                )
            ),
        }
        self._save_index(index)

        return stored, created

    def get_by_hash(
        self,
        document_hash: str,
    ) -> KnowledgeDocument | None:
        index = self._load_index()

        return self._validated_document_from_index(
            document_hash,
            index,
        )

    def get_by_id(
        self,
        knowledge_id: str,
    ) -> KnowledgeDocument | None:
        index = self._load_index()

        matches = []

        for document_hash, entry in index["documents"].items():
            if not isinstance(entry, dict):
                raise KnowledgeStoreIntegrityError(
                    "Knowledge-store index entry must be a JSON object: "
                    f"{document_hash}"
                )

            if entry.get("knowledge_id") == knowledge_id:
                document = self._validated_document_from_index(
                    document_hash,
                    index,
                )

                if document is not None:
                    matches.append((document_hash, document))

        if len(matches) > 1:
            hashes = ", ".join(
                document_hash
                for document_hash, _ in sorted(matches)
            )
            raise KnowledgeIdCollisionError(
                "Short knowledge_id collision for "
                f"{knowledge_id}: {hashes}"
            )

        if matches:
            return matches[0][1]

        return None

    def _matches(
        self,
        document: KnowledgeDocument,
        *,
        technologies: Iterable[str] | None,
        xss_types: Iterable[str] | None,
        contexts: Iterable[str] | None,
        wafs: Iterable[str] | None,
        techniques: Iterable[str] | None,
        source_types: Iterable[str] | None,
        evidence_quality: Iterable[str] | None,
        tags: Iterable[str] | None,
    ) -> bool:
        values = lambda items: [item.value for item in items]
        filters = (
            (technologies, values(document.aggregate.technologies)),
            (xss_types, values(document.aggregate.xss_types)),
            (contexts, values(document.aggregate.contexts)),
            (wafs, values(document.aggregate.wafs)),
            (techniques, values(document.aggregate.techniques)),
            (
                source_types,
                [
                    document.source_type,
                    *(
                        item.source_type
                        for item in document.provenance
                    ),
                ],
            ),
            (
                evidence_quality,
                [
                    item.evidence_quality
                    for item in document.aggregate.source_confidence
                ],
            ),
            (tags, values(document.aggregate.tags)),
        )

        for requested, available in filters:
            requested_values = _normalize_values(requested)

            if not requested_values:
                continue

            if not requested_values.intersection(
                _normalize_values(available)
            ):
                return False

        return True

    def retrieve(
        self,
        *,
        technologies: Iterable[str] | None = None,
        xss_types: Iterable[str] | None = None,
        contexts: Iterable[str] | None = None,
        wafs: Iterable[str] | None = None,
        techniques: Iterable[str] | None = None,
        source_types: Iterable[str] | None = None,
        evidence_quality: Iterable[str] | None = None,
        tags: Iterable[str] | None = None,
    ) -> list[KnowledgeDocument]:
        """Return deterministically ordered metadata matches."""

        index = self._load_index()
        documents = []

        for document_hash in sorted(index["documents"]):
            document = self._validated_document_from_index(
                document_hash,
                index,
            )

            if document is None:
                raise KnowledgeStoreIntegrityError(
                    "Knowledge-store index references a missing document: "
                    f"{document_hash}"
                )

            if self._matches(
                document,
                technologies=technologies,
                xss_types=xss_types,
                contexts=contexts,
                wafs=wafs,
                techniques=techniques,
                source_types=source_types,
                evidence_quality=evidence_quality,
                tags=tags,
            ):
                documents.append(document)

        return sorted(
            documents,
            key=lambda document: document.knowledge_id,
        )
