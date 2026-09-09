from pydantic import BaseModel, Field


class ReferenceDocument(BaseModel):
    url: str
    source_type: str

    title: str | None = None
    # Normalized extracted body text (Stage R13). For legacy producers
    # this may hold the raw fetched text; ``content_hash`` below always
    # hashes the exact persisted representation of ``content``.
    content: str = ""

    status_code: int | None = None

    # SHA-256 of the normalized UTF-8 ``content`` above (None when
    # extraction failed or was never performed -- never fabricated).
    content_hash: str | None = None

    # Stage R13 additive provenance (all optional; old records stay valid).
    raw_content_hash: str | None = None
    extraction_format: str | None = None
    extraction_status: str | None = None

    tags: list[str] = Field(
        default_factory=list
    )


class ReferenceContext(BaseModel):
    source_url: str
    source_type: str
    title: str | None = None

    exact_record: str | None = None

    context_chunks: list[str] = Field(
        default_factory=list
    )