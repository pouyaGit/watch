from pydantic import BaseModel, Field


class ReferenceDocument(BaseModel):
    url: str
    source_type: str

    title: str | None = None
    content: str = ""

    status_code: int | None = None

    content_hash: str | None = None

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