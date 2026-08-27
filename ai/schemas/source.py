from pydantic import BaseModel, Field


class AffectedVersion(BaseModel):
    version: str | None = None
    less_than: str | None = None
    version_type: str | None = None
    status: str | None = None


class ResearchDocument(BaseModel):
    source_type: str
    title: str
    url: str | None = None
    published_at: str | None = None

    content: str

    vendor: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)

    affected_versions: list[AffectedVersion] = Field(
        default_factory=list
    )

    cvss_score: float | None = None
    cvss_vector: str | None = None

    references: list[str] = Field(default_factory=list)

    tags: list[str] = Field(default_factory=list)