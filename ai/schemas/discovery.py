from __future__ import annotations

from pydantic import BaseModel, Field


class DiscoveredSource(BaseModel):
    url: str
    source_type: str
    title: str | None = None
    query: str | None = None

    priority: int = 0
    confidence: float = 0.0

    tags: list[str] = Field(default_factory=list)


class DiscoveryResult(BaseModel):
    cve_id: str
    sources: list[DiscoveredSource] = Field(
        default_factory=list
    )