from __future__ import annotations

from pydantic import BaseModel, Field


class DetectionSpec(BaseModel):
    cve_id: str

    protocol: list[str] = Field(
        default_factory=list
    )

    http_method: str | None = None
    path: str | None = None

    query_parameters: list[str] = Field(
        default_factory=list
    )

    headers: dict[str, str] = Field(
        default_factory=dict
    )

    body_pattern: str | None = None

    response_status: list[int] = Field(
        default_factory=list
    )

    response_matchers: list[str] = Field(
        default_factory=list
    )

    version_required: bool = True
    affected_versions: list[str] = Field(
        default_factory=list
    )

    authentication_required: bool | None = None

    destructive: bool = False

    reliable_signature: bool = False

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    evidence: list[str] = Field(
        default_factory=list
    )

    missing_requirements: list[str] = Field(
        default_factory=list
    )