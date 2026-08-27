from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class NucleiFinding(BaseModel):
    cve_id: str
    target: str
    program: str

    template_id: str
    severity: str

    matched: bool = False

    scope_status: str
    presence_status: str
    version_status: str

    matched_at: str = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    evidence: list[str] = Field(
        default_factory=list
    )

    raw_output: str = ""

    error: str | None = None