"""EPIC 6 research data models: normalized records with provenance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalizedRecord:
    """One Watch-domain record, normalized without inference."""

    host: str
    url: str
    endpoint: str
    parameter: str
    method: str
    technologies: tuple[str, ...]
    versions: tuple[str, ...]
    source_mode: str
    provenance: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "url": self.url,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "technologies": list(self.technologies),
            "versions": list(self.versions),
            "source_mode": self.source_mode,
            "provenance": dict(self.provenance),
        }


__all__ = ["NormalizedRecord"]
