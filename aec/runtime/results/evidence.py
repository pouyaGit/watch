"""EPIC7 Part 8: evidence output — bridge-compatible, never a finding.

Every successful observation produces an evidence artifact carrying the
documented fields (evidence_id, request_id, research_job_id, case_id,
target_id, observation_type, timestamp, status, selected_headers,
content_metadata, response_size, timing_metadata, scope_validation,
authorization_reference, policy_version, redaction_status, integrity).

Raw observation output is never promoted to a confirmed finding: the
strongest claim here is a redacted, integrity-sealed evidence artifact.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from aec.runtime.results.redaction import redact_headers

RULE_VERSION = "aec-runtime-evidence/v1"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      default=str)


@dataclass(frozen=True)
class EvidenceArtifact:
    evidence_id: str
    request_id: str
    research_job_id: str
    case_id: str
    target_id: str
    observation_type: str
    timestamp: int
    status: int
    selected_headers: Mapping[str, str]
    content_metadata: Mapping[str, object]
    response_size: int
    timing_metadata: Mapping[str, int]
    scope_validation: str
    authorization_reference: str
    policy_version: str
    redaction_status: str
    integrity: str
    mode: str = "DRY_RUN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "request_id": self.request_id,
            "research_job_id": self.research_job_id,
            "case_id": self.case_id,
            "target_id": self.target_id,
            "observation_type": self.observation_type,
            "timestamp": self.timestamp,
            "status": self.status,
            "selected_headers": dict(self.selected_headers),
            "content_metadata": dict(self.content_metadata),
            "response_size": self.response_size,
            "timing_metadata": dict(self.timing_metadata),
            "scope_validation": self.scope_validation,
            "authorization_reference": self.authorization_reference,
            "policy_version": self.policy_version,
            "redaction_status": self.redaction_status,
            "integrity": self.integrity,
            "mode": self.mode,
        }

    def bridge_result(self) -> dict[str, Any]:
        """The subset accepted by the EPIC6 evidence bridge ingest."""
        observed = [name for name in self.selected_headers]
        observed.append(self.observation_type)
        return {
            "observation_id": self.evidence_id,
            "request_id": self.request_id,
            "observed_fields": observed,
            "missing_fields": [],
            "tick": self.timestamp,
            "source": "observation-runtime",
        }


def build_evidence(
    *,
    request: Mapping[str, Any],
    tick: int,
    status: int,
    selected_headers: Mapping[str, str],
    content_metadata: Mapping[str, object],
    response_size: int,
    timing_ms: int,
    target_id: str,
    authorization_reference: str,
    policy_version: str,
    mode: str,
    scope_validation: str = "PASS",
) -> EvidenceArtifact:
    """Deterministically construct one sealed evidence artifact."""
    safe_headers = redact_headers(dict(selected_headers))
    basis = _canonical({
        "request_id": request.get("request_id", ""),
        "research_job_id": request.get("research_job_id", ""),
        "case_id": request.get("case_id", ""),
        "target_id": target_id,
        "observation_type": request.get("observation_type", ""),
        "tick": tick,
        "status": status,
        "headers": safe_headers,
        "content": dict(content_metadata),
        "authorization_reference": authorization_reference,
        "policy_version": policy_version,
    })
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    integrity = hashlib.sha256(
        (basis + "|integrity").encode("utf-8")).hexdigest()
    return EvidenceArtifact(
        evidence_id="ev-" + digest[:16],
        request_id=str(request.get("request_id", "")),
        research_job_id=str(request.get("research_job_id", "")),
        case_id=str(request.get("case_id", "")),
        target_id=target_id,
        observation_type=str(request.get("observation_type", "")),
        timestamp=tick if isinstance(tick, int) and tick >= 0 else 0,
        status=status,
        selected_headers=dict(sorted(safe_headers.items())),
        content_metadata=dict(content_metadata),
        response_size=response_size,
        timing_metadata={"total_ms": timing_ms},
        scope_validation=scope_validation,
        authorization_reference=authorization_reference,
        policy_version=policy_version,
        redaction_status="scrubbed",
        integrity=integrity,
        mode=mode,
    )


__all__ = ["EvidenceArtifact", "RULE_VERSION", "build_evidence"]