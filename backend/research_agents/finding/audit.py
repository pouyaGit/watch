"""Audit lineage for the finding verification layer (Phase 16).

research -> candidate -> triage -> correlation -> verification objective
-> hunt plan -> authorization -> observation -> evidence -> verification
gate -> case -> handoff.

Rows never carry secrets (rule: no API keys/headers/secret-bearing data).
"""

from __future__ import annotations

from typing import Any

FINDING_RULE_VERSION = "finding-audit-1"

# exact secret-bearing key names never persisted (rule: no API keys /
# Authorization headers / secret-bearing request data — ever)
_SECRET_KEYS = frozenset({
    "api_key", "apikey", "openrouter_api_key", "authorization",
    "password", "passwd", "secret", "token", "access_token",
    "refresh_token", "cookie", "set-cookie", "session",
})


def _is_secret_key(key: str) -> bool:
    low = str(key).strip().lower()
    return low in _SECRET_KEYS or low.endswith("_secret") \
        or low.endswith("_password") or low.endswith("_api_key")


def _scrub_value(value: Any) -> Any:
    """Redact credential-looking VALUES even under innocent keys."""
    if isinstance(value, str):
        low = value.strip().lower()
        if low.startswith("sk-") or low.startswith("bearer ") \
                or low.startswith("key-") or "openrouter_api_key=" in low:
            return "[REDACTED]"
    return value


def finding_event(stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Bounded audit event for the runtime audit chain (event name is
    ``finding_<stage>`` — never collides with runtime/hunt/campaign).
    Secret-like keys are dropped and credential-like values redacted."""
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            continue
        if _is_secret_key(key):
            continue
        value = _scrub_value(value)
        if isinstance(value, (str, int, float, bool)):
            clean[str(key)[:40]] = value
        elif isinstance(value, (list, tuple)):
            clean[str(key)[:40]] = [
                str(_scrub_value(v))[:120] for v in list(value)[:20]]
        elif isinstance(value, dict):
            clean[str(key)[:40]] = {
                str(k)[:60]: str(_scrub_value(v))[:160]
                for k, v in list(value.items())[:20]
                if not _is_secret_key(k)}
    return {
        "event": f"finding_{str(stage)[:60]}",
        "rule_version": FINDING_RULE_VERSION,
        **clean,
    }


def lineage_row(*, candidate_id: str, verification_id: str = "",
                case_id: str = "", job_id: str = "", plan_id: str = "",
                authorization_ids: list[str] | None = None,
                observation_ids: list[str] | None = None,
                evidence_refs: list[str] | None = None,
                campaign_id: str = "", objective_id: str = "",
                specialist: str = "", model_requested: str = "",
                model_resolved: str = "", prompt_version: str = "",
                gate_result: str = "", lifecycle_transition: str = "",
                reason_codes: list[str] | None = None,
                ) -> dict[str, Any]:
    """Full-lineage row (Phase 16).  Every id is a reference; no secrets."""
    return {
        "candidate_id": candidate_id,
        "verification_id": verification_id,
        "case_id": case_id,
        "job_id": job_id,
        "plan_id": plan_id,
        "authorization_ids": list(authorization_ids or []),
        "observation_ids": list(observation_ids or []),
        "evidence_refs": list(evidence_refs or []),
        "campaign_id": campaign_id,
        "objective_id": objective_id,
        "specialist": specialist,
        "model_requested": model_requested,
        "model_resolved": model_resolved,
        "prompt_version": prompt_version,
        "gate_result": gate_result,
        "lifecycle_transition": lifecycle_transition,
        "reason_codes": list(reason_codes or []),
        "rule_version": FINDING_RULE_VERSION,
    }
