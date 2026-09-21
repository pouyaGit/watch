"""Record/candidate normalization (EPIC 4 Part 1).

Accepts Watch asset-intelligence shapes as plain mappings (the backend
modules are never imported here) and emits ResearchCandidateDrafts.
Normalization: lowercase asset, endpoint verbatim, sorted/deduped
lowercase technology, uppercased method, category suffix stripped. Draft
ids are content hashes so the same source always yields the same draft.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from aec.surface.models import (
    INITIAL_OBSERVATION,
    KNOWN_CATEGORIES,
    AdaptOutcome,
    ResearchCandidateDraft,
)


def _refuse(code: str) -> AdaptOutcome:
    return AdaptOutcome(ok=False, draft=None, refusal_code=code)


def _normalize_category(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    token = raw.strip().lower()
    if token.endswith("_candidate"):
        token = token[: -len("_candidate")]
    return token or None


def _candidate_id(source_reference: str, asset: str, endpoint: str,
                  parameter: str, category: str) -> str:
    basis = "|".join((source_reference, asset, endpoint, parameter, category))
    return "rc-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]


def _build(asset: str, endpoint: str, parameters: tuple[str, ...],
           technology: tuple[str, ...], method: str, category: str,
           source_reference: str, notes: tuple[str, ...]) -> AdaptOutcome:
    parameter = parameters[0] if parameters else ""
    draft = ResearchCandidateDraft(
        candidate_id=_candidate_id(
            source_reference, asset, endpoint, parameter, category),
        asset=asset,
        endpoint=endpoint,
        parameters=parameters,
        technology=technology,
        method=method,
        research_category=category,
        evidence_gap={
            "required": [INITIAL_OBSERVATION],
            "missing": [INITIAL_OBSERVATION],
        },
        source_reference=source_reference,
        classification_notes=notes,
    )
    return AdaptOutcome(ok=True, draft=draft, refusal_code=None)


def _common_fields(record: Mapping) -> tuple[str, str, tuple, tuple, str] | AdaptOutcome:
    endpoint = record.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint:
        return _refuse("MISSING_ENDPOINT")
    asset = record.get("subdomain") or record.get("asset") or ""
    if not isinstance(asset, str) or not asset.strip():
        return _refuse("MISSING_ASSET")
    asset = asset.strip().lower()
    raw_parameter = record.get("parameter", "")
    parameters = (raw_parameter,) if isinstance(raw_parameter, str) and raw_parameter else ()
    raw_technology = record.get("technology", ())
    technology: tuple[str, ...] = ()
    if isinstance(raw_technology, (list, tuple)):
        technology = tuple(sorted({
            str(item).strip().lower()
            for item in raw_technology
            if str(item).strip()
        }))
    method = record.get("method", "GET")
    method = str(method).upper() if isinstance(method, str) and method else "GET"
    return asset, endpoint, parameters, technology, method


def adapt_record(record: Any, default_category: str | None = None) -> AdaptOutcome:
    """Normalize an asset-intelligence record mapping into a draft."""
    if not isinstance(record, Mapping):
        return _refuse("INVALID_INPUT")
    fields = _common_fields(record)
    if isinstance(fields, AdaptOutcome):
        return fields
    asset, endpoint, parameters, technology, method = fields
    raw_category = record.get("category", record.get("research_category"))
    category = _normalize_category(raw_category)
    if category is None and default_category is not None:
        category = _normalize_category(default_category)
    if category is None:
        return _refuse("MISSING_CATEGORY")
    if category not in KNOWN_CATEGORIES:
        return _refuse("UNKNOWN_CATEGORY")
    source = record.get("url") or record.get("source") or "watch"
    return _build(asset, endpoint, parameters, technology, method, category,
                  str(source), ())


def adapt_candidate(candidate: Any) -> AdaptOutcome:
    """Normalize a classified-candidate mapping into a draft."""
    if not isinstance(candidate, Mapping):
        return _refuse("INVALID_INPUT")
    fields = _common_fields(candidate)
    if isinstance(fields, AdaptOutcome):
        return fields
    asset, endpoint, parameters, technology, method = fields
    category = _normalize_category(candidate.get("category"))
    if category is None:
        return _refuse("MISSING_CATEGORY")
    if category not in KNOWN_CATEGORIES:
        return _refuse("UNKNOWN_CATEGORY")
    notes: list[str] = []
    confidence = candidate.get("confidence")
    if isinstance(confidence, str) and confidence:
        notes.append(confidence)
    reasons = candidate.get("reasons", ())
    if isinstance(reasons, (list, tuple)):
        notes.extend(str(reason) for reason in reasons)
    source = candidate.get("id") or candidate.get("url") or "watch"
    return _build(asset, endpoint, parameters, technology, method, category,
                  str(source), tuple(notes))


def to_case_kwargs(draft: ResearchCandidateDraft) -> dict[str, Any]:
    """Project a draft onto CaseRef constructor kwargs. No URL is invented."""
    return {
        "case_id": draft.candidate_id,
        "job_id": draft.candidate_id,
        "program": "pilot",
        "host": draft.asset,
        "endpoint": draft.endpoint,
        "parameter": draft.parameters[0] if draft.parameters else "",
        "method": draft.method,
        "category": draft.research_category,
        "confidence": "MEDIUM",
        "url": "",
        "evidence_gap": None,
    }


def serialize_draft(draft: ResearchCandidateDraft) -> str:
    """Stable JSON for a draft (sorted keys, compact separators)."""
    return json.dumps(draft.to_dict(), sort_keys=True, separators=(",", ":"))
