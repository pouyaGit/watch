"""Deterministic research queue (Stage R18).

Combines the R15 exploitability / R16 research-priority score with the R17
asset-relevance score into a single, explainable, research-planning queue of
deterministic CVE x program candidates.

RESEARCH PLANNING ONLY. This module is pure and offline: no HTTP, DNS, Nuclei,
browser, subprocess, exploit execution, active validation, 5B-5J, findings,
alerts, production mutation, LLM, or external network. Items never say a
target is vulnerable and never instruct exploitation.

No intelligence engine is duplicated here: priority comes from R16, relevance
from R17, and this module only generates candidates, applies explicit hard
gates, combines the two scores, and ranks deterministically.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path

from ai.knowledge.intelligence import IntelligenceEvidence
from ai.knowledge.relevance import (
    AssetRecord,
    assess_asset_relevance,
    assets_from_programs,
    assets_from_research_metadata,
    derive_technology_hints,
    load_program_definitions,
)

QUEUE_RULE_VERSION = "r18-1"
QUEUE_PRIORITY_WEIGHT = 0.60
QUEUE_RELEVANCE_WEIGHT = 0.40
QUEUE_MIN_SCORE = 0
QUEUE_MAX_SCORE = 100

# Only these R17 relevance classes produce a queue candidate. NONE / UNKNOWN
# never do, so a CVE with no deterministic relationship creates no item.
_QUEUE_ELIGIBLE_RELEVANCE = frozenset({"LOW", "MEDIUM", "HIGH"})

_MAX_EVIDENCE = 40

_PRIORITY_LABELS = {
    "CRITICAL_RESEARCH": "critical research priority",
    "HIGH_RESEARCH": "high research priority",
    "MEDIUM_RESEARCH": "medium research priority",
    "LOW_RESEARCH": "low research priority",
    "INSUFFICIENT_DATA": "insufficient research data",
}


@dataclass
class ResearchQueueItem:
    """Deterministic, explainable research-planning queue item."""

    queue_id: str = ""
    cve: str = ""
    program: str = ""
    priority_class: str = "INSUFFICIENT_DATA"
    priority_score: int = 0
    relevance: str = "UNKNOWN"
    relevance_score: int = 0
    queue_score: int = 0
    rank: int = 0
    reasons: list[str] = dataclass_field(default_factory=list)
    blockers: list[str] = dataclass_field(default_factory=list)
    unknown_factors: list[str] = dataclass_field(default_factory=list)
    evidence: list[IntelligenceEvidence] = dataclass_field(default_factory=list)
    rule_version: str = QUEUE_RULE_VERSION


def _ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def queue_id_for(cve: str, program: str) -> str:
    """Stable slot identity for a CVE x program research candidate."""

    basis = f"{QUEUE_RULE_VERSION}\n{cve}\n{program}"
    return "rq-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def queue_score_for(priority_score: int, relevance_score: int) -> int:
    """Deterministic half-up integer combination of both bounded scores."""

    raw = (
        QUEUE_PRIORITY_WEIGHT * int(priority_score)
        + QUEUE_RELEVANCE_WEIGHT * int(relevance_score)
    )
    return max(
        QUEUE_MIN_SCORE,
        min(QUEUE_MAX_SCORE, int(math.floor(raw + 0.5))),
    )


def _priority_label(priority_class: str) -> str:
    return _PRIORITY_LABELS.get(
        priority_class, "research priority"
    )


def _dedupe_evidence(
    evidence: list[IntelligenceEvidence],
) -> list[IntelligenceEvidence]:
    merged: dict[tuple, IntelligenceEvidence] = {}
    for item in evidence or []:
        key = (
            getattr(item, "field", ""),
            getattr(item, "value", ""),
            getattr(item, "source_artifact", ""),
            getattr(item, "source_url", "") or "",
            getattr(item, "source_type", ""),
            getattr(item, "evidence", ""),
            getattr(item, "rule_id", ""),
            getattr(item, "rule_version", ""),
        )
        merged.setdefault(key, item)
    ordered = [merged[key] for key in sorted(merged)]
    return ordered[:_MAX_EVIDENCE]


def _as_asset(record: object) -> AssetRecord | None:
    if isinstance(record, AssetRecord):
        return record
    if isinstance(record, dict):
        return AssetRecord.from_dict(record)
    return None


def queue_items_for_vulnerability(
    vulnerability: dict, assets: object
) -> list[ResearchQueueItem]:
    """Build deterministic CVE x program candidates for one vulnerability.

    A candidate is created only when the vulnerability carries research
    intelligence, the program exists in the local inventory, and the R17
    relevance for that program is deterministically positive (LOW+). NONE or
    UNKNOWN relevance never creates an item.
    """

    cve = str((vulnerability or {}).get("cve") or "").strip()
    if not cve:
        return []

    products = list(vulnerability.get("products") or [])
    technologies = list(vulnerability.get("technologies") or [])
    components = list(vulnerability.get("components") or [])
    parameters = list(vulnerability.get("parameters") or [])
    vulnerability_types = list(
        vulnerability.get("vulnerability_types") or []
    )
    cwes = list(vulnerability.get("cwes") or [])
    evidence = list(vulnerability.get("evidence") or [])
    priority_class = str(
        vulnerability.get("priority_class") or "INSUFFICIENT_DATA"
    )
    priority_score = int(vulnerability.get("priority_score") or 0)
    priority_reasons = list(vulnerability.get("priority_reasons") or [])
    priority_evidence = list(vulnerability.get("priority_evidence") or [])
    version_expected = bool(vulnerability.get("version_expected"))

    if not (products or components or technologies or vulnerability_types):
        return []

    groups: dict[str, list[AssetRecord]] = {}
    for raw in assets or []:
        record = _as_asset(raw)
        if record is None or not record.program:
            continue
        groups.setdefault(record.program, []).append(record)

    items: list[ResearchQueueItem] = []
    for program in sorted(groups):
        group = groups[program]
        relevance = assess_asset_relevance(
            products=products,
            technologies=technologies,
            components=components,
            parameters=parameters,
            vulnerability_types=vulnerability_types,
            cwes=cwes,
            assets=group,
            evidence=evidence,
        )
        if (
            relevance.relevance not in _QUEUE_ELIGIBLE_RELEVANCE
            or relevance.score <= 0
        ):
            continue

        blockers: list[str] = []
        only_technology_match = bool(relevance.reasons) and all(
            reason.startswith("technology match:")
            for reason in relevance.reasons
        )
        if only_technology_match:
            blockers.append("only generic technology match")

        group_has_component = any(record.components for record in group)
        group_has_path = any(record.paths for record in group)
        if products and not group_has_component:
            blockers.append("affected plugin not observed")
        if components and not (group_has_component or group_has_path):
            blockers.append("asset component not observed")
        if version_expected:
            blockers.append("asset version unknown")

        reasons = _ordered_unique(
            [_priority_label(priority_class)]
            + priority_reasons
            + list(relevance.reasons)
        )
        items.append(
            ResearchQueueItem(
                queue_id=queue_id_for(cve, program),
                cve=cve,
                program=program,
                priority_class=priority_class,
                priority_score=max(
                    QUEUE_MIN_SCORE, min(QUEUE_MAX_SCORE, priority_score)
                ),
                relevance=relevance.relevance,
                relevance_score=relevance.score,
                queue_score=queue_score_for(priority_score, relevance.score),
                rank=0,
                reasons=reasons,
                blockers=_ordered_unique(blockers),
                unknown_factors=_ordered_unique(
                    list(relevance.unknown_factors)
                ),
                evidence=_dedupe_evidence(
                    list(priority_evidence) + list(relevance.evidence)
                ),
            )
        )
    return items


def rank_research_queue(
    items: list[ResearchQueueItem],
) -> list[ResearchQueueItem]:
    """Assign 1-based ranks with a fully deterministic sort key.

    queue_score desc, priority_score desc, relevance_score desc, CVE asc,
    program asc. No timestamps, no randomness.
    """

    ordered = sorted(
        items,
        key=lambda item: (
            -item.queue_score,
            -item.priority_score,
            -item.relevance_score,
            item.cve,
            item.program,
        ),
    )
    ranked: list[ResearchQueueItem] = []
    for index, item in enumerate(ordered, start=1):
        ranked.append(
            ResearchQueueItem(
                queue_id=item.queue_id,
                cve=item.cve,
                program=item.program,
                priority_class=item.priority_class,
                priority_score=item.priority_score,
                relevance=item.relevance,
                relevance_score=item.relevance_score,
                queue_score=item.queue_score,
                rank=index,
                reasons=list(item.reasons),
                blockers=list(item.blockers),
                unknown_factors=list(item.unknown_factors),
                evidence=list(item.evidence),
                rule_version=item.rule_version,
            )
        )
    return ranked


def build_research_queue(
    entries: object,
) -> list[ResearchQueueItem]:
    """Build and rank the queue from per-CVE (vulnerability, assets) entries.

    ``entries`` is an iterable of dicts with keys ``vulnerability`` and
    ``assets``. Candidate generation stays per-CVE, so no evidence or asset
    leaks across CVEs and no program leaks across items.
    """

    items: list[ResearchQueueItem] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        items.extend(
            queue_items_for_vulnerability(
                entry.get("vulnerability") or {},
                entry.get("assets") or [],
            )
        )
    return rank_research_queue(items)


def _evidence_dict(item: object) -> dict:
    return {
        "field": getattr(item, "field", ""),
        "value": getattr(item, "value", ""),
        "source_artifact": getattr(item, "source_artifact", ""),
        "source_url": getattr(item, "source_url", None),
        "source_type": getattr(item, "source_type", ""),
        "evidence": getattr(item, "evidence", ""),
        "rule_id": getattr(item, "rule_id", ""),
        "rule_version": getattr(item, "rule_version", ""),
    }


def queue_item_projection(item: ResearchQueueItem) -> dict:
    """Serialize one queue item for the ``KnowledgeResearchQueueItem`` schema."""

    return {
        "queue_id": item.queue_id,
        "cve": item.cve,
        "program": item.program,
        "priority_class": item.priority_class,
        "priority_score": item.priority_score,
        "relevance": item.relevance,
        "relevance_score": item.relevance_score,
        "queue_score": item.queue_score,
        "rank": item.rank,
        "reasons": list(item.reasons),
        "blockers": list(item.blockers),
        "unknown_factors": list(item.unknown_factors),
        "evidence": [_evidence_dict(entry) for entry in item.evidence],
        "rule_version": item.rule_version,
    }


def research_queue_projection(
    items: list[ResearchQueueItem],
) -> list[dict]:
    return [queue_item_projection(item) for item in items]


# ===========================================================================
# Local orchestration over the R15-R18 engines (shared by CLI and dashboard).
#
# Reads only local persisted artifacts: the KnowledgeStore (local JSON), the
# local research payloads, and the local program definitions. No network, no
# Mongo, no subprocess.
# ===========================================================================

# Keys accepted by ai.knowledge.relevance.assess_asset_relevance.
RELEVANCE_INPUT_KEYS: tuple[str, ...] = (
    "products",
    "technologies",
    "components",
    "parameters",
    "vulnerability_types",
    "cwes",
    "evidence",
)


def cve_from_document(document) -> str:
    """Best-effort CVE id for a KB document (tag first, then artifact name)."""

    for tag in getattr(document, "tags", None) or []:
        text = str(tag)
        if text.startswith("cve:"):
            return text[4:]
    name = str(getattr(document, "source_url", "") or "").rsplit("/", 1)[-1]
    if name.endswith(".cli.json"):
        return name[: -len(".cli.json")]
    return ""


def load_research_payload(cve: str, research_dir: object) -> dict:
    """Read the local ``<CVE>.cli.json`` (read-only); {} when absent."""

    if not cve:
        return {}
    path = Path(research_dir) / f"{cve}.cli.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def vulnerability_profile(document, payload: dict, cve: str) -> dict:
    """Deterministic vulnerability profile for one CVE from local data."""

    cve_block = payload.get("cve") if isinstance(payload.get("cve"), dict) else {}
    research = (
        payload.get("research")
        if isinstance(payload.get("research"), dict)
        else {}
    )
    products = list(cve_block.get("products") or []) + list(
        research.get("affected_products") or []
    )
    priority = getattr(document, "research_priority", None)
    return {
        "cve": cve,
        "products": products,
        "technologies": derive_technology_hints(products),
        "components": list(getattr(document, "components", []) or []),
        "parameters": list(getattr(document, "parameters", []) or []),
        "vulnerability_types": list(
            getattr(document, "vulnerability_types", []) or []
        ),
        "cwes": list(getattr(document, "cwes", []) or []),
        "evidence": list(getattr(document, "intelligence_evidence", []) or []),
        "priority_class": getattr(priority, "priority", "INSUFFICIENT_DATA"),
        "priority_score": int(getattr(priority, "score", 0) or 0),
        "priority_reasons": list(getattr(priority, "reasons", []) or []),
        "priority_evidence": list(getattr(priority, "evidence", []) or []),
        "version_expected": bool(research.get("affected_versions")),
    }


def relevance_inputs(profile: dict) -> dict:
    """Select the assess_asset_relevance inputs from a vulnerability profile."""

    return {key: profile.get(key, []) for key in RELEVANCE_INPUT_KEYS}


def _dedupe_assets(records: list[AssetRecord]) -> list[AssetRecord]:
    deduped: dict[tuple, AssetRecord] = {}
    for record in records:
        deduped.setdefault((record.program, record.asset), record)
    return [deduped[key] for key in sorted(deduped)]


def local_cve_context(
    store, research_dir: object, programs_dir: object, cve: str | None = None
) -> list[dict]:
    """Return local per-CVE contexts (document + payload + assets).

    Deterministic ordering; strictly per-CVE so no evidence or asset leaks
    across CVEs.
    """

    programs = load_program_definitions(programs_dir)
    if cve:
        documents = store.retrieve(tags=[f"cve:{cve}"])
    else:
        documents = store.retrieve()
    synthesis = [
        document
        for document in documents
        if str(getattr(document, "source_url", "")).endswith(".cli.json")
    ]
    synthesis.sort(
        key=lambda document: cve_from_document(document)
        or str(getattr(document, "knowledge_id", ""))
    )
    contexts: list[dict] = []
    for document in synthesis:
        cve_id = cve_from_document(document)
        if cve and cve_id and cve_id != cve:
            continue
        payload = load_research_payload(cve_id, research_dir)
        assets = list(assets_from_programs(programs)) + list(
            assets_from_research_metadata(payload, programs)
        )
        contexts.append(
            {
                "cve": cve_id,
                "document": document,
                "payload": payload,
                "assets": _dedupe_assets(assets),
            }
        )
    return contexts


def build_local_research_queue(
    store, research_dir: object, programs_dir: object, cve: str | None = None
) -> list[ResearchQueueItem]:
    """Build and rank the queue from the local KB + research + programs."""

    entries = [
        {
            "vulnerability": vulnerability_profile(
                context["document"], context["payload"], context["cve"]
            ),
            "assets": context["assets"],
        }
        for context in local_cve_context(
            store, research_dir, programs_dir, cve=cve
        )
    ]
    return build_research_queue(entries)


