"""Report generation (EPIC 5 Part 8): restating run records as sections.

Observed facts carry intake fields only; planned observations carry
plan step summaries only; missing evidence is the sorted union of
outstanding items; context carries prior-work references; blocked
actions carry failures; next steps carry each review item's
recommended action. Nothing is added, nothing is concluded.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from aec.reporting.models import ResearchReport

_FACT_KEYS = ("case_id", "asset", "endpoint", "parameter", "category",
              "technology")


def _cases(run: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    cases = run.get("cases", [])
    return [item for item in cases if isinstance(item, Mapping)]


def generate_report(run: Any) -> ResearchReport:
    """Build a deterministic report from a run mapping."""
    if not isinstance(run, Mapping):
        raise ValueError("report needs a run mapping")
    run_id = str(run.get("run_id", ""))
    cases = _cases(run)
    facts = tuple(
        {
            "case_id": str(case.get("case_id", "")),
            "asset": str(case.get("asset", "")),
            "endpoint": str(case.get("endpoint", "")),
            "parameter": str(case.get("parameter", "")),
            "category": str(case.get("category", "")),
            "technology": list(case.get("technology", [])),
        }
        for case in sorted(cases, key=lambda item: str(item.get("case_id", "")))
    )
    planned = tuple(
        {
            "plan_id": str(case.get("plan_id", "")),
            "case_id": str(case.get("case_id", "")),
            "steps": [
                {
                    "step_id": str(step.get("step_id", "")),
                    "purpose": str(step.get("purpose", "")),
                    "endpoint": str(step.get("endpoint", "")),
                }
                for step in case.get("steps", [])
                if isinstance(step, Mapping)
            ],
        }
        for case in sorted(cases, key=lambda item: str(item.get("case_id", "")))
        if case.get("plan_id")
    )
    missing = tuple(sorted({
        str(item)
        for case in cases
        for item in (case.get("missing", []) or [])
        if str(item)
    }))
    duplicates: list[str] = []
    patterns = 0
    for case in cases:
        prior = case.get("prior", {})
        if isinstance(prior, Mapping) and int(prior.get("related_patterns", 0) or 0):
            patterns += int(prior.get("related_patterns", 0))
    for skip in run.get("cases_skipped", []) or []:
        if isinstance(skip, Mapping) and skip.get("reason") == "DUPLICATE_CANDIDATE":
            duplicates.append(str(skip.get("ref", "")))
    context = {
        "duplicate_refs": sorted(duplicates),
        "related_pattern_count": patterns,
        "cases_with_prior": sum(
            1 for case in cases
            if isinstance(case.get("prior"), Mapping)
            and case["prior"].get("researched")
        ),
    }
    failures = run.get("failures", []) or []
    blocked = tuple(
        {
            "ref": str(item.get("ref", "")),
            "kind": str(item.get("kind", "")),
            "detail": str(item.get("detail", "")),
        }
        for item in failures
        if isinstance(item, Mapping)
    )
    review_items = run.get("review_items", []) or []
    steps = tuple(
        {
            "case_id": str(item.get("case_id", "")),
            "action": str(item.get("recommended_next_action", "")),
        }
        for item in review_items
        if isinstance(item, Mapping)
    )
    canonical = json.dumps(
        {"run_id": run_id, "facts": facts, "planned": planned,
         "missing": missing, "blocked": blocked, "steps": steps},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    report_id = "report-" + hashlib.sha256(canonical.encode()).hexdigest()[:12]
    return ResearchReport(
        report_id=report_id,
        run_id=run_id,
        observed_facts=facts,
        planned_observations=planned,
        missing_evidence=missing,
        context=context,
        blocked_actions=blocked,
        next_steps=steps,
    )


def serialize_report(report: ResearchReport) -> str:
    """Stable JSON for a research report."""
    return json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":"))
