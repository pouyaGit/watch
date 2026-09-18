"""Stage R100 — persisted case human triage decisions (atomic writer).

Records one explicit human triage decision (R100) against the current R99
evidence package of one persisted R76 case:

- loads the existing case artifact (read) and composes the current evidence
  package through the unchanged R99/R91/R77 authorities;
- builds the decision through the pure R100 engine (R56 vocabulary and
  authority rules; case + package fingerprint binding);
- appends the decision to the bounded ``triage_decisions`` block of the case
  artifact and writes atomically (same convention as the existing case
  writers); identical decisions replay without a write;
- never changes case status, readiness, confirmation, evidence or
  acquisition state; never executes anything.

Dry-run (``write=False``) performs the full validation and returns a
``PREVIEW`` outcome without writing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

from ai.knowledge.research_acquisition_ledger import (
    build_case_acquisition_ledger,
)
from ai.knowledge.research_case_evidence_package import (
    EvidencePackageError,
    build_case_evidence_package,
)
from ai.knowledge.research_triage_decision import (
    CaseTriageDecisionError,
    build_case_triage_decision,
    decision_signature,
)
from ai.research_agent.case_evidence import load_case_artifact

RULE_VERSION = "r100-1"

MAX_DECISIONS = 8
MAX_TEXT_CHARS = 320

STATUS_RECORDED = "RECORDED"
STATUS_REPLAYED = "REPLAYED"
STATUS_PREVIEW = "PREVIEW"
STATUS_ERROR = "ERROR"


def _text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _block(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _atomic_write_text(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, dest)


def _case_from_artifact(artifact: Mapping) -> dict | None:
    workspace = _block(artifact.get("research_case_workspace"))
    cases = workspace.get("cases")
    if not isinstance(cases, (list, tuple)) or not cases:
        return None
    case = cases[0]
    return dict(case) if isinstance(case, Mapping) else None


def build_case_package(artifact: object) -> dict:
    """Current R99 evidence package for one persisted case artifact."""

    payload = _block(artifact)
    case = _case_from_artifact(payload)
    if case is None:
        raise CaseTriageDecisionError(
            "MALFORMED_CASE", "case workspace is missing"
        )
    try:
        ledger = build_case_acquisition_ledger(
            case,
            acquisition_plan=payload.get("acquisition_plan"),
            readiness_plan=payload.get("readiness_plan"),
            evidence_provenance=payload.get("evidence_provenance"),
            evidence_completion=payload.get("evidence_completion"),
            evidence_acquisition=payload.get("evidence_acquisition"),
        )
    except Exception:
        ledger = None
    try:
        return build_case_evidence_package(
            case,
            action_plan=payload.get("action_plan"),
            evidence_provenance=payload.get("evidence_provenance"),
            limitations=payload.get("limitations"),
            acquisition_ledger=ledger,
            human_review=_block(payload.get("research_workbench")).get(
                "human_review"
            ),
            source_cve=_block(payload.get("result")).get("cve_id"),
        )
    except EvidencePackageError as exc:
        raise CaseTriageDecisionError(exc.code, exc.safe_message) from None


def load_case_triage_decisions(artifact: object) -> list[dict]:
    """Bounded existing human decisions from one artifact (read-only)."""

    raw = _block(artifact).get("triage_decisions")
    if not isinstance(raw, (list, tuple)):
        return []
    records = [dict(item) for item in raw if isinstance(item, Mapping)]
    return records[-MAX_DECISIONS:]


def record_case_triage_decision(
    case_path: object,
    *,
    decision: object,
    decided_by: object,
    rationale_code: object = "",
    rationale_note: object = "",
    escalation_target: object = "",
    decided_at: object = "",
    write: bool = False,
) -> dict:
    """Validate (and optionally persist) one case human triage decision."""

    outcome: dict = {
        "rule_version": RULE_VERSION,
        "status": STATUS_ERROR,
        "case_id": "",
        "decision": "",
        "decision_ref": "",
        "reviewed_package_fingerprint": "",
        "written": False,
        "replayed": False,
        "reason": "",
    }
    path = Path(case_path)
    try:
        artifact = load_case_artifact(path)
    except CaseTriageDecisionError as exc:  # pragma: no cover - defensive
        outcome["reason"] = exc.code
        return outcome
    except Exception as exc:
        outcome["reason"] = _text(type(exc).__name__, 64)
        return outcome

    case = _case_from_artifact(artifact)
    if case is None:
        outcome["reason"] = "MALFORMED_CASE"
        return outcome
    outcome["case_id"] = _text(case.get("case_id"), 96)

    try:
        package = build_case_package(artifact)
        record = build_case_triage_decision(
            case,
            package,
            decision=decision,
            decided_by=decided_by,
            rationale_code=rationale_code,
            rationale_note=rationale_note,
            escalation_target=escalation_target,
            decided_at=decided_at,
        )
    except CaseTriageDecisionError as exc:
        outcome["reason"] = exc.code
        return outcome
    except Exception as exc:
        outcome["reason"] = _text(type(exc).__name__, 64)
        return outcome

    outcome["decision"] = record["decision"]
    outcome["decision_ref"] = record["decision_ref"]
    outcome["reviewed_package_fingerprint"] = record[
        "reviewed_package_fingerprint"
    ]

    history = load_case_triage_decisions(artifact)
    signature = decision_signature(record)
    if any(decision_signature(item) == signature for item in history):
        outcome["status"] = STATUS_REPLAYED
        outcome["replayed"] = True
        return outcome
    if not write:
        outcome["status"] = STATUS_PREVIEW
        return outcome

    history.append(record)
    updated = dict(artifact)
    updated["triage_decisions"] = history[-MAX_DECISIONS:]
    try:
        _atomic_write_text(
            path,
            json.dumps(
                updated, ensure_ascii=False, indent=2, sort_keys=True
            ),
        )
    except OSError:
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = "WRITE_FAILED"
        return outcome
    outcome["status"] = STATUS_RECORDED
    outcome["written"] = True
    return outcome


__all__ = [
    "RULE_VERSION",
    "MAX_DECISIONS",
    "STATUS_RECORDED",
    "STATUS_REPLAYED",
    "STATUS_PREVIEW",
    "STATUS_ERROR",
    "build_case_package",
    "load_case_triage_decisions",
    "record_case_triage_decision",
]
