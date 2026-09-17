"""Stage R86 — research-result -> research-case activation bridge.

R85 showed the production chain runs end to end (scheduler -> real agent run ->
persisted result -> R83 activity -> UI -> R84 Telegram) but the R76 research
case workspace stayed empty because nothing connected a persisted research
agent result to the existing R70-R77 case lifecycle.

R86 is that bridge and nothing else. It is the smallest deterministic link:

    persisted research agent result (R23 result / R24.6 loop artifact)
      -> explicit, fail-closed eligibility decision
      -> R70 outcomes/actions
      -> R71 acquisition plans
      -> R72 readiness
      -> R73 feedback iteration
      -> R74 evidence intake (no external package: NOT_PROVIDED)
      -> R75 provenance
      -> R76 research case workspace
      -> R77 workbench
      -> one bounded case artifact under ai_data/research/cases/

No authority is reimplemented and no stage output is re-derived: every stage
is called exactly as the existing pipeline calls it, and only the hypothesis
mapping (canonical persisted evidence -> R70 hypothesis shape) is new code.

Hard boundaries encoded here:

- Deterministic eligibility: status, plan/program binding, result-id
  integrity, production-finding flag and canonical evidence are checked in a
  fixed order; the first failure is the reason. Unsupported or malformed
  results fail closed and create no artifact.
- Model output never becomes evidence: hypotheses are derived only from the
  canonical evidence items the agent persisted (evidence ids, source ids,
  content hashes); LLM claims and inferences stay in the source artifact.
- Idempotent by construction: the case artifact is keyed by the deterministic
  R76 case id and is never overwritten; reprocessing the same result creates
  no duplicate case and repeated runs are byte-stable.
- Read-only with respect to the source: agent results are only read, never
  mutated; no Mongo access, no network, no target interaction, no execution,
  no findings, no authorization semantics.
- Bounded and hygiene-safe: only canonical ids, content hashes, bounded
  summaries and the existing stage blocks enter the artifact; the source
  artifact filename (never an absolute path), credentials, tokens, URLs and
  target data are never written into a case artifact.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Callable, Mapping

from ai.knowledge.research_case_workspace import (
    ResearchCaseError,
    build_research_cases,
    summarize_research_cases,
)
from ai.knowledge.research_decision_readiness_planner import (
    plan_decision_readiness,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    plan_evidence_acquisition,
)
from ai.knowledge.research_evidence_intake import intake_and_reevaluate
from ai.knowledge.research_evidence_provenance import (
    analyze_evidence_provenance,
)
from ai.knowledge.research_feedback_loop import evaluate_research_iteration
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)
from ai.knowledge.research_workbench import build_workbench_set
from ai.research_agent import storage
from ai.research_agent.llm_loop import (
    LOOP_RULE_VERSION,
    STATUS_COMPLETED,
    loop_result_id_for,
)
from ai.schemas.research_agent import (
    RESEARCH_AGENT_RULE_VERSION,
    result_id_for,
)

RULE_VERSION = "r86-1"

DEFAULT_CASES_DIR = Path("ai_data/research/cases")

MAX_RESULTS = 32
MAX_HYPOTHESES = 8
MAX_EVIDENCE_IDS = 16
MAX_MISSING_EVIDENCE = 6
MAX_TEXT_CHARS = 240

RESULT_KIND_LOOP = "r24-loop-1"
RESULT_KIND_R23 = "r23-1"
RESULT_KINDS: tuple[str, ...] = (RESULT_KIND_LOOP, RESULT_KIND_R23)

# Closed eligibility reasons (first failure wins; "" means eligible).
REASON_ELIGIBLE = ""
REASON_MALFORMED_RESULT = "MALFORMED_RESULT"
REASON_UNSUPPORTED_RESULT_KIND = "UNSUPPORTED_RESULT_KIND"
REASON_PLAN_BINDING_MISSING = "PLAN_BINDING_MISSING"
REASON_RESULT_ID_MISMATCH = "RESULT_ID_MISMATCH"
REASON_STATUS_NOT_COMPLETED = "STATUS_NOT_COMPLETED"
REASON_PRODUCTION_FINDING = "PRODUCTION_FINDING_NOT_ALLOWED"
REASON_PROGRAM_BINDING_MISSING = "PROGRAM_BINDING_MISSING"
REASON_MALFORMED_EVIDENCE = "MALFORMED_EVIDENCE"
REASON_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

ELIGIBILITY_REASONS: tuple[str, ...] = (
    REASON_ELIGIBLE,
    REASON_MALFORMED_RESULT,
    REASON_UNSUPPORTED_RESULT_KIND,
    REASON_PLAN_BINDING_MISSING,
    REASON_RESULT_ID_MISMATCH,
    REASON_STATUS_NOT_COMPLETED,
    REASON_PRODUCTION_FINDING,
    REASON_PROGRAM_BINDING_MISSING,
    REASON_MALFORMED_EVIDENCE,
    REASON_INSUFFICIENT_EVIDENCE,
)

# Activation statuses (bounded, workflow vocabulary only).
STATUS_ACTIVATED = "ACTIVATED"
STATUS_EXISTS = "EXISTS"
STATUS_INELIGIBLE = "INELIGIBLE"
STATUS_BUILD_REJECTED = "BUILD_REJECTED"
STATUS_ERROR = "ERROR"

_PLAN_ID_RE = re.compile(r"^r22-[0-9a-f]{16}$")
_SAFE_CASE_ID_RE = re.compile(r"^case-[a-z0-9-]{1,72}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

_PRIORITY_BANDS: dict[str, str] = {
    "CRITICAL_RESEARCH": "HIGH",
    "HIGH_RESEARCH": "HIGH",
    "MEDIUM_RESEARCH": "MEDIUM",
    "LOW_RESEARCH": "LOW",
    "INSUFFICIENT_DATA": "LOW",
}

_CONFIDENCE_RANK: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

PlanLoader = Callable[[str], object]

LIMITATIONS: tuple[str, ...] = (
    "Case activation is research-only and advisory; a case is never a "
    "vulnerability verdict and never authorizes execution.",
    "Hypotheses are derived from canonical persisted agent evidence only; "
    "model claims and inferences remain in the source artifact and never "
    "become case evidence.",
    "One case per correlated R70 action: the case artifact is keyed by the "
    "deterministic R76 case id and immutable once written; evidence updates "
    "flow through the existing external evidence submission boundary.",
    "No target interaction, Mongo access, network access, LLM call or "
    "execution is performed by this bridge.",
)


class CaseBridgeError(ValueError):
    """Deterministic, secret-free R86 bridge failure."""

    def __init__(self, code: str, safe_message: str = "") -> None:
        self.code = str(code)
        self.safe_message = " ".join(str(safe_message).split())[:160]
        super().__init__(f"{self.code}: {self.safe_message}")


# ---------------------------------------------------------------------------
# Bounded helpers
# ---------------------------------------------------------------------------


def _text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_strings(value: object, limit: int, item_limit: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        if not isinstance(item, (str, int, float)):
            continue
        text = _text(item, item_limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _content_hash(payload: object) -> str:
    try:
        serialized = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, default=str
        )
    except (TypeError, ValueError):
        return ""
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def default_plan_loader(plan_id: str) -> object:
    """R22 plan projection loader (read-only; ``None`` when unavailable)."""

    try:
        from backend import research_execution

        return research_execution.get_plan(str(plan_id))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Result kind detection (explicit markers only)
# ---------------------------------------------------------------------------


def result_kind(payload: object) -> str:
    """Explicit persisted-result kind; ``""`` when unsupported/malformed."""

    if not isinstance(payload, Mapping):
        return ""
    if (
        _text(payload.get("loop_rule_version"), 32) == LOOP_RULE_VERSION
        and isinstance(payload.get("rounds"), list)
    ):
        return RESULT_KIND_LOOP
    if (
        _text(payload.get("rule_version"), 32) == RESEARCH_AGENT_RULE_VERSION
        and isinstance(payload.get("evidence"), list)
    ):
        return RESULT_KIND_R23
    return ""


def _loop_evidence(payload: Mapping) -> list[Mapping]:
    items: list[Mapping] = []
    for round_item in _mapping_items(payload.get("rounds")):
        discovery = round_item.get("discovery")
        if not isinstance(discovery, Mapping):
            continue
        for evidence in _mapping_items(discovery.get("evidence")):
            items.append(evidence)
    return items


def canonical_evidence(payload: object, kind: str) -> tuple[list[dict], str]:
    """Canonical, bounded evidence items for one persisted result.

    Returns ``(items, error_code)``. ``error_code`` is non-empty when an item
    is not canonical (fail closed) — items are never silently dropped.
    """

    if not isinstance(payload, Mapping):
        return [], REASON_MALFORMED_RESULT
    if kind == RESULT_KIND_LOOP:
        raw = _loop_evidence(payload)
    elif kind == RESULT_KIND_R23:
        raw = _mapping_items(payload.get("evidence"))
    else:
        return [], REASON_UNSUPPORTED_RESULT_KIND
    items: list[dict] = []
    for evidence in raw:
        evidence_id = _text(evidence.get("evidence_id"), 64)
        content_hash = _text(evidence.get("content_hash"), 128)
        source_id = _text(evidence.get("source_id"), 64)
        source_url = _text(evidence.get("source_url"), 512)
        if kind == RESULT_KIND_R23:
            source_id = evidence_id
        if not (evidence_id and content_hash and source_id):
            return [], REASON_MALFORMED_EVIDENCE
        if kind == RESULT_KIND_R23 and not source_url:
            return [], REASON_MALFORMED_EVIDENCE
        items.append(
            {
                "evidence_id": evidence_id,
                "source_id": source_id,
                "content_hash": content_hash,
                "claim": _text(evidence.get("claim")),
                "confidence": _text(evidence.get("confidence"), 16) or "LOW",
                "ref": f"evidence:{evidence_id}",
            }
        )
        if len(items) >= MAX_EVIDENCE_IDS:
            break
    return items, ""


# ---------------------------------------------------------------------------
# Eligibility (deterministic, ordered, fail closed)
# ---------------------------------------------------------------------------


def evaluate_result(
    payload: object,
    *,
    kind: object = None,
    plan_loader: PlanLoader | None = None,
) -> dict:
    """Bounded eligibility decision for one persisted research result."""

    loader = plan_loader or default_plan_loader
    decision: dict = {
        "rule_version": RULE_VERSION,
        "eligible": False,
        "reason": REASON_ELIGIBLE,
        "detail": "",
        "result_kind": "",
        "plan_id": "",
        "cve_id": "",
        "program": "",
        "priority_level": "",
        "result_id": "",
        "evidence_ids": [],
        "evidence_count": 0,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }

    def _reject(reason: str, detail: str = "") -> dict:
        decision["reason"] = reason
        decision["detail"] = _text(detail, 160)
        return decision

    if not isinstance(payload, Mapping):
        return _reject(REASON_MALFORMED_RESULT, "result is not an object")
    detected = _text(kind, 32) or result_kind(payload)
    if detected not in RESULT_KINDS:
        return _reject(
            REASON_UNSUPPORTED_RESULT_KIND, "unsupported result kind"
        )
    decision["result_kind"] = detected

    plan_id = _text(payload.get("plan_id"), 64)
    cve_id = _text(payload.get("cve_id"), 64)
    decision["plan_id"] = plan_id
    decision["cve_id"] = cve_id
    if not _PLAN_ID_RE.match(plan_id) or not cve_id:
        return _reject(
            REASON_PLAN_BINDING_MISSING, "plan/cve binding is missing"
        )

    result_id = _text(payload.get("result_id"), 64)
    decision["result_id"] = result_id
    expected = (
        loop_result_id_for(plan_id, cve_id)
        if detected == RESULT_KIND_LOOP
        else result_id_for(plan_id)
    )
    if result_id != expected:
        return _reject(
            REASON_RESULT_ID_MISMATCH, "result identity does not match plan"
        )

    status = _text(payload.get("status"), 32).upper()
    if status != STATUS_COMPLETED:
        return _reject(
            REASON_STATUS_NOT_COMPLETED, f"status is {status or 'UNKNOWN'}"
        )

    if payload.get("production_finding"):
        return _reject(
            REASON_PRODUCTION_FINDING, "result claims a production finding"
        )

    program = _text(payload.get("program"), 64)
    plan = loader(plan_id)
    plan = plan if isinstance(plan, Mapping) else {}
    priority_level = ""
    metadata = plan.get("metadata")
    if isinstance(metadata, Mapping):
        priority_level = _text(metadata.get("priority_level"), 32)
    if detected == RESULT_KIND_LOOP:
        program = program or _text(plan.get("program"), 64)
    if not program:
        return _reject(
            REASON_PROGRAM_BINDING_MISSING, "program binding is missing"
        )
    decision["program"] = program
    decision["priority_level"] = priority_level

    items, error = canonical_evidence(payload, detected)
    if error:
        return _reject(error, "evidence is not canonical")
    if not items:
        return _reject(REASON_INSUFFICIENT_EVIDENCE, "no canonical evidence")
    decision["evidence_ids"] = [item["evidence_id"] for item in items]
    decision["evidence_count"] = len(items)
    decision["eligible"] = True
    return decision


# ---------------------------------------------------------------------------
# Hypothesis mapping (canonical evidence -> R70 hypothesis shape)
# ---------------------------------------------------------------------------


def build_hypotheses(
    payload: object,
    decision: Mapping,
    *,
    kind: object = None,
) -> list[dict]:
    """One R70-shaped hypothesis per canonical evidence item (bounded)."""

    detected = _text(kind, 32) or _text(decision.get("result_kind"), 32)
    items, error = canonical_evidence(payload, detected)
    if error or not items:
        raise CaseBridgeError(error or REASON_INSUFFICIENT_EVIDENCE)
    cve_id = _text(decision.get("cve_id"), 64)
    priority = _PRIORITY_BANDS.get(
        _text(decision.get("priority_level"), 32).upper(), "LOW"
    )
    hypotheses: list[dict] = []
    for position, item in enumerate(items[:MAX_HYPOTHESES], start=1):
        claim = item["claim"]
        title = claim or f"{cve_id} public-source evidence {position}"
        confidence = item["confidence"].upper()
        if confidence not in _CONFIDENCE_RANK:
            confidence = "LOW"
        hypotheses.append(
            {
                "title": title,
                "category": "CVE_RESEARCH",
                "priority": priority,
                "confidence": confidence,
                "evidence": {
                    "observations": [
                        {"ref": item["ref"], "fact": claim}
                    ],
                    "derived_signals": [],
                },
                "selected_evidence_refs": [item["ref"]],
                "missing_evidence": _missing_evidence(payload, detected),
                "model_generated": False,
            }
        )
    return hypotheses


def _missing_evidence(payload: Mapping, kind: str) -> list[str]:
    values: list[str] = []
    if kind == RESULT_KIND_LOOP:
        values.extend(_bounded_strings(payload.get("gaps"), 8, 160))
        values.extend(_bounded_strings(payload.get("unknowns"), 8, 160))
    else:
        values.extend(_bounded_strings(payload.get("unknowns"), 8, 160))
    out: list[str] = []
    for value in values:
        if value not in out:
            out.append(value)
        if len(out) >= MAX_MISSING_EVIDENCE:
            break
    return out


# ---------------------------------------------------------------------------
# Existing R70-R77 lifecycle composition (authorities reused unchanged)
# ---------------------------------------------------------------------------


def build_case_artifact(
    payload: object,
    *,
    kind: object = None,
    plan_loader: PlanLoader | None = None,
    source_name: str = "",
) -> dict:
    """Run the existing R70-R77 lifecycle for one eligible result.

    Pure with respect to the input (never mutated) and offline; returns the
    bounded case artifact payload that the R81/R83 readers consume.
    """

    decision = evaluate_result(payload, kind=kind, plan_loader=plan_loader)
    if not decision["eligible"]:
        raise CaseBridgeError(decision["reason"], decision["detail"])
    detected = decision["result_kind"]
    program = decision["program"]
    hypotheses = build_hypotheses(payload, decision, kind=detected)

    action_plan = plan_research_actions(hypotheses)
    acquisition_plan = plan_evidence_acquisition(action_plan)
    readiness_plan = plan_decision_readiness(action_plan, acquisition_plan)
    iteration_plan = evaluate_research_iteration(
        hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
    )
    evidence_intake = intake_and_reevaluate(
        None,
        hypotheses=hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
    )
    evidence_provenance = analyze_evidence_provenance(
        evidence_intake,
        hypotheses=hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
    )
    try:
        cases = build_research_cases(
            action_plan,
            acquisition_plan,
            readiness_plan,
            iteration_plan,
            program=program,
            evidence_intake=evidence_intake,
            evidence_provenance=evidence_provenance,
        )
    except ResearchCaseError as exc:
        raise CaseBridgeError("CASE_BUILD_REJECTED", exc.code) from None
    workspace = {
        "rule_version": "r76-1",
        "status": "BUILT",
        "cases": cases,
        "summary": summarize_research_cases(cases),
        "safety": dict(SAFETY_BLOCK),
        "research_only": True,
    }
    workbench = build_workbench_set(
        cases,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        evidence_provenance=evidence_provenance,
    )
    source_payload = payload if isinstance(payload, Mapping) else {}
    return {
        "case_artifact_version": RULE_VERSION,
        "research_run_version": RULE_VERSION,
        "source": "research-agent-result",
        "program": program,
        "result": {
            "artifact": Path(source_name).name if source_name else "",
            "kind": detected,
            "content_hash": _content_hash(source_payload),
            "result_id": decision["result_id"],
            "plan_id": decision["plan_id"],
            "cve_id": decision["cve_id"],
            "status": _text(source_payload.get("status"), 32),
            "rule_version": _text(
                source_payload.get("loop_rule_version")
                or source_payload.get("rule_version"),
                32,
            ),
            "evidence_ids": list(decision["evidence_ids"]),
        },
        "eligibility": {
            "rule_version": RULE_VERSION,
            "eligible": True,
            "reason": REASON_ELIGIBLE,
            "result_kind": detected,
            "evidence_count": decision["evidence_count"],
            "advisory": True,
            "research_only": True,
            "confirmation_state": "NOT_CONFIRMED",
        },
        "research": {"hypotheses": hypotheses},
        "action_plan": action_plan,
        "acquisition_plan": acquisition_plan,
        "readiness_plan": readiness_plan,
        "iteration_plan": iteration_plan,
        "evidence_intake": evidence_intake,
        "evidence_provenance": evidence_provenance,
        "research_case_workspace": workspace,
        "research_workbench": workbench,
        "safety": dict(SAFETY_BLOCK),
        "limitations": list(LIMITATIONS),
    }


# ---------------------------------------------------------------------------
# Idempotent persistence
# ---------------------------------------------------------------------------


def _atomic_write_text(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, dest)


def case_artifact_path(case_id: object, cases_dir: object = None) -> Path:
    """Deterministic artifact path for one R76 case id."""

    safe = _text(case_id, 96)
    if not _SAFE_CASE_ID_RE.match(safe):
        raise CaseBridgeError("INVALID_CASE_ID", "case id is not safe")
    root = Path(cases_dir) if cases_dir is not None else DEFAULT_CASES_DIR
    return root / f"{safe}.json"


def _existing_artifact(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, Mapping):
        return {}
    result = payload.get("result")
    result = result if isinstance(result, Mapping) else {}
    return {
        "result_id": _text(result.get("result_id"), 64),
        "plan_id": _text(result.get("plan_id"), 64),
        "program": _text(payload.get("program"), 64),
    }


def activate_result(
    payload: object,
    *,
    kind: object = None,
    plan_loader: PlanLoader | None = None,
    source_name: str = "",
    cases_dir: object = None,
    write: bool = True,
) -> dict:
    """Activate one persisted result into the case lifecycle (idempotent)."""

    outcome: dict = {
        "rule_version": RULE_VERSION,
        "status": STATUS_ERROR,
        "eligible": False,
        "reason": "",
        "detail": "",
        "result_kind": "",
        "result_id": "",
        "plan_id": "",
        "cve_id": "",
        "program": "",
        "case_id": "",
        "case_status": "",
        "case_path": "",
        "written": False,
        "evidence_count": 0,
        "hypothesis_count": 0,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }
    try:
        decision = evaluate_result(payload, kind=kind, plan_loader=plan_loader)
    except Exception as exc:
        outcome["reason"] = REASON_MALFORMED_RESULT
        outcome["detail"] = type(exc).__name__
        return outcome

    for key in ("result_kind", "result_id", "plan_id", "cve_id", "program"):
        outcome[key] = _text(decision.get(key), 64)
    outcome["eligible"] = bool(decision.get("eligible"))
    outcome["evidence_count"] = int(decision.get("evidence_count") or 0)
    if not decision.get("eligible"):
        outcome["status"] = STATUS_INELIGIBLE
        outcome["reason"] = _text(decision.get("reason"), 64)
        outcome["detail"] = _text(decision.get("detail"), 160)
        return outcome

    try:
        artifact = build_case_artifact(
            payload,
            kind=decision["result_kind"],
            plan_loader=plan_loader,
            source_name=source_name,
        )
    except CaseBridgeError as exc:
        outcome["status"] = STATUS_BUILD_REJECTED
        outcome["reason"] = _text(exc.code, 64)
        outcome["detail"] = _text(exc.safe_message, 160)
        return outcome
    except Exception as exc:
        outcome["reason"] = _text(type(exc).__name__, 64)
        return outcome

    cases = _mapping_items(
        artifact.get("research_case_workspace", {}).get("cases")
    )
    if not cases:
        outcome["status"] = STATUS_BUILD_REJECTED
        outcome["reason"] = "NO_CASE_BUILT"
        return outcome
    case = cases[0]
    case_id = _text(case.get("case_id"), 96)
    try:
        dest = case_artifact_path(case_id, cases_dir)
    except CaseBridgeError as exc:
        outcome["status"] = STATUS_BUILD_REJECTED
        outcome["reason"] = exc.code
        return outcome

    outcome["case_id"] = case_id
    outcome["case_status"] = _text(case.get("status"), 40)
    outcome["hypothesis_count"] = int(case.get("hypothesis_count") or 0)
    outcome["case_path"] = dest.name
    if dest.exists():
        existing = _existing_artifact(dest)
        outcome["status"] = STATUS_EXISTS
        outcome["reason"] = "CASE_EXISTS"
        if existing:
            outcome["detail"] = (
                f"existing case for result "
                f"{existing.get('result_id') or 'unknown'}"
            )
        return outcome

    if not write:
        outcome["status"] = STATUS_ACTIVATED
        return outcome
    try:
        _atomic_write_text(
            dest,
            json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True),
        )
    except OSError:
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = "WRITE_FAILED"
        return outcome
    outcome["status"] = STATUS_ACTIVATED
    outcome["written"] = True
    return outcome


# ---------------------------------------------------------------------------
# Persisted-result processing (bounded, deterministic ordering)
# ---------------------------------------------------------------------------


def _result_artifact_paths(agent_dir: object = None) -> list[Path]:
    directory = Path(agent_dir) if agent_dir is not None else storage.DEFAULT_AGENT_DIR
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.glob("*.json")
        if path.is_file()
        and not path.name.endswith(".discovery.json")
        and not path.name.endswith(".tmp")
    )


def activate_persisted_results(
    *,
    agent_dir: object = None,
    cases_dir: object = None,
    plan_loader: PlanLoader | None = None,
    limit: int = MAX_RESULTS,
) -> dict:
    """Process persisted agent results in deterministic order (idempotent)."""

    cap = max(int(limit), 0)
    paths = _result_artifact_paths(agent_dir)
    items: list[dict] = []
    counts = {
        STATUS_ACTIVATED: 0,
        STATUS_EXISTS: 0,
        STATUS_INELIGIBLE: 0,
        STATUS_BUILD_REJECTED: 0,
        STATUS_ERROR: 0,
    }
    for path in paths[:cap]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = None
        item = activate_result(
            payload,
            plan_loader=plan_loader,
            source_name=path.name,
            cases_dir=cases_dir,
        )
        item["artifact"] = path.name
        counts[item["status"]] = counts.get(item["status"], 0) + 1
        items.append(item)
    return {
        "rule_version": RULE_VERSION,
        "status": "COMPLETED",
        "processed": len(items),
        "truncated": len(paths) > len(items),
        "activated": counts[STATUS_ACTIVATED],
        "existing": counts[STATUS_EXISTS],
        "ineligible": counts[STATUS_INELIGIBLE],
        "build_rejected": counts[STATUS_BUILD_REJECTED],
        "errors": counts[STATUS_ERROR],
        "items": items,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "RULE_VERSION",
    "DEFAULT_CASES_DIR",
    "MAX_RESULTS",
    "MAX_HYPOTHESES",
    "MAX_MISSING_EVIDENCE",
    "MAX_TEXT_CHARS",
    "RESULT_KIND_LOOP",
    "RESULT_KIND_R23",
    "RESULT_KINDS",
    "REASON_ELIGIBLE",
    "REASON_MALFORMED_RESULT",
    "REASON_UNSUPPORTED_RESULT_KIND",
    "REASON_PLAN_BINDING_MISSING",
    "REASON_RESULT_ID_MISMATCH",
    "REASON_STATUS_NOT_COMPLETED",
    "REASON_PRODUCTION_FINDING",
    "REASON_PROGRAM_BINDING_MISSING",
    "REASON_MALFORMED_EVIDENCE",
    "REASON_INSUFFICIENT_EVIDENCE",
    "ELIGIBILITY_REASONS",
    "STATUS_ACTIVATED",
    "STATUS_EXISTS",
    "STATUS_INELIGIBLE",
    "STATUS_BUILD_REJECTED",
    "STATUS_ERROR",
    "CaseBridgeError",
    "result_kind",
    "canonical_evidence",
    "evaluate_result",
    "build_hypotheses",
    "build_case_artifact",
    "case_artifact_path",
    "activate_result",
    "activate_persisted_results",
]
