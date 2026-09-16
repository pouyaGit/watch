"""R78 — first real research case walkthrough (offline validation only).

R78 is not a planner, not an intelligence layer and not a new state machine.
It walks ONE existing real Watch research case through the complete lifecycle
using only the existing authorities:

    real R77 artifact
      -> researcher action (R70 action + R71 plan + R72 blocking)
      -> synthetic/offline evidence package (labelled, never persisted)
      -> R74 intake -> R75 provenance -> R72 readiness -> R73 feedback
      -> R76 case update -> R77 workbench

Authorities are never bypassed or duplicated:

- R74 ``intake_and_reevaluate`` performs intake and the R72/R73 re-evaluation.
- R75 ``analyze_evidence_provenance`` performs provenance/conflict analysis.
- R76 ``update_research_case`` appends bounded history; the pipeline is not
  re-run.
- R77 ``build_research_workbench`` renders the result.
- R73 ``evaluate_research_iteration`` is used directly only for the stopped
  demonstration, with an explicit evidence bundle and the unchanged R73 rules.

Hard boundaries: no network, no HTTP client, no socket, no subprocess, no
shell, no scanner, no target interaction, no LLM call, no Mongo access and no
persistence. Synthetic evidence is bounded, clearly labelled, lives only in
memory and is never written into the real artifact. Nothing here is a security
verdict.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Mapping, Sequence

from ai.knowledge.research_case_workspace import (
    build_research_case,
    update_research_case,
)
from ai.knowledge.research_evidence_intake import (
    STATUS_ACCEPTED,
    intake_and_reevaluate,
)
from ai.knowledge.research_evidence_provenance import (
    analyze_evidence_provenance,
)
from ai.knowledge.research_feedback_loop import evaluate_research_iteration
from ai.knowledge.research_workbench import build_research_workbench

RULE_VERSION = "r78-1"

REAL_ARTIFACT_DEFAULT = (
    "ai_data/research/r77/r64-indeed-b1ebaaf9f2211f82.json"
)
REAL_CASE_ID = "case-indeed-a1-endpoint-behavior"
REAL_PROGRAM = "indeed"

SYNTHETIC_LABEL = "SYNTHETIC/OFFLINE"
METHOD_AUTH_REF = "response:synth-offline-method-auth-1"
RESPONSE_BEHAVIOR_REF = "response:synth-offline-response-behavior-1"
CONFLICT_REF = "response:synth-offline-method-auth-contradiction-1"
STOP_REF = "response:synth-offline-stop-basis-removed-1"

MAX_TEXT_CHARS = 320

STAGE_KEYS: tuple[str, ...] = (
    "action_plan",
    "acquisition_plan",
    "readiness_plan",
    "iteration_plan",
    "evidence_intake",
    "evidence_provenance",
    "research_case_workspace",
    "research_workbench",
)


class WalkthroughError(ValueError):
    """Deterministic, secret-free R78 walkthrough failure."""

    def __init__(self, code: str, safe_message: str = "") -> None:
        self.code = str(code)
        self.safe_message = " ".join(str(safe_message).split())[:160]
        super().__init__(f"{self.code}: {self.safe_message}")


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


# ---------------------------------------------------------------------------
# STEP 1 — load the real case (read-only)
# ---------------------------------------------------------------------------


def load_real_case(
    artifact_path: str | Path = REAL_ARTIFACT_DEFAULT,
    *,
    case_id: str = REAL_CASE_ID,
) -> dict:
    """Load one real R77 artifact read-only and extract the case + stages."""

    path = Path(artifact_path)
    if not path.is_file():
        raise WalkthroughError(
            "ARTIFACT_NOT_FOUND", f"artifact not found: {path.name}"
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        raise WalkthroughError(
            "ARTIFACT_MALFORMED", f"artifact is not valid JSON: {path.name}"
        ) from None
    if not isinstance(payload, Mapping):
        raise WalkthroughError(
            "ARTIFACT_MALFORMED", "artifact is not a JSON object"
        )
    for key in STAGE_KEYS:
        if not isinstance(payload.get(key), Mapping):
            raise WalkthroughError(
                "ARTIFACT_MALFORMED", f"artifact is missing {key}"
            )
    cases = _mapping_items(
        _block(payload.get("research_case_workspace")).get("cases")
    )
    case = None
    for candidate in cases:
        if _text(candidate.get("case_id")) == case_id:
            case = candidate
            break
    if case is None:
        raise WalkthroughError(
            "CASE_NOT_FOUND", f"case not present: {case_id}"
        )
    return {
        "artifact_path": str(path),
        "source": _text(payload.get("source")),
        "program": _text(payload.get("program")),
        "research_run_version": _text(payload.get("research_run_version")),
        "case_id": _text(case.get("case_id")),
        "case": dict(case),
        "hypotheses": list(
            _block(payload.get("research")).get("hypotheses") or ()
        ),
        "action_plan": dict(_block(payload.get("action_plan"))),
        "acquisition_plan": dict(_block(payload.get("acquisition_plan"))),
        "readiness_plan": dict(_block(payload.get("readiness_plan"))),
        "iteration_plan": dict(_block(payload.get("iteration_plan"))),
        "evidence_intake": dict(_block(payload.get("evidence_intake"))),
        "evidence_provenance": dict(
            _block(payload.get("evidence_provenance"))
        ),
        "research_case_workspace": dict(
            _block(payload.get("research_case_workspace"))
        ),
        "research_workbench": dict(_block(payload.get("research_workbench"))),
    }


# ---------------------------------------------------------------------------
# STEP 2 — researcher action from existing R71/R72 outputs
# ---------------------------------------------------------------------------


def researcher_action(stages: Mapping) -> dict:
    """What the researcher is asked to obtain, from the existing plan only."""

    case = _block(stages.get("case"))
    plan_ref = _text(_block(case.get("acquisition")).get("plan_ref"))
    plan = None
    for candidate in _mapping_items(
        _block(stages.get("acquisition_plan")).get("plans")
    ):
        if _text(candidate.get("plan_id")) == plan_ref:
            plan = candidate
            break
    record = None
    for candidate in _mapping_items(
        _block(stages.get("readiness_plan")).get("records")
    ):
        if _text(candidate.get("plan_ref")) == plan_ref:
            record = candidate
            break
    if plan is None or record is None:
        raise WalkthroughError(
            "STAGE_MISSING", "acquisition plan or readiness record not found"
        )
    blocking = {
        _text(kind).upper()
        for kind in record.get("blocking_codes") or ()
    }
    requirements: list[dict] = []
    for entry in _mapping_items(plan.get("required_evidence")):
        kind = _text(entry.get("requirement_kind")).upper()
        if kind not in blocking:
            continue
        requirements.append(
            {
                "requirement_kind": kind,
                "status": _text(entry.get("status")).upper(),
                "description": _text(entry.get("description"))[
                    :MAX_TEXT_CHARS
                ],
                "decision_critical": True,
            }
        )
    return {
        "action_ref": _text(case.get("action_ref")),
        "plan_ref": plan_ref,
        "objective": _text(_block(case.get("action")).get("objective")),
        "acquisition_method": _text(plan.get("acquisition_method")).upper(),
        "sources": [
            _text(source)
            for source in plan.get("acquisition_sources") or ()
        ],
        "requirements": requirements,
        "expected_result": _text(plan.get("expected_result"))[
            :MAX_TEXT_CHARS
        ],
        "stopping_condition": _text(plan.get("stopping_condition"))[
            :MAX_TEXT_CHARS
        ],
        "decision_basis": _text(
            _block(record.get("decision_basis")).get("code")
        ),
        "synthetic_note": SYNTHETIC_LABEL,
    }


# ---------------------------------------------------------------------------
# STEP 3 — bounded offline synthetic evidence packages
# ---------------------------------------------------------------------------


def _synthetic_item(
    ref: str, requirement_kind: str, effect: str = "PROVIDES"
) -> dict:
    return {
        "hypothesis_ref": "H1",
        "requirement_kind": requirement_kind,
        "effect": effect,
        "source": "HUMAN_REVIEW",
        "evidence_ref": ref,
        "observations": [
            {
                "ref": ref,
                "fact": (
                    f"{SYNTHETIC_LABEL} abstract observation for "
                    f"{requirement_kind}"
                ),
            }
        ],
    }


def synthetic_method_auth_package() -> dict:
    return {
        "package_version": "r74-1",
        "items": [_synthetic_item(METHOD_AUTH_REF, "METHOD_AUTH")],
    }


def synthetic_complete_package() -> dict:
    return {
        "package_version": "r74-1",
        "items": [
            _synthetic_item(METHOD_AUTH_REF, "METHOD_AUTH"),
            _synthetic_item(RESPONSE_BEHAVIOR_REF, "RESPONSE_BEHAVIOR"),
        ],
    }


def synthetic_conflict_package() -> dict:
    return {
        "package_version": "r74-1",
        "items": [
            _synthetic_item(
                CONFLICT_REF, "METHOD_AUTH", effect="CONTRADICTS"
            )
        ],
    }


def synthetic_stop_bundle() -> dict:
    return {
        "items": [
            {
                "hypothesis_ref": "H1",
                "requirement_kind": "METHOD_AUTH",
                "effect": "CONTRADICTS",
                "source": "HUMAN_REVIEW",
                "observations": [
                    {
                        "ref": STOP_REF,
                        "fact": (
                            f"{SYNTHETIC_LABEL} contradiction used only to "
                            "demonstrate the existing R73 stop rule"
                        ),
                    }
                ],
            }
        ]
    }


# ---------------------------------------------------------------------------
# STEPS 4-7 — evidence roundtrip through existing authorities
# ---------------------------------------------------------------------------


def effective_stages(stages: Mapping, roundtrip: Mapping) -> dict:
    """Chain the R72/R73 authority projections produced by one roundtrip."""

    updated = dict(stages)
    readiness = _block(roundtrip.get("readiness_after"))
    feedback = _block(roundtrip.get("feedback"))
    acquisition = _block(roundtrip.get("acquisition_after"))
    if _mapping_items(readiness.get("records")):
        updated["readiness_plan"] = readiness
    if _mapping_items(feedback.get("iterations")):
        updated["iteration_plan"] = feedback
    if _mapping_items(acquisition.get("plans")):
        updated["acquisition_plan"] = acquisition
    return updated


def run_evidence_roundtrip(
    stages: Mapping,
    package: Mapping,
    *,
    previous_provenance: object = None,
) -> dict:
    """R74 intake -> R75 provenance -> R72 readiness -> R73 feedback."""

    intake = intake_and_reevaluate(
        package,
        hypotheses=stages.get("hypotheses"),
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        readiness_plan=stages.get("readiness_plan"),
    )
    provenance = analyze_evidence_provenance(
        intake,
        hypotheses=stages.get("hypotheses"),
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        readiness_plan=stages.get("readiness_plan"),
        previous_provenance=previous_provenance,
    )
    reevaluation = _block(intake.get("reevaluation"))
    feedback = _block(reevaluation.get("feedback"))
    iteration = _block(_mapping_items(feedback.get("iterations"))[0]) if (
        _mapping_items(feedback.get("iterations"))
    ) else {}
    return {
        "package_status": _text(intake.get("package_status")).upper(),
        "accepted_count": int(intake.get("accepted_external_evidence") or 0),
        "rejections": list(intake.get("rejections") or ()),
        "accepted_items": list(intake.get("accepted_items") or ()),
        "intake_result": intake,
        "provenance": provenance,
        "readiness_after": dict(_block(reevaluation.get("readiness_after"))),
        "acquisition_after": dict(
            _block(reevaluation.get("acquisition_after"))
        ),
        "transitions": list(reevaluation.get("transitions") or ()),
        "feedback": dict(feedback),
        "iteration": dict(iteration),
    }


# ---------------------------------------------------------------------------
# STEPS 8-9 — R76 update and R77 workbench
# ---------------------------------------------------------------------------


def update_case_with_evidence(
    stages: Mapping,
    case: Mapping,
    roundtrip: Mapping,
) -> dict:
    """R76 update contract: identity preserved, one bounded iteration."""

    return update_research_case(
        case,
        stages.get("action_plan"),
        stages.get("acquisition_plan"),
        stages.get("readiness_plan"),
        stages.get("iteration_plan"),
        evidence_intake=roundtrip.get("intake_result"),
        evidence_provenance=roundtrip.get("provenance"),
    )


def render_workbench(
    stages: Mapping,
    case: Mapping,
    evidence_provenance: object = None,
) -> dict:
    """R77 render of one case (presentation only)."""

    return build_research_workbench(
        case,
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        evidence_provenance=(
            evidence_provenance
            if evidence_provenance is not None
            else stages.get("evidence_provenance")
        ),
    )


# ---------------------------------------------------------------------------
# STEP 11 — stopped demonstration using existing R73/R76/R77 semantics
# ---------------------------------------------------------------------------


def build_stopped_case(stages: Mapping) -> dict:
    """Existing R73 stop semantics + R76 case + R77 workbench (offline)."""

    hypotheses = stages.get("hypotheses")
    iteration_plan = evaluate_research_iteration(
        hypotheses,
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        readiness_plan=stages.get("readiness_plan"),
        new_evidence=synthetic_stop_bundle(),
    )
    case = build_research_case(
        stages.get("action_plan"),
        stages.get("acquisition_plan"),
        stages.get("readiness_plan"),
        iteration_plan,
        program=stages.get("program") or REAL_PROGRAM,
    )
    return {
        "iteration_plan": iteration_plan,
        "case": case,
        "workbench": build_research_workbench(
            case,
            action_plan=stages.get("action_plan"),
            acquisition_plan=stages.get("acquisition_plan"),
        ),
    }


# ---------------------------------------------------------------------------
# STEPS 10 + 12 — full walkthrough
# ---------------------------------------------------------------------------


def walkthrough(
    artifact_path: str | Path = REAL_ARTIFACT_DEFAULT,
) -> dict:
    """Run the complete offline walkthrough on the real R77 artifact."""

    stages = load_real_case(artifact_path)
    action = researcher_action(stages)
    base_case = stages["case"]

    partial = run_evidence_roundtrip(
        stages, synthetic_method_auth_package()
    )
    partial_case = update_case_with_evidence(stages, base_case, partial)
    partial_workbench = render_workbench(
        stages, partial_case, partial["provenance"]
    )
    partial_stages = effective_stages(stages, partial)

    complete = run_evidence_roundtrip(
        partial_stages,
        synthetic_complete_package(),
        previous_provenance=partial["provenance"],
    )
    complete_case = update_case_with_evidence(
        partial_stages, partial_case, complete
    )
    complete_workbench = render_workbench(
        partial_stages, complete_case, complete["provenance"]
    )

    conflict = run_evidence_roundtrip(
        partial_stages,
        synthetic_conflict_package(),
        previous_provenance=partial["provenance"],
    )
    conflict_case = update_case_with_evidence(
        partial_stages, partial_case, conflict
    )
    conflict_workbench = render_workbench(
        partial_stages, conflict_case, conflict["provenance"]
    )

    stopped = build_stopped_case(stages)

    return {
        "rule_version": RULE_VERSION,
        "synthetic_label": SYNTHETIC_LABEL,
        "real": {
            "artifact_path": stages["artifact_path"],
            "source": stages["source"],
            "program": stages["program"],
            "research_run_version": stages["research_run_version"],
            "case_id": stages["case_id"],
            "case": base_case,
            "workbench": stages["research_workbench"],
        },
        "researcher_action": action,
        "partial": {
            **partial,
            "case": partial_case,
            "workbench_after": partial_workbench,
        },
        "complete": {
            **complete,
            "case": complete_case,
            "workbench_after": complete_workbench,
        },
        "conflict": {
            **conflict,
            "case": conflict_case,
            "workbench_after": conflict_workbench,
        },
        "stopped": stopped,
        "safety": dict(_block(base_case.get("safety"))),
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# CLI (prints only; writes nothing)
# ---------------------------------------------------------------------------


def _print_workbench_sections(workbench: Mapping) -> None:
    current = _block(workbench.get("current_state"))
    known = _block(workbench.get("what_we_know"))
    missing = _block(workbench.get("what_is_missing"))
    review = _block(workbench.get("human_review"))
    print(
        f"   state={current.get('status')} "
        f"readiness={current.get('readiness')} "
        f"decision={current.get('decision')}"
    )
    print(
        "   know="
        f"{known.get('available_requirement_kinds')} "
        f"(accepted={known.get('accepted_evidence_count')})"
    )
    print(f"   missing={missing.get('decision_critical_missing')}")
    print(
        "   next="
        + ", ".join(
            step.get("action", "")
            for step in workbench.get("next_steps") or []
        )
    )
    print(
        f"   human_review={review.get('required')} "
        f"reasons={review.get('reasons')}"
    )
    conflicts = _block(workbench.get("conflicts"))
    if conflicts.get("count"):
        print(
            f"   conflicts={conflicts.get('count')} "
            f"resolved={conflicts.get('resolved')} "
            f"kinds={conflicts.get('requirement_kinds')}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tests.local_e2e.r78_case_walkthrough",
        description=(
            "R78 offline walkthrough of the first real research case "
            "(no target interaction, no persistence)"
        ),
    )
    parser.add_argument("--artifact", default=REAL_ARTIFACT_DEFAULT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        result = walkthrough(args.artifact)
    except WalkthroughError as exc:
        print(f"ERROR: {exc.code}: {exc.safe_message}")
        return 2

    if args.json:
        print(json.dumps(result, indent=1, sort_keys=True))
        return 0

    real = result["real"]
    print("")
    print("=" * 66)
    print("WATCH R78 — FIRST REAL RESEARCH CASE WALKTHROUGH (offline)")
    print("=" * 66)
    print(f"REAL case        : {real['case_id']}")
    print(
        f"REAL artifact    : {real['artifact_path']} "
        f"({real['research_run_version']})"
    )
    action = result["researcher_action"]
    print(f"RESEARCHER action: {action['objective']}")
    print(
        "   acquire       : "
        + ", ".join(
            item["requirement_kind"] for item in action["requirements"]
        )
    )
    print(
        f"   method        : {action['acquisition_method']} "
        f"sources={action['sources']}"
    )
    print("")
    print(f"SYNTHETIC step 1 — {SYNTHETIC_LABEL} METHOD_AUTH package")
    _print_workbench_sections(result["partial"]["workbench_after"])
    print("")
    print(
        "SYNTHETIC step 2 — "
        f"{SYNTHETIC_LABEL} complete decision package"
    )
    _print_workbench_sections(result["complete"]["workbench_after"])
    print("")
    print(f"SYNTHETIC step 3 — {SYNTHETIC_LABEL} conflict package")
    _print_workbench_sections(result["conflict"]["workbench_after"])
    print("")
    print(f"SYNTHETIC step 4 — {SYNTHETIC_LABEL} stopped demonstration")
    _print_workbench_sections(result["stopped"]["workbench"])
    print("")
    print("-" * 66)
    print("[SAFETY] advisory research only; execution_performed=false;")
    print("         vulnerability_confirmed=false; exploit_authorized=false;")
    print("         confirmation_state=NOT_CONFIRMED; no target interaction")
    print("[NOTE] no synthetic evidence was persisted into any real artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
