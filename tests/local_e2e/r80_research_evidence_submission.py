"""R80 — research evidence submission boundary validation (offline).

Demonstrates the R80 submission boundary on the real case:

    researcher submission envelope -> R80 boundary (case/requirement binding
    + safety pre-scan) -> R74 intake -> R75 provenance -> R72/R73 (via R74)
    -> R76 case update -> R77 workbench

All evidence packages here are clearly labelled ``NON-REAL/OFFLINE`` contract
fixtures. No target interaction, no HTTP, no scanner, no Mongo writes and no
persistence. Real evidence availability keeps the R79 result
(``REAL_EVIDENCE_NOT_AVAILABLE``); the read-only archive probe is reused from
R79 and copies no values.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Mapping

from ai.knowledge.research_evidence_provenance import (
    analyze_evidence_provenance,
)
from ai.knowledge.research_evidence_submission import (
    RULE_VERSION as SUBMISSION_RULE_VERSION,
    submit_research_evidence,
)
from tests.local_e2e.r78_case_walkthrough import (
    REAL_ARTIFACT_DEFAULT,
    effective_stages,
    load_real_case,
    render_workbench,
    update_case_with_evidence,
)
from tests.local_e2e.r79_real_evidence_intake import (
    NON_REAL_LABEL,
    PRIMARY_CASE_ID,
    real_evidence_availability,
)

RULE_VERSION = "r80-1"

METHOD_REF = "response:nonreal-submission-method-auth-1"
RESPONSE_REF = "response:nonreal-submission-response-behavior-1"
CONFLICT_REF = "response:nonreal-submission-method-auth-conflict-1"

UNKNOWN_REQUIREMENT = "TOKEN_VALIDATION"
NOT_A_REQUIREMENT = "NOT_A_REQUIREMENT"


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def submission_item(
    ref: str,
    *,
    kind: str = "METHOD_AUTH",
    effect: str = "PROVIDES",
    source: str = "HUMAN_REVIEW",
) -> dict:
    return {
        "hypothesis_ref": "H1",
        "requirement_kind": kind,
        "effect": effect,
        "source": source,
        "evidence_ref": ref,
        "observations": [
            {
                "ref": ref,
                "fact": f"{NON_REAL_LABEL} submission fixture for {kind}",
            }
        ],
    }


def envelope(items, *, case_ref: str, submitted_by: str = "") -> dict:
    return {
        "submission_version": SUBMISSION_RULE_VERSION,
        "case_ref": case_ref,
        "submitted_by": submitted_by,
        "items": list(items),
    }


def submit(
    stages: Mapping,
    case: Mapping,
    items,
    *,
    case_ref: str | None = None,
    submitted_by: str = "",
) -> dict:
    return submit_research_evidence(
        envelope(
            items,
            case_ref=(
                _text(case.get("case_id"))
                if case_ref is None
                else case_ref
            ),
            submitted_by=submitted_by,
        ),
        case=case,
        hypotheses=stages.get("hypotheses"),
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        readiness_plan=stages.get("readiness_plan"),
    )


def run_submission_path(
    stages: Mapping,
    case: Mapping,
    items,
    *,
    previous_provenance: object = None,
    case_ref: str | None = None,
    submitted_by: str = "",
) -> dict:
    """Compose the boundary with the unchanged downstream authorities."""

    submitted = submit(
        stages,
        case,
        items,
        case_ref=case_ref,
        submitted_by=submitted_by,
    )
    if submitted.get("intake") is None:
        return {
            "submission": submitted,
            "provenance": None,
            "case": None,
            "workbench": None,
        }
    provenance = analyze_evidence_provenance(
        submitted["intake"],
        hypotheses=stages.get("hypotheses"),
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        readiness_plan=stages.get("readiness_plan"),
        previous_provenance=previous_provenance,
    )
    updated = update_case_with_evidence(
        stages,
        case,
        {
            "intake_result": submitted["intake"],
            "provenance": provenance,
        },
    )
    reevaluation = _block(_block(submitted["intake"]).get("reevaluation"))
    return {
        "submission": submitted,
        "provenance": provenance,
        "case": updated,
        "workbench": render_workbench(stages, updated, provenance),
        "effective_stages": effective_stages(
            stages,
            {
                "readiness_after": reevaluation.get("readiness_after"),
                "feedback": reevaluation.get("feedback"),
                "acquisition_after": reevaluation.get("acquisition_after"),
            },
        ),
    }


def negative_submissions(stages: Mapping, case: Mapping) -> dict:
    """Boundary contract negatives (all NON-REAL/OFFLINE, in memory)."""

    case_ref = _text(case.get("case_id"))
    results: dict[str, dict] = {}

    valid = submit(stages, case, [submission_item(METHOD_REF)])
    results["valid_case_bound_submission"] = {
        "status": _text(submitted_status(valid)),
        "expected": "ACCEPTED",
        "passed": _text(submitted_status(valid)) == "ACCEPTED",
        "label": NON_REAL_LABEL,
    }

    wrong_case = submit(
        stages, case, [submission_item(METHOD_REF)], case_ref="case-other"
    )
    results["wrong_case_ref"] = {
        "code": first_code(wrong_case),
        "expected": "CASE_MISMATCH",
        "passed": first_code(wrong_case) == "CASE_MISMATCH",
        "label": NON_REAL_LABEL,
    }

    unknown_requirement = submit(
        stages,
        case,
        [submission_item(METHOD_REF, kind=UNKNOWN_REQUIREMENT)],
    )
    results["unknown_requirement"] = {
        "code": first_code(unknown_requirement),
        "expected": "UNKNOWN_REQUIREMENT_FOR_CASE",
        "passed": first_code(unknown_requirement)
        == "UNKNOWN_REQUIREMENT_FOR_CASE",
        "label": NON_REAL_LABEL,
    }

    not_a_requirement = submit(
        stages,
        case,
        [submission_item(METHOD_REF, kind=NOT_A_REQUIREMENT)],
    )
    results["requirement_not_belonging_to_case"] = {
        "code": first_code(not_a_requirement),
        "expected": "UNKNOWN_REQUIREMENT_FOR_CASE",
        "passed": first_code(not_a_requirement)
        == "UNKNOWN_REQUIREMENT_FOR_CASE",
        "label": NON_REAL_LABEL,
    }

    malformed = submit_research_evidence(
        {
            "submission_version": SUBMISSION_RULE_VERSION,
            "case_ref": case_ref,
            "items": "nope",
        },
        case=case,
        hypotheses=stages.get("hypotheses"),
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        readiness_plan=stages.get("readiness_plan"),
    )
    results["malformed_envelope"] = {
        "code": first_code(malformed),
        "expected": "MALFORMED_ENVELOPE",
        "passed": first_code(malformed) == "MALFORMED_ENVELOPE",
        "label": NON_REAL_LABEL,
    }

    bad_source = submit(
        stages,
        case,
        [submission_item(METHOD_REF, source="RANDOM_PROCESS")],
    )
    source_codes = [
        entry.get("code")
        for entry in _block(source_codes_intake(bad_source)).get(
            "rejections"
        )
        or ()
    ]
    results["unsupported_source"] = {
        "codes": source_codes,
        "expected": "INVALID_EVIDENCE_SOURCE",
        "passed": "INVALID_EVIDENCE_SOURCE" in source_codes,
        "label": NON_REAL_LABEL,
    }

    sensitive = submit(
        stages,
        case,
        [
            {
                "hypothesis_ref": "H1",
                "requirement_kind": "METHOD_AUTH",
                "effect": "PROVIDES",
                "source": "HUMAN_REVIEW",
                "observations": [
                    {
                        "ref": "response:nonreal-submission-sensitive-1",
                        "fact": "authorization token=nonreal-secret-12345",
                    }
                ],
            }
        ],
    )
    results["sensitive_evidence"] = {
        "code": first_code(sensitive),
        "expected": "SENSITIVE_SUBMISSION_REJECTED",
        "passed": first_code(sensitive) == "SENSITIVE_SUBMISSION_REJECTED",
        "label": NON_REAL_LABEL,
    }

    execution = submit(
        stages,
        case,
        [
            {
                "hypothesis_ref": "H1",
                "requirement_kind": "METHOD_AUTH",
                "effect": "PROVIDES",
                "source": "HUMAN_REVIEW",
                "observations": [
                    {
                        "ref": "response:nonreal-submission-exec-1",
                        "fact": "curl target",
                    }
                ],
            }
        ],
    )
    results["execution_instruction"] = {
        "code": first_code(execution),
        "expected": "EXECUTION_CONTENT_REJECTED",
        "passed": first_code(execution) == "EXECUTION_CONTENT_REJECTED",
        "label": NON_REAL_LABEL,
    }

    duplicate = submit(
        stages,
        case,
        [
            submission_item(METHOD_REF),
            submission_item(METHOD_REF),
        ],
    )
    duplicate_codes = [
        entry.get("code")
        for entry in _block(duplicate.get("intake")).get("rejections") or ()
    ]
    results["duplicate_evidence"] = {
        "status": _text(duplicate.get("status")),
        "codes": duplicate_codes,
        "expected": "DUPLICATE_EVIDENCE",
        "passed": "DUPLICATE_EVIDENCE" in duplicate_codes,
        "label": NON_REAL_LABEL,
    }

    partial = run_submission_path(
        stages,
        case,
        [submission_item("response:nonreal-submission-prior-1")],
    )
    contradiction = run_submission_path(
        stages,
        case,
        [submission_item(CONFLICT_REF, effect="CONTRADICTS")],
        previous_provenance=(partial.get("provenance") or {}),
    )
    provenance_records = (
        _block(contradiction.get("provenance")).get("records") or ()
    )
    conflict_records = [
        record
        for record in provenance_records
        if isinstance(record, Mapping)
        and _text(record.get("conflict_state")) == "CONFLICTING"
    ]
    results["contradictory_evidence"] = {
        "conflict_count": int(
            _block(contradiction.get("provenance"))
            .get("summary", {})
            .get("conflict_count")
            or len(
                _block(contradiction.get("provenance")).get("conflicts") or ()
            )
        ),
        "resolved": bool(
            _block(contradiction.get("workbench"))
            .get("conflicts", {})
            .get("resolved", False)
        ),
        "relationship": (
            _text(conflict_records[0].get("relation_to_previous"))
            if conflict_records
            else ""
        ),
        "expected": "CONFLICTING",
        "passed": bool(conflict_records),
        "label": NON_REAL_LABEL,
    }
    return results


def first_code(result: Mapping) -> str:
    rejections = _block(result).get("rejections") or ()
    for entry in rejections:
        if isinstance(entry, Mapping) and entry.get("code"):
            return _text(entry.get("code"))
    return ""


def submitted_status(result: Mapping) -> object:
    return _block(result).get("status")


def source_codes_intake(result: Mapping) -> dict:
    return _block(_block(result).get("intake"))


def validate(
    artifact_path: str | Path = REAL_ARTIFACT_DEFAULT,
    *,
    stages: object = None,
    availability: object = None,
) -> dict:
    """Full offline validation: real availability + boundary contract."""

    if stages is None:
        stages = load_real_case(artifact_path, case_id=PRIMARY_CASE_ID)
    stages = _block(stages)
    if availability is None:
        availability = real_evidence_availability()
    availability = _block(availability)
    case = stages["case"]

    before_workbench = render_workbench(
        stages, case, stages.get("evidence_provenance")
    )
    partial = run_submission_path(
        stages,
        case,
        [submission_item(METHOD_REF)],
        previous_provenance=stages.get("evidence_provenance"),
    )
    partial_case = partial["case"] or case
    partial_stages = partial.get("effective_stages") or stages
    complete = run_submission_path(
        partial_stages,
        partial_case,
        [
            submission_item(METHOD_REF),
            submission_item(RESPONSE_REF, kind="RESPONSE_BEHAVIOR"),
        ],
        previous_provenance=partial.get("provenance"),
    )

    return {
        "rule_version": RULE_VERSION,
        "primary_case": {
            "case_id": _text(case.get("case_id")),
            "program": _text(case.get("program")),
            "gap_id": _text(case.get("gap_id")),
        },
        "real_evidence": {
            "status": _text(availability.get("status")),
            "reason": _text(availability.get("reason")),
            "checks": dict(_block(availability.get("checks"))),
            "values_copied": bool(availability.get("values_copied")),
        },
        "partial_submission": {
            "submission_status": _text(
                submitted_status(partial.get("submission") or {})
            ),
            "case_status": _text((partial.get("case") or {}).get("status")),
            "sufficiency": _text(
                (
                    (
                        _block(partial.get("case") or {}).get("readiness")
                        or {}
                    )
                ).get("sufficiency_state")
            ),
            "workbench_after": _block(partial.get("workbench")).get(
                "current_state"
            )
            if partial.get("workbench")
            else {},
        },
        "complete_submission": {
            "submission_status": _text(
                submitted_status(complete.get("submission") or {})
            ),
            "case_status": _text((complete.get("case") or {}).get("status")),
            "stopping_reason": _text(
                (complete.get("case") or {}).get("stopping_reason")
            ),
            "sufficiency": _text(
                (
                    (
                        _block(complete.get("case") or {}).get("readiness")
                        or {}
                    )
                ).get("sufficiency_state")
            ),
            "workbench_before": _block(before_workbench).get("current_state"),
            "workbench_after": _block(complete.get("workbench")).get(
                "current_state"
            ),
            "workbench_missing": list(
                (
                    _block(complete.get("workbench")).get("what_is_missing")
                    or {}
                ).get("decision_critical_missing")
                or ()
            ),
            "human_review_required": bool(
                (
                    _block(complete.get("workbench")).get("human_review")
                    or {}
                ).get("required")
            ),
        },
        "negative_submissions": negative_submissions(stages, case),
        "safety": dict(_block(case.get("safety"))),
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tests.local_e2e.r80_research_evidence_submission",
        description=(
            "R80 submission boundary validation (offline; no target "
            "interaction, no persistence)"
        ),
    )
    parser.add_argument("--artifact", default=REAL_ARTIFACT_DEFAULT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not os.environ.get("WATCH_MONGO_URI"):
        try:
            from dotenv import load_dotenv

            load_dotenv(Path(__file__).resolve().parents[2] / ".env")
        except Exception:
            pass

    try:
        result = validate(args.artifact)
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {str(exc)[:160]}")
        return 2

    if args.json:
        print(json.dumps(result, indent=1, sort_keys=True))
        return 0

    print("")
    print("=" * 66)
    print("WATCH R80 — RESEARCH EVIDENCE SUBMISSION BOUNDARY (offline)")
    print("=" * 66)
    print(f"Primary case  : {result['primary_case']['case_id']}")
    print(f"REAL evidence : {result['real_evidence']['status']}")
    partial = result["partial_submission"]
    complete = result["complete_submission"]
    print(
        f"Submission 1  : {partial['submission_status']} -> case "
        f"{partial['case_status']} ({partial['sufficiency']})"
    )
    print(
        f"Submission 2  : {complete['submission_status']} -> case "
        f"{complete['case_status']} / {complete['stopping_reason']} "
        f"({complete['sufficiency']})"
    )
    print(
        f"R77 after     : status={complete['workbench_after'].get('status')} "
        f"review={complete['human_review_required']} "
        f"missing={complete['workbench_missing']}"
    )
    print("")
    print("Negative submissions (NON-REAL/OFFLINE):")
    for name, entry in result["negative_submissions"].items():
        observed = (
            entry.get("code")
            or entry.get("codes")
            or entry.get("relationship")
            or entry.get("status")
        )
        print(
            f"   {name}: passed={entry.get('passed')} "
            f"expected={entry.get('expected')} observed={observed}"
        )
    print("")
    print("-" * 66)
    print("[SAFETY] advisory research only; execution_performed=false;")
    print("         vulnerability_confirmed=false; exploit_authorized=false;")
    print("         confirmation_state=NOT_CONFIRMED; no target interaction")
    print("[NOTE] no evidence was persisted; fixtures are NON-REAL/OFFLINE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
