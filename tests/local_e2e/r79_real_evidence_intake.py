"""R79 — real researcher evidence intake validation (offline, read-only).

R79 validates the first real researcher-supplied evidence flow:

    researcher obtains evidence outside Watch
      -> structured package -> R74 intake -> R75 provenance
      -> R72 readiness -> R73 feedback -> R76 case update -> R77 workbench

Watch never acquires the evidence and never interacts with the target. This
module is a validation adapter: it checks whether genuine researcher evidence
exists in the authorized read-only archive and either processes it (REAL path)
or reports ``REAL EVIDENCE NOT AVAILABLE`` and validates the contract with
clearly labelled ``NON-REAL/OFFLINE`` fixtures (honest no-real-evidence path).

Result of the availability check in this environment: the authorized archive
contains endpoint/crawl records for the primary case path but has no HTTP
method field and no stored HTTP response records for that endpoint (nor for
the ``/api/internal`` namespace), so no genuine METHOD_AUTH or
RESPONSE_BEHAVIOR observation exists. R79 therefore reports
``REAL_EVIDENCE_NOT_AVAILABLE`` and performs only offline contract validation.
Synthetic data is never relabelled as real.

Hard boundaries: no target interaction, no HTTP client, no socket, no
subprocess, no shell, no scanner, no payloads, no authentication attempt, no
LLM call, no persistence, no Mongo writes. The archive probe uses read-only
``count_documents`` queries only and copies no field values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Mapping

from ai.knowledge.research_case_workspace import summarize_research_case
from ai.knowledge.research_evidence_intake import (
    REJECTION_DUPLICATE_EVIDENCE,
    REJECTION_INVALID_EVIDENCE_REF,
    REJECTION_MALFORMED_EVIDENCE,
    REJECTION_SENSITIVE_EVIDENCE,
    normalize_evidence_package,
)
from tests.local_e2e.r78_case_walkthrough import (
    REAL_ARTIFACT_DEFAULT,
    effective_stages,
    load_real_case,
    render_workbench,
    run_evidence_roundtrip,
    update_case_with_evidence,
)

RULE_VERSION = "r79-1"

PRIMARY_CASE_ID = "case-indeed-a1-endpoint-behavior"
PRIMARY_PROGRAM = "indeed"
PRIMARY_PATH = "/api/internal/brand/theme/style-sheet"

NON_REAL_LABEL = "NON-REAL/OFFLINE"

REAL_AVAILABLE = "REAL_EVIDENCE_AVAILABLE"
REAL_NOT_AVAILABLE = "REAL_EVIDENCE_NOT_AVAILABLE"
NOT_CHECKED = "NOT_CHECKED"

METHOD_REF = "response:nonreal-contract-method-auth-1"
RESPONSE_REF = "response:nonreal-contract-response-behavior-1"
CONFLICT_REF = "response:nonreal-contract-method-auth-conflict-1"
DUPLICATE_REF = "response:nonreal-contract-duplicate-1"
SENSITIVE_FACT = "authorization token=nonreal-secret-value-12345"

# ---------------------------------------------------------------------------
# R74 input contract (documentation only; R74 remains the authority)
# ---------------------------------------------------------------------------

R74_INPUT_CONTRACT: dict = {
    "package_version": "r74-1",
    "required_package_fields": ("package_version", "items"),
    "required_item_fields": (
        "hypothesis_ref",
        "requirement_kind",
        "effect",
        "source",
    ),
    "evidence_identity": (
        "canonical kind:value reference from the R68 vocabulary, supplied via "
        "observations or evidence_ref; kinds include path, parameter, record, "
        "response, authorization, redirect, status, header, error"
    ),
    "allowed_effects": ("PROVIDES", "CONTRADICTS", "INVALIDATES"),
    "allowed_sources": (
        "EXISTING_CONTEXT",
        "STORED_RESPONSE",
        "HUMAN_REVIEW",
        "WATCH_DERIVED",
        "AUTHORIZED_TEST_CONTEXT",
    ),
    "requirement_association": (
        "explicit requirement_kind that exists for the target hypothesis; "
        "METHOD_AUTH and RESPONSE_BEHAVIOR for the primary case"
    ),
    "bounds": (
        "max 16 items; max 4 observations per item; refs bounded; facts "
        "bounded and truncated; canonical refs rejected when malformed"
    ),
    "rejection_conditions": (
        "unknown hypothesis/requirement, unsupported effect, invalid source, "
        "invalid canonical reference, duplicate evidence, ambiguous "
        "invalidation reference, sensitive data, execution instructions, "
        "malformed item/package"
    ),
    "sensitive_restrictions": (
        "no raw URLs, IPs, Mongo ids, credentials, tokens, cookies, "
        "authorization headers, personal data, request/response bodies or "
        "secrets; rejected bodies are never persisted"
    ),
}


class IntakeValidationError(ValueError):
    """Deterministic, secret-free R79 validation failure."""

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
# REAL evidence availability (read-only archive probe)
# ---------------------------------------------------------------------------


def real_evidence_availability(
    client: object = None,
    *,
    program: str = PRIMARY_PROGRAM,
    path: str = PRIMARY_PATH,
    mongo_uri: str | None = None,
) -> dict:
    """Bounded read-only check for genuine stored observations.

    The probe counts matching records only; no document values are copied into
    the result, so no raw URLs, IPs, headers or credentials can leak.
    """

    if client is None:
        uri = (
            mongo_uri
            if mongo_uri is not None
            else os.environ.get("WATCH_MONGO_URI", "")
        )
        if not _text(uri):
            return {
                "status": NOT_CHECKED,
                "reason": "NO_MONGO_URI",
                "checks": {
                    "method_observations": 0,
                    "response_observations": 0,
                    "url_records": 0,
                },
                "values_copied": False,
            }
        try:
            from pymongo import MongoClient

            client = MongoClient(uri)
        except Exception:
            return {
                "status": NOT_CHECKED,
                "reason": "MONGO_UNAVAILABLE",
                "checks": {
                    "method_observations": 0,
                    "response_observations": 0,
                    "url_records": 0,
                },
                "values_copied": False,
            }

    pattern = re.escape(path)
    try:
        database = client.get_default_database()
        method_observations = int(
            database["endpoints"].count_documents(
                {
                    "program_name": program,
                    "method": {"$exists": True},
                    "path": {"$regex": pattern},
                }
            )
        )
        response_observations = int(
            database["http"].count_documents(
                {
                    "program_name": program,
                    "status_code": {"$exists": True},
                    "url": {"$regex": pattern},
                }
            )
        )
        url_records = int(
            database["urls"].count_documents(
                {"program_name": program, "path": path}
            )
        )
    except Exception:
        return {
            "status": NOT_CHECKED,
            "reason": "MONGO_QUERY_FAILED",
            "checks": {
                "method_observations": 0,
                "response_observations": 0,
                "url_records": 0,
            },
            "values_copied": False,
        }

    checks = {
        "method_observations": method_observations,
        "response_observations": response_observations,
        "url_records": url_records,
    }
    status = (
        REAL_AVAILABLE
        if method_observations > 0 or response_observations > 0
        else REAL_NOT_AVAILABLE
    )
    return {
        "status": status,
        "reason": (
            "no stored HTTP method observation and no stored HTTP response "
            "observation for the primary endpoint"
            if status == REAL_NOT_AVAILABLE
            else "stored observations found in the authorized archive"
        ),
        "checks": checks,
        "provenance_note": (
            "read-only archive inspection (counts only; no values copied, no "
            "target interaction)"
        ),
        "values_copied": False,
    }


# ---------------------------------------------------------------------------
# NON-REAL/OFFLINE contract fixtures
# ---------------------------------------------------------------------------


def _non_real_item(
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
                    f"{NON_REAL_LABEL} contract fixture for "
                    f"{requirement_kind}"
                ),
            }
        ],
    }


def non_real_partial_package() -> dict:
    return {
        "package_version": "r74-1",
        "items": [_non_real_item(METHOD_REF, "METHOD_AUTH")],
    }


def non_real_complete_package() -> dict:
    return {
        "package_version": "r74-1",
        "items": [
            _non_real_item(METHOD_REF, "METHOD_AUTH"),
            _non_real_item(RESPONSE_REF, "RESPONSE_BEHAVIOR"),
        ],
    }


def non_real_conflict_package() -> dict:
    return {
        "package_version": "r74-1",
        "items": [
            _non_real_item(CONFLICT_REF, "METHOD_AUTH", effect="CONTRADICTS")
        ],
    }


def negative_fixtures() -> dict:
    """Clearly labelled contract-level negative cases (never real)."""

    return {
        "missing_required_field": {
            "package_version": "r74-1",
            "items": [
                {
                    "hypothesis_ref": "H1",
                    "requirement_kind": "METHOD_AUTH",
                    "effect": "PROVIDES",
                    "source": "HUMAN_REVIEW",
                }
            ],
        },
        "invalid_canonical_reference": {
            "package_version": "r74-1",
            "items": [
                {
                    "hypothesis_ref": "H1",
                    "requirement_kind": "METHOD_AUTH",
                    "effect": "PROVIDES",
                    "source": "HUMAN_REVIEW",
                    "evidence_ref": "not-a-canonical-reference",
                }
            ],
        },
        "sensitive_data": {
            "package_version": "r74-1",
            "items": [
                {
                    "hypothesis_ref": "H1",
                    "requirement_kind": "METHOD_AUTH",
                    "effect": "PROVIDES",
                    "source": "HUMAN_REVIEW",
                    "evidence_ref": "response:nonreal-sensitive-1",
                    "observations": [
                        {
                            "ref": "response:nonreal-sensitive-1",
                            "fact": SENSITIVE_FACT,
                        }
                    ],
                }
            ],
        },
        "duplicate_evidence": {
            "package_version": "r74-1",
            "items": [
                _non_real_item(DUPLICATE_REF, "METHOD_AUTH"),
                _non_real_item(DUPLICATE_REF, "METHOD_AUTH"),
            ],
        },
    }


def run_negative_validations(stages: Mapping) -> dict:
    """Contract-level negative checks through the existing R74/R75 gates."""

    hypotheses = stages.get("hypotheses")
    action_plan = stages.get("action_plan")
    acquisition_plan = stages.get("acquisition_plan")
    readiness_plan = stages.get("readiness_plan")
    results: dict[str, dict] = {}

    fixtures = negative_fixtures()
    expected = {
        "missing_required_field": REJECTION_MALFORMED_EVIDENCE,
        "invalid_canonical_reference": REJECTION_INVALID_EVIDENCE_REF,
        "sensitive_data": REJECTION_SENSITIVE_EVIDENCE,
        "duplicate_evidence": REJECTION_DUPLICATE_EVIDENCE,
    }
    for name, package in fixtures.items():
        intake = normalize_evidence_package(
            package,
            hypotheses=hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
        )
        codes = [entry.get("code") for entry in intake.get("rejections") or ()]
        results[name] = {
            "package_status": _text(intake.get("package_status")).upper(),
            "accepted": int(intake.get("accepted_external_evidence") or 0),
            "rejection_codes": codes,
            "expected_code": expected[name],
            "passed": expected[name] in codes,
            "label": NON_REAL_LABEL,
        }

    partial = run_evidence_roundtrip(stages, non_real_partial_package())
    conflict = run_evidence_roundtrip(
        stages,
        non_real_conflict_package(),
        previous_provenance=partial["provenance"],
    )
    conflict_record = _block(
        _mapping_items(conflict["provenance"].get("records"))[0]
    ) if _mapping_items(conflict["provenance"].get("records")) else {}
    results["contradictory_evidence"] = {
        "package_status": partial["package_status"],
        "relation_to_previous": _text(
            conflict_record.get("relation_to_previous")
        ),
        "conflict_state": _text(conflict_record.get("conflict_state")),
        "conflict_count": len(
            _mapping_items(conflict["provenance"].get("conflicts"))
        ),
        "resolved": False,
        "expected_code": "CONFLICTING",
        "passed": _text(conflict_record.get("conflict_state"))
        == "CONFLICTING",
        "label": NON_REAL_LABEL,
    }
    return results


# ---------------------------------------------------------------------------
# Offline contract path (labelled NON-REAL/OFFLINE)
# ---------------------------------------------------------------------------


def _workbench_view(workbench: Mapping) -> dict:
    current = _block(workbench.get("current_state"))
    known = _block(workbench.get("what_we_know"))
    missing = _block(workbench.get("what_is_missing"))
    review = _block(workbench.get("human_review"))
    conflicts = _block(workbench.get("conflicts"))
    return {
        "status": _text(current.get("status")).upper(),
        "readiness": _text(current.get("readiness")).upper(),
        "decision": _text(current.get("decision")).upper(),
        "know": list(known.get("available_requirement_kinds") or ()),
        "missing": list(missing.get("decision_critical_missing") or ()),
        "next": [
            _text(step.get("action"))
            for step in _mapping_items(workbench.get("next_steps"))
        ],
        "human_review": bool(review.get("required")),
        "review_reasons": list(review.get("reasons") or ()),
        "conflicts": int(conflicts.get("count") or 0),
        "conflicts_resolved": bool(conflicts.get("resolved")),
    }


def validate_real_evidence_intake(
    artifact_path: str | Path = REAL_ARTIFACT_DEFAULT,
    *,
    stages: object = None,
    availability: object = None,
    client: object = None,
    mongo_uri: str | None = None,
) -> dict:
    """Report REAL availability, then validate the contract offline.

    ``stages`` may be supplied for hermetic tests; otherwise the real R77
    artifact is loaded read-only.
    """

    if stages is None:
        stages = load_real_case(artifact_path, case_id=PRIMARY_CASE_ID)
    stages = _block(stages)
    if availability is None:
        availability = real_evidence_availability(
            client, mongo_uri=mongo_uri
        )
    availability = _block(availability)
    real_path_used = (
        _text(availability.get("status")) == REAL_AVAILABLE
    )

    base_case = stages["case"]
    before_workbench = render_workbench(
        stages, base_case, stages.get("evidence_provenance")
    )

    partial = run_evidence_roundtrip(
        stages, non_real_partial_package()
    )
    partial_case = update_case_with_evidence(stages, base_case, partial)
    partial_workbench = render_workbench(
        stages, partial_case, partial["provenance"]
    )
    partial_stages = effective_stages(stages, partial)

    complete = run_evidence_roundtrip(
        partial_stages,
        non_real_complete_package(),
        previous_provenance=partial["provenance"],
    )
    complete_case = update_case_with_evidence(
        partial_stages, partial_case, complete
    )
    complete_workbench = render_workbench(
        partial_stages, complete_case, complete["provenance"]
    )

    return {
        "rule_version": RULE_VERSION,
        "primary_case": {
            "case_id": stages["case_id"],
            "program": stages["program"],
            "artifact_path": stages["artifact_path"],
            "path_ref": f"path:{PRIMARY_PATH}",
            "gap_id": _text(base_case.get("gap_id")),
            "blocking_codes": list(
                _block(base_case.get("readiness")).get("blocking_codes") or ()
            ),
        },
        "real_evidence_available": real_path_used,
        "real_evidence_status": (
            REAL_AVAILABLE if real_path_used else _text(availability.get("status"))
        ),
        "availability": {
            "status": _text(availability.get("status")),
            "reason": _text(availability.get("reason")),
            "checks": dict(_block(availability.get("checks"))),
            "provenance_note": _text(availability.get("provenance_note")),
            "values_copied": bool(availability.get("values_copied")),
        },
        "r74_input_contract": dict(R74_INPUT_CONTRACT),
        "non_real_contract_validation": {
            "label": NON_REAL_LABEL,
            "partial": {
                "package_status": partial["package_status"],
                "accepted": partial["accepted_count"],
                "sufficiency_after": _text(
                    _block(
                        _mapping_items(
                            _block(partial["readiness_after"]).get("records")
                        )[0] if _mapping_items(
                            _block(partial["readiness_after"]).get("records")
                        ) else {}
                    ).get("sufficiency_state")
                ).upper(),
                "feedback_state": _text(
                    partial["iteration"].get("feedback_state")
                ).upper(),
                "hypothesis_state": _text(
                    partial["iteration"].get("current_state")
                ).upper(),
                "next_iteration": _text(
                    partial["iteration"].get("next_iteration")
                ).upper(),
                "relations": [
                    _text(record.get("relation_to_previous"))
                    for record in _mapping_items(
                        partial["provenance"].get("records")
                    )
                ],
            },
            "complete": {
                "package_status": complete["package_status"],
                "accepted": complete["accepted_count"],
                "sufficiency_after": _text(
                    _block(
                        _mapping_items(
                            _block(complete["readiness_after"]).get("records")
                        )[0] if _mapping_items(
                            _block(complete["readiness_after"]).get("records")
                        ) else {}
                    ).get("sufficiency_state")
                ).upper(),
                "decision_after": _text(
                    _block(
                        _mapping_items(
                            _block(complete["readiness_after"]).get("records")
                        )[0] if _mapping_items(
                            _block(complete["readiness_after"]).get("records")
                        ) else {}
                    ).get("decision_state")
                ).upper(),
                "feedback_state": _text(
                    complete["iteration"].get("feedback_state")
                ).upper(),
                "next_iteration": _text(
                    complete["iteration"].get("next_iteration")
                ).upper(),
                "relations": [
                    _text(record.get("relation_to_previous"))
                    for record in _mapping_items(
                        complete["provenance"].get("records")
                    )
                ],
            },
            "case_updates": {
                "partial": summarize_research_case(partial_case),
                "complete": summarize_research_case(complete_case),
                "identity_preserved": (
                    partial_case.get("case_id") == base_case.get("case_id")
                    and complete_case.get("case_id") == base_case.get("case_id")
                    and partial_case.get("gap_id") == base_case.get("gap_id")
                    and partial_case.get("hypothesis_refs")
                    == base_case.get("hypothesis_refs")
                ),
            },
            "workbench": {
                "before": _workbench_view(before_workbench),
                "after_partial": _workbench_view(partial_workbench),
                "after_complete": _workbench_view(complete_workbench),
            },
        },
        "negative_validations": run_negative_validations(stages),
        "safety": dict(_block(base_case.get("safety"))),
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# CLI (prints only; writes nothing)
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tests.local_e2e.r79_real_evidence_intake",
        description=(
            "R79 real researcher evidence intake validation "
            "(no target interaction, no persistence)"
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
        result = validate_real_evidence_intake(args.artifact)
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {str(exc)[:160]}")
        return 2

    if args.json:
        print(json.dumps(result, indent=1, sort_keys=True))
        return 0

    availability = result["availability"]
    print("")
    print("=" * 66)
    print("WATCH R79 — REAL RESEARCHER EVIDENCE INTAKE (offline)")
    print("=" * 66)
    print(f"Primary case : {result['primary_case']['case_id']}")
    print(f"REAL evidence: {result['real_evidence_status']}")
    print(f"Reason       : {availability['reason']}")
    print(f"Checks       : {availability['checks']}")
    print("")
    print(f"REAL EVIDENCE NOT AVAILABLE — validating the contract offline "
          f"({NON_REAL_LABEL})")
    contract = result["non_real_contract_validation"]
    partial = contract["partial"]
    complete = contract["complete"]
    print(
        "   R74 partial : "
        f"{partial['package_status']} accepted={partial['accepted']} "
        f"relations={partial['relations']}"
    )
    print(
        "   R72/R73     : "
        f"{partial['sufficiency_after']} / {partial['feedback_state']} / "
        f"{partial['hypothesis_state']} -> {partial['next_iteration']}"
    )
    print(
        "   R74 complete: "
        f"{complete['package_status']} accepted={complete['accepted']} "
        f"relations={complete['relations']}"
    )
    print(
        "   R72/R73     : "
        f"{complete['sufficiency_after']} / {complete['decision_after']} / "
        f"{complete['feedback_state']} -> {complete['next_iteration']}"
    )
    print(
        "   R76 identity: "
        f"preserved={contract['case_updates']['identity_preserved']}"
    )
    print(
        "   R77 after   : "
        f"{contract['workbench']['after_complete']}"
    )
    print("")
    print("Negative validations:")
    for name, entry in result["negative_validations"].items():
        detail = entry.get("rejection_codes") or [
            entry.get("relation_to_previous") or entry.get("conflict_state")
        ]
        print(
            f"   {name}: passed={entry.get('passed')} "
            f"expected={entry.get('expected_code')} observed={detail}"
        )
    print("")
    print("-" * 66)
    print("[SAFETY] advisory research only; execution_performed=false;")
    print("         vulnerability_confirmed=false; exploit_authorized=false;")
    print("         confirmation_state=NOT_CONFIRMED; no target interaction")
    print("[NOTE] no evidence was persisted; synthetic data was never "
          "relabelled as real")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
