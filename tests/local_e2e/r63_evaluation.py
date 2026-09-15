"""Stage R63 additive offline evaluation and quality gate.

Evaluates the deterministic output of the R62 offline pipeline
(R61 snapshot -> inventory -> R30.1/R31-R38 -> R59 -> R60) against the
current structural, sampling, safety, boundedness, specialist-signal,
CVE-integrity, program-isolation and determinism contracts.

Hard boundaries:

- Evaluation only: the evaluator never fixes, normalizes, recomputes or
  removes pipeline values. It reports violations.
- Offline only: no MongoDB, no network, no target activity, no LLM, no
  randomness, no timestamps.
- Deterministic: the same input always produces byte-identical canonical
  JSON (including the evaluator's own reasons).
- A PASS means the evaluated output is internally consistent with the
  existing safety and boundedness contracts. It never means a target is
  secure, a vulnerability exists, or research is complete.
"""

from __future__ import annotations

import re
from typing import Mapping, Sequence

from ai.knowledge.specialist_eligibility import specialist_is_eligible
from tests.local_e2e import r62_bridge as br

RULE_VERSION = "r63-1"

MAX_CONTEXT_DEPTH = br.MAX_CONTEXT_DEPTH
MAX_CONTEXT_LIST = br.MAX_CONTEXT_LIST
MAX_CONTEXT_KEYS = br.MAX_CONTEXT_KEYS

WORKFLOW_RULE_VERSION = "r59-4"
COPILOT_RULE_VERSION = "r60-4"
COPILOT_STATUSES: tuple[str, ...] = ("COMPLETED", "PARTIAL", "NO_CONTEXT")
ASSET_MATCH_STATES: tuple[str, ...] = (
    "CONFIRMED",
    "SUPPORTED",
    "WEAK",
    "UNKNOWN",
)
SAFETY_TRUTHY_KEYS: tuple[str, ...] = (
    "execution_performed",
    "vulnerability_confirmed",
    "exploit_authorized",
    "external_executor_present",
    "auto_execute",
)

COMPLETENESS_CLAIM_KEYS: tuple[str, ...] = (
    "complete",
    "completeness",
    "coverage",
    "full_coverage",
    "program_coverage",
    "coverage_complete",
    "complete_coverage",
    "complete_program",
    "absence",
    "absence_claim",
    "absence_claims",
)

FORBIDDEN_SECRET_KEYS: tuple[str, ...] = (
    "_id",
    "mongo_id",
    "object_id",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "access_token",
    "refresh_token",
    "authorization_header",
)

R31_LAYER_RULE_VERSION_PREFIXES: dict[str, str] = {
    "hunt_priority_rule_version": "r31-",
    "hunt_action_plan_rule_version": "r31-",
    "evidence_quality_rule_version": "r31-",
    "research_intelligence_export_plan_rule_version": "r31-",
    "research_memory_export_plan_rule_version": "r32-",
    "research_learning_export_plan_rule_version": "r33-",
    "research_strategy_export_plan_rule_version": "r34-",
    "research_orchestration_export_plan_rule_version": "r35-",
    "research_execution_authorization_export_plan_rule_version": "r36-",
    "research_governance_export_plan_rule_version": "r37-",
    "security_agent_framework_plan_rule_version": "r38-",
}

CORE_R31_RULE_VERSION_KEYS: tuple[str, ...] = (
    "hunt_priority_rule_version",
    "evidence_quality_rule_version",
)

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{3,}")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MONGO_ID_RE = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{24}(?![0-9a-fA-F])"
)
SAFE_REASON_LIMIT = 120


class EvaluationError(ValueError):
    """Deterministic, secret-free evaluation misuse failure."""


def canonical_json(value: object) -> str:
    """Canonical JSON matching the R62 pipeline representation."""

    return br.canonical_json(value)


def _new_result() -> dict:
    return {
        "rule_version": RULE_VERSION,
        "status": "PASS",
        "checks": {},
        "summary": {"passed": 0, "failed": 0},
    }


def _add(result: dict, name: str, ok: bool, reason_fail: str) -> None:
    reason = "ok"
    if not ok:
        reason = " ".join(str(reason_fail or "check failed").split())
        reason = reason[:SAFE_REASON_LIMIT]
    result["checks"][name] = {
        "status": "PASS" if ok else "FAIL",
        "reason": reason,
    }


def _finalize(result: dict) -> dict:
    passed = sum(
        1 for check in result["checks"].values()
        if check["status"] == "PASS"
    )
    failed = len(result["checks"]) - passed
    result["summary"] = {"passed": passed, "failed": failed}
    result["status"] = "PASS" if failed == 0 else "FAIL"
    return result


def _merge(result: dict, other: Mapping) -> None:
    checks = other.get("checks")
    if isinstance(checks, Mapping):
        for name, payload in checks.items():
            result["checks"][name] = payload


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _walk(value: object, visitor) -> None:
    visitor(value)
    if isinstance(value, Mapping):
        for item in value.values():
            _walk(item, visitor)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk(item, visitor)


def _first_completeness_claim(value: object) -> str:
    found: list[str] = []

    def visit(item: object) -> None:
        if found:
            return
        if isinstance(item, Mapping):
            for key in item:
                if _text(key).lower() in COMPLETENESS_CLAIM_KEYS:
                    found.append(_text(key)[:40])
                    return

    _walk(value, visit)
    return found[0] if found else ""


def _first_hygiene_violation(value: object) -> str:
    found: list[str] = []

    def visit(item: object) -> None:
        if found:
            return
        if isinstance(item, Mapping):
            for key in item:
                if _text(key).lower() in FORBIDDEN_SECRET_KEYS:
                    found.append("forbidden identifier or secret key present")
                    return
        elif isinstance(item, str):
            if "://" in item:
                found.append("raw url present")
            elif IPV4_RE.search(item):
                found.append("ip address present")
            elif MONGO_ID_RE.search(item):
                found.append("mongo identifier present")

    _walk(value, visit)
    return found[0] if found else ""


def _first_truthy_flag(value: object, keys: Sequence[str]) -> str:
    found: list[str] = []

    def visit(item: object) -> None:
        if found:
            return
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if _text(key) in keys and nested is True:
                    found.append(f"forbidden true flag: {_text(key)[:40]}")
                    return

    _walk(value, visit)
    return found[0] if found else ""


def _cve_ids_in(value: object) -> list[str]:
    found: list[str] = []

    def visit(item: object) -> None:
        if isinstance(item, str):
            for match in CVE_ID_RE.findall(item):
                if match not in found:
                    found.append(match)

    _walk(value, visit)
    return found


def evaluate_context(context: object, *, label: str = "context") -> dict:
    """Bounds + hygiene evaluation for one bounded R59/R60 context."""

    result = _new_result()
    bounds_ok = isinstance(context, Mapping)
    bounds_reason = "context must be a mapping"
    if bounds_ok:
        try:
            br.validate_context(context)
            bounds_reason = ""
        except br.BridgeError as exc:
            bounds_ok = False
            bounds_reason = f"bounds violated: {exc}"
    _add(result, f"{label}_bounds", bounds_ok, bounds_reason)
    hygiene = _first_hygiene_violation(context)
    _add(result, f"{label}_hygiene", not hygiene, hygiene or "hygiene violation")
    return _finalize(result)


def evaluate_sampling(
    research_context: object, intelligence_context: object
) -> dict:
    """Sampling honesty: explicit sample flag, no completeness claims."""

    result = _new_result()
    contexts = (
        ("research_context", research_context),
        ("intelligence_context", intelligence_context),
    )
    sampled_ok = all(
        isinstance(context, Mapping) and context.get("sampled") is True
        for _, context in contexts
    )
    _add(
        result,
        "sampling_flag",
        sampled_ok,
        "sampled must be true in both contexts",
    )
    claims = ""
    for _, context in contexts:
        claims = _first_completeness_claim(context)
        if claims:
            break
    _add(
        result,
        "sampling_claims",
        not claims,
        f'forbidden completeness or coverage key: "{claims}"',
    )
    stats = (
        research_context.get("collection_stats")
        if isinstance(research_context, Mapping)
        else None
    )
    counters_ok = isinstance(stats, Mapping) and all(
        isinstance(entry, Mapping)
        and isinstance(entry.get("selected"), int)
        and isinstance(entry.get("cap_reached"), bool)
        for entry in stats.values()
    )
    _add(
        result,
        "sampling_counters",
        counters_ok,
        "research_context collection_stats must carry selected/cap_reached",
    )
    return _finalize(result)


def evaluate_safety(workflow: object, copilot: object) -> dict:
    """Advisory/no-execution/no-confirmation invariants for R59/R60."""

    result = _new_result()
    wf = workflow if isinstance(workflow, Mapping) else {}
    next_action = (
        wf.get("next_action") if isinstance(wf.get("next_action"), Mapping) else {}
    )
    workflow_ok = (
        wf.get("advisory") is True
        and wf.get("execution_performed") is False
        and wf.get("vulnerability_confirmed") is False
        and wf.get("exploit_authorized") is False
        and wf.get("external_executor_present") is False
        and wf.get("confirmation_state") == "NOT_CONFIRMED"
        and wf.get("human_authority_preserved") is True
        and next_action.get("advisory") is True
        and next_action.get("auto_execute") is False
    )
    _add(
        result,
        "safety_workflow",
        workflow_ok,
        "workflow violates advisory/no-execution/no-confirmation invariants",
    )

    cp = copilot if isinstance(copilot, Mapping) else {}
    copilot_ok = (
        cp.get("advisory") is True
        and cp.get("execution_performed") is False
        and cp.get("vulnerability_confirmed") is False
        and cp.get("exploit_authorized") is False
        and cp.get("external_executor_present") is False
        and cp.get("confirmation_state") == "NOT_CONFIRMED"
        and cp.get("human_authority_preserved") is True
        and cp.get("status") in COPILOT_STATUSES
    )
    _add(
        result,
        "safety_copilot",
        copilot_ok,
        "copilot violates advisory/no-execution/no-confirmation invariants",
    )

    brief = cp.get("brief") if isinstance(cp.get("brief"), Mapping) else {}
    boundary = (
        brief.get("non_execution_boundary")
        if isinstance(brief.get("non_execution_boundary"), Mapping)
        else {}
    )
    boundary_ok = (
        brief.get("advisory") is True
        and boundary.get("advisory_only") is True
        and boundary.get("r58_gate_required") is True
        and boundary.get("human_authority_required") is True
        and boundary.get("execution_performed") is False
        and boundary.get("vulnerability_confirmed") is False
        and boundary.get("exploit_authorized") is False
        and boundary.get("confirmation_state") == "NOT_CONFIRMED"
    )
    _add(
        result,
        "safety_boundary",
        boundary_ok,
        "copilot non_execution_boundary is incomplete or violated",
    )

    recommendations = brief.get("recommended_actions") or []
    recommendations_ok = all(
        isinstance(entry, Mapping)
        and entry.get("advisory") is True
        and entry.get("auto_execute") is False
        for entry in recommendations
    )
    _add(
        result,
        "safety_recommendations",
        recommendations_ok,
        "recommendation is not advisory-only",
    )

    truthy = _first_truthy_flag(
        {"workflow": wf, "copilot": cp}, SAFETY_TRUTHY_KEYS
    )
    _add(
        result,
        "no_confirmation_claims",
        not truthy,
        truthy or "forbidden execution or confirmation flag is true",
    )
    return _finalize(result)


def _evidence_paths(snapshot: Mapping, inventory: Mapping) -> list[str]:
    program = _text(inventory.get("program") or snapshot.get("program"))
    paths: set[str] = set()
    for item in inventory.get("paths") or ():
        value = item.get("value") if isinstance(item, Mapping) else item
        text = _text(value)
        if text:
            paths.add(text)
    collections = snapshot.get("collections")
    collections = collections if isinstance(collections, Mapping) else {}
    for name in ("endpoints", "urls"):
        payload = collections.get(name)
        payload = payload if isinstance(payload, Mapping) else {}
        for record in payload.get("records") or ():
            if not isinstance(record, Mapping):
                continue
            if _text(record.get("program_name")) != program:
                continue
            path = _text(record.get("path"))
            if path:
                paths.add(path)
    return sorted(paths)


def _object_reference_evidence(snapshot: Mapping, inventory: Mapping) -> bool:
    program = _text(inventory.get("program") or snapshot.get("program"))
    collections = snapshot.get("collections")
    collections = collections if isinstance(collections, Mapping) else {}
    payload = collections.get("endpoints")
    payload = payload if isinstance(payload, Mapping) else {}
    for record in payload.get("records") or ():
        if not isinstance(record, Mapping):
            continue
        if _text(record.get("program_name")) != program:
            continue
        path = _text(record.get("path"))
        if not br.IDOR_OBJECT_REFERENCE_RE.search(path):
            continue
        for key in (
            "params",
            "params_from_crawl",
            "params_from_x8",
            "param_records",
        ):
            value = record.get(key)
            if isinstance(value, (list, tuple)) and value:
                return True
    return False


def _specialist_evidence(
    signals: Mapping,
    snapshot: Mapping,
    inventory: Mapping,
    r31: Mapping | None,
) -> tuple[bool, str]:
    paths = _evidence_paths(snapshot, inventory)
    recon = signals.get("RECON")
    if isinstance(recon, Mapping):
        api_type = _text(recon.get("api_type"))
        if api_type == "REST":
            if not any(br.RECON_API_PATH_RE.search(path) for path in paths):
                return False, "RECON api_type REST without observed API path"
        elif api_type == "GRAPHQL":
            if not any(
                br.RECON_GRAPHQL_PATH_RE.search(path) for path in paths
            ):
                return False, "RECON api_type GRAPHQL without observed path"
        else:
            return False, "RECON api_type outside the closed vocabulary"
        versioning = recon.get("api_versioning")
        if versioning is not None:
            if versioning != "VERSIONED_OBSERVED":
                return False, "RECON api_versioning outside the vocabulary"
            if not any(
                br.RECON_VERSION_PATH_RE.search(path) for path in paths
            ):
                return False, "VERSIONED_OBSERVED without observed /vN/ path"
    cve = signals.get("CVE_RESEARCH")
    if isinstance(cve, Mapping):
        value = _text(cve.get("cve_metadata"))
        if not isinstance(r31, Mapping):
            return False, "CVE_RESEARCH signal without matcher output"
        if _text(r31.get("cve_id")) != value:
            return False, "CVE_RESEARCH signal without matching matcher output"
        if _text(r31.get("asset_match_state")).upper() not in (
            br.MATCHED_ASSET_STATES
        ):
            return False, "CVE_RESEARCH signal without an actual match"
    idor = signals.get("IDOR")
    if isinstance(idor, Mapping):
        if _text(idor.get("object_reference")) != "PATH_PARAMETER":
            return False, "IDOR object_reference outside the vocabulary"
        if not _object_reference_evidence(snapshot, inventory):
            return False, "IDOR signal without object-reference path evidence"
    return True, ""


def evaluate_specialist_signals(
    signals: object,
    *,
    snapshot: Mapping | None = None,
    inventory: Mapping | None = None,
    r31: Mapping | None = None,
) -> dict:
    """Category, eligibility and evidence evaluation for specialist signals."""

    result = _new_result()
    sig = signals if isinstance(signals, Mapping) else {}
    supported = set(br.SUPPORTED_SPECIALIST_CATEGORIES)
    categories_ok = isinstance(signals, Mapping) and set(sig) <= supported
    _add(
        result,
        "specialist_categories",
        categories_ok,
        "unsupported or malformed specialist category present",
    )
    eligibility_ok = isinstance(signals, Mapping)
    for category, context in sig.items():
        if (
            category not in supported
            or not isinstance(context, Mapping)
            or not specialist_is_eligible(category, dict(context))
        ):
            eligibility_ok = False
            break
    _add(
        result,
        "specialist_eligibility",
        eligibility_ok,
        "signal is not accepted by the existing eligibility engine",
    )
    if isinstance(snapshot, Mapping) and isinstance(inventory, Mapping):
        evidence_ok, evidence_reason = _specialist_evidence(
            sig, snapshot, inventory, r31
        )
        _add(
            result,
            "specialist_evidence",
            evidence_ok,
            evidence_reason,
        )
    return _finalize(result)


def evaluate_r31(result: Mapping) -> dict:
    """R31-R38 layer presence, vocabulary and rule-version consistency."""

    evaluated = _new_result()
    item = result.get("r31") if isinstance(result, Mapping) else None
    item_ok = isinstance(item, Mapping)
    _add(
        evaluated,
        "r31_item",
        item_ok,
        "R31 matcher item missing from the pipeline result",
    )
    if not item_ok:
        _add(
            evaluated,
            "r31_layer_consistency",
            False,
            "layer consistency cannot be evaluated without a matcher item",
        )
        return _finalize(evaluated)

    vocabulary_ok = (
        _text(item.get("asset_match_state")) in ASSET_MATCH_STATES
        and bool(_text(item.get("cve_id")))
    )
    _add(
        evaluated,
        "r31_match_vocabulary",
        vocabulary_ok,
        "matcher state or cve id outside the closed vocabulary",
    )

    problems: list[str] = []
    for key in CORE_R31_RULE_VERSION_KEYS:
        if not _text(item.get(key)):
            problems.append(f"missing {key}")
    for key, prefix in R31_LAYER_RULE_VERSION_PREFIXES.items():
        if key not in item:
            continue
        value = _text(item.get(key))
        if not value:
            problems.append(f"empty {key}")
        elif not value.startswith(prefix):
            problems.append(f"unexpected prefix for {key}")
    _add(
        evaluated,
        "r31_layer_consistency",
        not problems,
        problems[0] if problems else "layer consistency violation",
    )
    return _finalize(evaluated)


def evaluate_program_isolation(
    result: Mapping,
    *,
    program: str = "",
    foreign_programs: Sequence[str] = (),
    snapshot: Mapping | None = None,
) -> dict:
    """Program identity and cross-program exclusion for every stage."""

    evaluated = _new_result()
    data = result if isinstance(result, Mapping) else {}
    stage_names = (
        "inventory",
        "research_context",
        "intelligence_context",
        "workflow",
        "copilot",
    )
    observed_programs: list[str] = []
    for name in stage_names:
        stage = data.get(name)
        if not isinstance(stage, Mapping):
            continue
        value = _text(stage.get("program"))
        if value:
            observed_programs.append(value)
    expected = _text(program) or (
        observed_programs[0] if observed_programs else ""
    )
    identity_ok = bool(expected) and all(
        value == expected for value in observed_programs
    )
    _add(
        evaluated,
        "program_identity",
        identity_ok,
        "pipeline stages disagree on the program identity",
    )

    text = canonical_json(data)
    foreign = [
        name
        for name in foreign_programs
        if _text(name) and _text(name) in text
    ]
    _add(
        evaluated,
        "program_isolation",
        not foreign,
        "foreign program reference present in pipeline output",
    )

    if isinstance(snapshot, Mapping):
        research = data.get("research_context")
        research = research if isinstance(research, Mapping) else {}
        refs = research.get("record_refs")
        refs = refs if isinstance(refs, Mapping) else {}
        allowed: set[str] = set()
        collections = snapshot.get("collections")
        collections = collections if isinstance(collections, Mapping) else {}
        for payload in collections.values():
            if not isinstance(payload, Mapping):
                continue
            for record in payload.get("records") or ():
                if not isinstance(record, Mapping):
                    continue
                if _text(record.get("program_name")) != expected:
                    continue
                reference = _text(record.get("record_ref"))
                if reference:
                    allowed.add(reference)
        leaked = False
        for values in refs.values():
            for reference in values or ():
                if _text(reference) and _text(reference) not in allowed:
                    leaked = True
        _add(
            evaluated,
            "record_ref_scope",
            not leaked,
            "record_ref outside the evaluated program scope",
        )
    return _finalize(evaluated)


def evaluate_sampling_honesty(
    research_context: object, intelligence_context: object
) -> dict:
    """Alias kept separate for API clarity (same checks as evaluate_sampling)."""

    return evaluate_sampling(research_context, intelligence_context)


def evaluate_pipeline(
    result: object,
    *,
    snapshot: Mapping | None = None,
    foreign_programs: Sequence[str] = (),
    require_r31: bool = True,
) -> dict:
    """Full offline evaluation of one R62 pipeline result."""

    gate = _new_result()
    structure_ok = isinstance(result, Mapping)
    _add(
        gate,
        "pipeline_structure",
        structure_ok,
        "pipeline result must be a mapping",
    )
    if not structure_ok:
        return _finalize(gate)

    inventory = result.get("inventory")
    inventory_ok = (
        isinstance(inventory, Mapping) and bool(_text(inventory.get("program")))
    )
    _add(
        gate,
        "stage_inventory",
        inventory_ok,
        "R62 inventory stage missing or malformed",
    )

    research_context = result.get("research_context")
    intelligence_context = result.get("intelligence_context")
    snapshot_reference_ok = all(
        isinstance(context, Mapping)
        and isinstance(context.get("snapshot_version"), int)
        and bool(_text(context.get("snapshot_rule_version")))
        for context in (research_context, intelligence_context)
    )
    _add(
        gate,
        "stage_snapshot_reference",
        snapshot_reference_ok,
        "R61 snapshot reference missing from the bounded contexts",
    )

    r31 = result.get("r31")
    r31_ok = isinstance(r31, Mapping)
    _add(
        gate,
        "stage_r31",
        r31_ok if require_r31 else r31 is None or r31_ok,
        "R31/R38 intelligence stage missing",
    )

    workflow = result.get("workflow")
    workflow_ok = (
        isinstance(workflow, Mapping)
        and _text(workflow.get("rule_version")) == WORKFLOW_RULE_VERSION
    )
    _add(
        gate,
        "stage_workflow",
        workflow_ok,
        "R59 workflow stage missing or mis-versioned",
    )

    copilot = result.get("copilot")
    copilot_ok = (
        isinstance(copilot, Mapping)
        and _text(copilot.get("rule_version")) == COPILOT_RULE_VERSION
    )
    _add(
        gate,
        "stage_copilot",
        copilot_ok,
        "R60 copilot stage missing or mis-versioned",
    )

    signals = result.get("specialist_signals")
    program = (
        _text(inventory.get("program")) if isinstance(inventory, Mapping) else ""
    )

    _merge(
        gate,
        evaluate_sampling(research_context, intelligence_context),
    )
    _merge(gate, evaluate_context(research_context, label="research_context"))
    _merge(
        gate,
        evaluate_context(intelligence_context, label="intelligence_context"),
    )
    _merge(gate, evaluate_safety(workflow, copilot))
    _merge(
        gate,
        evaluate_specialist_signals(
            signals,
            snapshot=snapshot,
            inventory=inventory if isinstance(inventory, Mapping) else None,
            r31=r31 if isinstance(r31, Mapping) else None,
        ),
    )
    if require_r31:
        _merge(gate, evaluate_r31(result))
    _merge(
        gate,
        evaluate_program_isolation(
            result,
            program=program,
            foreign_programs=foreign_programs,
            snapshot=snapshot,
        ),
    )

    r31_id = _text(r31.get("cve_id")) if isinstance(r31, Mapping) else ""
    matched = (
        isinstance(r31, Mapping)
        and _text(r31.get("asset_match_state")).upper()
        in br.MATCHED_ASSET_STATES
    )
    allowed_cves = {r31_id} if matched and r31_id else set()
    context_cves = set(
        _cve_ids_in(
            {
                "research_context": research_context,
                "intelligence_context": intelligence_context,
            }
        )
    )
    invented = sorted(context_cves - allowed_cves)
    _add(
        gate,
        "cve_integrity",
        not invented,
        "cve id emitted without a corresponding matcher output",
    )

    brief = (
        copilot.get("brief")
        if isinstance(copilot, Mapping)
        and isinstance(copilot.get("brief"), Mapping)
        else {}
    )
    wf_summary = (
        workflow.get("summary")
        if isinstance(workflow, Mapping)
        and isinstance(workflow.get("summary"), Mapping)
        else {}
    )
    opportunities = brief.get("opportunities") or []
    findings = brief.get("related_finding_ids") or []
    opportunity_count = brief.get("opportunity_count")
    fabricated_ok = (
        opportunity_count in (0, None)
        and not opportunities
        and not findings
        and wf_summary.get("finding_count", 0) in (0, None)
        and wf_summary.get("specialists_completed", 0) in (0, None)
    )
    _add(
        gate,
        "no_fabricated_outputs",
        fabricated_ok,
        "opportunities or findings present without matching artifacts",
    )
    return _finalize(gate)


def quality_gate(
    result: object,
    *,
    snapshot: Mapping | None = None,
    foreign_programs: Sequence[str] = (),
    require_r31: bool = True,
) -> dict:
    """Quality-gate alias: the same deterministic evaluation as the pipeline."""

    return evaluate_pipeline(
        result,
        snapshot=snapshot,
        foreign_programs=foreign_programs,
        require_r31=require_r31,
    )


def evaluate_determinism(
    snapshot: Mapping, pipeline_args: Mapping | None = None
) -> dict:
    """Reproduce the offline pipeline twice and compare canonical JSON."""

    result = _new_result()
    args = dict(pipeline_args or {})
    try:
        first = br.pipeline(snapshot, **args)
        second = br.pipeline(snapshot, **args)
    except Exception as exc:
        _add(
            result,
            "pipeline_determinism",
            False,
            f"pipeline raised during determinism evaluation: "
            f"{type(exc).__name__}",
        )
        return _finalize(result)
    first_json = canonical_json(first)
    second_json = canonical_json(second)
    _add(
        result,
        "pipeline_determinism",
        first_json == second_json,
        "repeated offline pipeline runs produced different output",
    )
    first_eval = canonical_json(
        evaluate_pipeline(first, snapshot=snapshot)
    )
    second_eval = canonical_json(
        evaluate_pipeline(second, snapshot=snapshot)
    )
    _add(
        result,
        "evaluator_determinism",
        first_eval == second_eval,
        "repeated evaluations produced different output",
    )
    return _finalize(result)


__all__ = [
    "RULE_VERSION",
    "MAX_CONTEXT_DEPTH",
    "MAX_CONTEXT_LIST",
    "MAX_CONTEXT_KEYS",
    "EvaluationError",
    "canonical_json",
    "evaluate_pipeline",
    "evaluate_r31",
    "evaluate_context",
    "evaluate_specialist_signals",
    "evaluate_safety",
    "evaluate_sampling",
    "evaluate_sampling_honesty",
    "evaluate_program_isolation",
    "evaluate_determinism",
    "quality_gate",
]
