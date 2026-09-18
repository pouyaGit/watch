"""Stage R92 — focused tests for case-aware research scheduling.

Covers exactly the new behavior:

- the bounded case scheduling context built from the R76 case and the R91
  acquisition ledger (constraints, requirement projection, no evidence
  contents, fail-closed inputs, determinism, read-only inputs);
- deterministic plan/case compatibility (SELECT/SKIP + closed reason codes)
  across case status, ledger next action, requirement state and plan
  relevance;
- case-aware selection (no redundant acquisition for exhausted requirements,
  fail-closed unbound plans, stable multi-case attention order, no scoring,
  no LLM, no network, no execution, no confirmation);
- the opt-in scheduler integration (default behavior byte-identical, run
  records bounded, existing execution gate still separate);
- the read-only `agent schedule` CLI;
- the real production-derived case fixture read-only.

No network, no LLM, no Mongo, no subprocess.
"""

from __future__ import annotations

import contextlib
import inspect
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ai.knowledge.research_acquisition_ledger import (
    OUTCOME_ACCEPTED,
    SOURCE_WATCH_DERIVED,
    build_case_acquisition_ledger,
)
from ai.research_agent.case_scheduling import (
    CASE_SCHEDULING_ERROR_CODES,
    CONSTRAINT_CASE_SATISFIED,
    CONSTRAINT_OFFLINE_SOURCES_EXHAUSTED,
    DECISION_SELECT,
    DECISION_SKIP,
    REASON_ACQUISITION_EXHAUSTED,
    REASON_CASE_ALREADY_SATISFIED,
    REASON_CASE_NOT_ACTIVE,
    REASON_CASE_STOPPED,
    REASON_CONFLICT_REVIEW_REQUIRED,
    REASON_HUMAN_EVIDENCE_REQUIRED,
    REASON_MALFORMED_PLAN,
    REASON_MISSING_CASE_CONTEXT,
    REASON_PLAN_ALREADY_ATTEMPTED,
    REASON_PLAN_NOT_RELEVANT,
    REASON_REQUIREMENT_ALREADY_SATISFIED,
    REASON_UNSAFE_ACTION,
    SCHEDULING_REASONS,
    CaseSchedulingError,
    build_case_scheduling_context,
    evaluate_plan_compatibility,
    plan_requirement_kinds,
    select_case_aware_plans,
)
from ai.research_agent.scheduler import (
    RUN_STATUS_BLOCKED,
    ResearchScheduler,
    SchedulerConfig,
    load_case_contexts,
    select_plans,
)
from ai.knowledge.research_workbench import WORKFLOW_ACTIONS

PLAN_ID = "r22-" + "ab" * 8
OTHER_PLAN_ID = "r22-" + "cd" * 8
CVE = "CVE-2026-99999"
CASE_ID = "case-dell-a1-component-mapping"
REAL_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "ai_data"
    / "research"
    / "r76"
    / "r64-indeed-b1ebaaf9f2211f82.json"
)

ALL_KINDS = (
    "TECHNOLOGY_IDENTITY",
    "VERSION_IDENTITY",
    "COMPONENT_BINDING",
    "WATCH_SIGNAL",
)

_CLASS_OF = {
    "TECHNOLOGY_IDENTITY": "SUPPORT",
    "VERSION_IDENTITY": "SUPPORT",
    "COMPONENT_BINDING": "DECISION",
    "WATCH_SIGNAL": "SUPPORT",
    "INPUT_SURFACE": "SUPPORT",
}


def case_fixture(
    *,
    case_id=CASE_ID,
    status="ACTIVE",
    available=("TECHNOLOGY_IDENTITY",),
    missing=("VERSION_IDENTITY", "COMPONENT_BINDING", "WATCH_SIGNAL"),
    sufficiency="INSUFFICIENT",
    decision_state="NEEDS_EVIDENCE",
    human_review=False,
):
    return {
        "case_id": case_id,
        "case_version": "r76-1",
        "program": "dell",
        "status": status,
        "iteration_count": 2,
        "human_review_required": human_review,
        "evidence": {
            "available_requirement_kinds": list(available),
            "missing_requirement_kinds": list(missing),
        },
        "readiness": {
            "sufficiency_state": sufficiency,
            "decision_state": decision_state,
            "blocking_codes": [
                kind for kind in missing if _CLASS_OF.get(kind) == "DECISION"
            ],
        },
    }


def readiness_fixture(kinds=ALL_KINDS):
    return {
        "records": [
            {
                "required_evidence": [
                    {
                        "requirement_kind": kind,
                        "requirement_class": _CLASS_OF.get(kind, "SUPPORT"),
                    }
                    for kind in kinds
                ]
            }
        ]
    }


def completion_fixture(
    accepted=("TECHNOLOGY_IDENTITY",),
    missing=("VERSION_IDENTITY", "COMPONENT_BINDING", "WATCH_SIGNAL"),
    rule_version="r87-1",
):
    return {
        "rule_version": rule_version,
        "status": "COMPLETED",
        "accepted_items": len(accepted),
        "requirement_kinds": list(accepted),
        "missing_requirement_kinds": list(missing),
    }


def ledger_for(case, *, completion=True, kinds=ALL_KINDS, **overrides):
    kwargs = {
        "readiness_plan": readiness_fixture(kinds),
        "evidence_completion": completion_fixture() if completion else None,
    }
    kwargs.update(overrides)
    return build_case_acquisition_ledger(case, **kwargs)


def context_for(case=None, *, completion=True, source_plan_ref=PLAN_ID, **kwargs):
    case = case if case is not None else case_fixture()
    ledger = kwargs.pop("ledger", None) or ledger_for(case, completion=completion)
    return build_case_scheduling_context(
        case,
        acquisition_ledger=ledger,
        source_plan_ref=source_plan_ref,
        source_cve=CVE,
    )


def make_plan(
    plan_id=PLAN_ID,
    *,
    cve=CVE,
    program="dell",
    targets=("ASSET_COMPONENT",),
    steps=(),
    status="RESEARCH_PLAN_READY",
    **extra,
):
    plan = {
        "plan_id": plan_id,
        "cve_id": cve,
        "program": program,
        "status": status,
        "evidence_targets": [{"code": code} for code in targets],
        "steps": [{"code": code} for code in steps],
        "metadata": {"priority_level": "HIGH_RESEARCH"},
    }
    plan.update(extra)
    return plan


class RecordingAgent:
    def __init__(self):
        self.seen_plan_ids = []

    def run_plans(
        self,
        plans,
        *,
        run_id,
        deadline,
        dry_run,
        network,
        persist,
        per_plan_timeout=None,
    ):
        results = []
        for plan in plans:
            self.seen_plan_ids.append(plan["plan_id"])
            results.append(_FakeResult(plan["plan_id"]))
        return results, []


class _FakeResult:
    def __init__(self, plan_id):
        self.plan_id = plan_id
        self.result_id = "ra-" + plan_id[-4:]
        self.cve_id = CVE
        self.program = "dell"
        self.status = "RESEARCH_COMPLETED"
        self.evidence = []
        self.sources = []


class ExplodingAgent:
    def run_plans(self, *args, **kwargs):  # pragma: no cover
        raise AssertionError("agent must not run")


def scheduler_for(tmp, plans, contexts=None, **cfg_kwargs):
    cfg_kwargs.setdefault("enabled", True)
    cfg_kwargs.setdefault("window_start", "00:00")
    cfg_kwargs.setdefault("window_end", "23:59")
    cfg_kwargs.setdefault("lock_path", os.path.join(tmp, "l.lock"))
    cfg_kwargs.setdefault("agent_dir", tmp)
    cfg = SchedulerConfig(**cfg_kwargs)
    loader = None
    if contexts is not None:
        loader = lambda: list(contexts)  # noqa: E731
    return ResearchScheduler(
        cfg,
        plan_loader=lambda: list(plans),
        case_context_loader=loader,
    )


# ---------------------------------------------------------------------------
# context builder
# ---------------------------------------------------------------------------


class TestContextBuilder(unittest.TestCase):
    def test_exhausted_case_context(self):
        context = context_for()
        self.assertEqual(context["case_ref"], CASE_ID)
        self.assertEqual(context["case_status"], "ACTIVE")
        self.assertEqual(context["next_action"], "PROVIDE_EVIDENCE")
        self.assertTrue(context["offline_sources_exhausted"])
        self.assertTrue(context["human_action_required"])
        self.assertEqual(context["source_plan_ref"], PLAN_ID)
        self.assertEqual(context["source_cve"], CVE)
        constraints = context["scheduling_constraints"]
        self.assertIn(CONSTRAINT_OFFLINE_SOURCES_EXHAUSTED, constraints)
        self.assertNotIn(CONSTRAINT_CASE_SATISFIED, constraints)
        statuses = {
            entry["requirement_kind"]: entry["status"]
            for entry in context["requirements"]
        }
        self.assertEqual(
            statuses["COMPONENT_BINDING"], "ATTEMPTED_NO_OBSERVATION"
        )
        self.assertEqual(statuses["WATCH_SIGNAL"], "HUMAN_REQUIRED")
        self.assertEqual(statuses["TECHNOLOGY_IDENTITY"], "SATISFIED")

    def test_no_evidence_contents_copied(self):
        ledger = ledger_for(
            case_fixture(),
            evidence_provenance={
                "records": [
                    {
                        "requirement_kind": "COMPONENT_BINDING",
                        "evidence_refs": ["response:secret-ref"],
                        "conflict_state": "NONE",
                    }
                ]
            },
        )
        context = context_for(ledger=ledger)
        serialized = json.dumps(context, sort_keys=True)
        self.assertNotIn("secret-ref", serialized)
        self.assertNotIn("evidence_refs", serialized)
        for entry in context["requirements"]:
            self.assertNotIn("attempts", entry)
            self.assertNotIn("evidence_refs", entry)

    def test_bounded_and_deterministic(self):
        case = case_fixture()
        ledger = ledger_for(case)
        snapshot = json.dumps([case, ledger], sort_keys=True)
        first = build_case_scheduling_context(case, acquisition_ledger=ledger)
        second = build_case_scheduling_context(case, acquisition_ledger=ledger)
        self.assertEqual(first, second)
        self.assertEqual(json.dumps([case, ledger], sort_keys=True), snapshot)

    def test_fail_closed_cases(self):
        ledger = ledger_for(case_fixture())
        for bad in (None, {}, {"case_id": ""}, "not-a-case"):
            with self.subTest(bad=bad):
                with self.assertRaises(CaseSchedulingError) as ctx:
                    build_case_scheduling_context(
                        bad, acquisition_ledger=ledger
                    )
                self.assertEqual(
                    ctx.exception.code, "MALFORMED_CASE_CONTEXT"
                )
        unknown = case_fixture()
        unknown["status"] = "IMAGINARY"
        with self.assertRaises(CaseSchedulingError) as ctx:
            build_case_scheduling_context(
                unknown, acquisition_ledger=ledger
            )
        self.assertEqual(ctx.exception.code, "UNKNOWN_CASE_STATUS")

    def test_fail_closed_ledgers(self):
        case = case_fixture()
        for bad in (None, {}, "nope"):
            with self.subTest(bad=bad):
                with self.assertRaises(CaseSchedulingError) as ctx:
                    build_case_scheduling_context(
                        case, acquisition_ledger=bad
                    )
                self.assertEqual(ctx.exception.code, "MALFORMED_LEDGER")
        broken = ledger_for(case)
        broken["case_id"] = "case-other"
        with self.assertRaises(CaseSchedulingError) as ctx:
            build_case_scheduling_context(case, acquisition_ledger=broken)
        self.assertEqual(ctx.exception.code, "CONTRADICTORY_CASE_CONTEXT")

        broken = ledger_for(case)
        broken["next_action"] = "DO_SOMETHING"
        with self.assertRaises(CaseSchedulingError) as ctx:
            build_case_scheduling_context(case, acquisition_ledger=broken)
        self.assertEqual(ctx.exception.code, "UNKNOWN_NEXT_ACTION")

        broken = ledger_for(case)
        broken["requirements"] = [{"requirement_kind": "X", "status": "???"}]
        with self.assertRaises(CaseSchedulingError) as ctx:
            build_case_scheduling_context(case, acquisition_ledger=broken)
        self.assertEqual(ctx.exception.code, "MALFORMED_LEDGER")

        broken = ledger_for(case)
        broken["requirements"] = "not-a-list"
        with self.assertRaises(CaseSchedulingError) as ctx:
            build_case_scheduling_context(case, acquisition_ledger=broken)
        self.assertEqual(ctx.exception.code, "MALFORMED_LEDGER")

    def test_error_codes_are_closed(self):
        self.assertIn("MALFORMED_LEDGER", CASE_SCHEDULING_ERROR_CODES)
        self.assertIn(
            "CONTRADICTORY_CASE_CONTEXT", CASE_SCHEDULING_ERROR_CODES
        )


# ---------------------------------------------------------------------------
# plan compatibility
# ---------------------------------------------------------------------------


class TestPlanCompatibility(unittest.TestCase):
    def test_active_case_open_requirement_selects(self):
        context = context_for(completion=False)
        decision = evaluate_plan_compatibility(make_plan(), context)
        self.assertEqual(decision["decision"], DECISION_SELECT)
        self.assertEqual(decision["reason_code"], "")
        self.assertEqual(decision["case_id"], CASE_ID)
        self.assertEqual(decision["next_action"], "CONTINUE_RESEARCH")
        self.assertEqual(decision["acquisition_state"], "NOT_ATTEMPTED")
        self.assertFalse(decision["execution_authorized"])
        self.assertEqual(
            decision["authorization_state"], "NOT_AUTHORIZED"
        )
        self.assertEqual(decision["confirmation_state"], "NOT_CONFIRMED")
        kinds = [
            entry["requirement_kind"]
            for entry in decision["relevant_requirements"]
        ]
        self.assertEqual(kinds, ["COMPONENT_BINDING"])

    def test_step_vocabulary_binds_too(self):
        context = context_for(completion=False)
        plan = make_plan(targets=(), steps=("REVIEW_VERSION",))
        decision = evaluate_plan_compatibility(plan, context)
        self.assertEqual(decision["decision"], DECISION_SELECT)
        self.assertEqual(
            [entry["requirement_kind"] for entry in decision["relevant_requirements"]],
            ["VERSION_IDENTITY"],
        )

    def test_stopped_case_skips(self):
        case = case_fixture(status="STOPPED")
        context = context_for(case, completion=False)
        decision = evaluate_plan_compatibility(make_plan(), context)
        self.assertEqual(decision["decision"], DECISION_SKIP)
        self.assertEqual(decision["reason_code"], REASON_CASE_STOPPED)

    def test_ready_for_human_review_skips(self):
        case = case_fixture(
            status="READY_FOR_HUMAN_REVIEW",
            decision_state="READY_FOR_HUMAN_REVIEW",
            sufficiency="SUFFICIENT_FOR_REVIEW",
        )
        context = context_for(case, completion=False)
        decision = evaluate_plan_compatibility(make_plan(), context)
        self.assertEqual(decision["reason_code"], REASON_HUMAN_EVIDENCE_REQUIRED)

    def test_unknown_case_status_fails_closed_in_evaluation(self):
        context = context_for(completion=False)
        context["case_status"] = "IMAGINARY"
        decision = evaluate_plan_compatibility(make_plan(), context)
        self.assertEqual(decision["reason_code"], REASON_MISSING_CASE_CONTEXT)

    def test_case_already_satisfied(self):
        case = case_fixture(
            available=ALL_KINDS,
            missing=(),
            sufficiency="SUFFICIENT_FOR_REVIEW",
        )
        context = context_for(case, completion=False)
        self.assertIn(CONSTRAINT_CASE_SATISFIED, context["scheduling_constraints"])
        self.assertEqual(context["next_action"], "REVIEW_EVIDENCE")
        decision = evaluate_plan_compatibility(make_plan(), context)
        self.assertEqual(decision["reason_code"], REASON_CASE_ALREADY_SATISFIED)

    def test_satisfied_requirement_skips_even_with_other_open_work(self):
        case = case_fixture(
            available=("TECHNOLOGY_IDENTITY",),
            missing=("COMPONENT_BINDING",),
        )
        context = context_for(case, completion=False, kinds=("TECHNOLOGY_IDENTITY", "COMPONENT_BINDING"))
        self.assertEqual(context["next_action"], "CONTINUE_RESEARCH")
        plan = make_plan(targets=("ASSET_TECHNOLOGY",))
        decision = evaluate_plan_compatibility(plan, context)
        self.assertEqual(
            decision["reason_code"], REASON_REQUIREMENT_ALREADY_SATISFIED
        )

    def test_attempted_no_observation_skips(self):
        case = case_fixture(
            available=("TECHNOLOGY_IDENTITY",),
            missing=("COMPONENT_BINDING", "INPUT_SURFACE"),
        )
        ledger = ledger_for(
            case,
            kinds=("TECHNOLOGY_IDENTITY", "COMPONENT_BINDING", "INPUT_SURFACE"),
            evidence_completion=completion_fixture(
                accepted=("TECHNOLOGY_IDENTITY",),
                missing=("COMPONENT_BINDING",),
            ),
        )
        context = context_for(
            case, kinds=("TECHNOLOGY_IDENTITY", "COMPONENT_BINDING", "INPUT_SURFACE"), ledger=ledger
        )
        self.assertEqual(context["next_action"], "CONTINUE_RESEARCH")
        decision = evaluate_plan_compatibility(make_plan(), context)
        self.assertEqual(
            decision["reason_code"], REASON_ACQUISITION_EXHAUSTED
        )

    def test_offline_sources_exhausted_skips(self):
        context = context_for()
        self.assertTrue(context["offline_sources_exhausted"])
        decision = evaluate_plan_compatibility(
            make_plan(targets=("ASSET_COMPONENT", "ASSET_VERSION")), context
        )
        self.assertEqual(
            decision["reason_code"], REASON_ACQUISITION_EXHAUSTED
        )
        self.assertEqual(decision["next_action"], "PROVIDE_EVIDENCE")

    def test_human_action_never_selects_deterministic_plan(self):
        case = case_fixture(
            available=("TECHNOLOGY_IDENTITY",),
            missing=("WATCH_SIGNAL",),
            decision_state="READY_FOR_HUMAN_REVIEW",
            sufficiency="SUFFICIENT_FOR_REVIEW",
        )
        context = context_for(case, completion=False, kinds=("TECHNOLOGY_IDENTITY", "WATCH_SIGNAL"))
        self.assertEqual(context["next_action"], "HUMAN_REVIEW")
        decision = evaluate_plan_compatibility(
            make_plan(targets=("ASSET_TECHNOLOGY",)), context
        )
        self.assertEqual(
            decision["reason_code"], REASON_HUMAN_EVIDENCE_REQUIRED
        )

    def test_conflict_review_skips(self):
        case = case_fixture(
            available=("TECHNOLOGY_IDENTITY",),
            missing=("COMPONENT_BINDING",),
        )
        ledger = ledger_for(
            case,
            completion=False,
            kinds=("TECHNOLOGY_IDENTITY", "COMPONENT_BINDING"),
            evidence_provenance={
                "records": [
                    {
                        "requirement_kind": "COMPONENT_BINDING",
                        "evidence_refs": ["response:conflict-1"],
                        "conflict_state": "CONFLICTING",
                        "human_review_required": True,
                    }
                ]
            },
        )
        context = context_for(
            case,
            completion=False,
            kinds=("TECHNOLOGY_IDENTITY", "COMPONENT_BINDING"),
            ledger=ledger,
        )
        self.assertEqual(context["next_action"], "REVIEW_CONFLICT")
        decision = evaluate_plan_compatibility(make_plan(), context)
        self.assertEqual(
            decision["reason_code"], REASON_CONFLICT_REVIEW_REQUIRED
        )

    def test_already_attempted_unresolved_skips(self):
        case = case_fixture(
            available=("TECHNOLOGY_IDENTITY",),
            missing=("COMPONENT_BINDING", "INPUT_SURFACE"),
        )
        ledger = ledger_for(
            case,
            completion=False,
            kinds=("TECHNOLOGY_IDENTITY", "COMPONENT_BINDING", "INPUT_SURFACE"),
            evidence_acquisition={
                "attempts": [
                    {
                        "requirement_kind": "COMPONENT_BINDING",
                        "source": SOURCE_WATCH_DERIVED,
                        "outcome": OUTCOME_ACCEPTED,
                    }
                ]
            },
        )
        context = context_for(
            case,
            completion=False,
            kinds=("TECHNOLOGY_IDENTITY", "COMPONENT_BINDING", "INPUT_SURFACE"),
            ledger=ledger,
        )
        self.assertEqual(context["next_action"], "CONTINUE_RESEARCH")
        decision = evaluate_plan_compatibility(make_plan(), context)
        self.assertEqual(
            decision["reason_code"], REASON_PLAN_ALREADY_ATTEMPTED
        )

    def test_missing_or_malformed_context_fails_closed(self):
        for bad in (
            None,
            {},
            {"case_ref": CASE_ID},
            {"case_ref": CASE_ID, "case_status": "ACTIVE"},
        ):
            with self.subTest(bad=bad):
                decision = evaluate_plan_compatibility(make_plan(), bad)
                self.assertEqual(decision["decision"], DECISION_SKIP)
                self.assertEqual(
                    decision["reason_code"], REASON_MISSING_CASE_CONTEXT
                )

    def test_malformed_plan(self):
        context = context_for(completion=False)
        for bad in (None, {}, {"plan_id": ""}, {"plan_id": "r99-xyz"}):
            with self.subTest(bad=bad):
                decision = evaluate_plan_compatibility(bad, context)
                self.assertEqual(
                    decision["reason_code"], REASON_MALFORMED_PLAN
                )

    def test_unsafe_plan_never_selects(self):
        context = context_for(completion=False)
        plan = make_plan(execution_authorized=True)
        decision = evaluate_plan_compatibility(plan, context)
        self.assertEqual(decision["decision"], DECISION_SKIP)
        self.assertEqual(decision["reason_code"], REASON_UNSAFE_ACTION)
        self.assertFalse(decision["execution_authorized"])

    def test_irrelevant_plan_skips(self):
        context = context_for(completion=False)
        plan = make_plan(targets=("CVE_REFERENCE", "PUBLIC_POC"))
        self.assertEqual(plan_requirement_kinds(plan), [])
        decision = evaluate_plan_compatibility(plan, context)
        self.assertEqual(decision["reason_code"], REASON_PLAN_NOT_RELEVANT)

    def test_decisions_are_serializable_and_have_no_scores(self):
        context = context_for(completion=False)
        for decision in (
            evaluate_plan_compatibility(make_plan(), context),
            evaluate_plan_compatibility(
                make_plan(execution_authorized=True), context
            ),
        ):
            serialized = json.dumps(decision, sort_keys=True)
            self.assertNotIn("priority_score", serialized)
            self.assertNotIn('"score"', serialized)
            self.assertFalse(decision["execution_authorized"])
            self.assertEqual(
                decision["confirmation_state"], "NOT_CONFIRMED"
            )
            self.assertIn(decision["reason_code"], SCHEDULING_REASONS)


# ---------------------------------------------------------------------------
# case-aware selection
# ---------------------------------------------------------------------------


class TestCaseAwareSelection(unittest.TestCase):
    def test_no_redundant_acquisition_when_exhausted(self):
        context = context_for()
        plan = make_plan(targets=("ASSET_COMPONENT", "ASSET_VERSION"))
        selection = select_case_aware_plans([plan], [context])
        self.assertEqual(selection["eligible_plan_ids"], [])
        self.assertEqual(len(selection["decisions"]), 1)
        decision = selection["decisions"][0]
        self.assertEqual(
            decision["reason_code"], REASON_ACQUISITION_EXHAUSTED
        )
        attention = selection["case_attention"][0]
        self.assertFalse(attention["actionable"])
        self.assertEqual(
            attention["reason_code"], REASON_ACQUISITION_EXHAUSTED
        )
        self.assertEqual(attention["next_action"], "PROVIDE_EVIDENCE")
        self.assertTrue(attention["offline_sources_exhausted"])

    def test_open_requirement_selects(self):
        context = context_for(completion=False)
        plan = make_plan()
        selection = select_case_aware_plans([plan], [context])
        self.assertEqual(selection["eligible_plan_ids"], [PLAN_ID])
        decision = selection["decisions"][0]
        self.assertEqual(decision["decision"], DECISION_SELECT)
        self.assertEqual(decision["bound_by"], "SAME_PLAN")

    def test_same_cve_binding(self):
        context = context_for(completion=False)
        plan = make_plan(OTHER_PLAN_ID)
        selection = select_case_aware_plans([plan], [context])
        decision = selection["decisions"][0]
        self.assertEqual(decision["decision"], DECISION_SELECT)
        self.assertEqual(decision["bound_by"], "SAME_CVE")
        self.assertEqual(selection["eligible_plan_ids"], [OTHER_PLAN_ID])

    def test_unbound_plan_fails_closed(self):
        context = context_for(completion=False)
        plan = make_plan(OTHER_PLAN_ID, cve="CVE-2026-00001", program="other")
        selection = select_case_aware_plans([plan], [context])
        self.assertEqual(selection["eligible_plan_ids"], [])
        self.assertEqual(
            selection["decisions"][0]["reason_code"],
            REASON_MISSING_CASE_CONTEXT,
        )
        self.assertEqual(selection["summary"]["plans_unbound"], 1)

    def test_malformed_context_is_reported_not_selected(self):
        context = context_for(completion=False)
        selection = select_case_aware_plans(
            [make_plan()], [context, {"case_ref": ""}]
        )
        self.assertEqual(selection["summary"]["malformed_contexts"], 1)
        self.assertEqual(selection["malformed_contexts"][0]["artifact"], "")
        self.assertEqual(selection["eligible_plan_ids"], [PLAN_ID])

    def test_malformed_plan_is_reported(self):
        context = context_for(completion=False)
        selection = select_case_aware_plans(
            [make_plan(), {"plan_id": "bogus"}], [context]
        )
        codes = sorted(
            decision["reason_code"] for decision in selection["decisions"]
        )
        self.assertIn(REASON_MALFORMED_PLAN, codes)

    def test_multi_case_order_is_stable_and_not_scored(self):
        exhausted = context_for()
        open_case = case_fixture(case_id="case-aaa-a1-open")
        open_context = context_for(open_case, completion=False)
        stop_case = case_fixture(case_id="case-zzz-a1-stopped", status="STOPPED")
        stop_context = context_for(stop_case, completion=False)
        contexts = [stop_context, exhausted, open_context]
        first = select_case_aware_plans([make_plan()], contexts)
        second = select_case_aware_plans(
            [make_plan()], list(reversed(contexts))
        )
        self.assertEqual(first, second)
        order = [row["case_id"] for row in first["case_attention"]]
        # R91 action order: PROVIDE_EVIDENCE (0) before CONTINUE_RESEARCH (3)
        # before STOP (5).
        self.assertEqual(
            order,
            [
                "case-dell-a1-component-mapping",
                "case-aaa-a1-open",
                "case-zzz-a1-stopped",
            ],
        )
        self.assertEqual(
            [row["actionable"] for row in first["case_attention"]],
            [False, True, False],
        )
        serialized = json.dumps(first, sort_keys=True)
        self.assertNotIn("priority_score", serialized)
        self.assertNotIn('"score"', serialized)

    def test_deterministic_across_repeated_runs_and_input_order(self):
        context = context_for(completion=False)
        plans = [make_plan(), make_plan(OTHER_PLAN_ID)]
        first = select_case_aware_plans(plans, [context])
        second = select_case_aware_plans(list(reversed(plans)), [context])
        self.assertEqual(
            sorted(first["eligible_plan_ids"]), sorted(second["eligible_plan_ids"])
        )
        self.assertEqual(first, second)

    def test_decisions_are_bounded(self):
        context = context_for(completion=False)
        context["source_plan_ref"] = ""
        context["source_cve"] = ""
        plans = [make_plan(f"r22-{index:016x}") for index in range(300)]
        selection = select_case_aware_plans(plans, [context])
        self.assertEqual(selection["summary"]["decisions_total"], 300)
        self.assertEqual(len(selection["decisions"]), 256)
        self.assertTrue(selection["summary"]["decisions_truncated"])

    def test_no_case_context_means_no_selection(self):
        selection = select_case_aware_plans([make_plan()], [])
        self.assertEqual(selection["eligible_plan_ids"], [])
        self.assertEqual(selection["summary"]["contexts"], 0)
        self.assertEqual(
            selection["decisions"][0]["reason_code"],
            REASON_MISSING_CASE_CONTEXT,
        )


# ---------------------------------------------------------------------------
# scheduler integration
# ---------------------------------------------------------------------------


class TestSchedulerIntegration(unittest.TestCase):
    def test_config_defaults_and_env(self):
        self.assertFalse(SchedulerConfig.from_env({}).case_aware)
        self.assertTrue(
            SchedulerConfig.from_env(
                {"WATCH_RESEARCH_CASE_AWARE": "true"}
            ).case_aware
        )

    def test_default_mode_is_backward_compatible(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = make_plan()
            cfg = SchedulerConfig(
                enabled=True,
                window_start="00:00",
                window_end="23:59",
                lock_path=os.path.join(tmp, "l.lock"),
                agent_dir=tmp,
            )
            scheduler = ResearchScheduler(
                cfg, agent=ExplodingAgent(), plan_loader=lambda: [plan]
            )
            status = scheduler.status()
            self.assertNotIn("case_aware", status)
            self.assertNotIn("case_scheduling", status)
            self.assertEqual(status["eligible_plans"], select_plans([plan], 5))
            preview = scheduler.preview()
            self.assertNotIn("case_aware", preview)
            record = scheduler.run_once(dry_run=True)
            self.assertNotIn("case_aware", record)

    def test_case_aware_read_only_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = make_plan()
            context = context_for(completion=False)
            scheduler = scheduler_for(tmp, [plan], [context])
            scheduler.agent = ExplodingAgent()
            status = scheduler.status()
            self.assertTrue(status["case_aware"])
            scheduling = status["case_scheduling"]
            self.assertEqual(scheduling["summary"]["select_decisions"], 1)
            self.assertEqual(
                [p["plan_id"] for p in status["eligible_plans"]], [PLAN_ID]
            )
            preview = scheduler.preview()
            self.assertTrue(preview["case_aware"])
            self.assertEqual(
                [p["plan_id"] for p in preview["plans"]], [PLAN_ID]
            )

    def test_case_aware_run_uses_only_selected_plans(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            plans = [
                make_plan(),
                make_plan(OTHER_PLAN_ID, cve="CVE-2026-00002", program="other"),
            ]
            scheduler = scheduler_for(tmp, plans, [context])
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True)
            self.assertEqual(agent.seen_plan_ids, [PLAN_ID])
            self.assertEqual(record["plans_selected"], 1)
            self.assertTrue(record["case_aware"])
            self.assertIn("case_scheduling", record)
            self.assertEqual(
                record["case_scheduling"]["summary"]["select_decisions"], 1
            )

    def test_case_aware_run_blocked_when_nothing_eligible(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for()
            scheduler = scheduler_for(tmp, [make_plan()], [context])
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True)
            self.assertEqual(record["status"], RUN_STATUS_BLOCKED)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(agent.seen_plan_ids, [])

    def test_loader_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = SchedulerConfig(
                enabled=True,
                window_start="00:00",
                window_end="23:59",
                lock_path=os.path.join(tmp, "l.lock"),
                agent_dir=tmp,
            )

            def broken_loader():
                raise RuntimeError("boom")

            scheduler = ResearchScheduler(
                cfg,
                plan_loader=lambda: [make_plan()],
                case_context_loader=broken_loader,
                agent=RecordingAgent(),
            )
            record = scheduler.run_once(force=True)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(record["status"], RUN_STATUS_BLOCKED)

    def test_malformed_context_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            scheduler = scheduler_for(
                tmp, [make_plan()], [{"case_ref": ""}]
            )
            scheduler.agent = RecordingAgent()
            record = scheduler.run_once(force=True)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(
                record["case_scheduling"]["summary"]["malformed_contexts"], 1
            )

    def test_dry_run_writes_nothing_case_aware(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = scheduler_for(tmp, [make_plan()], [context])
            record = scheduler.run_once(dry_run=True)
            self.assertEqual(record["skipped"], "dry_run")
            self.assertEqual(record["plans_selected"], 1)
            self.assertFalse(os.path.exists(os.path.join(tmp, "runs")))

    def test_execution_gate_remains_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = scheduler_for(tmp, [make_plan()], [context])
            # No agent configured: the existing execution gate must still
            # block, proving scheduling never authorizes execution.
            record = scheduler.run_once(force=True)
            self.assertEqual(record["status"], "RESEARCH_FAILED")
            self.assertEqual(
                record["failures"][0]["error"], "no agent configured"
            )
            scheduling = json.dumps(
                record.get("case_scheduling") or {}, sort_keys=True
            )
            self.assertNotIn("execution_authorized", scheduling)
            self.assertNotIn("authorization", scheduling)

    def test_schedule_preview_case_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = scheduler_for(tmp, [make_plan()], [context])
            known = scheduler.schedule_preview(case_id=CASE_ID)
            self.assertTrue(known["case_known"])
            self.assertEqual(
                [p["plan_id"] for p in known["plans"]], [PLAN_ID]
            )
            unknown = scheduler.schedule_preview(case_id="case-nope")
            self.assertFalse(unknown["case_known"])
            self.assertEqual(unknown["plans"], [])

    def test_load_case_contexts_from_disk(self):
        from ai.research_agent.case_bridge import (
            activate_result,
            case_artifact_path,
        )
        from tests.test_research_case_evidence import (
            CASE_ID as BRIDGE_CASE_ID,
            loop_payload,
            plan_loader,
        )

        with tempfile.TemporaryDirectory() as tmp:
            cases = Path(tmp) / "cases"
            outcome = activate_result(
                loop_payload(), plan_loader=plan_loader, cases_dir=cases
            )
            self.assertEqual(outcome["status"], "ACTIVATED")
            artifact = case_artifact_path(BRIDGE_CASE_ID, cases)
            before = artifact.read_bytes()
            contexts = load_case_contexts(cases)
            self.assertEqual(len(contexts), 1)
            self.assertEqual(contexts[0]["case_ref"], BRIDGE_CASE_ID)
            self.assertEqual(contexts[0]["source_plan_ref"], "r22-" + "ab" * 8)
            self.assertEqual(contexts[0]["source_cve"], "CVE-2026-99999")
            self.assertEqual(artifact.read_bytes(), before)

    def test_load_case_contexts_marks_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text("{ not json", encoding="utf-8")
            contexts = load_case_contexts(tmp)
            self.assertEqual(len(contexts), 1)
            self.assertEqual(contexts[0]["case_ref"], "")
            selection = select_case_aware_plans([make_plan()], contexts)
            self.assertEqual(
                selection["summary"]["malformed_contexts"], 1
            )
            self.assertEqual(selection["eligible_plan_ids"], [])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCliSchedule(unittest.TestCase):
    def test_parser_parses_schedule(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        args = parser.parse_args(
            [
                "agent",
                "schedule",
                "--case",
                CASE_ID,
                "--plan",
                PLAN_ID,
                "--cases-dir",
                "/tmp/cases",
                "--limit",
                "3",
                "--json",
            ]
        )
        self.assertEqual(args.command, "agent")
        self.assertEqual(args.agent_command, "schedule")
        self.assertEqual(args.case, CASE_ID)
        self.assertEqual(args.plan, PLAN_ID)
        self.assertEqual(args.cases_dir, "/tmp/cases")
        self.assertEqual(args.limit, 3)
        self.assertTrue(args.json)

    def _artifact_root(self):
        from ai.research_agent.case_bridge import (
            activate_result,
            case_artifact_path,
        )
        from tests.test_research_case_evidence import (
            CASE_ID as BRIDGE_CASE_ID,
            loop_payload,
            plan_loader,
        )

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cases = Path(tmp.name) / "cases"
        outcome = activate_result(
            loop_payload(), plan_loader=plan_loader, cases_dir=cases
        )
        self.assertEqual(outcome["status"], "ACTIVATED")
        return cases, case_artifact_path(BRIDGE_CASE_ID, cases)

    def test_cli_schedule_is_read_only(self):
        from ai import research_cli

        cases, artifact = self._artifact_root()
        before = artifact.read_bytes()
        plan = {
            "plan_id": "r22-" + "ab" * 8,
            "cve_id": "CVE-2026-99999",
            "program": "dell",
            "status": "RESEARCH_PLAN_READY",
            "evidence_targets": [{"code": "ASSET_COMPONENT"}],
            "steps": [],
            "metadata": {"priority_level": "HIGH_RESEARCH"},
        }
        buffer = io.StringIO()
        with mock.patch(
            "ai.research_agent.scheduler._default_plan_loader",
            return_value=[plan],
        ), contextlib.redirect_stdout(buffer):
            code = research_cli.main(
                [
                    "agent",
                    "schedule",
                    "--cases-dir",
                    str(cases),
                    "--json",
                ]
            )
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertTrue(payload["case_aware"])
        self.assertEqual(payload["case_scheduling"]["summary"]["contexts"], 1)
        decision = payload["case_scheduling"]["decisions"][0]
        self.assertEqual(decision["plan_id"], plan["plan_id"])
        self.assertEqual(decision["decision"], DECISION_SELECT)
        self.assertEqual(artifact.read_bytes(), before)

    def test_cli_schedule_unknown_case(self):
        from ai import research_cli

        cases, _artifact = self._artifact_root()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = research_cli.main(
                [
                    "agent",
                    "schedule",
                    "--cases-dir",
                    str(cases),
                    "--case",
                    "case-does-not-exist",
                ]
            )
        self.assertEqual(code, 1)


# ---------------------------------------------------------------------------
# real production-derived fixture (read-only)
# ---------------------------------------------------------------------------


class TestRealCaseReadOnly(unittest.TestCase):
    def test_real_fixture_state_is_recognized_without_mutation(self):
        if not REAL_FIXTURE.is_file():
            self.skipTest("real read-only case fixture is not present")
        before = REAL_FIXTURE.read_bytes()
        artifact = json.loads(before.decode("utf-8"))
        case = artifact["research_case_workspace"]["cases"][0]
        ledger = build_case_acquisition_ledger(
            case,
            acquisition_plan=artifact.get("acquisition_plan"),
            readiness_plan=artifact.get("readiness_plan"),
            evidence_provenance=artifact.get("evidence_provenance"),
            evidence_completion=artifact.get("evidence_completion"),
            evidence_acquisition=artifact.get("evidence_acquisition"),
        )
        context = build_case_scheduling_context(
            case,
            acquisition_ledger=ledger,
            source_plan_ref="",
            source_cve="",
        )
        self.assertEqual(context["case_ref"], "case-indeed-a1-endpoint-behavior")
        self.assertEqual(context["case_status"], "WAITING_FOR_EVIDENCE")
        self.assertIn(context["next_action"], WORKFLOW_ACTIONS)
        # No plan can bind without a persisted result binding: fail closed.
        selection = select_case_aware_plans([make_plan()], [context])
        self.assertEqual(selection["eligible_plan_ids"], [])
        self.assertEqual(
            selection["decisions"][0]["reason_code"],
            REASON_MISSING_CASE_CONTEXT,
        )
        # A CVE-research plan bound to the case reviews no case requirement.
        bound = build_case_scheduling_context(
            case,
            acquisition_ledger=ledger,
            source_plan_ref=PLAN_ID,
            source_cve=CVE,
        )
        decision = evaluate_plan_compatibility(
            make_plan(targets=("CVE_REFERENCE",)), bound
        )
        self.assertEqual(decision["reason_code"], REASON_PLAN_NOT_RELEVANT)
        self.assertEqual(REAL_FIXTURE.read_bytes(), before)


# ---------------------------------------------------------------------------
# safety
# ---------------------------------------------------------------------------


class TestSafety(unittest.TestCase):
    def _source(self, module_name):
        module = __import__(module_name, fromlist=["x"])
        return inspect.getsource(module)

    def test_no_io_or_execution_primitives(self):
        source = self._source("ai.research_agent.case_scheduling")
        for forbidden in (
            "import socket",
            "import subprocess",
            "import requests",
            "import urllib",
            "from openai",
            "import openai",
            "MongoClient",
            "write_text(",
            "os.system",
            "Popen",
            "import datetime",
            "import random",
            "time.time",
        ):
            self.assertNotIn(forbidden, source, forbidden)

    def test_no_llm_dependency(self):
        source = self._source("ai.research_agent.case_scheduling")
        for forbidden in (
            "from ai.llm",
            "import ai.llm",
            "from ai.researcher",
            "import ai.researcher",
            "generate(",
        ):
            self.assertNotIn(forbidden, source, forbidden)

    def test_reason_codes_are_closed(self):
        self.assertEqual(
            len(set(SCHEDULING_REASONS)), len(SCHEDULING_REASONS)
        )
        for code in (
            REASON_ACQUISITION_EXHAUSTED,
            REASON_HUMAN_EVIDENCE_REQUIRED,
            REASON_CONFLICT_REVIEW_REQUIRED,
        ):
            self.assertIn(code, SCHEDULING_REASONS)

    def test_selected_plan_does_not_imply_confirmation(self):
        context = context_for(completion=False)
        plan = make_plan()
        selection = select_case_aware_plans([plan], [context])
        self.assertEqual(selection["confirmation_state"], "NOT_CONFIRMED")
        decision = selection["decisions"][0]
        self.assertEqual(decision["decision"], DECISION_SELECT)
        self.assertEqual(decision["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(decision["execution_authorized"])

    def test_case_status_bypass_is_not_possible(self):
        context = context_for(completion=False)
        # Even a plan that binds perfectly is skipped when the case is stopped.
        case = case_fixture(status="STOPPED")
        stopped = context_for(case, completion=False)
        decision = evaluate_plan_compatibility(make_plan(), stopped)
        self.assertEqual(decision["decision"], DECISION_SKIP)
        self.assertEqual(decision["reason_code"], REASON_CASE_STOPPED)
        self.assertNotEqual(decision["decision"], DECISION_SELECT)

    def test_ledger_bypass_is_not_possible(self):
        # A hand-crafted ledger claiming CONTINUE_RESEARCH while all
        # requirements are exhausted cannot force a selection, because the
        # requirement statuses themselves are consumed.
        case = case_fixture()
        ledger = ledger_for(case)
        ledger["next_action"] = "CONTINUE_RESEARCH"
        context = build_case_scheduling_context(
            case, acquisition_ledger=ledger
        )
        decision = evaluate_plan_compatibility(make_plan(), context)
        self.assertEqual(
            decision["reason_code"], REASON_ACQUISITION_EXHAUSTED
        )


if __name__ == "__main__":
    unittest.main()
