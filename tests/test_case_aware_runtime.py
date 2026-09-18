"""Stage R93 — controlled case-aware runtime activation tests.

Covers the runtime activation of the R92 case-aware scheduler:

- explicit, inspectable activation states (``CASE_AWARE_DISABLED`` /
  ``CASE_AWARE_ENABLED`` / ``CASE_AWARE_ERROR``);
- the controlled in-process case-context loader (persisted artifacts + R91
  ledger + R92 context only; no network, no Mongo, no LLM, no writes);
- the real ``run_once`` portfolio behavior (actionable / exhausted /
  human-required / stopped / malformed / mixed);
- fail-closed semantics (a case-aware error can NEVER fall back to ordinary
  unfiltered scheduling);
- execution-gate separation (``agent=None``, dry-run, disabled scheduler,
  time window, lock) and the bounded run-record projection;
- idempotency and no artifact mutation;
- observability through the existing activity projection and CLI surfaces;
- adversarial inputs (forged next action/status, duplicates, shuffled
  ordering, malformed/stale artifacts).

Matrix mapping (STEP 17): A disabled; B context loaded; C actionable select;
D exhausted; E human-required; F stopped; G malformed; H missing directory;
I contradictory; J invalid plan; K unsafe marker; L select != authorization;
M agent=None; N dry-run; O scheduler disabled; P window; Q lock;
R deterministic; S no artifact mutation; T no attempt mutation;
U no evidence fabrication; V no confirmation escalation; W no LLM; X no
network; Y no Mongo; Z run-record projection; AA legacy record; AB preview
read-only; AC mixed portfolio; AD all exhausted; AE all human-required;
AF error no-fallback.

No network, no LLM, no Mongo, no subprocess, no live targets.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from ai.knowledge.ai_activity_status import build_activity_status
from ai.knowledge.research_acquisition_ledger import (
    build_case_acquisition_ledger,
)
from ai.research_agent.case_scheduling import (
    CASE_SCHEDULING_ERROR_CODES,
    CONSTRAINT_CASE_STOPPED,
    REASON_ACQUISITION_EXHAUSTED,
    REASON_CASE_STOPPED,
    REASON_HUMAN_EVIDENCE_REQUIRED,
    REASON_MALFORMED_PLAN,
    REASON_MISSING_CASE_CONTEXT,
    REASON_UNSAFE_ACTION,
    build_case_scheduling_context,
)
from ai.research_agent.scheduler import (
    CASE_AWARE_DISABLED,
    CASE_AWARE_ENABLED,
    CASE_AWARE_ERROR,
    CASE_AWARE_STATES,
    CASE_CONTEXT_ALL_MALFORMED,
    CASE_CONTEXT_DIRECTORY_MISSING,
    CASE_CONTEXT_LOADER_FAILED,
    CASE_CONTEXT_OK,
    RUN_STATUS_BLOCKED,
    RUN_STATUS_FAILED,
    ResearchScheduler,
    SchedulerConfig,
    acquire_lock,
    load_case_contexts,
    select_plans,
)
from tests.test_case_aware_scheduling import (
    ALL_KINDS,
    CVE,
    OTHER_PLAN_ID,
    PLAN_ID,
    ExplodingAgent,
    RecordingAgent,
    case_fixture,
    completion_fixture,
    context_for,
    make_plan,
    readiness_fixture,
    scheduler_for,
)

PLAN_A = "r22-" + "a1" * 8
PLAN_B = "r22-" + "b2" * 8
PLAN_C = "r22-" + "c3" * 8
PLAN_D = "r22-" + "d4" * 8
CVE_A = "CVE-2026-10001"
CVE_B = "CVE-2026-10002"
CVE_C = "CVE-2026-10003"
CVE_D = "CVE-2026-10004"
TEHRAN = ZoneInfo("Asia/Tehran")
FIXED_NOW = datetime(2026, 9, 18, 13, 0, tzinfo=TEHRAN)


def runtime_scheduler(tmp, plans, *, contexts=None, **cfg_kwargs):
    """Case-aware runtime scheduler over a temporary local directory."""

    cfg_kwargs.setdefault("case_aware", True)
    cfg_kwargs.setdefault("research_dir", tmp)
    return scheduler_for(tmp, plans, contexts, **cfg_kwargs)


def human_context(*, case_id="case-runtime-human"):
    return context_for(
        case_fixture(
            case_id=case_id,
            available=("TECHNOLOGY_IDENTITY",),
            missing=("WATCH_SIGNAL",),
            decision_state="READY_FOR_HUMAN_REVIEW",
            sufficiency="SUFFICIENT_FOR_REVIEW",
        ),
        completion=False,
        kinds=("TECHNOLOGY_IDENTITY", "WATCH_SIGNAL"),
    )


def case_artifact(case, plan_id, cve, *, completion=None, kinds=None):
    """Persisted case artifact shape consumed by ``load_case_contexts``."""

    artifact = {
        "research_case_workspace": {"cases": [case]},
        "readiness_plan": readiness_fixture(kinds or ALL_KINDS),
        "result": {"plan_id": plan_id, "cve_id": cve},
    }
    if completion is not None:
        artifact["evidence_completion"] = completion
    return artifact


def write_runtime_portfolio(cases_dir: Path) -> dict[str, bytes]:
    """On-disk portfolio: A actionable, B exhausted, C human, D stopped,
    E malformed. Returns the original artifact bytes by filename."""

    cases_dir.mkdir(parents=True, exist_ok=True)
    payloads: dict[str, object] = {
        "case-runtime-a.json": case_artifact(
            case_fixture(case_id="case-runtime-a"), PLAN_A, CVE_A
        ),
        "case-runtime-b.json": case_artifact(
            case_fixture(case_id="case-runtime-b"),
            PLAN_B,
            CVE_B,
            completion=completion_fixture(),
        ),
        "case-runtime-c.json": case_artifact(
            case_fixture(
                case_id="case-runtime-c",
                available=("TECHNOLOGY_IDENTITY",),
                missing=("WATCH_SIGNAL",),
                decision_state="READY_FOR_HUMAN_REVIEW",
                sufficiency="SUFFICIENT_FOR_REVIEW",
            ),
            PLAN_C,
            CVE_C,
            kinds=("TECHNOLOGY_IDENTITY", "WATCH_SIGNAL"),
        ),
        "case-runtime-d.json": case_artifact(
            case_fixture(case_id="case-runtime-d", status="STOPPED"),
            PLAN_D,
            CVE_D,
        ),
        "case-runtime-e.json": "{ not json",
    }
    originals: dict[str, bytes] = {}
    for name, payload in payloads.items():
        path = cases_dir / name
        text = (
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
            if isinstance(payload, dict)
            else payload
        )
        path.write_text(text, encoding="utf-8")
        originals[name] = path.read_bytes()
    return originals


def portfolio_plans():
    return [
        make_plan(PLAN_A, cve=CVE_A),
        make_plan(PLAN_B, cve=CVE_B),
        make_plan(PLAN_C, cve=CVE_C),
        make_plan(PLAN_D, cve=CVE_D),
    ]


def reason_counts(record: dict) -> dict:
    return (record.get("case_scheduling") or {}).get("reason_counts") or {}


# ---------------------------------------------------------------------------
# STEP 2 — activation states
# ---------------------------------------------------------------------------


class TestActivationState(unittest.TestCase):
    def test_state_vocabulary_is_closed(self):
        self.assertEqual(
            CASE_AWARE_STATES,
            (CASE_AWARE_DISABLED, CASE_AWARE_ENABLED, CASE_AWARE_ERROR),
        )
        self.assertEqual(CASE_CONTEXT_OK, "")

    def test_env_flag_is_the_single_activation_boundary(self):
        self.assertFalse(SchedulerConfig.from_env({}).case_aware)
        self.assertTrue(
            SchedulerConfig.from_env(
                {"WATCH_RESEARCH_CASE_AWARE": "true"}
            ).case_aware
        )

    def test_disabled_runtime_reports_disabled_everywhere(self):  # A
        with tempfile.TemporaryDirectory() as tmp:
            scheduler = runtime_scheduler(
                tmp, [make_plan()], case_aware=False
            )
            self.assertEqual(
                scheduler.status()["case_aware_state"], CASE_AWARE_DISABLED
            )
            self.assertEqual(
                scheduler.preview()["case_aware_state"], CASE_AWARE_DISABLED
            )
            record = scheduler.run_once(dry_run=True, now=FIXED_NOW)
            self.assertEqual(
                record["case_aware_state"], CASE_AWARE_DISABLED
            )
            self.assertNotIn("case_aware", record)

    def test_enabled_runtime_reports_enabled(self):  # B
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[context]
            )
            status = scheduler.status()
            self.assertEqual(
                status["case_aware_state"], CASE_AWARE_ENABLED
            )
            self.assertEqual(
                status["case_context"],
                {"artifacts": 1, "valid": 1, "malformed": 0, "error": ""},
            )
            record = scheduler.run_once(dry_run=True, now=FIXED_NOW)
            self.assertEqual(
                record["case_aware_state"], CASE_AWARE_ENABLED
            )

    def test_error_runtime_reports_error_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = SchedulerConfig(
                enabled=True,
                window_start="00:00",
                window_end="23:59",
                lock_path=os.path.join(tmp, "l.lock"),
                agent_dir=tmp,
                research_dir=tmp,
                case_aware=True,
            )

            def broken_loader():
                raise RuntimeError("boom")

            scheduler = ResearchScheduler(
                cfg,
                plan_loader=lambda: [make_plan()],
                case_context_loader=broken_loader,
            )
            status = scheduler.status()
            self.assertEqual(status["case_aware_state"], CASE_AWARE_ERROR)
            self.assertEqual(
                status["case_context"]["error"], CASE_CONTEXT_LOADER_FAILED
            )


# ---------------------------------------------------------------------------
# STEP 5 — portfolio scenarios
# ---------------------------------------------------------------------------


class TestPortfolioScenarios(unittest.TestCase):
    def test_no_cases_enabled_fails_closed(self):  # B
        with tempfile.TemporaryDirectory() as tmp:
            scheduler = runtime_scheduler(tmp, [make_plan()], contexts=[])
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(
                record["case_aware_state"], CASE_AWARE_ENABLED
            )
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(record["status"], RUN_STATUS_BLOCKED)
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertEqual(
                record["case_context"]["valid"], 0
            )
            self.assertIn(
                REASON_MISSING_CASE_CONTEXT, reason_counts(record)
            )

    def test_all_cases_stopped_filters_plans(self):  # D / F
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(
                case_fixture(status="STOPPED"), completion=False
            )
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[context]
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertEqual(
                reason_counts(record).get(REASON_CASE_STOPPED), 1
            )

    def test_all_cases_human_required_filters_plans(self):  # E / AE
        with tempfile.TemporaryDirectory() as tmp:
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[human_context()]
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertEqual(
                reason_counts(record).get(REASON_HUMAN_EVIDENCE_REQUIRED), 1
            )
            attention = record["case_scheduling"]["case_attention"]
            self.assertTrue(attention[0]["human_action_required"])

    def test_all_cases_exhausted_filters_plans(self):  # AD
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for()  # PROVIDE_EVIDENCE / offline exhausted
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[context]
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertEqual(
                reason_counts(record).get(REASON_ACQUISITION_EXHAUSTED), 1
            )
            attention = record["case_scheduling"]["case_attention"]
            self.assertTrue(attention[0]["offline_sources_exhausted"])
            self.assertFalse(attention[0]["actionable"])

    def test_actionable_case_reaches_r23_and_agent(self):  # C
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            plans = [
                make_plan(),
                make_plan(OTHER_PLAN_ID, cve="CVE-2026-00002", program="other"),
            ]
            scheduler = runtime_scheduler(tmp, plans, contexts=[context])
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["plans_selected"], 1)
            self.assertEqual(agent.seen_plan_ids, [PLAN_ID])
            self.assertEqual(record["status"], "RESEARCH_COMPLETED")
            self.assertEqual(
                record["case_scheduling"]["eligible_plan_ids"], [PLAN_ID]
            )
            self.assertEqual(
                record["case_scheduling"]["cap"],
                scheduler.config.max_plans,
            )

    def test_mixed_valid_and_invalid_portfolio_fails_safely(self):  # AC
        with tempfile.TemporaryDirectory() as tmp:
            contexts = [context_for(completion=False), {"case_ref": ""}]
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=contexts
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(
                record["case_aware_state"], CASE_AWARE_ENABLED
            )
            self.assertEqual(
                record["case_context"],
                {"artifacts": 2, "valid": 1, "malformed": 1, "error": ""},
            )
            self.assertEqual(agent.seen_plan_ids, [PLAN_ID])


# ---------------------------------------------------------------------------
# STEP 3 / 14 — fail closed
# ---------------------------------------------------------------------------


class TestFailClosed(unittest.TestCase):
    def test_loader_failure_cannot_fall_back_to_unfiltered(self):  # G / AF
        with tempfile.TemporaryDirectory() as tmp:
            cfg = SchedulerConfig(
                enabled=True,
                window_start="00:00",
                window_end="23:59",
                lock_path=os.path.join(tmp, "l.lock"),
                agent_dir=tmp,
                research_dir=tmp,
                case_aware=True,
            )

            def broken_loader():
                raise RuntimeError("boom")

            scheduler = ResearchScheduler(
                cfg,
                plan_loader=lambda: [make_plan()],
                case_context_loader=broken_loader,
                agent=ExplodingAgent(),
            )
            status = scheduler.status()
            self.assertEqual(status["case_aware_state"], CASE_AWARE_ERROR)
            self.assertEqual(status["eligible_count"], 0)
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(record["status"], RUN_STATUS_BLOCKED)
            self.assertEqual(
                record["case_context"]["error"], CASE_CONTEXT_LOADER_FAILED
            )

    def test_non_list_loader_result_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            scheduler = runtime_scheduler(tmp, [make_plan()], contexts=[])
            scheduler.case_context_loader = lambda: {"not": "a list"}
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(
                record["case_context"]["error"], CASE_CONTEXT_LOADER_FAILED
            )

    def test_missing_cases_directory_fails_closed(self):  # H
        with tempfile.TemporaryDirectory() as tmp:
            scheduler = runtime_scheduler(tmp, [make_plan()], contexts=None)
            status = scheduler.status()
            self.assertEqual(status["case_aware_state"], CASE_AWARE_ERROR)
            self.assertEqual(
                status["case_context"]["error"],
                CASE_CONTEXT_DIRECTORY_MISSING,
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(agent.seen_plan_ids, [])

    def test_empty_cases_directory_fails_closed_without_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "cases").mkdir()
            scheduler = runtime_scheduler(tmp, [make_plan()], contexts=None)
            status = scheduler.status()
            self.assertEqual(
                status["case_aware_state"], CASE_AWARE_ENABLED
            )
            self.assertEqual(status["case_context"]["valid"], 0)
            self.assertEqual(status["eligible_count"], 0)

    def test_malformed_artifacts_only_is_error_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            cases = Path(tmp) / "cases"
            cases.mkdir()
            (cases / "broken.json").write_text("{ not json", encoding="utf-8")
            scheduler = runtime_scheduler(tmp, [make_plan()], contexts=None)
            status = scheduler.status()
            self.assertEqual(status["case_aware_state"], CASE_AWARE_ERROR)
            self.assertEqual(
                status["case_context"]["error"], CASE_CONTEXT_ALL_MALFORMED
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertEqual(record["plans_selected"], 0)

    def test_unknown_case_status_on_disk_marks_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cases = Path(tmp) / "cases"
            cases.mkdir()
            unknown = case_fixture(case_id="case-runtime-unknown")
            unknown["status"] = "IMAGINARY"
            (cases / "case-unknown.json").write_text(
                json.dumps(case_artifact(unknown, PLAN_A, CVE_A)),
                encoding="utf-8",
            )
            scheduler = runtime_scheduler(tmp, [make_plan()], contexts=None)
            status = scheduler.status()
            self.assertEqual(status["case_aware_state"], CASE_AWARE_ERROR)
            self.assertEqual(
                status["case_context"]["error"], CASE_CONTEXT_ALL_MALFORMED
            )

    def test_contradictory_ledger_raises_in_context_builder(self):  # I
        case = case_fixture()
        ledger = build_case_acquisition_ledger(
            case, readiness_plan=readiness_fixture(ALL_KINDS)
        )
        ledger["case_id"] = "case-other"
        with self.assertRaises(Exception) as ctx:
            build_case_scheduling_context(case, acquisition_ledger=ledger)
        self.assertEqual(ctx.exception.code, "CONTRADICTORY_CASE_CONTEXT")
        self.assertIn(
            "CONTRADICTORY_CASE_CONTEXT", CASE_SCHEDULING_ERROR_CODES
        )

    def test_forged_next_action_raw_context_is_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            forged = dict(context_for(completion=False))
            forged["next_action"] = "DO_SOMETHING"
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[forged]
            )
            status = scheduler.status()
            self.assertEqual(status["case_aware_state"], CASE_AWARE_ERROR)
            self.assertEqual(
                status["case_context"]["error"], CASE_CONTEXT_ALL_MALFORMED
            )

    def test_forged_case_status_raw_context_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            forged = dict(context_for(completion=False))
            forged["case_status"] = "IMAGINARY"
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[forged]
            )
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(
                record["case_aware_state"], CASE_AWARE_ERROR
            )

    def test_invalid_plan_is_malformed_and_never_runs(self):  # J
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            plans = [
                {"plan_id": ""},
                {"plan_id": "r99-xyz", "cve_id": CVE},
            ]
            scheduler = runtime_scheduler(tmp, plans, contexts=[context])
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(
                reason_counts(record).get(REASON_MALFORMED_PLAN), 2
            )

    def test_unsafe_plan_execution_marker_is_rejected(self):  # K
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            plan = make_plan(execution_authorized=True)
            scheduler = runtime_scheduler(tmp, [plan], contexts=[context])
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertEqual(
                reason_counts(record).get(REASON_UNSAFE_ACTION), 1
            )

    def test_unbound_plan_is_missing_case_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            plan = make_plan(
                OTHER_PLAN_ID, cve="CVE-2026-00003", program="other"
            )
            scheduler = runtime_scheduler(tmp, [plan], contexts=[context])
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(
                reason_counts(record).get(REASON_MISSING_CASE_CONTEXT), 1
            )


# ---------------------------------------------------------------------------
# STEP 8 — execution authorization separation
# ---------------------------------------------------------------------------


class TestExecutionGates(unittest.TestCase):
    def _actionable(self, tmp):
        context = context_for(completion=False)
        return runtime_scheduler(tmp, [make_plan()], contexts=[context])

    def test_selected_plan_does_not_imply_authorization(self):  # L / M
        with tempfile.TemporaryDirectory() as tmp:
            scheduler = self._actionable(tmp)
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["plans_selected"], 1)
            self.assertEqual(record["status"], RUN_STATUS_FAILED)
            self.assertEqual(
                record["failures"][0]["error"], "no agent configured"
            )
            gate = record["execution_gate"]
            self.assertTrue(gate["lock_acquired"])
            self.assertFalse(gate["agent_configured"])
            self.assertFalse(gate["executed"])
            serialized = json.dumps(record, sort_keys=True)
            self.assertNotIn('"AUTHORIZED"', serialized)
            self.assertNotIn('"CONFIRMED"', serialized)

    def test_dry_run_plans_but_never_executes_or_writes(self):  # N
        with tempfile.TemporaryDirectory() as tmp:
            scheduler = self._actionable(tmp)
            scheduler.agent = ExplodingAgent()
            record = scheduler.run_once(dry_run=True, now=FIXED_NOW)
            self.assertEqual(record["skipped"], "dry_run")
            self.assertEqual(record["plans_selected"], 1)
            self.assertEqual(record["plans_processed"], 0)
            self.assertFalse(record["execution_gate"]["executed"])
            self.assertTrue(record["execution_gate"]["dry_run"])
            self.assertFalse(os.path.exists(os.path.join(tmp, "runs")))

    def test_disabled_scheduler_blocks_before_selection(self):  # O
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = runtime_scheduler(
                tmp,
                [make_plan()],
                contexts=[context],
                enabled=False,
            )
            scheduler.agent = RecordingAgent()
            record = scheduler.run_once(now=FIXED_NOW)
            self.assertEqual(record["skipped"], "disabled")
            self.assertEqual(record["plans_selected"], 0)
            self.assertFalse(record["execution_gate"]["scheduler_enabled"])
            self.assertFalse(record["execution_gate"]["lock_acquired"])

    def test_outside_window_blocks_before_selection(self):  # P
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = runtime_scheduler(
                tmp,
                [make_plan()],
                contexts=[context],
                window_start="00:00",
                window_end="00:01",
            )
            scheduler.agent = RecordingAgent()
            record = scheduler.run_once(now=FIXED_NOW)
            self.assertEqual(record["skipped"], "outside_window")
            self.assertEqual(record["plans_selected"], 0)
            self.assertFalse(record["execution_gate"]["in_window"])

    def test_lock_unavailable_blocks_execution(self):  # Q
        with tempfile.TemporaryDirectory() as tmp:
            scheduler = self._actionable(tmp)
            scheduler.agent = RecordingAgent()
            with acquire_lock(scheduler.config.lock_path) as locked:
                self.assertTrue(locked)
                record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["skipped"], "locked")
            self.assertEqual(record["plans_selected"], 0)
            self.assertFalse(record["execution_gate"]["lock_acquired"])


# ---------------------------------------------------------------------------
# STEP 6 / 9 — run-record + activity observability
# ---------------------------------------------------------------------------


class TestRunRecordProjection(unittest.TestCase):
    def test_case_aware_run_record_is_bounded_and_complete(self):  # Z
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[context]
            )
            scheduler.agent = RecordingAgent()
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(
                record["case_aware_state"], CASE_AWARE_ENABLED
            )
            self.assertEqual(
                record["case_context"],
                {"artifacts": 1, "valid": 1, "malformed": 0, "error": ""},
            )
            scheduling = record["case_scheduling"]
            self.assertEqual(scheduling["cap"], scheduler.config.max_plans)
            summary = scheduling["summary"]
            self.assertEqual(summary["contexts"], 1)
            self.assertEqual(summary["plans"], 1)
            self.assertEqual(summary["plans_eligible"], 1)
            self.assertEqual(summary["select_decisions"], 1)
            self.assertEqual(summary["confirmation_state"], "NOT_CONFIRMED")
            self.assertEqual(scheduling["rule_version"], "r92-1")
            self.assertTrue(scheduling["case_attention"])
            self.assertTrue(record["execution_gate"]["executed"])
            serialized = json.dumps(record, sort_keys=True)
            self.assertNotIn("evidence_refs", serialized)
            self.assertNotIn("attempts", serialized)
            self.assertNotIn("API_KEY", serialized)

    def test_default_record_remains_backward_compatible(self):  # AA
        with tempfile.TemporaryDirectory() as tmp:
            plan = make_plan()
            scheduler = runtime_scheduler(
                tmp, [plan], contexts=None, case_aware=False
            )
            scheduler.agent = RecordingAgent()
            record = scheduler.run_once(dry_run=True, now=FIXED_NOW)
            self.assertNotIn("case_aware", record)
            self.assertNotIn("case_scheduling", record)
            self.assertNotIn("case_context", record)
            self.assertEqual(
                record["case_aware_state"], CASE_AWARE_DISABLED
            )
            self.assertEqual(select_plans([plan], 5), [plan])
            self.assertEqual(record["plans_selected"], 1)
            self.assertIn("execution_gate", record)

    def test_activity_projection_surfaces_case_awareness(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[context]
            )
            scheduler.agent = RecordingAgent()
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            activity = build_activity_status(
                run_records=[record],
                case_records=[],
                lock_state="free",
                scheduler_enabled=True,
            )
            last_run = activity["last_run"]
            self.assertEqual(
                last_run["case_aware_state"], CASE_AWARE_ENABLED
            )
            self.assertEqual(last_run["case_contexts"], 1)
            self.assertEqual(last_run["case_malformed_contexts"], 0)
            self.assertEqual(last_run["case_eligible_plans"], 1)
            self.assertEqual(last_run["case_context_error"], "")

    def test_activity_projection_tolerates_legacy_records(self):
        activity = build_activity_status(
            run_records=[
                {
                    "run_id": "run-legacy",
                    "started_at": FIXED_NOW.isoformat(),
                    "completed_at": FIXED_NOW.isoformat(),
                    "status": "RESEARCH_COMPLETED",
                    "plans_selected": 1,
                    "plans_processed": 1,
                    "results": [],
                    "failures": [],
                }
            ],
            case_records=[],
            lock_state="free",
            scheduler_enabled=True,
        )
        last_run = activity["last_run"]
        self.assertEqual(last_run["case_aware_state"], "")
        self.assertEqual(last_run["case_contexts"], 0)
        self.assertEqual(last_run["case_eligible_plans"], 0)
        self.assertEqual(last_run["case_top_reason"], "")


# ---------------------------------------------------------------------------
# STEP 15 — idempotency / no mutation
# ---------------------------------------------------------------------------


class TestIdempotency(unittest.TestCase):
    def test_repeated_read_only_evaluation_is_deterministic(self):  # R / AB
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = runtime_scheduler(
                tmp, portfolio_plans(), contexts=[context]
            )
            first = scheduler.status(now=FIXED_NOW)
            second = scheduler.status(now=FIXED_NOW)
            self.assertEqual(first, second)
            one = scheduler.preview(now=FIXED_NOW)
            two = scheduler.preview(now=FIXED_NOW)
            self.assertEqual(one, two)

    def test_repeated_dry_run_record_is_equal(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[context]
            )
            first = scheduler.run_once(dry_run=True, now=FIXED_NOW)
            second = scheduler.run_once(dry_run=True, now=FIXED_NOW)
            self.assertEqual(first, second)

    def test_no_case_or_attempt_mutation_and_no_writes_on_preview(  # S / T
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            cases = Path(tmp) / "cases"
            originals = write_runtime_portfolio(cases)
            scheduler = runtime_scheduler(
                tmp, portfolio_plans(), contexts=None
            )
            scheduler.status(now=FIXED_NOW)
            scheduler.preview(now=FIXED_NOW)
            scheduler.schedule_preview()
            scheduler.run_once(dry_run=True, now=FIXED_NOW)
            for name, before in originals.items():
                self.assertEqual((cases / name).read_bytes(), before)
            self.assertFalse(os.path.exists(os.path.join(tmp, "runs")))

    def test_no_duplicate_execution_for_duplicate_contexts(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[context, dict(context)]
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(agent.seen_plan_ids, [PLAN_ID])
            self.assertEqual(record["case_context"]["valid"], 1)


# ---------------------------------------------------------------------------
# STEP 17 — adversarial
# ---------------------------------------------------------------------------


class TestAdversarial(unittest.TestCase):
    def test_forged_continue_research_cannot_authorize(self):
        with tempfile.TemporaryDirectory() as tmp:
            exhausted = context_for()  # PROVIDE_EVIDENCE, ATTEMPTED_NO_OBSERVATION
            forged = dict(exhausted)
            forged["next_action"] = "CONTINUE_RESEARCH"
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[forged]
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertEqual(
                reason_counts(record).get(REASON_ACQUISITION_EXHAUSTED), 1
            )

    def test_forged_case_status_cannot_bypass_next_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            stopped = context_for(
                case_fixture(status="STOPPED"), completion=False
            )
            forged = dict(stopped)
            forged["case_status"] = "ACTIVE"
            self.assertIn(
                CONSTRAINT_CASE_STOPPED, forged["scheduling_constraints"]
            )
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[forged]
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertEqual(
                reason_counts(record).get(REASON_CASE_STOPPED), 1
            )

    def test_shuffled_inputs_produce_same_eligible_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            contexts_a = [context_for(completion=False), human_context()]
            plans = [make_plan(), make_plan(OTHER_PLAN_ID, cve="CVE-2026-00004")]
            forward = runtime_scheduler(tmp, plans, contexts=contexts_a)
            reverse = runtime_scheduler(
                tmp, list(reversed(plans)), contexts=list(reversed(contexts_a))
            )
            first = forward.status(now=FIXED_NOW)
            second = reverse.status(now=FIXED_NOW)
            self.assertEqual(
                first["case_scheduling"]["eligible_plan_ids"],
                second["case_scheduling"]["eligible_plan_ids"],
            )

    def test_no_llm_network_mongo_dependency_in_scheduler(self):  # W / X / Y
        source = (
            Path(__file__).resolve().parents[1]
            / "ai"
            / "research_agent"
            / "scheduler.py"
        ).read_text(encoding="utf-8").lower()
        for token in (
            "import requests",
            "import httpx",
            "import urllib",
            "import socket",
            "import pymongo",
            "openai",
            "anthropic",
            "subprocess",
        ):
            self.assertNotIn(token, source)

    def test_confirmation_never_escalates(self):  # U / V
        with tempfile.TemporaryDirectory() as tmp:
            context = context_for(completion=False)
            scheduler = runtime_scheduler(
                tmp, [make_plan()], contexts=[context]
            )
            scheduler.agent = RecordingAgent()
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(
                record["case_scheduling"]["summary"]["confirmation_state"],
                "NOT_CONFIRMED",
            )
            self.assertTrue(
                record["case_scheduling"]["summary"]["advisory"]
            )
            serialized = json.dumps(record, sort_keys=True).upper()
            self.assertNotIn('"AUTHORIZED"', serialized)
            self.assertNotIn('"CONFIRMED"', serialized)


# ---------------------------------------------------------------------------
# STEP 16 — realistic on-disk runtime fixture
# ---------------------------------------------------------------------------


class TestOnDiskRuntimeFixture(unittest.TestCase):
    def test_runtime_selects_only_the_actionable_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            cases = Path(tmp) / "cases"
            originals = write_runtime_portfolio(cases)
            scheduler = runtime_scheduler(
                tmp, portfolio_plans(), contexts=None
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)

            self.assertEqual(record["case_aware_state"], CASE_AWARE_ENABLED)
            self.assertEqual(
                record["case_context"],
                {"artifacts": 5, "valid": 4, "malformed": 1, "error": ""},
            )
            self.assertEqual(agent.seen_plan_ids, [PLAN_A])
            self.assertEqual(record["plans_selected"], 1)
            counts = reason_counts(record)
            self.assertEqual(counts.get(REASON_ACQUISITION_EXHAUSTED), 1)
            self.assertEqual(
                counts.get(REASON_HUMAN_EVIDENCE_REQUIRED), 1
            )
            self.assertEqual(counts.get(REASON_CASE_STOPPED), 1)

            for name, before in originals.items():
                self.assertEqual((cases / name).read_bytes(), before)

            stored = list((Path(tmp) / "runs").glob("*.json"))
            self.assertEqual(len(stored), 1)
            payload = json.loads(stored[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["case_aware_state"], CASE_AWARE_ENABLED)
            self.assertNotIn("evidence_refs", json.dumps(payload))

    def test_only_malformed_portfolio_is_error_and_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            cases = Path(tmp) / "cases"
            cases.mkdir()
            (cases / "case-broken.json").write_text(
                "{ not json", encoding="utf-8"
            )
            scheduler = runtime_scheduler(
                tmp, portfolio_plans(), contexts=None
            )
            agent = RecordingAgent()
            scheduler.agent = agent
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["case_aware_state"], CASE_AWARE_ERROR)
            self.assertEqual(
                record["case_context"]["error"], CASE_CONTEXT_ALL_MALFORMED
            )
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(record["status"], RUN_STATUS_BLOCKED)

    def test_missing_directory_runtime_is_error_and_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            scheduler = runtime_scheduler(
                tmp, portfolio_plans(), contexts=None
            )
            record = scheduler.run_once(force=True, now=FIXED_NOW)
            self.assertEqual(record["case_aware_state"], CASE_AWARE_ERROR)
            self.assertEqual(
                record["case_context"]["error"],
                CASE_CONTEXT_DIRECTORY_MISSING,
            )
            self.assertEqual(record["plans_selected"], 0)
            self.assertEqual(record["execution_gate"]["executed"], False)

    def test_loaded_contexts_come_from_persisted_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            cases = Path(tmp) / "cases"
            write_runtime_portfolio(cases)
            contexts = load_case_contexts(cases)
            by_ref = {
                context["case_ref"]: context
                for context in contexts
                if context.get("case_ref")
            }
            self.assertEqual(
                set(by_ref),
                {
                    "case-runtime-a",
                    "case-runtime-b",
                    "case-runtime-c",
                    "case-runtime-d",
                },
            )
            self.assertEqual(
                by_ref["case-runtime-a"]["next_action"], "CONTINUE_RESEARCH"
            )
            self.assertEqual(
                by_ref["case-runtime-b"]["next_action"], "PROVIDE_EVIDENCE"
            )
            self.assertEqual(
                by_ref["case-runtime-c"]["next_action"], "HUMAN_REVIEW"
            )
            self.assertEqual(
                by_ref["case-runtime-d"]["next_action"], "STOP"
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
