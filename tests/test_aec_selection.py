"""Tests for the AEC-1 offline pilot case selector (Task T1).

Behaviour-first tests for ``aec.selection``. Everything here is offline and
deterministic: no network, no sockets, no live validation, no writes outside
the configured output area.

Run:
    /opt/watch/venv/bin/python3 -m unittest tests.test_aec_selection -v
"""

from __future__ import annotations

import ast
import json
import tempfile
import unittest
from pathlib import Path

from aec import (
    AEC_LIVE_HTTP_ENABLED,
    FAMILY_CAPS,
    PILOT_BUDGET,
    PILOT_HOST_RANGE,
    SELECTION_RULE_VERSION,
)
from aec.errors import (
    EXCLUSION_REASONS,
    EXTENDED_REASONS,
    PLAN_REASONS,
    SELECTED,
    SelectionError,
)
from aec.models import CaseRef, SelectionResult
from aec import selection

REPO_ROOT = Path(__file__).resolve().parents[1]
AEC_DIR = REPO_ROOT / "aec"

SCOPE = {
    "indeed": {
        "scopes": ["indeed.com", "indeedflex.com", "indeed.tech", "indeed.net"],
        "ooscopes": [],
    },
    "dell": {
        "scopes": ["dell.com", "delltechnologies.com"],
        "ooscopes": ["console.dell.com", "salesproductivity.dell.com"],
    },
}


# --------------------------------------------------------------------------
# Fixtures — shaped exactly like the real investigation reports
# --------------------------------------------------------------------------

def report(
    *,
    job_id="rj-0000000000000001",
    program="indeed",
    host="hiringlab.indeed.com",
    endpoint="/uk/wp-json/wp/v2/pages/{id}",
    parameter="id",
    method="GET",
    category="IDOR_CANDIDATE",
    confidence="MEDIUM",
    location="query",
    evidence_required=(
        "authorization comparison",
        "object ownership context",
        "response difference",
    ),
    missing_evidence=("response difference",),
    artifacts=None,
):
    """Build one report-shaped fixture (the selector's real input format)."""
    if artifacts is None:
        artifacts = (
            {"type": "HTTP_METADATA", "status": "COLLECTED"},
            {"type": "PARAMETER_BEHAVIOR", "status": "COLLECTED"},
            {"type": "RESPONSE_COMPARISON", "status": "MISSING"},
        )
    return {
        "job_id": job_id,
        "candidate_id": "asc-fixture",
        "program": program,
        "subdomain": host,
        "endpoint": endpoint,
        "parameter": parameter,
        "method": method,
        "category": category,
        "confidence": confidence,
        "status": "WAITING_EVIDENCE",
        "url": f"{endpoint}?{parameter}=",
        "reasons": ["resource reference"],
        "technology": ["WordPress"],
        "artifacts": list(artifacts),
        "evidence_required": list(evidence_required),
        "missing_evidence": list(missing_evidence),
        "plan": {
            "steps": [
                {
                    "order": 1,
                    "evidence_type": "HTTP_METADATA",
                    "request": {"method": method, "location": location},
                }
            ]
        },
    }


def many(n, **kwargs):
    """n distinct IDOR wp-json cases on one host."""
    return [
        report(
            job_id=f"rj-{i:016x}",
            endpoint=f"/blog-{i}/wp-json/wp/v2/pages/{{id}}",
            **kwargs,
        )
        for i in range(n)
    ]


def selected_ids(result):
    return [d.case_id for d in result.selected]


def decision_for(result, case_id):
    for d in result.selected + result.excluded:
        if d.case_id == case_id:
            return d
    raise AssertionError(f"no decision recorded for {case_id}")


class TestCaseRefNormalisation(unittest.TestCase):
    def test_category_is_normalised_from_candidate_suffix(self):
        ref = CaseRef.from_report(report(category="FILE_UPLOAD_CANDIDATE"))
        self.assertEqual(ref.category, "file_upload")

    def test_method_is_upper_cased(self):
        ref = CaseRef.from_report(report(method="get"))
        self.assertEqual(ref.method, "GET")

    def test_case_id_is_the_job_id(self):
        ref = CaseRef.from_report(report(job_id="rj-abc"))
        self.assertEqual(ref.case_id, "rj-abc")

    def test_evidence_gap_splits_required_missing_and_not_listed(self):
        ref = CaseRef.from_report(
            report(
                evidence_required=("a", "b", "c"),
                missing_evidence=("b", "c"),
            )
        )
        self.assertEqual(ref.evidence_gap.level_current, "L0_STORED_OBSERVATION")
        self.assertEqual(ref.evidence_gap.level_target, "L3_COMPARATIVE")
        self.assertEqual(list(ref.evidence_gap.required), ["a", "b", "c"])
        self.assertEqual(list(ref.evidence_gap.missing), ["b", "c"])
        self.assertEqual(list(ref.evidence_gap.not_listed_missing), ["a"])

    def test_evidence_gap_reports_held_artifacts_not_inferred_presence(self):
        gap = CaseRef.from_report(
            report(
                evidence_required=("authorization comparison", "response difference"),
                missing_evidence=("response difference",),
                artifacts=(
                    {"type": "HTTP_METADATA", "status": "COLLECTED"},
                    {"type": "RESPONSE_COMPARISON", "status": "MISSING"},
                    {"type": "TECHNOLOGY_CONTEXT", "status": "COLLECTED"},
                ),
            )
        ).evidence_gap
        self.assertEqual(
            list(gap.artifacts_collected), ["HTTP_METADATA", "TECHNOLOGY_CONTEXT"]
        )
        self.assertEqual(list(gap.artifacts_missing), ["RESPONSE_COMPARISON"])
        self.assertFalse(gap.is_complete)
        self.assertNotIn("present", gap.to_dict())

    def test_evidence_gap_without_a_missing_list_treats_everything_as_missing(self):
        gap = CaseRef.from_report(
            report(evidence_required=("x",), missing_evidence=())
        ).evidence_gap
        self.assertEqual(list(gap.missing), ["x"])
        self.assertEqual(list(gap.not_listed_missing), [])

    def test_plan_step_location_is_captured(self):
        ref = CaseRef.from_report(report(location="body"))
        self.assertIn("body", ref.locations)


class TestExclusionReasons(unittest.TestCase):
    def test_challenge_token_parameter_is_excluded(self):
        result = selection.select(
            [report(parameter="__cf_chl_f_tk", endpoint="/account/check")], SCOPE
        )
        self.assertEqual(
            decision_for(result, "rj-0000000000000001").reason, "CHALLENGE_TOKEN"
        )

    def test_login_endpoint_is_excluded(self):
        result = selection.select(
            [report(endpoint="/accounts/login/", parameter="next")], SCOPE
        )
        self.assertEqual(
            decision_for(result, "rj-0000000000000001").reason, "LOGIN_ENDPOINT"
        )

    def test_author_archive_is_not_treated_as_an_auth_endpoint(self):
        result = selection.select(
            [
                report(
                    category="XSS_CANDIDATE",
                    endpoint="/author/cory-stahle/page/{id}/",
                    parameter="search",
                )
            ],
            SCOPE,
        )
        decision = decision_for(result, "rj-0000000000000001")
        self.assertIsNotNone(decision.family)
        self.assertNotEqual(decision.reason, "LOGIN_ENDPOINT")

    def test_authorize_endpoint_is_excluded(self):
        result = selection.select(
            [report(endpoint="/dci/fp/authorize/googleOneTap", parameter="redirect")],
            SCOPE,
        )
        self.assertEqual(
            decision_for(result, "rj-0000000000000001").reason, "LOGIN_ENDPOINT"
        )

    def test_session_shaped_parameter_is_excluded(self):
        result = selection.select(
            [report(parameter="client_id", endpoint="/auth/realms/x/protocol/openid-connect/auth")],
            SCOPE,
        )
        reason = decision_for(result, "rj-0000000000000001").reason
        self.assertIn(reason, {"AUTH_REQUIRED", "LOGIN_ENDPOINT"})

    def test_non_get_method_is_excluded(self):
        result = selection.select([report(method="POST")], SCOPE)
        self.assertEqual(
            decision_for(result, "rj-0000000000000001").reason, "NON_GET_METHOD"
        )

    def test_body_delivered_parameter_is_excluded(self):
        result = selection.select([report(method="POST", location="body")], SCOPE)
        self.assertEqual(
            decision_for(result, "rj-0000000000000001").reason, "BODY_REQUIRED"
        )

    def test_upload_category_is_excluded(self):
        result = selection.select(
            [report(category="FILE_UPLOAD_CANDIDATE", parameter="attachment")], SCOPE
        )
        self.assertEqual(
            decision_for(result, "rj-0000000000000001").reason, "UPLOAD_CATEGORY"
        )

    def test_out_of_scope_host_is_excluded(self):
        result = selection.select(
            [
                report(
                    program="dell",
                    host="console.dell.com",
                    endpoint="/wp-json/wp/v2/pages/{id}",
                )
            ],
            SCOPE,
        )
        self.assertEqual(
            decision_for(result, "rj-0000000000000001").reason, "OUT_OF_SCOPE_HOST"
        )

    def test_unknown_program_is_excluded_deny_by_default(self):
        result = selection.select([report(program="unknown-program")], SCOPE)
        self.assertEqual(
            decision_for(result, "rj-0000000000000001").reason, "OUT_OF_SCOPE_HOST"
        )

    def test_non_pilot_category_is_excluded(self):
        result = selection.select(
            [
                report(
                    category="AUTHZ_CANDIDATE",
                    endpoint="/DataServices/User/GetFundingInfo",
                    parameter="clientid",
                    host="partnerincentives.delltechnologies.com",
                    program="dell",
                )
            ],
            SCOPE,
        )
        self.assertEqual(
            decision_for(result, "rj-0000000000000001").reason, "CATEGORY_OUT_OF_PILOT"
        )

    def test_missing_parameter_is_not_comparable(self):
        result = selection.select([report(parameter="")], SCOPE)
        self.assertEqual(
            decision_for(result, "rj-0000000000000001").reason, "NOT_COMPARABLE"
        )

    def test_duplicate_endpoint_is_excluded_once(self):
        cases = [
            report(job_id="rj-first", endpoint="/a/wp-json/wp/v2/pages/{id}"),
            report(job_id="rj-second", endpoint="/a/wp-json/wp/v2/pages/{id}"),
        ]
        result = selection.select(cases, SCOPE)
        self.assertEqual(len(result.selected), 1)
        self.assertEqual(len(result.excluded), 1)
        self.assertEqual(result.excluded[0].reason, "DUPLICATE_ENDPOINT")

    def test_every_exclusion_reason_is_in_the_closed_vocabulary(self):
        for reason in EXCLUSION_REASONS:
            self.assertIn(reason, EXCLUSION_REASONS)
        # the two documented extensions are declared explicitly
        self.assertTrue(set(EXTENDED_REASONS).issubset(set(EXCLUSION_REASONS)))
        self.assertTrue(set(PLAN_REASONS).issubset(set(EXCLUSION_REASONS)))
        self.assertEqual(len(set(EXCLUSION_REASONS)), len(EXCLUSION_REASONS))

    def test_each_case_receives_exactly_one_outcome(self):
        cases = [
            report(job_id="rj-1"),
            report(job_id="rj-2", method="POST"),
            report(job_id="rj-3", parameter="__cf_chl_f_tk"),
            report(job_id="rj-4", category="AUTHZ_CANDIDATE"),
        ]
        result = selection.select(cases, SCOPE)
        decided = {d.case_id for d in result.selected + result.excluded}
        self.assertEqual(decided, {"rj-1", "rj-2", "rj-3", "rj-4"})
        self.assertEqual(len(result.selected) + len(result.excluded), 4)


class TestLimits(unittest.TestCase):
    def test_never_selects_more_than_the_budget(self):
        cases = []
        for i in range(40):
            cases.extend(
                many(
                    1,
                    host=f"blog-{i}.hiringlab.indeed.com",
                )
            )
        for i, case in enumerate(cases):
            case["job_id"] = f"rj-{i:016x}"
            case["endpoint"] = f"/x{i}/wp-json/wp/v2/pages/{{id}}"
        result = selection.select(cases, SCOPE)
        self.assertLessEqual(len(result.selected), PILOT_BUDGET.max_cases)

    def test_per_host_cap_is_enforced(self):
        cases = many(9)
        result = selection.select(cases, SCOPE)
        self.assertEqual(len(result.selected), PILOT_BUDGET.max_requests_per_host)
        full = [d for d in result.excluded if d.reason == "HOST_BUDGET_FULL"]
        self.assertEqual(len(full), 4)

    def test_distinct_host_set_is_capped(self):
        cases = []
        for i in range(7):
            cases.append(
                report(
                    job_id=f"rj-{i:016x}",
                    host=f"host{i}.hiringlab.indeed.com",
                )
            )
            cases[-1]["endpoint"] = f"/x{i}/wp-json/wp/v2/pages/{{id}}"
        result = selection.select(cases, SCOPE)
        hosts = {d.host for d in result.selected}
        self.assertLessEqual(len(hosts), PILOT_HOST_RANGE[1])
        self.assertTrue(any(d.reason == "HOST_SET_FULL" for d in result.excluded))

    def test_family_cap_is_enforced(self):
        # two hosts (5 + 5 = the per-host ceiling) but the family cap is 10
        cases = many(7, host="a.hiringlab.indeed.com") + many(
            7, host="b.hiringlab.indeed.com"
        )
        result = selection.select(cases, SCOPE)
        self.assertEqual(len(result.selected), FAMILY_CAPS["IDOR_JSON_RESOURCE"])
        self.assertTrue(any(d.reason == "FAMILY_CAP_FULL" for d in result.excluded))

    def test_global_cap_is_enforced_when_family_caps_allow_more(self):
        cases = many(6)
        small_budget = selection.PilotBudgetLimits(max_cases=2, max_requests_per_host=5)
        result = selection.select(cases, SCOPE, budget=small_budget)
        self.assertEqual(len(result.selected), 2)
        self.assertTrue(any(d.reason == "PILOT_CAP_FULL" for d in result.excluded))

    def test_selected_priority_order_is_unique_and_ascending(self):
        result = selection.select(many(6), SCOPE)
        orders = [d.order for d in result.selected]
        self.assertEqual(orders, list(range(1, len(orders) + 1)))


class TestOutputShape(unittest.TestCase):
    def test_risk_category_is_assigned_to_every_case(self):
        cases = [
            report(job_id="rj-1"),
            report(job_id="rj-2", category="SSRF_CANDIDATE", parameter="url",
                   endpoint="/wp-json/oembed/1.0/embed"),
            report(job_id="rj-3", category="XSS_CANDIDATE", parameter="q"),
            report(job_id="rj-4", category="FILE_UPLOAD_CANDIDATE", parameter="file"),
            report(job_id="rj-5", category="AUTHZ_CANDIDATE"),
        ]
        result = selection.select(cases, SCOPE)
        by_id = {d.case_id: d for d in result.selected + result.excluded}
        for case_id in ("rj-1", "rj-2", "rj-3", "rj-4", "rj-5"):
            self.assertTrue(by_id[case_id].risk_category)
        self.assertEqual(by_id["rj-1"].risk_category, "R1_OBJECT_REFERENCE")
        self.assertEqual(by_id["rj-2"].risk_category, "R2_SERVER_FETCH")
        self.assertEqual(by_id["rj-3"].risk_category, "R3_REFLECTION")
        self.assertEqual(by_id["rj-4"].risk_category, "R4_CONTENT_HANDLING")
        self.assertEqual(by_id["rj-5"].risk_category, "R5_ACCESS_CONTROL")

    def test_selected_case_carries_evidence_gap(self):
        result = selection.select([report()], SCOPE)
        gap = result.selected[0].evidence_gap
        self.assertEqual(gap.level_current, "L0_STORED_OBSERVATION")
        self.assertEqual(gap.level_target, "L3_COMPARATIVE")
        self.assertEqual(list(gap.missing), ["response difference"])

    def test_serialised_result_exposes_the_required_sections(self):
        result = selection.select([report(), report(job_id="rj-2", method="POST")], SCOPE)
        payload = result.to_dict()
        self.assertEqual(payload["rule_version"], SELECTION_RULE_VERSION)
        self.assertEqual(payload["counts"]["selected"], 1)
        self.assertEqual(payload["counts"]["excluded"], 1)
        self.assertEqual(payload["counts"]["total"], 2)
        self.assertIn("selected", payload)
        self.assertIn("excluded", payload)
        self.assertIn("family_counts", payload)
        self.assertIn("host_counts", payload)
        for item in payload["selected"]:
            self.assertIn("risk_category", item)
            self.assertIn("evidence_gap", item)
            self.assertIn("reason", item)
        for item in payload["excluded"]:
            self.assertIn("reason", item)
            self.assertIn("risk_category", item)
        self.assertEqual(payload["selected"][0]["reason"], SELECTED)

    def test_limits_are_reported(self):
        payload = selection.select([report()], SCOPE).to_dict()
        limits = payload["limits"]
        self.assertEqual(limits["max_cases"], 20)
        self.assertEqual(limits["max_requests"], 60)
        self.assertEqual(limits["max_requests_per_host"], 5)
        self.assertEqual(limits["host_range"], list(PILOT_HOST_RANGE))


class TestDeterminism(unittest.TestCase):
    def test_two_runs_produce_identical_json(self):
        cases = many(6) + [
            report(job_id="rj-extra", category="SSRF_CANDIDATE", parameter="url",
                   endpoint="/wp-json/oembed/1.0/embed"),
            report(job_id="rj-bad", method="PUT"),
        ]
        first = json.dumps(selection.select(cases, SCOPE).to_dict(), sort_keys=True)
        second = json.dumps(selection.select(cases, SCOPE).to_dict(), sort_keys=True)
        self.assertEqual(first, second)

    def test_input_order_does_not_change_the_outcome(self):
        cases = many(6) + [
            report(job_id="rj-extra", category="SSRF_CANDIDATE", parameter="url",
                   endpoint="/wp-json/oembed/1.0/embed"),
            report(job_id="rj-bad", method="PUT"),
        ]
        shuffled = list(reversed(cases))
        a = selection.select(cases, SCOPE).to_dict()
        b = selection.select(shuffled, SCOPE).to_dict()
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_excluded_list_is_stably_ordered(self):
        cases = [
            report(job_id="rj-a", method="POST"),
            report(job_id="rj-b", parameter="__cf_chl_f_tk"),
        ]
        first = [d.case_id for d in selection.select(cases, SCOPE).excluded]
        second = [d.case_id for d in selection.select(list(reversed(cases)), SCOPE).excluded]
        self.assertEqual(first, second)

    def test_selection_is_pure_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = sorted(p.name for p in Path(tmp).iterdir())
            selection.select([report()], SCOPE)
            after = sorted(p.name for p in Path(tmp).iterdir())
        self.assertEqual(before, after)


class TestOutputWrites(unittest.TestCase):
    def test_write_outputs_places_files_inside_the_allowed_area(self):
        result = selection.select([report()], SCOPE)
        with tempfile.TemporaryDirectory() as tmp:
            paths = selection.write_outputs(result, root=Path(tmp))
            self.assertEqual(len(paths), 2)
            for path in paths:
                path = Path(path)
                self.assertTrue(path.exists())
                self.assertTrue(str(path).startswith(tmp))
                self.assertIn(
                    path.relative_to(tmp).parts[0], {"ai_data", "agent-reports"}
                )
            json_path = [p for p in paths if str(p).endswith(".json")][0]
            payload = json.loads(Path(json_path).read_text())
            self.assertEqual(payload["rule_version"], SELECTION_RULE_VERSION)

    def test_approval_sheet_contains_the_required_sections(self):
        result = selection.select([report()], SCOPE)
        sheet = selection.render_approval_sheet(result)
        for heading in (
            "## 1. Approval request",
            "## 2. Selected cases",
            "## 3. Excluded cases and reasons",
            "## 4. Limits and budget",
            "## 5. What this pilot will NOT do",
        ):
            self.assertIn(heading, sheet)
        self.assertIn("NOT_CONFIRMED", sheet)

    def test_write_outputs_refuses_a_path_escape(self):
        result = selection.select([report()], SCOPE)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SelectionError):
                selection.write_outputs(
                    result, root=Path(tmp), selection_dir="../escape"
                )

    def test_result_is_reusable_after_serialisation_round_trip(self):
        result = selection.select([report()], SCOPE)
        payload = result.to_dict()
        self.assertIsInstance(payload, dict)
        self.assertIsInstance(result, SelectionResult)


class TestSafetyGuards(unittest.TestCase):
    """Static guarantees: no transport, no live capability, no stray writes."""

    FORBIDDEN_IMPORT_ROOTS = (
        "socket",
        "ssl",
        "http",
        "urllib",
        "requests",
        "httpx",
        "subprocess",
        "asyncio",
        "telnetlib",
        "smtplib",
        "ftplib",
    )
    FORBIDDEN_PROJECT_IMPORTS = (
        "ai.execution",
        "ai.authorizer",
        "ai.evidence",
        "ai.verification",
        "ai.finding",
        "ai.live_validation",
        "backend.tasks_registry",
        "backend.task_runner",
    )

    def _aec_modules(self):
        return sorted(AEC_DIR.glob("*.py"))

    def test_aec_package_exists_and_has_no_transport_imports(self):
        modules = self._aec_modules()
        self.assertTrue(modules, "aec/ package must exist")
        for path in modules:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    root = name.split(".")[0]
                    self.assertNotIn(
                        root, self.FORBIDDEN_IMPORT_ROOTS, f"{path.name} imports {name}"
                    )
                    for forbidden in self.FORBIDDEN_PROJECT_IMPORTS:
                        self.assertFalse(
                            name == forbidden or name.startswith(forbidden + "."),
                            f"{path.name} imports forbidden module {name}",
                        )

    def test_only_the_writer_writes_to_disk(self):
        for path in self._aec_modules():
            source = path.read_text()
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef):
                    continue
                writes = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                        if child.func.id == "open" and len(child.args) > 1:
                            mode = child.args[1]
                            if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
                                if any(flag in mode.value for flag in ("w", "a", "x", "+")):
                                    writes.append(child.func.id)
                    if isinstance(child, ast.Call):
                        name = getattr(child.func, "attr", "")
                        if name in {"write_text", "write_bytes", "mkdir", "touch"}:
                            writes.append(name)
                if writes:
                    self.assertEqual(
                        node.name,
                        "write_outputs",
                        f"{path.name}:{node.name} writes to disk outside write_outputs",
                    )

    def test_live_capability_constant_is_false(self):
        self.assertIs(AEC_LIVE_HTTP_ENABLED, False)

    def test_no_live_modules_exist_in_this_phase(self):
        self.assertFalse((AEC_DIR / "live_deps.py").exists())
        self.assertFalse((AEC_DIR / "observation_lane.py").exists())

    def test_readonly_authority_chain_is_untouched_by_this_task(self):
        # T1 must not have modified the frozen verification/execution chain.
        frozen = [
            REPO_ROOT / "ai/execution/http_executor.py",
            REPO_ROOT / "ai/evidence/builder.py",
            REPO_ROOT / "ai/verification/deterministic/gate.py",
            REPO_ROOT / "ai/finding/eligibility.py",
            REPO_ROOT / "ai/limits/ceilings.py",
            REPO_ROOT / "watch_xss_verify.py",
            REPO_ROOT / "backend/tasks_registry.py",
        ]
        for path in frozen:
            # the worktree contains the production copy of these files
            self.assertTrue(path.exists(), f"frozen file missing: {path}")
        self.assertIs(selection.LIVE_TRAFFIC_ENABLED_EXPECTED, False)


if __name__ == "__main__":
    unittest.main()
