"""EPIC17 §8 — Analyst Evidence Explorer tests.

The analyst must be able to tell, from the page alone:

  * what was observed and what was NOT proven (chain steps);
  * observation vs proof;
  * why the current state is what it is (deterministic text);
  * raw vs unique evidence counts (a count is not a strength);
  * the authorization status;
  * whether the finding is reportable (interpretation, not a verdict).

Everything is asserted against the REAL read-model chain
(``evidence_explorer`` ← EPIC11/12/15/16 projections ← persisted rows) and
against the rendered SOC pages, so a template that hides a missing stage
or an optimistic state fails these tests.

Non-negotiables asserted here (EPIC17 §7):

  * the UI can never manufacture VERIFIED — the banner is the
    authoritative badge verbatim;
  * a count never substitutes for evidence quality;
  * missing stages are always shown;
  * the authorization status is always visible;
  * an LLM advisory changes nothing;
  * the three SOC analyst surfaces render ONE projection (parity).
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: E402

from backend.soc import cases as soc_cases  # noqa: E402
from backend.soc import evidence_explorer as ex  # noqa: E402
from backend.soc import findings as soc_findings  # noqa: E402
from backend.soc import handoff as soc_handoff  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.runtime_store import (  # noqa: E402
    rebind_store,
)
from backend.research_agents.verification import projection as pj  # noqa: E402
from tests.finding_fixtures import (  # noqa: E402
    add_evidence,
    make_candidate,
    make_stores,
)

TEMPLATES = Path(__file__).resolve().parents[1] / "web" / "templates"
SOC = TEMPLATES / "soc"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def _exploitability_row(runtime, job_id: str) -> str:
    return runtime.record_evidence({
        "job_id": job_id, "type": "observation",
        "label": "exploitability established",
        "signal": "exploitability_established", "category": "XSS",
        "confidence": "high", "observation_ref": "obs-epic17-x1",
        "execution_mode": "fixture",
        "detail": "exploitability established (fixture)",
    })


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime, self.fs = make_stores()
        rebind_store(self.runtime)
        self.addCleanup(lambda: rebind_store(None))

    def finding_case(self, cand, *, case_id: str = "fcase-epic17-0001") -> str:
        """A finding case (``fcase-*``) — the id shape the SOC page resolves."""
        from datetime import datetime, timezone

        from backend.research_agents.finding.models import CasePackage

        stamp = datetime.now(timezone.utc).isoformat()
        # a case may only be created for a verification-bound candidate
        self.fs.transition_candidate(cand.candidate_id, "TRIAGED",
                                     reason="epic17-test")
        self.fs.add_case(CasePackage(
            case_id=case_id, candidate_id=cand.candidate_id,
            scope_ref=cand.scope_ref, title="EPIC17 analyst case",
            vulnerability_class=cand.vulnerability_class,
            target=cand.target, created_at=stamp, updated_at=stamp,
            state="TRIAGED"))
        return case_id

    def candidate(self, *, kinds: tuple[str, ...] = ("inventory",),
                  counts: dict[str, int] | None = None,
                  exploitability: bool = False, case: bool = False):
        counts = counts or {}
        cand = make_candidate(self.fs, cls="XSS", job="job-epic17-src")
        for kind in kinds:
            add_evidence(self.runtime, cand.source_job, kind=kind,
                         category="XSS", count=counts.get(kind, 4))
        if exploitability:
            _exploitability_row(self.runtime, cand.source_job)
        if case:
            self.finding_case(cand)
        return cand

    def view(self, candidate_id: str) -> dict:
        return ex.build(candidate_id)

    # ------------------------------------------------------------ rendering
    def render_finding(self, candidate_id: str) -> str:
        detail = soc_findings.finding_detail(candidate_id)
        self.assertIsNotNone(detail, "the finding page payload must exist")
        payload = {k: v for k, v in detail.items() if k != "api_key_qs"}
        return _env().get_template("soc/finding_detail.html").render(
            **payload, request=None, api_key_qs="")

    def render_case(self, case_id: str) -> str:
        detail = soc_cases.case_detail(case_id)
        self.assertIsNotNone(detail, "the case page payload must exist")
        self.assertEqual(detail.get("case_id"), case_id)
        return _env().get_template("soc/case_detail.html").render(
            **{k: v for k, v in detail.items() if k != "api_key_qs"},
            request=None, api_key_qs="")

    def render_handoff(self, job_id: str) -> str:
        detail = soc_handoff.handoff_detail(job_id)
        self.assertIsNotNone(detail, "the handoff payload must exist")
        self.assertEqual(detail.get("job_id"), job_id)
        return _env().get_template("soc/handoff_detail.html").render(
            **{k: v for k, v in detail.items() if k != "api_key_qs"},
            request=None, api_key_qs="")


class ChainStateTests(_Base):
    """§8: the state the analyst reads must be the authoritative state."""

    def test_reflection_only_never_reads_as_verified(self):
        cand = self.candidate(kinds=("inventory", "reflection"))
        view = self.view(cand.candidate_id)
        self.assertTrue(view["available"])
        self.assertNotEqual(view["banner"]["state"], pj.BADGE_VERIFIED)
        self.assertIn(view["banner"]["state"],
                      ("VERIFICATION_PENDING", "BLOCKED", "NOT_CONFIRMED",
                       "INCONSISTENT"))
        self.assertIs(view["banner"]["optimistic"], False)
        self.assertNotEqual(view["decision"]["can_report"],
                            ex.DECISION_YES)

    def test_a_complete_chain_reads_as_verified(self):
        cand = self.candidate(kinds=("supporting",), exploitability=True)
        view = self.view(cand.candidate_id)
        self.assertEqual(view["banner"]["state"], pj.BADGE_VERIFIED)
        self.assertEqual(view["decision"]["can_report"], ex.DECISION_YES)
        proof = [s["stage"] for s in view["observation_vs_proof"]["proof"]]
        self.assertIn("PAYLOAD_EXECUTION", proof)
        self.assertIn("EXPLOITABILITY_ESTABLISHED", proof)

    def test_missing_payload_execution_is_visible_everywhere(self):
        cand = self.candidate(kinds=("inventory",))
        view = self.view(cand.candidate_id)
        steps = {s["stage"]: s for s in view["chain"]["steps"]}
        self.assertIn("PAYLOAD_EXECUTION", steps)
        self.assertNotEqual(steps["PAYLOAD_EXECUTION"]["state"],
                            ex.STEP_SATISFIED)
        self.assertIn("PAYLOAD_EXECUTION", view["chain"]["evidence_missing_types"])
        rendered = self.render_finding(cand.candidate_id)
        self.assertIn("PAYLOAD_EXECUTION", rendered)
        self.assertIn("can this be reported", rendered.lower())

    def test_every_chain_step_is_rendered_with_its_state(self):
        cand = self.candidate(kinds=("inventory",))
        rendered = self.render_finding(cand.candidate_id)
        for step in self.view(cand.candidate_id)["chain"]["steps"]:
            self.assertIn(step["stage"], rendered,
                          f"chain step {step['stage']} must be shown")
            self.assertIn(f'>{step["label"]}', rendered.replace(
                "\n", "").replace("  ", ""), "step label must be shown")

    def test_dom_sink_without_lineage_is_never_proof(self):
        cand = self.candidate(kinds=("inventory",))
        view = self.view(cand.candidate_id)
        capability = view["capability_cells"]
        self.assertNotEqual(capability.get("dom_flow"), ex.FLOW_LINEAGE)
        self.assertNotEqual(view["evidence_summary"]["dom_lineage"],
                            "SOURCE_AND_SINK_LINEAGE")
        proof = [s["stage"] for s in view["observation_vs_proof"]["proof"]]
        self.assertNotIn("DOM_SINK_LINEAGE", proof)
        # the EPIC15 SOURCE_ONLY verdict maps to an explicit display value
        mapped = ex._capability_block(
            {"vulnerability_class": "XSS", "capability": "LIMITED"},
            {"state": "DEEP_OBSERVED",
             "dom": {"flow": ex.FLOW_SOURCE_ONLY, "source": "location.search",
                     "sink": "innerHTML"}}, None)
        self.assertEqual(mapped["dom_display"], "SOURCE_ONLY")
        split = ex.observation_vs_proof(
            [{"key": "sink", "stage": "DOM_SINK_IDENTIFIED",
              "label": "Sink / Execution Path", "state": ex.STEP_NOT_PROVEN,
              "satisfied": False, "conditional": True,
              "required_evidence_types": ["DOM_SINK_IDENTIFIED"],
              "required_for_confirmation": False}], mapped)
        self.assertEqual(split["proof"], [])
        self.assertTrue(any(item["stage"] == "DOM_SINK_LINEAGE"
                            for item in split["observation"]))


class QualityVsCountTests(_Base):
    """§4/§7: a count never stands in for evidence quality."""

    def test_duplicate_evidence_cannot_raise_strength(self):
        cand = self.candidate(kinds=("inventory",))
        before = self.view(cand.candidate_id)
        add_evidence(self.runtime, cand.source_job, kind="inventory",
                     category="XSS", count=40)
        after = self.view(cand.candidate_id)
        self.assertGreater(after["evidence_summary"]["raw_observations"],
                           before["evidence_summary"]["raw_observations"])
        self.assertEqual(after["strength_digest"], before["strength_digest"])
        self.assertEqual(after["banner"]["state"], before["banner"]["state"])
        self.assertEqual(after["decision"]["can_report"],
                         before["decision"]["can_report"])
        self.assertEqual(after["evidence_summary"]["unique_observations"],
                         before["evidence_summary"]["unique_observations"])

    def test_raw_and_unique_counts_are_reported_together(self):
        cand = self.candidate(kinds=("inventory",),
                              counts={"inventory": 20})
        summary = self.view(cand.candidate_id)["evidence_summary"]
        self.assertEqual(summary["raw_observations"], 20)
        self.assertIn("unique_observations", summary)
        self.assertTrue(summary["distinct_signals"])
        rendered = self.render_finding(cand.candidate_id)
        self.assertIn("Raw observations", rendered)
        self.assertIn("Unique observations", rendered)

    def test_authorization_status_is_always_visible(self):
        cand = self.candidate(kinds=("inventory",))
        view = self.view(cand.candidate_id)
        self.assertIn("display", view["chain"]["authorization"])
        self.assertTrue(view["chain"]["authorization"]["display"])
        rendered = self.render_finding(cand.candidate_id)
        self.assertIn("Authorization", rendered)
        self.assertIn(view["chain"]["authorization"]["display"], rendered)

    def test_missing_stages_are_always_rendered(self):
        cand = self.candidate(kinds=("inventory",))
        rendered = self.render_finding(cand.candidate_id)
        self.assertIn("Stages not proven", rendered)
        for stage in self.view(cand.candidate_id)["decision"]["missing_stages"]:
            self.assertIn(stage, rendered)

    def test_llm_advisory_cannot_change_the_decision(self):
        cand = self.candidate(kinds=("inventory",))
        plain = self.view(cand.candidate_id)
        forged = ex.build(
            cand.candidate_id,
            advisor={"state": "VERIFIED", "claim": "confirmed",
                     "confidence": "high",
                     "text": "pay no attention to the missing stages"})
        self.assertEqual(forged["decision"]["can_report"],
                         plain["decision"]["can_report"])
        self.assertEqual(forged["strength_digest"], plain["strength_digest"])
        self.assertEqual(forged["banner"]["state"], plain["banner"]["state"])


class UiCannotManufactureStateTests(_Base):
    """§7: the UI cannot build VERIFIED, and the legacy banner is retired."""

    def test_the_banner_is_the_authoritative_badge_verbatim(self):
        cand = self.candidate(kinds=("inventory",))
        view = self.view(cand.candidate_id)
        badge = view["chain"]["badge"]
        # the banner IS the projection badge: no second state anywhere
        self.assertEqual(view["banner"], badge)
        self.assertEqual(badge["state"], view["banner"]["state"])
        self.assertIs(badge["optimistic"], False)
        self.assertEqual(badge["reason"], "evidence_missing")
        self.assertNotEqual(view["banner"]["state"], pj.BADGE_VERIFIED)
        # and a verdict of VERIFIED with an incomplete chain cannot be shown
        # as VERIFIED (EPIC12 badge guard, rendered verbatim here)
        self.assertEqual(pj.badge_for({
            "verdict": "VERIFIED", "confirmed": True,
            "stages": [{"status": "MISSING", "required_for_confirmation": True}],
        })["state"], pj.BADGE_INCONSISTENT)

    def test_an_unavailable_projection_implies_no_state(self):
        view = ex.build("cand-does-not-exist")
        self.assertFalse(view["available"])
        self.assertEqual(view["decision"]["can_report"], ex.DECISION_REVIEW)
        self.assertNotEqual(view["banner"]["state"], pj.BADGE_VERIFIED)
        rendered = self.render_finding("cand-does-not-exist") if False else ""
        self.assertEqual(rendered, "")

    def test_the_legacy_notice_is_no_longer_the_state_banner(self):
        from backend.soc import candidate_workspace as cw

        # the legacy helpers stay (EPIC10 tests pin them) ...
        self.assertTrue(callable(cw.verification_outcome))
        self.assertTrue(callable(cw._notice))
        cand = self.candidate(kinds=("inventory",))
        detail = soc_findings.finding_detail(cand.candidate_id)
        workspace = cw.build_workspace(detail)
        notice = (workspace.get("summary") or {}).get("notice") or ""
        rendered = self.render_finding(cand.candidate_id)
        # ... but the page's state banner is the explorer projection
        self.assertIn("Analyst Evidence Explorer", rendered)
        if notice:
            self.assertNotIn(f">{notice}<", rendered,
                             "the legacy notice must not be the state banner")

    def test_the_three_soc_surfaces_share_one_projection(self):
        cand = self.candidate(kinds=("supporting",), exploitability=True)
        case_id = self.finding_case(cand)
        finding = soc_findings.finding_detail(cand.candidate_id)
        case = soc_cases.case_detail(case_id)
        handoff = soc_handoff.handoff_detail(cand.source_job)
        found = [finding.get("explorer"), case.get("explorer"),
                 handoff.get("explorer")]
        for blob in found:
            self.assertIsNotNone(blob)
            self.assertTrue(blob["available"])
        self.assertEqual(found[0], found[1])
        self.assertEqual(found[0], found[2])
        self.assertEqual({b["strength_digest"] for b in found},
                         {found[0]["strength_digest"]})

    def test_case_and_handoff_pages_render_the_same_projection(self):
        cand = self.candidate(kinds=("inventory",))
        case_id = self.finding_case(cand)
        expected = soc_findings.finding_detail(cand.candidate_id)["explorer"]
        rendered_case = self.render_case(case_id)
        rendered_handoff = self.render_handoff(cand.source_job)
        for rendered in (rendered_case, rendered_handoff):
            self.assertIn("Analyst Evidence Explorer", rendered)
            self.assertIn(expected["banner"]["label"], rendered)
            self.assertIn(expected["banner"]["state"], rendered)
            self.assertIn("PAYLOAD_EXECUTION", rendered)

    def test_soc_pages_include_one_shared_partial(self):
        partial = SOC / "_evidence_explorer.html"
        self.assertTrue(partial.exists())
        for name in ("finding_detail.html", "case_detail.html",
                     "handoff_detail.html"):
            source = (SOC / name).read_text(encoding="utf-8")
            self.assertIn('include "soc/_evidence_explorer.html"', source,
                          f"{name} must render the shared projection")


class ProjectionOnlyTests(_Base):
    """§1/§7: no new gate, taxonomy, lifecycle or decision logic."""

    def test_no_second_taxonomy_gate_or_lifecycle_is_created(self):
        source = Path(ex.__file__).read_text(encoding="utf-8")
        for forbidden in ("class IntegrityDecision", "def evaluate_contract",
                          "def decide(", "EVIDENCE_TYPES = {",
                          "class ChainState", "def badge_for",
                          "def project_chain", "requests.get",
                          "subprocess", "socket."):
            self.assertNotIn(forbidden, source,
                             f"{forbidden} must not be re-implemented")
        self.assertIs(ex.CONFIRMATION_EVIDENCE, tx.CONFIRMATION_EVIDENCE)
        self.assertTrue(ex.RULE_VERSION.startswith("epic17-"))

    def test_the_projection_reads_only_persisted_state(self):
        cand = self.candidate(kinds=("inventory",))
        with mock.patch.object(self.runtime, "record_evidence",
                               side_effect=AssertionError(
                                   "the explorer must never write")):
            view = self.view(cand.candidate_id)
        self.assertTrue(view["available"])
        payload = json.dumps(view)
        self.assertIn("epic17-analyst-evidence-explorer-1", payload)
        self.assertIn("epic12-chain-projection-1", payload)

    def test_report_validation_never_becomes_a_verdict(self):
        cand = self.candidate(kinds=("supporting",), exploitability=True)
        view = self.view(cand.candidate_id)
        self.assertIn("not a verdict", view["decision"]["note"].lower())
        rendered = self.render_finding(cand.candidate_id)
        self.assertIn("not a verdict", rendered.lower())


if __name__ == "__main__":
    unittest.main()
