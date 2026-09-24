"""EPIC15 §5/§6/§13 — the deterministic DOM source→sink verifier."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from ai.limits import ceilings as ce  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.verification import deep as dp  # noqa: E402
from backend.research_agents.verification import executors as ex  # noqa: E402
from tests.epic15_fixtures import (  # noqa: E402
    MARKER, PARAMETER, document_huge, document_lineage, document_lineage_eval,
    document_lineage_write, document_no_lineage, document_presence_only,
    document_reflection_only, document_script_text_only, document_sink_only,
    document_wrong_parameter)


class TestLineageBoundTracing(unittest.TestCase):
    """§6: only a lineage-bound source→sink flow is DOM sink evidence."""

    def test_a_bound_flow_is_identified(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertEqual(trace.flow, dp.dom.FLOW_LINEAGE)

    def test_a_bound_flow_produces_dom_sink_evidence(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertTrue(trace.produces_dom_sink_evidence)

    def test_a_bound_flow_names_the_source(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertEqual(trace.source, "location_search")

    def test_a_bound_flow_names_the_sink(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertEqual(trace.sink, "innerHTML")

    def test_a_bound_flow_names_the_variable(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertEqual(trace.variable, PARAMETER)

    def test_a_bound_flow_is_a_dom_sink_kind(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertEqual(trace.kind, dp.dom.KIND_DOM_SINK)

    def test_the_evidence_string_names_the_flow(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertIn("location_search", trace.evidence)
        self.assertIn("innerHTML", trace.evidence)

    def test_an_eval_flow_is_identified(self):
        trace = dp.trace_dom_flow(document_lineage_eval(), parameter="")
        self.assertEqual(trace.sink, "eval")

    def test_a_document_write_flow_is_identified(self):
        trace = dp.trace_dom_flow(document_lineage_write(), parameter="")
        self.assertEqual(trace.sink, "document_write")

    def test_a_flow_bound_to_another_parameter_is_not_evidence(self):
        trace = dp.trace_dom_flow(document_wrong_parameter(),
                                  parameter=PARAMETER)
        self.assertFalse(trace.produces_dom_sink_evidence)

    def test_a_flow_bound_to_another_parameter_is_recorded_as_source_only(self):
        trace = dp.trace_dom_flow(document_wrong_parameter(),
                                  parameter=PARAMETER)
        self.assertEqual(trace.flow, dp.dom.FLOW_SOURCE_ONLY)


class TestFalsePositivesAreRefused(unittest.TestCase):
    """§5/§8: presence is not reachability; text is not execution."""

    def test_a_static_sink_with_a_source_elsewhere_is_not_evidence(self):
        trace = dp.trace_dom_flow(document_no_lineage(), parameter=PARAMETER)
        self.assertFalse(trace.produces_dom_sink_evidence)

    def test_the_static_sink_case_is_recorded(self):
        trace = dp.trace_dom_flow(document_no_lineage(), parameter=PARAMETER)
        self.assertEqual(trace.flow, dp.dom.FLOW_SOURCE_ONLY)
        self.assertIn("no_bound_parameter_lineage", trace.reason)

    def test_a_sink_without_a_source_is_not_evidence(self):
        trace = dp.trace_dom_flow(document_sink_only(), parameter=PARAMETER)
        self.assertFalse(trace.produces_dom_sink_evidence)
        self.assertEqual(trace.flow, dp.dom.FLOW_NO_SOURCE)

    def test_a_source_without_a_sink_is_not_evidence(self):
        trace = dp.trace_dom_flow(document_presence_only(), parameter=PARAMETER)
        self.assertFalse(trace.produces_dom_sink_evidence)
        self.assertEqual(trace.flow, dp.dom.FLOW_NO_SINK)

    def test_an_empty_document_is_not_evidence(self):
        trace = dp.trace_dom_flow("", parameter=PARAMETER)
        self.assertFalse(trace.produces_dom_sink_evidence)
        self.assertEqual(trace.flow, dp.dom.FLOW_NO_SOURCE)

    def test_a_reflected_marker_is_not_a_dom_sink(self):
        trace = dp.trace_dom_flow(document_reflection_only(), parameter="q")
        self.assertFalse(trace.produces_dom_sink_evidence)

    def test_script_text_in_the_response_is_not_a_dom_sink(self):
        trace = dp.trace_dom_flow(document_script_text_only(), parameter="q")
        self.assertFalse(trace.produces_dom_sink_evidence)

    def test_a_source_and_sink_in_separate_scripts_without_lineage_is_not_evidence(self):
        document = ("<script>var a = location.search;</script>"
                    "<script>document.write('static');</script>")
        trace = dp.trace_dom_flow(document, parameter="q")
        self.assertFalse(trace.produces_dom_sink_evidence)

    def test_the_trace_never_produces_execution_evidence(self):
        for document in (document_lineage(), document_lineage_eval(),
                         document_lineage_write()):
            trace = dp.trace_dom_flow(document, parameter=PARAMETER)
            self.assertNotEqual(trace.kind, dp.dom.KIND_EXECUTION)

    def test_no_trace_produces_an_execution_kind(self):
        """§8: this layer can never emit execution evidence."""
        for document in (document_lineage(), document_lineage_eval(),
                         document_lineage_write(), document_no_lineage(),
                         document_sink_only(), document_presence_only()):
            trace = dp.trace_dom_flow(document, parameter=PARAMETER)
            self.assertNotEqual(trace.kind, dp.dom.KIND_EXECUTION)

    def test_the_trace_carries_no_evidence_type_at_all(self):
        """The trace describes material; classification belongs to EPIC11."""
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertFalse(hasattr(trace, "evidence_type"))


class TestInstrumentationMetadata(unittest.TestCase):
    """§13/§14: the method and version are persisted, and honest."""

    def test_the_method_is_recorded(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertEqual(trace.instrumentation_method,
                         dp.DOM_INSTRUMENTATION_METHOD)

    def test_the_version_is_recorded(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertEqual(trace.instrumentation_version,
                         dp.DOM_INSTRUMENTATION_VERSION)

    def test_the_method_is_the_static_analysis_one(self):
        self.assertEqual(dp.DOM_INSTRUMENTATION_METHOD,
                         "served_document_static_analysis")

    def test_the_version_is_epic15(self):
        self.assertEqual(dp.DOM_INSTRUMENTATION_VERSION,
                         "epic15-dom-trace-1")

    def test_the_trace_is_serialisable(self):
        payload = dp.trace_dom_flow(document_lineage(),
                                    parameter=PARAMETER).to_dict()
        self.assertEqual(payload["flow"], dp.dom.FLOW_LINEAGE)
        self.assertTrue(payload["reaches_sink"])
        self.assertEqual(payload["instrumentation_version"],
                         dp.DOM_INSTRUMENTATION_VERSION)

    def test_the_summary_carries_the_audit_fields(self):
        summary = dp.dom.trace_summary(
            dp.trace_dom_flow(document_lineage(), parameter=PARAMETER))
        for key in ("kind", "flow", "source", "sink", "parameter",
                    "instrumentation_method", "instrumentation_version",
                    "reaches_sink", "reason"):
            self.assertIn(key, summary)

    def test_the_inline_script_count_is_reported(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertEqual(trace.inline_scripts, 1)

    def test_the_document_size_is_reported(self):
        document = document_lineage()
        trace = dp.trace_dom_flow(document, parameter=PARAMETER)
        self.assertEqual(trace.document_bytes, len(document))


class TestBoundedAnalysis(unittest.TestCase):
    """§10/§17: the analysis is bounded by the frozen ceiling."""

    def test_a_large_document_is_marked_bounded(self):
        trace = dp.trace_dom_flow(document_huge(), parameter=PARAMETER)
        self.assertTrue(trace.bounded)

    def test_a_small_document_is_not_marked_bounded(self):
        trace = dp.trace_dom_flow(document_lineage(), parameter=PARAMETER)
        self.assertFalse(trace.bounded)

    def test_the_bound_is_the_frozen_ceiling(self):
        self.assertEqual(ce.CEILINGS["browser_dom_observation_bytes"],
                         8 * 1024)

    def test_a_bounded_analysis_still_finds_the_flow(self):
        trace = dp.trace_dom_flow(document_huge(), parameter=PARAMETER)
        self.assertTrue(trace.produces_dom_sink_evidence)

    def test_a_bounded_analysis_reports_the_real_size(self):
        document = document_huge()
        trace = dp.trace_dom_flow(document, parameter=PARAMETER)
        self.assertEqual(trace.document_bytes, len(document))


class TestDeterminismAndReuse(unittest.TestCase):
    """§1/§13: deterministic, and reusing EPIC12's vocabularies."""

    def test_the_trace_is_deterministic(self):
        first = dp.trace_dom_flow(document_lineage(),
                                  parameter=PARAMETER).to_dict()
        for _ in range(3):
            self.assertEqual(
                dp.trace_dom_flow(document_lineage(),
                                  parameter=PARAMETER).to_dict(), first)

    def test_the_source_vocabulary_is_epic12s(self):
        self.assertIs(dp.dom.DOM_SOURCE_PATTERNS, ex.DOM_SOURCE_PATTERNS)

    def test_the_sink_vocabulary_is_epic12s(self):
        self.assertIs(dp.dom.DOM_SINK_PATTERNS, ex.DOM_SINK_PATTERNS)

    def test_the_flow_states_are_closed(self):
        self.assertEqual(len(dp.dom.FLOW_STATES), 6)

    def test_the_observation_kinds_are_closed(self):
        self.assertEqual(dp.dom.OBSERVATION_KINDS,
                         ("SERVER_SIDE_REFLECTION", "DOM_SOURCE", "DOM_SINK",
                          "EXECUTION"))

    def test_the_kinds_distinguish_reflection_from_execution(self):
        self.assertIn("SERVER_SIDE_REFLECTION", dp.dom.OBSERVATION_KINDS)
        self.assertIn("EXECUTION", dp.dom.OBSERVATION_KINDS)

    def test_the_dom_module_imports_no_browser(self):
        source = (Path(__file__).resolve().parents[1] / "backend"
                  / "research_agents" / "verification" / "deep"
                  / "dom.py").read_text(encoding="utf-8")
        for forbidden in ("playwright", "selenium", "subprocess", "socket"):
            self.assertNotIn(forbidden, source)

    def test_the_dom_module_does_not_import_a_javascript_engine(self):
        source = (Path(__file__).resolve().parents[1] / "backend"
                  / "research_agents" / "verification" / "deep"
                  / "dom.py").read_text(encoding="utf-8")
        for forbidden in ("js2py", "quickjs", "dukpy", "node", "v8"):
            self.assertNotIn(forbidden, source)

    def test_no_source_pattern_was_added(self):
        self.assertEqual(len(ex.DOM_SOURCE_PATTERNS), 6)

    def test_no_sink_pattern_was_added(self):
        self.assertEqual(len(ex.DOM_SINK_PATTERNS), 8)

    def test_the_dom_sink_type_is_the_epic11_one(self):
        self.assertEqual(tx.DOM_SINK_IDENTIFIED, "DOM_SINK_IDENTIFIED")


if __name__ == "__main__":
    unittest.main()
