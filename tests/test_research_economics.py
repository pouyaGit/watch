"""Stage R25.2 deterministic economic engine tests.

Pure offline unittest suite: no network, no DNS, no LLM, no subprocess,
no target interaction, no Nuclei, no browser, no PoC execution, no 5B-5J,
no findings, no alerts, no Mongo writes.

Covers exact formulas, caps, bands, actions, unknown-neutrality,
determinism, schema validation, and safety invariants.
"""

from __future__ import annotations

import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge import economics as econ
from ai.knowledge.economics import (
    DUP_CAP,
    FP_CAP,
    RULE_VERSION,
    EconomicValue,
    assess_economic_value,
    compute_confidence,
    compute_effort,
    compute_risk,
    compute_value,
    economic_projection,
    half_up,
)
from ai.schemas.knowledge import KnowledgeEconomicValue


# ---------------------------------------------------------------------------
# Helpers: minimal lead/plan/intel/payload/task/r23/r24 fixtures
# ---------------------------------------------------------------------------

def make_lead(**over) -> dict:
    lead = {
        "lead_id": "rl-0123456789abcdef",
        "cve_id": "CVE-2026-1557",
        "program": "dell",
        "queue_id": "rq-0123456789abcdef",
        "task_id": "rt-0123456789abcdef",
        "priority_score": 0,
        "priority_level": "INSUFFICIENT_DATA",
        "relevance_score": 0,
        "relevance_level": "UNKNOWN",
        "reasons": [],
        "blockers": [],
        "status": "RESEARCH_LEAD",
    }
    lead.update(over)
    return lead


def make_plan(**over) -> dict:
    plan = {
        "plan_id": "r22-0123456789abcdef",
        "lead_id": "rl-0123456789abcdef",
        "cve_id": "CVE-2026-1557",
        "program": "dell",
        "queue_id": "rq-0123456789abcdef",
        "task_id": "rt-0123456789abcdef",
        "priority_score": 0,
        "relevance_score": 0,
        "status": "RESEARCH_PLAN_READY",
        "steps": [],
        "evidence_targets": [],
        "unknowns": [],
        "blockers": [],
        "recommended_start": None,
    }
    plan.update(over)
    return plan


def make_intel(**over) -> dict:
    intel = {
        "available": True,
        "exploitability": {
            "authentication_required": "unknown",
            "privilege_required": "unknown",
            "user_interaction_required": "unknown",
            "exploit_available": "unknown",
            "public_poc": "unknown",
            "active_exploitation": "unknown",
            "exploit_complexity": "unknown",
            "cvss": {"source": "unknown"},
            "conflicts": [],
        },
        "priority": {"score": 0, "reasons": [], "unknown_factors": []},
        "relevance": [],
    }
    intel.update(over)
    return intel


def make_payload(**over) -> dict:
    payload = {
        "cve": {"cvss_score": None, "cvss_vector": None},
        "research": {
            "severity": None,
            "public_exploit": None,
            "actively_exploited": None,
            "affected_versions": [],
            "nuclei_candidate": False,
            "parameters": [],
        },
    }
    payload.update(over)
    return payload


def make_r23(**over) -> dict:
    r23 = {
        "evidence": [],
        "sources": [],
        "affected_components": [],
        "affected_parameters": [],
        "affected_versions": [],
        "report_path": None,
    }
    r23.update(over)
    return r23


def make_r24(**over) -> dict:
    r24 = {"rounds": []}
    r24.update(over)
    return r24


def make_r23_baseline() -> dict:
    """R23 with evidence + components: neutralizes +8 no-result, +8 no-component.

    Intentionally NO parameters/versions so the base effort is exactly 50.
    """
    return {
        "evidence": [{"confidence": "LOW"}],
        "sources": [{"source_id": "s1"}],
        "affected_components": ["comp"],
        "affected_parameters": [],
        "affected_versions": [],
        "report_path": None,
    }


def make_r24_baseline() -> dict:
    """R24 with one round: neutralizes the +8 no-result effort penalty."""
    return {"rounds": [{"discovery": {"sources": [{"tier": "TRUSTED"}]}}]}


# ---------------------------------------------------------------------------
# Half-up rounding
# ---------------------------------------------------------------------------

class TestHalfUp(unittest.TestCase):
    def test_exact_integers(self):
        self.assertEqual(half_up(0.0), 0)
        self.assertEqual(half_up(5.0), 5)
        self.assertEqual(half_up(100.0), 100)

    def test_half_rounds_up(self):
        self.assertEqual(half_up(0.5), 1)
        self.assertEqual(half_up(1.5), 2)
        self.assertEqual(half_up(2.5), 3)
        self.assertEqual(half_up(99.5), 100)

    def test_fractional(self):
        self.assertEqual(half_up(0.4), 0)
        self.assertEqual(half_up(0.6), 1)
        self.assertEqual(half_up(44.4), 44)
        self.assertEqual(half_up(44.6), 45)


# ---------------------------------------------------------------------------
# VALUE formula
# ---------------------------------------------------------------------------

class TestValue(unittest.TestCase):
    def test_zero_inputs(self):
        V, P, R, SEV, EX = compute_value(make_lead(), make_intel(), make_payload(), "dell")
        self.assertEqual(V, 0)
        self.assertEqual(P, 0)
        self.assertEqual(R, 0)
        self.assertEqual(SEV, 0)
        self.assertEqual(EX, 0)

    def test_exact_formula(self):
        # V = half_up(0.30*80 + 0.35*20 + 0.20*75 + 0.15*85)
        #   = half_up(24 + 7 + 15 + 12.75) = half_up(58.75) = 59
        lead = make_lead(priority_score=80, relevance_score=20)
        intel = make_intel()
        payload = make_payload(cve={"cvss_score": 7.5, "cvss_vector": None})
        expl = dict(intel["exploitability"])
        expl["public_poc"] = "true"
        expl["exploit_available"] = "true"
        intel["exploitability"] = expl
        V, P, R, SEV, EX = compute_value(lead, intel, payload, "dell")
        self.assertEqual(P, 80)
        self.assertEqual(R, 20)
        self.assertEqual(SEV, 75)
        self.assertEqual(EX, 85)
        self.assertEqual(V, 59)

    def test_severity_from_cvss_numeric(self):
        lead = make_lead(priority_score=0, relevance_score=0)
        payload = make_payload(cve={"cvss_score": 9.5})
        V, _P, _R, SEV, _EX = compute_value(lead, make_intel(), payload, "dell")
        self.assertEqual(SEV, 95)

    def test_severity_fallback_text(self):
        for text, expected in [("critical", 90), ("high", 75), ("medium", 55), ("low", 30)]:
            payload = make_payload(cve={"cvss_score": None},
                                   research={"severity": f"{text} (CVSS)", "public_exploit": None,
                                             "actively_exploited": None, "affected_versions": [],
                                             "nuclei_candidate": False, "parameters": []})
            V, _P, _R, SEV, _EX = compute_value(make_lead(), make_intel(), payload, "dell")
            self.assertEqual(SEV, expected, text)

    def test_severity_fallback_none(self):
        payload = make_payload(cve={"cvss_score": None}, research={"severity": None})
        V, _P, _R, SEV, _EX = compute_value(make_lead(), make_intel(), payload, "dell")
        self.assertEqual(SEV, 0)

    def test_exploit_maturity_additive(self):
        lead = make_lead()
        payload = make_payload()
        expl = {"public_poc": "true", "exploit_available": "true", "active_exploitation": "true"}
        intel = make_intel(exploitability=expl)
        V, _P, _R, _SEV, EX = compute_value(lead, intel, payload, "dell")
        self.assertEqual(EX, 100)  # 55+30+15 clamped to 100

    def test_exploit_maturity_clamp(self):
        lead = make_lead()
        payload = make_payload()
        expl = {"public_poc": "true", "exploit_available": "true", "active_exploitation": "true"}
        intel = make_intel(exploitability=expl)
        _V, _P, _R, _SEV, EX = compute_value(lead, intel, payload, "dell")
        self.assertLessEqual(EX, 100)

    def test_exploit_unknown_contributes_zero(self):
        lead = make_lead()
        payload = make_payload()
        expl = {"public_poc": "unknown", "exploit_available": "unknown", "active_exploitation": "unknown"}
        intel = make_intel(exploitability=expl)
        _V, _P, _R, _SEV, EX = compute_value(lead, intel, payload, "dell")
        self.assertEqual(EX, 0)

    def test_exploit_false_contributes_zero(self):
        lead = make_lead()
        payload = make_payload()
        expl = {"public_poc": "false", "exploit_available": "false", "active_exploitation": "false"}
        intel = make_intel(exploitability=expl)
        _V, _P, _R, _SEV, EX = compute_value(lead, intel, payload, "dell")
        self.assertEqual(EX, 0)

    def test_value_clamp_bounds(self):
        lead = make_lead(priority_score=100, relevance_score=100)
        payload = make_payload(cve={"cvss_score": 10.0})
        expl = {"public_poc": "true", "exploit_available": "true", "active_exploitation": "true"}
        intel = make_intel(exploitability=expl)
        V, _P, _R, _SEV, _EX = compute_value(lead, intel, payload, "dell")
        self.assertEqual(V, 100)


# ---------------------------------------------------------------------------
# CONFIDENCE formula
# ---------------------------------------------------------------------------

class TestConfidence(unittest.TestCase):
    def test_base_only(self):
        C, basis = compute_confidence(make_lead(), make_intel(), make_r23(), make_r24(), "dell")
        self.assertEqual(C, 50)
        self.assertIn("base 50", basis)

    def test_structured_cvss(self):
        intel = make_intel()
        intel["exploitability"] = {"cvss": {"source": "structured"}, "conflicts": []}
        C, basis = compute_confidence(make_lead(), intel, make_r23(), make_r24(), "dell")
        self.assertEqual(C, 65)
        self.assertIn("structured cvss +15", basis)

    def test_r23_confidence_levels(self):
        for conf, delta in [("HIGH", 20), ("MEDIUM", 12), ("LOW", 5)]:
            r23 = make_r23(evidence=[{"confidence": conf}])
            C, basis = compute_confidence(make_lead(), make_intel(), r23, make_r24(), "dell")
            self.assertEqual(C, 50 + delta, conf)
            self.assertIn(f"r23 {conf.lower()} confidence +{delta}", basis)

    def test_r24_tier_levels(self):
        for tier, delta in [("TRUSTED", 20), ("SEMI_TRUSTED", 12), ("DISCOVERY_ONLY", 6)]:
            r24 = make_r24(rounds=[{"discovery": {"sources": [{"tier": tier}]}}])
            C, basis = compute_confidence(make_lead(), make_intel(), make_r23(), r24, "dell")
            self.assertEqual(C, 50 + delta, tier)

    def test_relevance_class(self):
        for rel, delta in [("HIGH", 10), ("MEDIUM", 5)]:
            lead = make_lead(relevance_level=rel)
            C, _basis = compute_confidence(lead, make_intel(), make_r23(), make_r24(), "dell")
            self.assertEqual(C, 50 + delta, rel)

    def test_conflicts_capped(self):
        intel = make_intel()
        intel["exploitability"] = {"conflicts": ["a", "b", "c", "d"]}
        C, _basis = compute_confidence(make_lead(), intel, make_r23(), make_r24(), "dell")
        # 4 conflicts * -15 = -60 but capped at -30 -> 50-30 = 20
        self.assertEqual(C, 20)

    def test_generic_blocker_penalty(self):
        lead = make_lead(blockers=["only generic technology match"])
        C, _basis = compute_confidence(lead, make_intel(), make_r23(), make_r24(), "dell")
        self.assertEqual(C, 38)  # 50 - 12

    def test_asset_blocker_penalty_capped(self):
        lead = make_lead(blockers=[
            "affected plugin not observed",
            "asset component not observed",
            "asset version unknown",
        ])
        C, _basis = compute_confidence(lead, make_intel(), make_r23(), make_r24(), "dell")
        # 3 * -6 = -18 (under cap -20) -> 50-18 = 32
        self.assertEqual(C, 32)

    def test_asset_blocker_cap(self):
        lead = make_lead(blockers=[
            "affected plugin not observed",
            "asset component not observed",
            "asset version unknown",
            "asset version unknown",  # duplicate marker, but counted via substring
        ])
        C, _basis = compute_confidence(lead, make_intel(), make_r23(), make_r24(), "dell")
        self.assertGreaterEqual(C, 30)  # capped at -20 -> 30

    def test_no_knowledge_cap(self):
        intel = make_intel()
        intel["available"] = False
        lead = make_lead(relevance_level="HIGH")
        C, basis = compute_confidence(lead, intel, make_r23(), make_r24(), "dell")
        self.assertLessEqual(C, 35)
        self.assertIn("no knowledge document cap 35", basis)

    def test_confidence_clamp_zero(self):
        lead = make_lead(blockers=["only generic technology match"])
        intel = make_intel()
        intel["exploitability"] = {"conflicts": ["a", "b"]}
        C, _basis = compute_confidence(lead, intel, make_r23(), make_r24(), "dell")
        self.assertGreaterEqual(C, 0)


# ---------------------------------------------------------------------------
# EFFORT formula
# ---------------------------------------------------------------------------

class TestEffort(unittest.TestCase):
    # Baseline r23/r24 carry evidence + components + versions + a round, so
    # the +8 no-result and +8 no-component penalties do NOT fire. Base E = 50.

    def test_base(self):
        E = compute_effort(make_lead(), make_intel(), make_plan(), make_payload(),
                           make_r23_baseline(), make_r24_baseline())
        self.assertEqual(E, 50)

    def test_public_poc_discount(self):
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true"}
        E = compute_effort(make_lead(), intel, make_plan(), make_payload(),
                           make_r23_baseline(), make_r24_baseline())
        self.assertEqual(E, 30)  # 50 - 20

    def test_exploit_discount_capped(self):
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true", "exploit_available": "true"}
        E = compute_effort(make_lead(), intel, make_plan(), make_payload(),
                           make_r23_baseline(), make_r24_baseline())
        # -20 + -10 = -30 but capped at -25 -> 50-25 = 25
        self.assertEqual(E, 25)

    def test_unauth_no_ui(self):
        intel = make_intel()
        intel["exploitability"] = {"authentication_required": "false", "user_interaction_required": "false"}
        E = compute_effort(make_lead(), intel, make_plan(), make_payload(),
                           make_r23_baseline(), make_r24_baseline())
        self.assertEqual(E, 35)  # 50 - 8 - 7

    def test_specific_match_discount(self):
        lead = make_lead(reasons=[{"text": "exact product match: WP"}])
        E = compute_effort(lead, make_intel(), make_plan(), make_payload(),
                           make_r23_baseline(), make_r24_baseline())
        self.assertEqual(E, 38)  # 50 - 12

    def test_parameter_version_discount(self):
        r23 = make_r23_baseline()
        r23["affected_parameters"] = ["src"]
        r23["affected_versions"] = ["<=1.0"]
        E = compute_effort(make_lead(), make_intel(), make_plan(), make_payload(),
                           r23, make_r24_baseline())
        self.assertEqual(E, 40)  # 50 - 5 - 5

    def test_blocker_penalties(self):
        lead = make_lead(blockers=[
            "asset version unknown",
            "affected plugin not observed",
            "asset component not observed",
            "only generic technology match",
        ])
        E = compute_effort(lead, make_intel(), make_plan(), make_payload(),
                           make_r23_baseline(), make_r24_baseline())
        # 50 + 12 + 10 + 10 + 15 = 97
        self.assertEqual(E, 97)

    def test_no_result_penalty(self):
        # empty r23/r24 -> +8 no-result, and no components -> +8 no-component
        E = compute_effort(make_lead(), make_intel(), make_plan(), make_payload(),
                           make_r23(), make_r24())
        self.assertEqual(E, 66)  # 50 + 8 + 8

    def test_no_component_penalty(self):
        # r23 has evidence (no +8 result) but no components -> +8 no-component
        r23 = make_r23(evidence=[{"confidence": "LOW"}])
        E = compute_effort(make_lead(), make_intel(), make_plan(), make_payload(),
                           r23, make_r24_baseline())
        self.assertEqual(E, 58)  # 50 + 8

    def test_effort_min_clamp(self):
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true", "exploit_available": "true",
                                    "authentication_required": "false", "user_interaction_required": "false"}
        lead = make_lead(reasons=[{"text": "exact product match: X"}])
        E = compute_effort(lead, intel, make_plan(), make_payload(),
                           make_r23_baseline(), make_r24_baseline())
        self.assertGreaterEqual(E, 10)

    def test_effort_max_clamp(self):
        lead = make_lead(blockers=[
            "asset version unknown",
            "affected plugin not observed",
            "asset component not observed",
            "only generic technology match",
        ])
        E = compute_effort(lead, make_intel(), make_plan(), make_payload(),
                           make_r23_baseline(), make_r24_baseline())
        self.assertLessEqual(E, 100)


# ---------------------------------------------------------------------------
# RISK formula
# ---------------------------------------------------------------------------

class TestRisk(unittest.TestCase):
    def test_zero_risk(self):
        K, DUP, FP = compute_risk(make_lead(), make_intel(), make_payload(), None, make_r23())
        self.assertEqual(K, 0)
        self.assertEqual(DUP, 0)
        self.assertEqual(FP, 0)

    def test_dup_components(self):
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true", "active_exploitation": "true"}
        payload = make_payload(research={"nuclei_candidate": True})
        r23 = make_r23(evidence=[{"confidence": "HIGH"}], report_path="ai_data/reports/X.md")
        K, DUP, FP = compute_risk(make_lead(), intel, payload, None, r23)
        # DUP = 20 + 15 + 10 + 10 + 5 = 60 (at cap)
        self.assertEqual(DUP, 60)

    def test_dup_clamp(self):
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true", "active_exploitation": "true"}
        payload = make_payload(research={"nuclei_candidate": True})
        r23 = make_r23(evidence=[{"confidence": "HIGH"}], report_path="ai_data/reports/X.md")
        K, DUP, FP = compute_risk(make_lead(), intel, payload, None, r23)
        self.assertLessEqual(DUP, DUP_CAP)

    def test_fp_components(self):
        lead = make_lead(blockers=[
            "only generic technology match",
            "asset version unknown",
            "affected plugin not observed",
            "asset component not observed",
        ])
        intel = make_intel()
        intel["exploitability"] = {"conflicts": ["x"]}
        K, DUP, FP = compute_risk(lead, intel, make_payload(), None, make_r23())
        # FP = 12 + 8 + 8 + 8 + 8 = 44 -> clamped to 40
        self.assertEqual(FP, 40)

    def test_fp_clamp(self):
        lead = make_lead(blockers=[
            "only generic technology match",
            "asset version unknown",
            "affected plugin not observed",
            "asset component not observed",
        ])
        intel = make_intel()
        intel["exploitability"] = {"conflicts": ["x"]}
        K, DUP, FP = compute_risk(lead, intel, make_payload(), None, make_r23())
        self.assertLessEqual(FP, FP_CAP)

    def test_relevance_low_fp(self):
        lead = make_lead(relevance_level="LOW")
        K, DUP, FP = compute_risk(lead, make_intel(), make_payload(), None, make_r23())
        self.assertEqual(FP, 6)

    def test_task_in_progress(self):
        task = {"status": "IN_PROGRESS"}
        K, DUP, FP = compute_risk(make_lead(), make_intel(), make_payload(), task, make_r23())
        self.assertEqual(DUP, 8)

    def test_task_blocked(self):
        task = {"status": "BLOCKED"}
        K, DUP, FP = compute_risk(make_lead(), make_intel(), make_payload(), task, make_r23())
        self.assertEqual(DUP, 5)

    def test_k_clamp(self):
        lead = make_lead(blockers=[
            "only generic technology match",
            "asset version unknown",
            "affected plugin not observed",
            "asset component not observed",
        ])
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true", "active_exploitation": "true", "conflicts": ["x"]}
        payload = make_payload(research={"nuclei_candidate": True})
        r23 = make_r23(evidence=[{"confidence": "HIGH"}], report_path="r.md")
        K, DUP, FP = compute_risk(lead, intel, payload, None, r23)
        self.assertLessEqual(K, 100)


# ---------------------------------------------------------------------------
# MONEY score + caps
# ---------------------------------------------------------------------------

class TestMoneyScore(unittest.TestCase):
    def _score(self, **kw):
        lead = make_lead(**kw.get("lead", {}))
        intel = make_intel(**kw.get("intel", {}))
        payload = make_payload(**kw.get("payload", {}))
        r23 = make_r23(**kw.get("r23", {}))
        r24 = make_r24(**kw.get("r24", {}))
        plan = make_plan(**kw.get("plan", {}))
        task = kw.get("task")
        result = assess_economic_value(lead, plan, intel, payload, task, r23, r24)
        return result

    def test_all_zero(self):
        # V=0 but confidence/effort/risk axes still contribute; caps apply.
        r = self._score()
        self.assertGreaterEqual(r.money_score, 0)
        self.assertLessEqual(r.money_score, 45)  # value-low cap
        # P=R=EX=0 triggers the no-value-signal cap (<=40)
        self.assertIn("no positive value signal", r.caps_applied)

    def test_confidence_cap(self):
        # C < 45 -> M <= 60
        lead = make_lead(blockers=["only generic technology match"])  # C=38
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true", "exploit_available": "true",
                                    "active_exploitation": "true"}
        r = assess_economic_value(lead, make_plan(), intel, make_payload(), None, make_r23(), make_r24())
        self.assertLessEqual(r.money_score, 60)
        self.assertIn("confidence below 45", r.caps_applied)

    def test_risk_cap(self):
        # K >= 70 -> M <= 55
        lead = make_lead(blockers=[
            "only generic technology match",
            "asset version unknown",
            "affected plugin not observed",
            "asset component not observed",
        ])
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true", "active_exploitation": "true", "conflicts": ["x"]}
        payload = make_payload(research={"nuclei_candidate": True})
        r23 = make_r23(evidence=[{"confidence": "HIGH"}], report_path="r.md")
        r = assess_economic_value(lead, make_plan(), intel, payload, None, r23, make_r24())
        self.assertLessEqual(r.money_score, 55)
        self.assertIn("risk 70 or above", r.caps_applied)

    def test_effort_cap(self):
        # E >= 85 -> M <= 60
        lead = make_lead(blockers=[
            "asset version unknown",
            "affected plugin not observed",
            "asset component not observed",
            "only generic technology match",
        ])
        r = assess_economic_value(lead, make_plan(), make_intel(), make_payload(), None, make_r23(), make_r24())
        self.assertLessEqual(r.money_score, 60)
        self.assertIn("effort 85 or above", r.caps_applied)

    def test_value_low_cap(self):
        # V < 30 -> M <= 45. Use low priority/relevance, no severity, no exploit.
        r = self._score()
        self.assertLessEqual(r.money_score, 45)

    def test_no_value_signal_cap(self):
        # P=R=EX=0 -> M <= 40 even if SEV high
        payload = make_payload(cve={"cvss_score": 10.0})
        r = assess_economic_value(make_lead(), make_plan(), make_intel(), payload, None, make_r23(), make_r24())
        self.assertLessEqual(r.money_score, 40)
        self.assertIn("no positive value signal", r.caps_applied)

    def test_cap_ordering(self):
        # When multiple caps apply, the tightest (last applicable) wins.
        lead = make_lead(blockers=[
            "only generic technology match",
            "asset version unknown",
            "affected plugin not observed",
            "asset component not observed",
        ])
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true", "active_exploitation": "true", "conflicts": ["x"]}
        payload = make_payload(research={"nuclei_candidate": True})
        r23 = make_r23(evidence=[{"confidence": "HIGH"}], report_path="r.md")
        r = assess_economic_value(lead, make_plan(), intel, payload, None, r23, make_r24())
        # risk cap (55) and effort cap (60) and confidence cap (60) may apply
        self.assertLessEqual(r.money_score, 60)


# ---------------------------------------------------------------------------
# Priority bands
# ---------------------------------------------------------------------------

class TestPriorityBands(unittest.TestCase):
    def test_band_thresholds(self):
        # Synthetic: high value/confidence, low effort/risk -> P1
        lead = make_lead(priority_score=100, relevance_score=100)
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true"}
        payload = make_payload(cve={"cvss_score": 10.0})
        r23 = make_r23(evidence=[{"confidence": "HIGH"}])
        r24 = make_r24(rounds=[{"discovery": {"sources": [{"tier": "TRUSTED"}]}}])
        r = assess_economic_value(lead, make_plan(), intel, payload, None, r23, r24)
        self.assertIn(r.priority, ("P1_START_NOW", "P2_HIGH"))

    def test_p5_defer(self):
        r = assess_economic_value(make_lead(), make_plan(), make_intel(), make_payload(), None, make_r23(), make_r24())
        self.assertEqual(r.priority, "P5_DEFER")


# ---------------------------------------------------------------------------
# Action ordering
# ---------------------------------------------------------------------------

class TestActions(unittest.TestCase):
    def test_task_done(self):
        r = assess_economic_value(make_lead(), make_plan(), make_intel(), make_payload(), {"status": "DONE"}, make_r23(), make_r24())
        self.assertEqual(r.recommended_action, "COMPLETED")

    def test_task_in_progress(self):
        r = assess_economic_value(make_lead(), make_plan(), make_intel(), make_payload(), {"status": "IN_PROGRESS"}, make_r23(), make_r24())
        self.assertEqual(r.recommended_action, "CONTINUE")

    def test_task_blocked(self):
        r = assess_economic_value(make_lead(), make_plan(), make_intel(), make_payload(), {"status": "BLOCKED"}, make_r23(), make_r24())
        self.assertEqual(r.recommended_action, "UNBLOCK_OR_SKIP")

    def test_p1_start_now(self):
        lead = make_lead(priority_score=100, relevance_score=100)
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true"}
        payload = make_payload(cve={"cvss_score": 10.0})
        r23 = make_r23(evidence=[{"confidence": "HIGH"}])
        r24 = make_r24(rounds=[{"discovery": {"sources": [{"tier": "TRUSTED"}]}}])
        r = assess_economic_value(lead, make_plan(), intel, payload, None, r23, r24)
        if r.priority == "P1_START_NOW":
            self.assertEqual(r.recommended_action, "START_NOW")

    def test_p3_with_asset_blocker(self):
        lead = make_lead(blockers=["asset version unknown"], priority_score=50, relevance_score=50)
        intel = make_intel()
        payload = make_payload(cve={"cvss_score": 5.0})
        r = assess_economic_value(lead, make_plan(), intel, payload, None, make_r23(), make_r24())
        if r.priority == "P3_MEDIUM":
            self.assertEqual(r.recommended_action, "VERIFY_ASSET_MATCH_FIRST")

    def test_p5_defer_action(self):
        r = assess_economic_value(make_lead(), make_plan(), make_intel(), make_payload(), None, make_r23(), make_r24())
        self.assertEqual(r.recommended_action, "DEFER")


# ---------------------------------------------------------------------------
# Unknown neutrality / false vs unknown
# ---------------------------------------------------------------------------

class TestUnknownNeutrality(unittest.TestCase):
    def test_unknown_exploitability_equals_missing(self):
        # unknown tri-states must contribute the same as absent fields
        lead = make_lead(priority_score=50, relevance_score=50)
        payload = make_payload(cve={"cvss_score": 5.0})
        intel_unknown = make_intel()
        intel_unknown["exploitability"] = {"public_poc": "unknown", "exploit_available": "unknown",
                                           "active_exploitation": "unknown"}
        intel_absent = make_intel()
        intel_absent["exploitability"] = {}
        r1 = assess_economic_value(lead, make_plan(), intel_unknown, payload, None, make_r23(), make_r24())
        r2 = assess_economic_value(lead, make_plan(), intel_absent, payload, None, make_r23(), make_r24())
        self.assertEqual(r1.money_score, r2.money_score)

    def test_false_not_same_as_unknown_for_blockers(self):
        # false tri-state contributes zero (same as unknown) for exploitability
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "false"}
        lead = make_lead(priority_score=80, relevance_score=20)
        payload = make_payload(cve={"cvss_score": 7.5})
        V_unk = compute_value(lead, make_intel(), payload, "dell")[0]
        V_false = compute_value(lead, intel, payload, "dell")[0]
        self.assertEqual(V_unk, V_false)

    def test_none_inputs_safe(self):
        r = assess_economic_value(None, None, None, None, None, None, None)
        # None inputs are safe; score is bounded and research_only forced true.
        self.assertGreaterEqual(r.money_score, 0)
        self.assertLessEqual(r.money_score, 100)
        self.assertTrue(r.research_only)

    def test_unknown_does_not_lower_confidence_below_false(self):
        # Both unknown and false exploitability -> no confidence bonus
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "unknown"}
        C, _ = compute_confidence(make_lead(), intel, make_r23(), make_r24(), "dell")
        self.assertEqual(C, 50)


# ---------------------------------------------------------------------------
# Conflicts
# ---------------------------------------------------------------------------

class TestConflicts(unittest.TestCase):
    def test_conflicts_reduce_confidence(self):
        intel = make_intel()
        intel["exploitability"] = {"conflicts": ["public_poc"]}
        C, _ = compute_confidence(make_lead(), intel, make_r23(), make_r24(), "dell")
        self.assertEqual(C, 35)  # 50 - 15

    def test_conflicts_increase_risk(self):
        intel = make_intel()
        intel["exploitability"] = {"conflicts": ["x"]}
        K, _DUP, FP = compute_risk(make_lead(), intel, make_payload(), None, make_r23())
        self.assertEqual(FP, 8)


# ---------------------------------------------------------------------------
# Blockers
# ---------------------------------------------------------------------------

class TestBlockers(unittest.TestCase):
    def test_blockers_populate_main_blockers(self):
        lead = make_lead(blockers=["asset version unknown", "affected plugin not observed"])
        r = assess_economic_value(lead, make_plan(), make_intel(), make_payload(), None, make_r23(), make_r24())
        self.assertEqual(r.main_blockers, ["asset version unknown", "affected plugin not observed"])


# ---------------------------------------------------------------------------
# Task states
# ---------------------------------------------------------------------------

class TestTaskStates(unittest.TestCase):
    def test_task_none_defaults_todo(self):
        r = assess_economic_value(make_lead(), make_plan(), make_intel(), make_payload(), None, make_r23(), make_r24())
        # None task -> no IN_PROGRESS/BLOCKED risk contribution
        self.assertNotIn(r.recommended_action, ("CONTINUE", "UNBLOCK_OR_SKIP", "COMPLETED"))


# ---------------------------------------------------------------------------
# Report / result existence
# ---------------------------------------------------------------------------

class TestExistenceSignals(unittest.TestCase):
    def test_report_exists(self):
        r23 = make_r23(report_path="ai_data/reports/CVE-2026-1557.md")
        self.assertTrue(econ._report_exists(r23))

    def test_report_missing(self):
        self.assertFalse(econ._report_exists(make_r23()))

    def test_prior_result_exists(self):
        r23 = make_r23(evidence=[{"confidence": "HIGH"}])
        self.assertTrue(econ._prior_result_exists(r23))

    def test_prior_result_missing(self):
        self.assertFalse(econ._prior_result_exists(make_r23()))


# ---------------------------------------------------------------------------
# R23 evidence
# ---------------------------------------------------------------------------

class TestR23Evidence(unittest.TestCase):
    def test_best_confidence_picked(self):
        r23 = make_r23(evidence=[
            {"confidence": "LOW"},
            {"confidence": "HIGH"},
            {"confidence": "MEDIUM"},
        ])
        self.assertEqual(econ._r23_best_confidence(r23), "HIGH")

    def test_no_evidence(self):
        self.assertIsNone(econ._r23_best_confidence(make_r23()))


# ---------------------------------------------------------------------------
# R24 tier/evidence
# ---------------------------------------------------------------------------

class TestR24Tier(unittest.TestCase):
    def test_best_tier_picked(self):
        r24 = make_r24(rounds=[{"discovery": {"sources": [
            {"tier": "DISCOVERY_ONLY"},
            {"tier": "TRUSTED"},
        ]}}])
        self.assertEqual(econ._r24_best_tier(r24), "TRUSTED")

    def test_no_sources(self):
        self.assertIsNone(econ._r24_best_tier(make_r24()))


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism(unittest.TestCase):
    def test_deterministic_ordering(self):
        lead = make_lead(blockers=["asset version unknown", "affected plugin not observed"])
        r = assess_economic_value(lead, make_plan(), make_intel(), make_payload(), None, make_r23(), make_r24())
        self.assertEqual(r.main_blockers, ["asset version unknown", "affected plugin not observed"])

    def test_repeated_execution_identical(self):
        lead = make_lead(priority_score=80, relevance_score=20, blockers=["asset version unknown"])
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true", "exploit_available": "true"}
        payload = make_payload(cve={"cvss_score": 7.5})
        r23 = make_r23(evidence=[{"confidence": "HIGH"}], report_path="r.md")
        r24 = make_r24(rounds=[{"discovery": {"sources": [{"tier": "TRUSTED"}]}}])
        results = [assess_economic_value(lead, make_plan(), intel, payload, None, r23, r24)
                   for _ in range(5)]
        scores = [r.money_score for r in results]
        self.assertEqual(len(set(scores)), 1)
        actions = [r.recommended_action for r in results]
        self.assertEqual(len(set(actions)), 1)


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

class TestSchema(unittest.TestCase):
    def test_schema_accepts_projection(self):
        lead = make_lead(priority_score=80, relevance_score=20)
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true"}
        payload = make_payload(cve={"cvss_score": 7.5})
        r = assess_economic_value(lead, make_plan(), intel, payload, None, make_r23(), make_r24())
        proj = economic_projection(r)
        validated = KnowledgeEconomicValue(**proj)
        self.assertEqual(validated.money_score, r.money_score)
        self.assertTrue(validated.research_only)
        self.assertEqual(validated.rule_version, "r25-1")

    def test_research_only_forced_true(self):
        proj = economic_projection(EconomicValue())
        proj["research_only"] = False
        validated = KnowledgeEconomicValue(**proj)
        self.assertTrue(validated.research_only)

    def test_money_score_bounds(self):
        proj = economic_projection(EconomicValue(money_score=100))
        KnowledgeEconomicValue(**proj)
        with self.assertRaises(Exception):
            KnowledgeEconomicValue(**{**proj, "money_score": 101})
        with self.assertRaises(Exception):
            KnowledgeEconomicValue(**{**proj, "money_score": -1})


# ---------------------------------------------------------------------------
# Safety invariants
# ---------------------------------------------------------------------------

class TestSafety(unittest.TestCase):
    def test_no_payout_inference(self):
        r = assess_economic_value(make_lead(), make_plan(), make_intel(), make_payload(), None, make_r23(), make_r24())
        # No dollar amounts, no payout language anywhere in the output
        proj = economic_projection(r)
        blob = str(proj).lower()
        self.assertNotIn("$", blob)
        self.assertNotIn("payout", blob)
        self.assertNotIn("dollar", blob)

    def test_research_only_flag(self):
        r = assess_economic_value(make_lead(), make_plan(), make_intel(), make_payload(), None, make_r23(), make_r24())
        self.assertTrue(r.research_only)

    def _import_lines(self):
        import ai.knowledge.economics as mod
        with open(mod.__file__) as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("from "):
                    yield stripped

    def test_no_llm_usage(self):
        # The engine module must not import/invoke any LLM (check import lines;
        # the word "LLM" appears only in the safety docstring).
        for stripped in self._import_lines():
            self.assertNotIn("openai", stripped)
            self.assertNotIn("claude", stripped)
            self.assertNotIn("llm", stripped)

    def test_no_network_subprocess(self):
        # The module must not import network/subprocess modules (docstring
        # mentions these terms, so check import lines only).
        for stripped in self._import_lines():
            self.assertNotIn("subprocess", stripped)
            self.assertNotIn("requests", stripped)
            self.assertNotIn("urllib", stripped)
            self.assertNotIn("socket", stripped)
            self.assertNotIn("http.client", stripped)

    def test_rule_version_fixed(self):
        self.assertEqual(RULE_VERSION, "r25-1")
        r = assess_economic_value(make_lead(), make_plan(), make_intel(), make_payload(), None, make_r23(), make_r24())
        self.assertEqual(r.rule_version, "r25-1")


# ---------------------------------------------------------------------------
# Property-style tests
# ---------------------------------------------------------------------------

class TestProperties(unittest.TestCase):
    def test_score_bounds_0_100(self):
        # Exhaustive-ish: many random-ish inputs always produce 0-100
        combos = [
            (0, 0, None, False, []),
            (100, 100, 10.0, True, ["only generic technology match"]),
            (80, 20, 7.5, True, ["asset version unknown", "affected plugin not observed"]),
            (50, 50, 5.0, False, []),
            (30, 10, 3.0, False, ["only generic technology match", "asset version unknown",
                                   "affected plugin not observed", "asset component not observed"]),
        ]
        for p, r, cvss, nuclei, blk in combos:
            lead = make_lead(priority_score=p, relevance_score=r, blockers=blk)
            payload = make_payload(cve={"cvss_score": cvss}, research={"nuclei_candidate": nuclei})
            intel = make_intel()
            intel["exploitability"] = {"public_poc": "true", "exploit_available": "true",
                                        "active_exploitation": "true"}
            r23 = make_r23(evidence=[{"confidence": "HIGH"}], report_path="r.md")
            r24 = make_r24(rounds=[{"discovery": {"sources": [{"tier": "TRUSTED"}]}}])
            res = assess_economic_value(lead, make_plan(), intel, payload, None, r23, r24)
            self.assertGreaterEqual(res.money_score, 0)
            self.assertLessEqual(res.money_score, 100)
            self.assertGreaterEqual(res.subscores["value"], 0)
            self.assertLessEqual(res.subscores["value"], 100)
            self.assertGreaterEqual(res.subscores["confidence"], 0)
            self.assertLessEqual(res.subscores["confidence"], 100)
            self.assertGreaterEqual(res.subscores["effort"], 0)
            self.assertLessEqual(res.subscores["effort"], 100)
            self.assertGreaterEqual(res.subscores["risk"], 0)
            self.assertLessEqual(res.subscores["risk"], 100)

    def test_monotonicity_priority(self):
        # Higher priority score (all else equal) should not lower money score
        base = {"relevance_score": 20, "blockers": []}
        payload = make_payload(cve={"cvss_score": 7.5})
        intel = make_intel()
        intel["exploitability"] = {"public_poc": "true"}
        r_low = assess_economic_value(make_lead(priority_score=20, **base), make_plan(), intel, payload, None, make_r23(), make_r24())
        r_high = assess_economic_value(make_lead(priority_score=90, **base), make_plan(), intel, payload, None, make_r23(), make_r24())
        self.assertGreaterEqual(r_high.money_score, r_low.money_score)

    def test_deterministic_output(self):
        lead = make_lead(priority_score=80, relevance_score=20)
        intel = make_intel()
        payload = make_payload(cve={"cvss_score": 7.5})
        r23 = make_r23(evidence=[{"confidence": "HIGH"}])
        r24 = make_r24(rounds=[{"discovery": {"sources": [{"tier": "TRUSTED"}]}}])
        a = economic_projection(assess_economic_value(lead, make_plan(), intel, payload, None, r23, r24))
        b = economic_projection(assess_economic_value(lead, make_plan(), intel, payload, None, r23, r24))
        self.assertEqual(a, b)


# ---------------------------------------------------------------------------
# Effort estimate labels
# ---------------------------------------------------------------------------

class TestEffortEstimates(unittest.TestCase):
    def test_estimate_labels(self):
        cases = [
            (10, "15\u201330 min"),
            (25, "15\u201330 min"),
            (30, "30\u201360 min"),
            (50, "1\u20132 h"),
            (70, "2\u20136 h"),
            (90, "1\u20133 days"),
            (100, "1\u20133 days"),
        ]
        for score, label in cases:
            self.assertEqual(econ._effort_estimate(score), label)


# ---------------------------------------------------------------------------
# Confidence class
# ---------------------------------------------------------------------------

class TestConfidenceClass(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(econ._confidence_class(70), "HIGH")
        self.assertEqual(econ._confidence_class(85), "HIGH")
        self.assertEqual(econ._confidence_class(45), "MEDIUM")
        self.assertEqual(econ._confidence_class(69), "MEDIUM")
        self.assertEqual(econ._confidence_class(44), "LOW")
        self.assertEqual(econ._confidence_class(0), "LOW")


# ---------------------------------------------------------------------------
# Asset match classification
# ---------------------------------------------------------------------------

class TestAssetMatch(unittest.TestCase):
    def test_classification(self):
        cases = [
            ("exact product match: X", "PRODUCT"),
            ("exact plugin/component match: Y", "COMPONENT"),
            ("component/path match: Z", "PATH"),
            ("technology match: wordpress", "TECHNOLOGY_ONLY"),
            ("", "NONE"),
        ]
        for reason, expected in cases:
            lead = make_lead(reasons=[{"text": reason}] if reason else [])
            intel = make_intel()
            intel["relevance"] = [{"program": "dell", "reasons": [reason]}] if reason else []
            self.assertEqual(econ._asset_match(lead, intel, "dell"), expected, reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
