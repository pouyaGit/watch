"""tests/test_research_economics_calibration.py — Stage R25.6 calibration tests.

Deterministic, offline tests for the read-only Money Score calibration audit:
dataset join, score bands, minimum-sample threshold, rates, recommendation
states, r25-1 preservation, API/CLI shape, and safety invariants.

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no PoC execution, no 5B-5J, no findings, no alerts, no Mongo writes. Money
Score weights are never changed by any code path under test.
"""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.knowledge import economic_calibration as cal

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"


def _lead_id(n: int) -> str:
    return f"rl-{n:016x}"


def proj(lead_id=None, score=53, cve=CVE, program="dell",
         confidence="HIGH", subs=None):
    return {
        "lead_id": lead_id or _lead_id(1),
        "cve_id": cve,
        "program": program,
        "money_score": score,
        "priority": cal.band_for_score(score) + "_BAND",
        "confidence": confidence,
        "subscores": subs or {"value": 50, "confidence": 70,
                              "effort": 40, "risk": 50},
    }


def perf(lead_id=None, accepted=0, duplicate=0, rejected=0,
         not_applicable=0, wasted=0, in_progress=0, avg=0, total=None):
    terminal = accepted + duplicate + rejected + not_applicable + wasted
    attempts = terminal + in_progress

    def rate(n):
        return round(n / terminal, 4) if terminal > 0 else 0.0

    return {
        "lead_id": lead_id or _lead_id(1),
        "attempts": attempts,
        "terminal_attempts": terminal,
        "accepted": accepted,
        "duplicate": duplicate,
        "rejected": rejected,
        "not_applicable": not_applicable,
        "wasted_time": wasted,
        "in_progress": in_progress,
        "total_time_spent_minutes": (
            total if total is not None else avg * terminal
        ),
        "average_time_spent_minutes": avg,
        "acceptance_rate": rate(accepted),
        "duplicate_rate": rate(duplicate),
        "wasted_rate": rate(wasted),
        "outcome_confidence": "MEDIUM",
        "data_quality": "MEDIUM",
        "research_only": True,
    }


class TestScoreBands(unittest.TestCase):
    def test_boundaries(self):
        cases = {
            100: "P1", 85: "P1", 84: "P2", 65: "P2", 64: "P3",
            45: "P3", 44: "P4", 30: "P4", 29: "P5", 0: "P5",
            101: "P1", -5: "P5", None: "P5", "bad": "P5",
        }
        for score, expected in cases.items():
            with self.subTest(score=score):
                self.assertEqual(cal.band_for_score(score), expected)

    def test_bands_cover_full_range(self):
        for score in range(0, 101):
            band = cal.band_for_score(score)
            self.assertIn(band, {"P1", "P2", "P3", "P4", "P5"})

    def test_band_definitions(self):
        self.assertEqual(cal.SCORE_BANDS[0], ("P1", 85, 100))
        self.assertEqual(cal.SCORE_BANDS[-1], ("P5", 0, 29))


class TestDataset(unittest.TestCase):
    def test_join_by_lead_id(self):
        projections = [proj(_lead_id(1), 53), proj(_lead_id(2), 90)]
        performances = {_lead_id(1): perf(_lead_id(1), accepted=3),
                        _lead_id(2): perf(_lead_id(2), accepted=5)}
        dataset = cal.build_calibration_dataset(projections, performances)
        by_lead = {row["lead_id"]: row for row in dataset}
        self.assertEqual(by_lead[_lead_id(1)]["accepted"], 3)
        self.assertEqual(by_lead[_lead_id(2)]["accepted"], 5)

    def test_missing_performance_yields_zero_row(self):
        dataset = cal.build_calibration_dataset([proj(_lead_id(1), 53)], {})
        row = dataset[0]
        self.assertEqual(row["terminal_outcomes"], 0)
        self.assertEqual(row["acceptance_rate"], 0.0)
        self.assertEqual(row["data_quality"], "NONE")

    def test_dataset_fields(self):
        dataset = cal.build_calibration_dataset(
            [proj(_lead_id(1), 53)],
            {_lead_id(1): perf(_lead_id(1), accepted=1, avg=10)})
        row = dataset[0]
        for key in ("lead_id", "cve_id", "program", "money_score",
                    "priority", "confidence", "value", "effort", "risk",
                    "terminal_outcomes", "accepted", "duplicate",
                    "rejected", "not_applicable", "wasted_time",
                    "total_time_spent_minutes",
                    "average_time_spent_minutes", "acceptance_rate",
                    "duplicate_rate", "wasted_rate", "data_quality"):
            self.assertIn(key, row)

    def test_dataset_ordering_deterministic(self):
        projections = [
            proj(_lead_id(3), 53, program="indeed"),
            proj(_lead_id(1), 90, program="dell"),
            proj(_lead_id(2), 53, program="dell"),
        ]
        first = cal.build_calibration_dataset(projections, {})
        second = cal.build_calibration_dataset(list(reversed(projections)), {})
        self.assertEqual(first, second)
        self.assertEqual(
            [(r["money_score"], r["program"]) for r in first],
            [(90, "dell"), (53, "dell"), (53, "indeed")])


class TestStatistics(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(cal.build_calibration_dataset([], []), [])
        self.assertEqual(cal.calculate_band_statistics([], 10), [])
        stats = cal.calculate_global_statistics([])
        self.assertEqual(stats["leads"], 0)
        self.assertEqual(stats["terminal_outcomes"], 0)

    def test_all_six_statuses_and_in_progress_excluded(self):
        performance = perf(_lead_id(1), accepted=1, duplicate=1, rejected=1,
                           not_applicable=1, wasted=1, in_progress=2, avg=10)
        dataset = cal.build_calibration_dataset(
            [proj(_lead_id(1), 53)], {_lead_id(1): performance})
        band = cal.calculate_band_statistics(dataset, min_samples=1)[0]
        self.assertEqual(band["attempts"], 7)
        self.assertEqual(band["terminal_outcomes"], 5)
        self.assertEqual(band["in_progress"], 2)
        self.assertEqual(band["accepted"], 1)
        self.assertEqual(band["duplicate"], 1)
        self.assertEqual(band["rejected"], 1)
        self.assertEqual(band["not_applicable"], 1)
        self.assertEqual(band["wasted_time"], 1)
        self.assertEqual(band["acceptance_rate"], 0.2)
        self.assertEqual(band["duplicate_rate"], 0.2)
        self.assertEqual(band["wasted_rate"], 0.2)
        self.assertEqual(band["observed_negative_rate"], 0.8)
        self.assertEqual(band["average_time_spent_minutes"], 10)
        self.assertEqual(band["sample_status"], cal.SUFFICIENT_SAMPLE)

    def test_rates_and_average(self):
        dataset = cal.build_calibration_dataset(
            [proj(_lead_id(1), 70), proj(_lead_id(2), 55)],
            {
                _lead_id(1): perf(_lead_id(1), accepted=3, duplicate=1,
                                  avg=20),
                _lead_id(2): perf(_lead_id(2), accepted=1, wasted=1,
                                  avg=40),
            })
        global_stats = cal.calculate_global_statistics(dataset)
        self.assertEqual(global_stats["terminal_outcomes"], 6)
        self.assertEqual(global_stats["accepted"], 4)
        self.assertEqual(global_stats["duplicate"], 1)
        self.assertEqual(global_stats["wasted_time"], 1)
        self.assertEqual(global_stats["acceptance_rate"], 0.6667)
        self.assertAlmostEqual(global_stats["duplicate_rate"], 0.1667)
        self.assertAlmostEqual(global_stats["wasted_rate"], 0.1667)
        # terminal-time average: (20*4 + 40*2) / 6 = 26.67 -> 26
        self.assertEqual(global_stats["average_time_spent_minutes"], 26)

    def test_band_only_populated_bands(self):
        dataset = cal.build_calibration_dataset(
            [proj(_lead_id(1), 90), proj(_lead_id(2), 20)], {})
        bands = cal.calculate_band_statistics(dataset, min_samples=1)
        self.assertEqual([b["band"] for b in bands], ["P1", "P5"])

    def test_minimum_sample_threshold(self):
        dataset = cal.build_calibration_dataset(
            [proj(_lead_id(1), 53)],
            {_lead_id(1): perf(_lead_id(1), accepted=5)})
        low = cal.calculate_band_statistics(dataset, min_samples=5)[0]
        high = cal.calculate_band_statistics(dataset, min_samples=6)[0]
        self.assertEqual(low["sample_status"], cal.SUFFICIENT_SAMPLE)
        self.assertEqual(low["minimum_terminal_outcomes"], 5)
        self.assertEqual(high["sample_status"], cal.INSUFFICIENT_SAMPLE)

    def test_stats_bounded_and_deterministic(self):
        dataset = cal.build_calibration_dataset([proj(_lead_id(1), 53)], {})
        self.assertEqual(
            cal.calculate_band_statistics(dataset, 10),
            cal.calculate_band_statistics(dataset, 10))


class TestRecommendations(unittest.TestCase):
    def test_no_data(self):
        report = cal.build_calibration_report([], [])
        self.assertEqual(report["recommendation"], cal.NO_DATA)
        self.assertEqual(report["total_leads"], 0)

    def test_insufficient_no_terminal_outcomes(self):
        projections = [proj(_lead_id(1), 53), proj(_lead_id(2), 53,
                                                   program="indeed")]
        report = cal.build_calibration_report(projections, {})
        self.assertEqual(report["recommendation"], cal.INSUFFICIENT_DATA)
        self.assertEqual(report["total_terminal_outcomes"], 0)
        self.assertEqual(report["total_leads"], 2)

    def test_insufficient_single_sufficient_band(self):
        report = cal.build_calibration_report(
            [proj(_lead_id(1), 53)],
            {_lead_id(1): perf(_lead_id(1), accepted=10)})
        self.assertEqual(report["recommendation"], cal.INSUFFICIENT_DATA)
        self.assertEqual(report["bands"][0]["sample_status"],
                         cal.SUFFICIENT_SAMPLE)

    def test_consistent_multiple_bands(self):
        projections = [proj(_lead_id(1), 90), proj(_lead_id(2), 70),
                       proj(_lead_id(3), 53)]
        performances = {
            _lead_id(1): perf(_lead_id(1), accepted=10),
            _lead_id(2): perf(_lead_id(2), accepted=7, duplicate=2,
                              wasted=1),
            _lead_id(3): perf(_lead_id(3), accepted=5, duplicate=2,
                              wasted=3),
        }
        report = cal.build_calibration_report(projections, performances)
        self.assertEqual(report["recommendation"], cal.CONSISTENT)
        self.assertEqual(
            [b["band"] for b in report["bands"]], ["P1", "P2", "P3"])

    def test_possible_misordering(self):
        projections = [proj(_lead_id(1), 90), proj(_lead_id(2), 53)]
        performances = {
            _lead_id(1): perf(_lead_id(1), accepted=2, duplicate=3,
                              wasted=5),
            _lead_id(2): perf(_lead_id(2), accepted=8, duplicate=1,
                              wasted=1),
        }
        report = cal.build_calibration_report(projections, performances)
        self.assertEqual(report["recommendation"], cal.POSSIBLE_MISORDERING)

    def test_review_required_mixed(self):
        projections = [proj(_lead_id(1), 90), proj(_lead_id(2), 70)]
        performances = {
            _lead_id(1): perf(_lead_id(1), accepted=5, duplicate=3,
                              wasted=2),
            _lead_id(2): perf(_lead_id(2), accepted=6, duplicate=2,
                              wasted=2),
        }
        report = cal.build_calibration_report(projections, performances)
        self.assertEqual(report["recommendation"], cal.REVIEW_REQUIRED)

    def test_custom_min_samples(self):
        projections = [proj(_lead_id(1), 90), proj(_lead_id(2), 53)]
        performances = {
            _lead_id(1): perf(_lead_id(1), accepted=5),
            _lead_id(2): perf(_lead_id(2), accepted=5, wasted=5),
        }
        self.assertEqual(
            cal.build_calibration_report(
                projections, performances, min_samples=5)["recommendation"],
            cal.CONSISTENT)
        self.assertEqual(
            cal.build_calibration_report(
                projections, performances, min_samples=11)["recommendation"],
            cal.INSUFFICIENT_DATA)


class TestReportContract(unittest.TestCase):
    def _report(self, **over):
        projections = over.pop("projections", [proj(_lead_id(1), 53)])
        performances = over.pop("performances", {})
        return cal.build_calibration_report(
            projections, performances,
            generated_at="2026-09-11T12:00:00+00:00")

    def test_report_keys(self):
        report = self._report()
        for key in ("rule_version", "current_money_score_rule",
                    "generated_at", "minimum_terminal_outcomes",
                    "total_leads", "total_terminal_outcomes", "bands",
                    "global_statistics", "recommendation",
                    "recommendation_reasons", "limitations",
                    "weights_unchanged", "statement", "research_only"):
            self.assertIn(key, report)

    def test_r25_1_preserved(self):
        from ai.knowledge import economics
        report = self._report()
        self.assertEqual(report["rule_version"], "r25-1")
        self.assertEqual(report["current_money_score_rule"], "r25-1")
        self.assertEqual(report["current_money_score_rule"],
                         economics.RULE_VERSION)
        self.assertEqual(cal.CALIBRATION_RULE_VERSION, "r25-1")

    def test_weights_unchanged_statement(self):
        report = self._report()
        self.assertTrue(report["weights_unchanged"])
        self.assertEqual(report["statement"],
                         "Money Score weights were not changed.")
        self.assertTrue(report["research_only"])

    def test_no_statistical_significance_claim(self):
        report = self._report()
        text = " ".join(report["limitations"]).lower()
        self.assertIn("no statistical significance", text)

    def test_no_payout_keys_or_fields(self):
        report = self._report()
        blob = json.dumps(report).lower()
        for token in ("payout_amount", "bounty_amount", "reward_amount",
                      "\"payout\"", "\"bounty\"", "\"reward\""):
            self.assertNotIn(token, blob)
        for band in report["bands"]:
            for key in band:
                for token in ("payout", "bounty", "reward", "amount",
                              "usd", "dollar"):
                    self.assertNotIn(token, key.lower())

    def test_report_deterministic(self):
        projections = [proj(_lead_id(1), 53), proj(_lead_id(2), 90)]
        performances = {_lead_id(1): perf(_lead_id(1), accepted=2),
                        _lead_id(2): perf(_lead_id(2), duplicate=2)}
        first = cal.build_calibration_report(
            projections, performances, generated_at="X")
        second = cal.build_calibration_report(
            list(reversed(projections)), performances, generated_at="X")
        self.assertEqual(first, second)


class TestBackendCalibration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patcher = mock.patch(
            "backend.research_outcomes.OUTCOMES_DIR", self.root)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_real_corpus_zero_outcomes_report(self):
        from backend import research_calibration
        report = research_calibration.build_report()
        self.assertEqual(report["total_leads"], 2)
        self.assertEqual(report["total_terminal_outcomes"], 0)
        self.assertEqual(report["recommendation"], cal.INSUFFICIENT_DATA)
        self.assertTrue(report["weights_unchanged"])
        self.assertTrue(report["research_only"])
        # Money Score values are read but never modified
        from backend import research_economics
        self.assertEqual(
            [e["money_score"] for e in research_economics.build_economics()],
            [53, 53])

    def test_filters(self):
        from backend import research_calibration
        self.assertEqual(
            research_calibration.build_report(program="dell")["total_leads"],
            1)
        self.assertEqual(
            research_calibration.build_report(cve=CVE)["total_leads"], 2)
        self.assertEqual(
            research_calibration.build_report(
                cve="CVE-2024-0001")["total_leads"], 0)

    def test_malformed_cve(self):
        from backend import research_calibration
        with self.assertRaises(ValueError):
            research_calibration.build_report(cve="not-a-cve")

    def test_min_samples_validation(self):
        from backend import research_calibration
        with self.assertRaises(ValueError):
            research_calibration.build_report(min_samples=0)
        report = research_calibration.build_report(min_samples=3)
        self.assertEqual(report["minimum_terminal_outcomes"], 3)

    def test_summary(self):
        from backend import research_calibration
        summary = research_calibration.calibration_summary()
        self.assertEqual(summary["recommendation"], cal.INSUFFICIENT_DATA)
        self.assertEqual(summary["terminal_outcomes"], 0)
        self.assertTrue(summary["weights_unchanged"])
        self.assertTrue(summary["research_only"])

    def test_reads_do_not_write(self):
        from backend import research_calibration
        research_calibration.build_report()
        self.assertFalse(any(self.root.rglob("*")))


class TestCalibrationApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patcher = mock.patch(
            "backend.research_outcomes.OUTCOMES_DIR", self.root)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_auth_required(self):
        r = self.client.get("/api/research/economics/calibration")
        if API_KEY:
            self.assertEqual(r.status_code, 401)

    def test_shape(self):
        r = self._get("/api/research/economics/calibration")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["rule_version"], "r25-1")
        self.assertEqual(body["current_money_score_rule"], "r25-1")
        self.assertTrue(body["research_only"])
        self.assertTrue(body["weights_unchanged"])
        self.assertEqual(body["recommendation"], cal.INSUFFICIENT_DATA)
        self.assertEqual(body["total_terminal_outcomes"], 0)
        self.assertEqual(body["minimum_terminal_outcomes"], 10)
        for key in ("bands", "global_statistics", "recommendation_reasons",
                    "limitations", "generated_at"):
            self.assertIn(key, body)

    def test_filters_and_min_samples(self):
        body = self._get("/api/research/economics/calibration",
                         program="dell").json()
        self.assertEqual(body["total_leads"], 1)
        body = self._get("/api/research/economics/calibration",
                         min_samples=5).json()
        self.assertEqual(body["minimum_terminal_outcomes"], 5)
        bad = self._get("/api/research/economics/calibration", min_samples=0)
        self.assertEqual(bad.status_code, 422)
        malformed = self._get("/api/research/economics/calibration",
                              cve="not-a-cve")
        self.assertEqual(malformed.status_code, 400)

    def test_route_precedes_lead_detail(self):
        r = self._get("/api/research/economics/calibration")
        self.assertEqual(r.status_code, 200)
        self.assertIn("recommendation", r.json())

    def test_no_write_method(self):
        r = self.client.post("/api/research/economics/calibration",
                             params={"api_key": API_KEY} if API_KEY else {})
        self.assertIn(r.status_code, (405, 401))

    def test_deterministic_ignoring_timestamp(self):
        first = self._get("/api/research/economics/calibration").json()
        second = self._get("/api/research/economics/calibration").json()
        first.pop("generated_at", None)
        second.pop("generated_at", None)
        self.assertEqual(first, second)

    def test_no_money_score_change(self):
        from backend import research_economics
        before = research_economics.build_economics()
        self._get("/api/research/economics/calibration")
        after = research_economics.build_economics()
        self.assertEqual(before, after)


class TestCalibrationCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patcher = mock.patch(
            "backend.research_outcomes.OUTCOMES_DIR", self.root)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def _run(self, argv):
        from ai.research_cli import main
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_human_output(self):
        code, out, _ = self._run(["economics", "calibration"])
        self.assertEqual(code, 0)
        self.assertIn("ECONOMIC CALIBRATION", out)
        self.assertIn("Rule: r25-1", out)
        self.assertIn("Minimum sample: 10", out)
        self.assertIn("Leads: 2", out)
        self.assertIn("Terminal outcomes: 0", out)
        self.assertIn("Recommendation: INSUFFICIENT_DATA", out)
        self.assertIn("Money Score weights: UNCHANGED", out)
        self.assertIn("P5: no leads", out)

    def test_json_output(self):
        code, out, _ = self._run(["economics", "calibration", "--json"])
        self.assertEqual(code, 0)
        body = json.loads(out)
        self.assertEqual(body["recommendation"], cal.INSUFFICIENT_DATA)
        self.assertEqual(body["rule_version"], "r25-1")
        self.assertTrue(body["weights_unchanged"])

    def test_options(self):
        code, out, _ = self._run([
            "economics", "calibration", "--min-samples", "5",
            "--program", "dell", "--json"])
        self.assertEqual(code, 0)
        body = json.loads(out)
        self.assertEqual(body["minimum_terminal_outcomes"], 5)
        self.assertEqual(body["total_leads"], 1)

    def test_errors(self):
        code, _, err = self._run([
            "economics", "calibration", "--min-samples", "0"])
        self.assertEqual(code, 1)
        self.assertIn("min_samples", err)
        code, _, err = self._run([
            "economics", "calibration", "--cve", "not-a-cve"])
        self.assertEqual(code, 1)


class TestCalibrationUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patcher = mock.patch(
            "backend.research_outcomes.OUTCOMES_DIR", self.root)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_leads_page_calibration_strip(self):
        params = {"api_key": API_KEY} if API_KEY else {}
        r = self.client.get("/ui/research/leads", params=params)
        self.assertEqual(r.status_code, 200)
        for text in ("ECONOMIC CALIBRATION", "INSUFFICIENT_DATA",
                     "r25-1", "0 terminal outcomes", "UNCHANGED"):
            self.assertIn(text, r.text)


class TestSafety(unittest.TestCase):
    def test_no_execution_tokens(self):
        for rel in ("ai/knowledge/economic_calibration.py",
                    "backend/research_calibration.py"):
            source = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            for token in ("import subprocess", "subprocess.",
                          "import socket", "socket.",
                          "import requests", "requests.",
                          "import httpx", "httpx.",
                          "import openai", "import anthropic",
                          "from ai.llm", "nuclei.", "Popen(",
                          "selenium", "playwright", "os.system("):
                self.assertNotIn(token, source,
                                 f"{token} found in {rel}")

    def test_no_self_tuning_or_write_paths(self):
        source = (Path("/opt/watch")
                  / "ai/knowledge/economic_calibration.py").read_text(
                      encoding="utf-8")
        for token in ("MONEY_W_VALUE", "MONEY_W_CONFIDENCE", "setattr",
                      "assign_weights", "update_weights", "retrain",
                      "open(", "write(", "os.replace"):
            self.assertNotIn(token, source)

    def test_weights_constants_unchanged(self):
        from ai.knowledge import economics
        self.assertEqual(economics.MONEY_W_VALUE, 0.55)
        self.assertEqual(economics.MONEY_W_CONFIDENCE, 0.15)
        self.assertEqual(economics.MONEY_W_EFFORT_EFF, 0.15)
        self.assertEqual(economics.MONEY_W_RISK_AVOID, 0.15)
        self.assertEqual(economics.RULE_VERSION, "r25-1")

    def test_calibration_module_pure(self):
        # same inputs -> same outputs; no hidden clock/randomness
        first = cal.build_calibration_report(
            [proj(_lead_id(1), 53)], {}, generated_at="T")
        second = cal.build_calibration_report(
            [proj(_lead_id(1), 53)], {}, generated_at="T")
        self.assertEqual(first, second)
        self.assertEqual(first["generated_at"], "T")


if __name__ == "__main__":
    unittest.main(verbosity=2)
