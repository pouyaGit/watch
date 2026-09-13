"""tests/test_historical_candidate_ranking.py — Stage R33.2 tests.

Deterministic, offline tests for the historical candidate ranking planner:

- deterministic output and ranking order stability
- empty history
- positive / negative signal scoring
- multiple records and candidate grouping
- malformed input handling
- no mutation, JSON serialization, closed vocabulary validation
- research_only always true, no operational attack content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import historical_candidate_ranking as hcr
from ai.schemas import historical_candidate_ranking as schema


def snapshot(identity="rc-a", outcome="IN_PROGRESS",
             improvement_area="VERSION", blockers=(), **over):
    record = {
        "rule_version": "r32-1",
        "candidate_identity": identity,
        "research_status": "ACTIVE",
        "outcome": outcome,
        "confidence_level": "MEDIUM",
        "feedback_signal": "CONTINUE_SIGNAL",
        "improvement_area": improvement_area,
        "blockers": list(blockers),
        "timestamp_reference": "ref",
        "source_export": {},
        "research_only": True,
    }
    record.update(over)
    return record


def score_for(result, identity):
    for entry in result["candidate_scores"]:
        if entry["candidate_identity"] == identity:
            return entry
    raise AssertionError(f"missing candidate {identity}")


class TestCandidateRanking(unittest.TestCase):
    def test_empty_history(self):
        for value in (None, [], (), {}, [None, "x", 0], [{}]):
            result = hcr.rank_historical_candidates(value)
            self.assertEqual(result["candidate_scores"], [], repr(value))
            self.assertEqual(result["ranking_reason"], "NO_HISTORY")
            self.assertEqual(result["historical_signals"], [])

    def test_single_candidate_reason(self):
        result = hcr.rank_historical_candidates([snapshot()])
        self.assertEqual(result["ranking_reason"], "SINGLE_CANDIDATE")
        self.assertEqual(len(result["candidate_scores"]), 1)

    def test_multiple_candidates_ranked(self):
        result = hcr.rank_historical_candidates(
            [
                snapshot("rc-low", outcome="DEFERRED",
                         improvement_area="UNKNOWN"),
                snapshot("rc-mid"),
                snapshot("rc-high", outcome="COMPLETED",
                         improvement_area="NONE"),
            ]
        )
        self.assertEqual(result["ranking_reason"], "HISTORICAL_SCORE")
        self.assertEqual(
            [entry["candidate_identity"]
             for entry in result["candidate_scores"]],
            ["rc-high", "rc-mid", "rc-low"],
        )
        self.assertGreater(score_for(result, "rc-high")["score"],
                           score_for(result, "rc-mid")["score"])
        self.assertGreaterEqual(score_for(result, "rc-mid")["score"],
                                score_for(result, "rc-low")["score"])

    def test_positive_signals(self):
        result = hcr.rank_historical_candidates(
            [
                snapshot("rc-a", outcome="COMPLETED",
                         improvement_area="NONE"),
                snapshot("rc-a", outcome="COMPLETED",
                         improvement_area="NONE"),
            ]
        )
        entry = score_for(result, "rc-a")
        self.assertIn("HISTORICAL_SUCCESS", entry["signals"])
        self.assertIn("REPEATED_SUCCESS", entry["signals"])
        self.assertEqual(
            entry["score"],
            hcr.DELTA_HISTORICAL_SUCCESS + hcr.DELTA_REPEATED_SUCCESS,
        )

    def test_technology_success_signal(self):
        result = hcr.rank_historical_candidates(
            [
                snapshot("rc-a", outcome="COMPLETED",
                         improvement_area="TECHNOLOGY"),
            ]
        )
        entry = score_for(result, "rc-a")
        self.assertIn("TECHNOLOGY_SUCCESS", entry["signals"])
        self.assertIn("HISTORICAL_SUCCESS", entry["signals"])

    def test_evidence_availability_signal(self):
        result = hcr.rank_historical_candidates(
            [snapshot("rc-a", outcome="WAITING_FOR_EVIDENCE")]
        )
        self.assertIn(
            "EVIDENCE_AVAILABILITY",
            score_for(result, "rc-a")["signals"],
        )

    def test_negative_signals(self):
        records = [
            snapshot("rc-a", outcome="DEFERRED", improvement_area="UNKNOWN"),
            snapshot("rc-a", outcome="DEFERRED", improvement_area="UNKNOWN"),
            snapshot(
                "rc-a",
                outcome="WAITING_FOR_EVIDENCE",
                improvement_area="VERSION",
                blockers=["VERSION_EVIDENCE_MISSING"],
            ),
            snapshot(
                "rc-a",
                outcome="WAITING_FOR_EVIDENCE",
                improvement_area="VERSION",
                blockers=["VERSION_EVIDENCE_MISSING"],
            ),
        ]
        entry = score_for(
            hcr.rank_historical_candidates(records), "rc-a"
        )
        self.assertIn("REPEATED_DEFER", entry["signals"])
        self.assertIn("REPEATED_MISSING_EVIDENCE", entry["signals"])
        self.assertIn("UNRESOLVED_BLOCKERS", entry["signals"])
        self.assertEqual(entry["score"], 0)

    def test_score_clamped_to_zero(self):
        records = [
            snapshot("rc-a", outcome="DEFERRED", improvement_area="UNKNOWN",
                     blockers=["VERSION_EVIDENCE_MISSING"]),
            snapshot("rc-a", outcome="DEFERRED", improvement_area="UNKNOWN",
                     blockers=["VERSION_EVIDENCE_MISSING"]),
        ]
        entry = score_for(
            hcr.rank_historical_candidates(records), "rc-a"
        )
        self.assertEqual(entry["score"], schema.SCORE_MIN)

    def test_grouping_and_record_counts(self):
        result = hcr.rank_historical_candidates(
            [
                snapshot("rc-a"),
                snapshot("rc-a"),
                snapshot("rc-b"),
            ]
        )
        self.assertEqual(score_for(result, "rc-a")["records"], 2)
        self.assertEqual(score_for(result, "rc-b")["records"], 1)

    def test_missing_identity_is_unspecified(self):
        result = hcr.rank_historical_candidates(
            [{"outcome": "COMPLETED", "improvement_area": "NONE"}]
        )
        self.assertEqual(
            result["candidate_scores"][0]["candidate_identity"],
            hcr.IDENTITY_UNSPECIFIED,
        )

    def test_malformed_records_are_skipped(self):
        result = hcr.rank_historical_candidates(
            [None, "x", {}, [1], snapshot("rc-a")]
        )
        self.assertEqual(len(result["candidate_scores"]), 1)
        self.assertEqual(
            result["candidate_scores"][0]["candidate_identity"], "rc-a"
        )

    def test_ranking_order_stability(self):
        records = [
            snapshot("rc-b", outcome="COMPLETED", improvement_area="NONE"),
            snapshot("rc-a", outcome="COMPLETED", improvement_area="NONE"),
            snapshot("rc-c", outcome="DEFERRED", improvement_area="UNKNOWN"),
        ]
        first = hcr.rank_historical_candidates(records)
        second = hcr.rank_historical_candidates(list(reversed(records)))
        self.assertEqual(
            [entry["candidate_identity"]
             for entry in first["candidate_scores"]],
            [entry["candidate_identity"]
             for entry in second["candidate_scores"]],
        )
        self.assertEqual(first, second)

    def test_deterministic_output(self):
        records = [snapshot("rc-a"), snapshot("rc-b")]
        first = hcr.rank_historical_candidates(records)
        second = hcr.rank_historical_candidates(records)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        records = [snapshot("rc-a", blockers=["VERSION_EVIDENCE_MISSING"])]
        before = copy.deepcopy(records)
        hcr.rank_historical_candidates(records)
        self.assertEqual(records, before)

    def test_json_serializable(self):
        result = hcr.rank_historical_candidates([snapshot()])
        self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_research_only_always_true(self):
        for value in (None, [snapshot()]):
            result = hcr.rank_historical_candidates(value)
            self.assertIs(result["research_only"], True)

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            hcr.rank_historical_candidates([snapshot()])
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.HistoricalCandidateRankingPlan(
                candidate_scores=[],
                ranking_reason="NOPE",
                historical_signals=[],
            )
        with self.assertRaises(ValidationError):
            schema.HistoricalCandidateRankingPlan(
                candidate_scores=[{
                    "candidate_identity": "rc-a",
                    "score": 1, "records": 1,
                    "signals": ["WIN_SIGNAL"],
                }],
                ranking_reason="SINGLE_CANDIDATE",
                historical_signals=[],
            )
        with self.assertRaises(ValidationError):
            schema.HistoricalCandidateRankingPlan(
                candidate_scores=[],
                ranking_reason="NO_HISTORY",
                historical_signals=["DEPLOY_EXPLOIT"],
            )
        with self.assertRaises(ValidationError):
            schema.HistoricalCandidateRankingPlan(
                candidate_scores=[], ranking_reason="NO_HISTORY",
                historical_signals=[], severity="HIGH",
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.HistoricalCandidateRankingPlan(
            rule_version="r99-9",
            candidate_scores=[],
            ranking_reason="NO_HISTORY",
            historical_signals=[],
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r33-2")
        with self.assertRaises(ValidationError):
            schema.HistoricalCandidateRankingPlan(
                candidate_scores=[],
                ranking_reason="NO_HISTORY",
                historical_signals=[],
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            hcr.RESEARCH_CANDIDATE_RANKING_PLANNER_RULE_VERSION, "r33-2"
        )
        result = hcr.rank_historical_candidates()
        self.assertEqual(result["rule_version"], "r33-2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
