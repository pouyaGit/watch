"""Stage R18 tests: deterministic research queue.

Pure, offline tests. No LLM, no network, no subprocess, no active validation,
no Nuclei, no production authority chain.
"""

from __future__ import annotations

import socket
import subprocess
import unittest
from unittest import mock

from ai.knowledge.queue import (
    QUEUE_RULE_VERSION,
    build_research_queue,
    queue_id_for,
    queue_item_projection,
    queue_score_for,
    research_queue_projection,
)


def _vuln(
    cve,
    *,
    products=(),
    technologies=(),
    components=(),
    types=(),
    priority_class="MEDIUM_RESEARCH",
    priority_score=50,
    priority_reasons=(),
    version_expected=False,
):
    return {
        "cve": cve,
        "products": list(products),
        "technologies": list(technologies),
        "components": list(components),
        "vulnerability_types": list(types),
        "priority_class": priority_class,
        "priority_score": priority_score,
        "priority_reasons": list(priority_reasons),
        "version_expected": version_expected,
    }


def _asset(program, asset, **kwargs):
    return {"program": program, "asset": asset, **kwargs}


def _build(entries):
    return build_research_queue(entries)


class RankingTests(unittest.TestCase):
    def test_high_priority_high_relevance_ranks_first(self):
        high = _vuln(
            "CVE-AAAA-0001",
            products=["nginx"],
            technologies=["nginx"],
            types=["xss"],
            priority_class="CRITICAL_RESEARCH",
            priority_score=100,
        )
        low = _vuln(
            "CVE-BBBB-0002",
            products=["apache"],
            priority_class="MEDIUM_RESEARCH",
            priority_score=50,
        )
        items = _build(
            [
                {
                    "vulnerability": low,
                    "assets": [
                        _asset("pb", "b.com", technologies=["apache"])
                    ],
                },
                {
                    "vulnerability": high,
                    "assets": [
                        _asset(
                            "pa",
                            "a.com",
                            technologies=["nginx"],
                            components=["nginx"],
                        )
                    ],
                },
            ]
        )
        self.assertEqual(items[0].cve, "CVE-AAAA-0001")
        self.assertEqual(items[0].rank, 1)
        self.assertGreater(items[0].queue_score, items[1].queue_score)

    def test_high_priority_low_relevance_visible(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001",
                        technologies=["wordpress"],
                        priority_class="CRITICAL_RESEARCH",
                        priority_score=100,
                    ),
                    "assets": [
                        _asset("p", "a.com", technologies=["WordPress"])
                    ],
                }
            ]
        )
        self.assertEqual(len(items), 1)
        self.assertGreater(items[0].queue_score, 0)

    def test_low_priority_high_relevance_visible(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001",
                        products=["nginx"],
                        technologies=["nginx"],
                        types=["xss"],
                        priority_class="LOW_RESEARCH",
                        priority_score=10,
                    ),
                    "assets": [
                        _asset(
                            "p",
                            "a.com",
                            technologies=["nginx"],
                            components=["nginx"],
                        )
                    ],
                }
            ]
        )
        self.assertEqual(len(items), 1)
        self.assertGreater(items[0].relevance_score, 0)
        self.assertGreater(items[0].queue_score, 0)

    def test_deterministic_tie_break(self):
        entry = {
            "vulnerability": _vuln(
                "CVE-AAAA-0001", products=["nginx"], priority_score=50
            ),
            "assets": [_asset("p", "a.com", technologies=["nginx"])],
        }
        other = {
            "vulnerability": _vuln(
                "CVE-AAAA-0000", products=["nginx"], priority_score=50
            ),
            "assets": [_asset("p", "a.com", technologies=["nginx"])],
        }
        items = _build([entry, other])
        self.assertEqual([item.cve for item in items], [
            "CVE-AAAA-0000",
            "CVE-AAAA-0001",
        ])
        self.assertEqual([item.rank for item in items], [1, 2])


class CandidateGenerationTests(unittest.TestCase):
    def test_none_relevance_creates_no_item(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001", products=["zabbix"]
                    ),
                    "assets": [
                        _asset("p", "a.com", technologies=["nginx"])
                    ],
                }
            ]
        )
        self.assertEqual(items, [])

    def test_unknown_relevance_creates_no_item(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001", technologies=["wordpress"]
                    ),
                    "assets": [_asset("p", "a.com")],
                }
            ]
        )
        self.assertEqual(items, [])

    def test_no_program_asset_creates_no_item(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001", products=["nginx"]
                    ),
                    "assets": [
                        {"program": "", "asset": "a.com", "technologies": ["nginx"]}
                    ],
                }
            ]
        )
        self.assertEqual(items, [])

    def test_no_vulnerability_intelligence_creates_no_item(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln("CVE-AAAA-0001"),
                    "assets": [
                        _asset("p", "a.com", technologies=["nginx"])
                    ],
                }
            ]
        )
        self.assertEqual(items, [])


class GateAndBlockerTests(unittest.TestCase):
    def test_generic_technology_match_is_blocked(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001", technologies=["wordpress"]
                    ),
                    "assets": [
                        _asset("p", "a.com", technologies=["WordPress"])
                    ],
                }
            ]
        )
        self.assertEqual(len(items), 1)
        self.assertIn("only generic technology match", items[0].blockers)

    def test_blockers_are_explicit(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001",
                        products=["nginx"],
                        components=["wp-content/plugins/foo/bar.php"],
                        version_expected=True,
                    ),
                    "assets": [
                        _asset("p", "a.com", technologies=["nginx"])
                    ],
                }
            ]
        )
        self.assertEqual(len(items), 1)
        blockers = items[0].blockers
        self.assertIn("affected plugin not observed", blockers)
        self.assertIn("asset component not observed", blockers)
        self.assertIn("asset version unknown", blockers)

    def test_unknown_factors_remain_visible(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001", technologies=["wordpress"]
                    ),
                    "assets": [
                        _asset("p", "a.com", technologies=["WordPress"])
                    ],
                }
            ]
        )
        self.assertTrue(items[0].unknown_factors)
        self.assertIn(
            "asset component/path not observed", items[0].unknown_factors
        )

    def test_reasons_explain_the_item(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001",
                        products=["nginx"],
                        priority_class="HIGH_RESEARCH",
                        priority_score=70,
                        priority_reasons=["public proof-of-concept available"],
                    ),
                    "assets": [
                        _asset("p", "a.com", technologies=["nginx"])
                    ],
                }
            ]
        )
        self.assertEqual(items[0].reasons[0], "high research priority")
        self.assertIn("public proof-of-concept available", items[0].reasons)
        self.assertIn("exact product match: nginx", items[0].reasons)


class ScoringTests(unittest.TestCase):
    def test_deterministic_weighting(self):
        self.assertEqual(queue_score_for(80, 20), 56)
        self.assertEqual(queue_score_for(100, 0), 60)
        self.assertEqual(queue_score_for(0, 100), 40)
        self.assertEqual(queue_score_for(50, 50), 50)

    def test_queue_score_bounded(self):
        self.assertEqual(queue_score_for(100, 100), 100)
        self.assertEqual(queue_score_for(-100, -100), 0)
        self.assertEqual(queue_score_for(1000, 1000), 100)

    def test_item_score_bounded(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001",
                        products=["nginx"],
                        technologies=["nginx"],
                        components=["nginx"],
                        types=["xss"],
                        priority_class="CRITICAL_RESEARCH",
                        priority_score=100,
                    ),
                    "assets": [
                        _asset(
                            "p",
                            "a.com",
                            technologies=["nginx"],
                            components=["nginx"],
                            paths=["/nginx"],
                        )
                    ],
                }
            ]
        )
        self.assertLessEqual(items[0].queue_score, 100)
        self.assertGreaterEqual(items[0].queue_score, 0)


class IsolationTests(unittest.TestCase):
    def test_cve_program_isolation(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001", products=["nginx"]
                    ),
                    "assets": [
                        _asset("pa", "a.com", technologies=["nginx"])
                    ],
                },
                {
                    "vulnerability": _vuln(
                        "CVE-BBBB-0002", products=["nginx"]
                    ),
                    "assets": [
                        _asset("pb", "b.com", technologies=["nginx"])
                    ],
                },
            ]
        )
        by_cve = {item.cve: item.program for item in items}
        self.assertEqual(by_cve["CVE-AAAA-0001"], "pa")
        self.assertEqual(by_cve["CVE-BBBB-0002"], "pb")

    def test_no_cross_program_contamination(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001", technologies=["wordpress"]
                    ),
                    "assets": [
                        _asset("no-tech", "a.com"),
                        _asset("has-tech", "b.com", technologies=["WordPress"]),
                    ],
                }
            ]
        )
        # Only the program with observed technology produces a candidate.
        self.assertEqual([item.program for item in items], ["has-tech"])


class DeterminismTests(unittest.TestCase):
    def test_repeated_computation_byte_identical(self):
        entry = {
            "vulnerability": _vuln(
                "CVE-AAAA-0001",
                products=["nginx"],
                priority_class="HIGH_RESEARCH",
                priority_score=70,
            ),
            "assets": [_asset("p", "a.com", technologies=["nginx"])],
        }
        first = research_queue_projection(build_research_queue([entry]))
        second = research_queue_projection(build_research_queue([entry]))
        self.assertEqual(first, second)

    def test_no_timestamps_or_randomness(self):
        self.assertEqual(
            queue_id_for("CVE-AAAA-0001", "p"),
            queue_id_for("CVE-AAAA-0001", "p"),
        )
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001", products=["nginx"]
                    ),
                    "assets": [
                        _asset("p", "a.com", technologies=["nginx"])
                    ],
                }
            ]
        )
        self.assertTrue(items[0].queue_id.startswith("rq-"))

    def test_evidence_bounded(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001",
                        products=["nginx"],
                        components=["nginx"],
                        types=["xss"],
                    ),
                    "assets": [
                        _asset(
                            "p",
                            "a.com",
                            technologies=["nginx"],
                            components=["nginx"],
                            paths=["/nginx"],
                        )
                    ],
                }
            ]
        )
        self.assertLessEqual(len(items[0].evidence), 40)
        for item in items[0].evidence:
            self.assertLessEqual(len(item.evidence), 240)

    def test_adversarial_names_bounded(self):
        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001",
                        products=["A" * 5000],
                        components=["b" * 5000],
                        priority_score=100000,
                    ),
                    "assets": [
                        _asset("p", "a" * 5000, technologies=["A" * 5000])
                    ],
                }
            ]
        )
        for item in items:
            self.assertLessEqual(item.queue_score, 100)
            self.assertGreaterEqual(item.queue_score, 0)


class SafetyBoundaryTests(unittest.TestCase):
    def test_no_network_or_subprocess(self):
        with mock.patch.object(
            socket, "socket", side_effect=AssertionError("network used")
        ):
            with mock.patch.object(
                subprocess, "Popen", side_effect=AssertionError("subprocess used")
            ):
                items = _build(
                    [
                        {
                            "vulnerability": _vuln(
                                "CVE-AAAA-0001", products=["nginx"]
                            ),
                            "assets": [
                                _asset("p", "a.com", technologies=["nginx"])
                            ],
                        }
                    ]
                )
        self.assertEqual(len(items), 1)


class SchemaCompatibilityTests(unittest.TestCase):
    def test_queue_item_schema_validates(self):
        from ai.schemas.knowledge import KnowledgeResearchQueueItem

        items = _build(
            [
                {
                    "vulnerability": _vuln(
                        "CVE-AAAA-0001", products=["nginx"]
                    ),
                    "assets": [_asset("p", "a.com", technologies=["nginx"])],
                }
            ]
        )
        model = KnowledgeResearchQueueItem.model_validate(
            queue_item_projection(items[0])
        )
        self.assertEqual(model.cve, "CVE-AAAA-0001")
        self.assertEqual(model.program, "p")
        self.assertEqual(model.rule_version, QUEUE_RULE_VERSION)

    def test_legacy_document_still_loads(self):
        from ai.schemas.knowledge import KnowledgeDocument

        document = KnowledgeDocument.model_validate(
            {
                "knowledge_id": "kb-legacy",
                "title": "legacy",
                "source_url": "https://legacy.test/x",
                "source_type": "reference",
                "content": "legacy content",
            }
        )
        self.assertEqual(document.asset_relevance.relevance, "UNKNOWN")
        self.assertEqual(
            document.research_priority.priority, "INSUFFICIENT_DATA"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
