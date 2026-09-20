"""tests/test_attack_surface_classifier.py — deterministic rule + score tests.

Offline and pure: no Mongo, no network, no LLM, no target interaction. Covers
parameter classification, endpoint classification, multi-category matches,
scoring, explainability, confidence thresholds, determinism and the closed
category/confidence vocabularies.
"""
from __future__ import annotations

import unittest

from backend.attack_surface import classifier as clf
from backend.attack_surface import scorer
from backend.attack_surface.models import (
    CANDIDATE_CATEGORIES,
    CONFIDENCE_LEVELS,
    AttackSurfaceRecord,
    CandidateCategory,
)


def record(parameter="", endpoint="/api/thing", method="GET", technology=(),
           program="dell", subdomain="a.dell.com"):
    return AttackSurfaceRecord(
        program=program,
        subdomain=subdomain,
        url=f"{endpoint}?{parameter}=",
        endpoint=endpoint,
        parameter=parameter,
        method=method,
        technology=tuple(technology),
    )


def categories(param, **kwargs):
    return {c.category for c in clf.classify(record(param, **kwargs))}


class TestParameterClassification(unittest.TestCase):
    def test_xss_signals(self):
        for name in ("q", "query", "search", "name", "message", "input",
                     "redirect", "return", "next"):
            with self.subTest(name=name):
                self.assertIn(CandidateCategory.XSS.value,
                              categories(name))

    def test_idor_signals(self):
        for name in ("id", "uid", "user", "user_id", "account", "profile",
                     "object", "item"):
            with self.subTest(name=name):
                self.assertIn(CandidateCategory.IDOR.value,
                              categories(name))

    def test_ssrf_signals(self):
        for name in ("url", "uri", "target", "callback", "webhook", "proxy",
                     "destination"):
            with self.subTest(name=name):
                self.assertIn(CandidateCategory.SSRF.value,
                              categories(name))

    def test_file_upload_signals(self):
        for name in ("upload", "file", "image", "attachment", "import"):
            with self.subTest(name=name):
                self.assertIn(CandidateCategory.FILE_UPLOAD.value,
                              categories(name))

    def test_unrelated_parameter_matches_nothing(self):
        self.assertEqual(categories("totally_unrelated"), set())

    def test_short_signal_is_not_heuristic(self):
        # ``q`` is a short signal: it must not match arbitrary words.
        self.assertNotIn(CandidateCategory.XSS.value, categories("quality"))
        self.assertIn(CandidateCategory.XSS.value, categories("q"))

    def test_heuristic_long_signal(self):
        self.assertIn(CandidateCategory.XSS.value, categories("searchTerm"))
        self.assertIn(CandidateCategory.SSRF.value, categories("callbackUrl"))
        self.assertIn(CandidateCategory.FILE_UPLOAD.value,
                      categories("avatarImage"))

    def test_token_match(self):
        self.assertIn(CandidateCategory.IDOR.value, categories("user_id"))
        self.assertIn(CandidateCategory.IDOR.value, categories("order-id"))

    def test_case_and_array_normalized(self):
        self.assertIn(CandidateCategory.XSS.value, categories("QUERY"))
        self.assertIn(CandidateCategory.XSS.value, categories("query[]"))


class TestEndpointClassification(unittest.TestCase):
    def test_idor_endpoint_segment(self):
        for path in ("/user/1", "/users", "/account/edit", "/profile",
                     "/order/9"):
            with self.subTest(path=path):
                found = categories("", endpoint=path)
                self.assertIn(CandidateCategory.IDOR.value, found)

    def test_endpoint_alone_still_classifies(self):
        result = clf.classify(record("", endpoint="/user/1"))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].category, CandidateCategory.IDOR.value)
        self.assertEqual(result[0].endpoint_signal, "user")
        self.assertEqual(result[0].reasons, ("resource reference",))

    def test_plural_endpoint_segment(self):
        result = clf.classify(record("", endpoint="/users/1"))
        self.assertEqual(result[0].endpoint_signal, "users")

    def test_unrelated_endpoint_matches_nothing(self):
        self.assertEqual(categories("", endpoint="/healthz"), set())


class TestMultiCategory(unittest.TestCase):
    def test_parameter_and_endpoint_produce_two_categories(self):
        found = categories("callback", endpoint="/user/1")
        self.assertIn(CandidateCategory.IDOR.value, found)
        self.assertIn(CandidateCategory.SSRF.value, found)

    def test_classify_is_deterministic(self):
        first = clf.classify_record(record("q", endpoint="/search"))
        second = clf.classify_record(record("q", endpoint="/search"))
        self.assertEqual(first, second)


class TestScoring(unittest.TestCase):
    def _score(self, param, **kwargs):
        rec = record(param, **kwargs)
        matches = clf.classify(rec)
        return [(m.category, scorer.score(rec, m)) for m in matches]

    def test_high_confidence_idor(self):
        scored = dict(self._score("id", endpoint="/api/user"))
        candidate = scored[CandidateCategory.IDOR.value]
        self.assertEqual(candidate.score, 100)
        self.assertEqual(candidate.confidence, "HIGH")
        self.assertIn("object identifier parameter", candidate.reasons)
        self.assertIn("numeric identifier parameter", candidate.reasons)
        self.assertIn("resource reference", candidate.reasons)

    def test_low_confidence_heuristic(self):
        scored = dict(self._score("userId"))
        candidate = scored[CandidateCategory.IDOR.value]
        self.assertEqual(candidate.confidence, "LOW")
        self.assertLess(candidate.score, scorer.MEDIUM_THRESHOLD)

    def test_method_contributes(self):
        get_score = dict(self._score("file", method="GET"))[
            CandidateCategory.FILE_UPLOAD.value
        ]
        post_score = dict(self._score("file", method="POST"))[
            CandidateCategory.FILE_UPLOAD.value
        ]
        self.assertEqual(post_score.score - get_score.score,
                         scorer.METHOD_POINTS)

    def test_technology_context_contributes(self):
        without = dict(self._score("url"))[CandidateCategory.SSRF.value]
        with_tech = dict(self._score("url", technology=("nginx",)))[
            CandidateCategory.SSRF.value
        ]
        self.assertEqual(with_tech.score - without.score,
                         scorer.TECHNOLOGY_POINTS)

    def test_score_is_capped(self):
        scored = dict(self._score("id", endpoint="/user/1", method="POST",
                                  technology=("nginx",)))
        self.assertLessEqual(scored[CandidateCategory.IDOR.value].score,
                             scorer.MAX_SCORE)

    def test_contributions_sum_to_capped_score(self):
        rec = record("id", endpoint="/api/user", method="POST")
        for match in clf.classify(rec):
            result = scorer.score(rec, match)
            total = sum(points for _, points in result.contributions)
            self.assertEqual(result.score, min(total, scorer.MAX_SCORE))

    def test_confidence_thresholds(self):
        self.assertEqual(scorer.confidence_for(scorer.HIGH_THRESHOLD), "HIGH")
        self.assertEqual(scorer.confidence_for(scorer.MEDIUM_THRESHOLD),
                         "MEDIUM")
        self.assertEqual(scorer.confidence_for(scorer.MEDIUM_THRESHOLD - 1),
                         "LOW")

    def test_scoring_deterministic(self):
        rec = record("q", endpoint="/search")
        match = clf.classify(rec)[0]
        self.assertEqual(scorer.score(rec, match).to_dict(),
                         scorer.score(rec, match).to_dict())


class TestVocabularies(unittest.TestCase):
    def test_closed_categories(self):
        self.assertEqual(
            set(CANDIDATE_CATEGORIES),
            {"XSS_CANDIDATE", "IDOR_CANDIDATE", "SSRF_CANDIDATE",
             "FILE_UPLOAD_CANDIDATE"},
        )

    def test_closed_confidence(self):
        self.assertEqual(set(CONFIDENCE_LEVELS), {"LOW", "MEDIUM", "HIGH"})

    def test_no_llm_or_network_tokens(self):
        from pathlib import Path

        for name in ("classifier.py", "scorer.py"):
            source = (Path(__file__).resolve().parents[1] / "backend"
                      / "attack_surface" / name).read_text(encoding="utf-8")
            for token in ("import requests", "import httpx", "import socket",
                          "subprocess", "openai", "anthropic", "from ai.llm",
                          "urlopen", "Popen("):
                self.assertNotIn(token, source, f"{token} in {name}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
