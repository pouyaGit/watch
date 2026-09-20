"""tests/test_attack_surface.py — repository, service and lifecycle tests.

Offline and deterministic: recon records are injected directly, so no Mongo,
no network, no LLM and no target interaction are required. One tolerant
real-corpus test exercises the read-only live projection when a database is
reachable and degrades honestly when it is not.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    ParamRecord,
    UrlRecord,
)
from backend.attack_surface import repository as repo
from backend.attack_surface import service as svc
from backend.attack_surface.models import (
    CANDIDATE_STATUSES,
    RULE_VERSION,
    AttackSurfaceCandidate,
    AttackSurfaceSnapshot,
    CandidateCategory,
)
from backend.attack_surface.service import CandidateQueue, CandidateQueueError


def http(subdomain, tech=(), *, program="dell"):
    return HttpRecord(program_name=program, subdomain=subdomain,
                      tech=tuple(tech))


def endpoint(subdomain, path, params=(), records=(), *, program="dell",
             last_update=None):
    return EndpointRecord(
        program_name=program,
        subdomain=subdomain,
        path=path,
        example_url=f"https://{subdomain}{path}",
        params=tuple(params),
        param_records=tuple(records),
        last_update=last_update,
    )


def param(name, method="GET", location="query", source="crawl"):
    return ParamRecord(name=name, method=method, location=location,
                       source=source)


def url(subdomain, raw, path, params=(), *, program="dell"):
    return UrlRecord(program_name=program, subdomain=subdomain, url=raw,
                     path=path, params=tuple(params))


def snapshot(**over):
    records = {
        "http_records": [],
        "url_records": [],
        "endpoint_records": [],
    }
    records.update(over)
    return repo.normalize_records(**records)


class TestNormalization(unittest.TestCase):
    def test_normalized_shape(self):
        snap = snapshot(
            http_records=[http("a.dell.com", ["WordPress:6.4", "nginx"])],
            endpoint_records=[
                endpoint("a.dell.com", "/api/user", params=("id",),
                         records=(param("id"),))
            ],
        )
        self.assertEqual(len(snap.records), 1)
        row = snap.records[0].to_dict()
        self.assertEqual(row["url"], "/api/user?id=")
        self.assertEqual(row["endpoint"], "/api/user")
        self.assertEqual(row["parameter"], "id")
        self.assertEqual(row["method"], "GET")
        self.assertEqual(row["technology"], ["WordPress", "nginx"])
        self.assertEqual(row["source"], "watch")

    def test_param_records_provide_method_and_location(self):
        snap = snapshot(
            endpoint_records=[
                endpoint("a.dell.com", "/upload", params=("file",),
                         records=(param("file", "POST", "body", "x8"),))
            ],
        )
        row = snap.records[0]
        self.assertEqual(row.method, "POST")
        self.assertEqual(row.location, "body")

    def test_params_fallback_when_no_records(self):
        snap = snapshot(
            endpoint_records=[endpoint("a.dell.com", "/x", params=("q", "id"))],
        )
        methods = {r.parameter: (r.method, r.location) for r in snap.records}
        self.assertEqual(methods, {"q": ("GET", "query"),
                                   "id": ("GET", "query")})

    def test_url_derived_records(self):
        snap = snapshot(
            url_records=[url("a.dell.com", "https://a.dell.com/search?q=x",
                             "/search", params=("q",))],
        )
        self.assertEqual(len(snap.records), 1)
        self.assertEqual(snap.records[0].endpoint, "/search")
        self.assertEqual(snap.url_count, 1)

    def test_url_path_derived_from_url_when_missing(self):
        snap = snapshot(
            url_records=[url("a.dell.com", "https://a.dell.com/a/b?x=1", "",
                             params=("x",))],
        )
        self.assertEqual(snap.records[0].endpoint, "/a/b")

    def test_technology_version_stripped(self):
        self.assertEqual(repo.technology_name("nginx:1.24.0"), "nginx")
        self.assertEqual(repo.technology_name("WordPress"), "WordPress")
        self.assertEqual(repo.technology_name(""), "")

    def test_discovery_counts_include_paramless_endpoints(self):
        snap = snapshot(
            http_records=[http("a.dell.com", ["nginx"])],
            endpoint_records=[
                endpoint("a.dell.com", "/with-param", params=("id",)),
                endpoint("a.dell.com", "/no-param"),
            ],
        )
        self.assertEqual(len(snap.domains), 1)
        self.assertEqual(snap.endpoint_count, 2)
        self.assertEqual(snap.parameter_count, 1)

    def test_malformed_endpoint_skipped(self):
        snap = snapshot(
            endpoint_records=[
                endpoint("a.dell.com", "/bad\npath", params=("id",)),
                endpoint("a.dell.com", "/good", params=("id",)),
            ],
        )
        self.assertEqual({r.endpoint for r in snap.records}, {"/good"})

    def test_deterministic_ordering(self):
        first = snapshot(
            endpoint_records=[
                endpoint("a.dell.com", "/b", params=("id",)),
                endpoint("a.dell.com", "/a", params=("q",)),
            ],
        ).to_dict()
        second = snapshot(
            endpoint_records=[
                endpoint("a.dell.com", "/a", params=("q",)),
                endpoint("a.dell.com", "/b", params=("id",)),
            ],
        ).to_dict()
        self.assertEqual(first, second)

    def test_empty_is_honest(self):
        snap = snapshot()
        self.assertFalse(snap.available)
        self.assertEqual(snap.records, ())
        self.assertEqual(snap.url_count, 0)
        self.assertEqual(snap.endpoint_count, 0)
        self.assertEqual(snap.parameter_count, 0)


class TestService(unittest.TestCase):
    def _snapshot(self):
        return snapshot(
            http_records=[http("a.dell.com", ["WordPress:6.4"])],
            endpoint_records=[
                endpoint("a.dell.com", "/api/user", params=("id",),
                         records=(param("id"),)),
                endpoint("a.dell.com", "/search", params=("q", "file"),
                         records=(param("q"),
                                  param("file", "POST", "body", "x8"))),
                endpoint("a.dell.com", "/proxy", params=("url",)),
            ],
        )

    def test_build_candidates_categories(self):
        candidates = svc.build_candidates(self._snapshot(),
                                          now="2026-09-20T00:00:00Z")
        by_param = {(c.endpoint, c.parameter): c for c in candidates}
        self.assertEqual(by_param[("/api/user", "id")].category,
                         CandidateCategory.IDOR.value)
        self.assertEqual(by_param[("/search", "q")].category,
                         CandidateCategory.XSS.value)
        self.assertEqual(by_param[("/search", "file")].category,
                         CandidateCategory.FILE_UPLOAD.value)
        self.assertEqual(by_param[("/proxy", "url")].category,
                         CandidateCategory.SSRF.value)
        for candidate in candidates:
            self.assertEqual(candidate.status, "NEW")
            self.assertEqual(candidate.rule_version, RULE_VERSION)
            self.assertEqual(candidate.created_at, "2026-09-20T00:00:00Z")

    def test_candidate_ids_are_deterministic(self):
        first = [c.id for c in svc.build_candidates(self._snapshot())]
        second = [c.id for c in svc.build_candidates(self._snapshot())]
        self.assertEqual(first, second)
        self.assertTrue(all(cid.startswith("asc-") for cid in first))

    def test_priority_queue_is_ranked(self):
        candidates = svc.build_candidates(self._snapshot())
        queue = svc.build_priority_queue(candidates, limit=2)
        self.assertEqual([row["rank"] for row in queue], [1, 2])
        self.assertGreaterEqual(queue[0]["score"], queue[1]["score"])
        self.assertIn("label", queue[0])

    def test_summary_counts(self):
        candidates = svc.build_candidates(self._snapshot())
        summary = svc.summarize_candidates(candidates)
        self.assertEqual(summary["total"], len(candidates))
        self.assertEqual(summary["short"]["IDOR"], 1)
        self.assertEqual(summary["short"]["XSS"], 1)
        self.assertEqual(summary["short"]["SSRF"], 1)
        self.assertEqual(summary["short"]["UPLOAD"], 1)
        self.assertEqual(sum(summary["by_confidence"].values()),
                         len(candidates))

    def test_payload_schema(self):
        payload = svc.attack_surface_payload(snapshot=self._snapshot())
        self.assertEqual(
            set(payload),
            {"available", "rule_version", "summary", "discovery",
             "candidates", "priority_queue"},
        )
        self.assertTrue(payload["available"])
        self.assertEqual(payload["rule_version"], RULE_VERSION)
        self.assertEqual(payload["discovery"]["domains"], 1)
        self.assertEqual(payload["discovery"]["endpoints"], 3)
        self.assertEqual(payload["candidates"]["total"],
                         len(payload["priority_queue"]))

    def test_empty_payload_is_honest(self):
        payload = svc.attack_surface_payload(
            snapshot=AttackSurfaceSnapshot()
        )
        self.assertFalse(payload["available"])
        self.assertEqual(payload["summary"]["total"], 0)
        self.assertEqual(payload["discovery"]["domains"], 0)
        self.assertEqual(payload["priority_queue"], [])
        for count in payload["candidates"]["short"].values():
            self.assertEqual(count, 0)

    def test_injected_records_load(self):
        snap = repo.load_snapshot(records={
            "http_records": [http("a.dell.com", ["nginx"])],
            "endpoint_records": [endpoint("a.dell.com", "/x", params=("id",))],
            "url_records": [],
        })
        self.assertTrue(snap.available)
        self.assertEqual(snap.records[0].parameter, "id")


class TestLifecycle(unittest.TestCase):
    def _candidate(self, cid="asc-0000000000000001"):
        return AttackSurfaceCandidate(
            id=cid,
            category=CandidateCategory.IDOR.value,
            confidence="HIGH",
            score=100,
            endpoint="/api/user",
            parameter="id",
            method="GET",
            reasons=("object identifier parameter",),
        )

    def test_full_transition_path(self):
        queue = CandidateQueue()
        queue.add(self._candidate())
        for status in ("TRIAGED", "ASSIGNED", "VERIFYING", "CONFIRMED",
                       "REPORTED"):
            updated = queue.transition("asc-0000000000000001", status)
            self.assertEqual(updated.status, status)

    def test_illegal_transition_rejected(self):
        queue = CandidateQueue()
        queue.add(self._candidate())
        with self.assertRaises(CandidateQueueError):
            queue.transition("asc-0000000000000001", "REPORTED")

    def test_unknown_candidate_rejected(self):
        queue = CandidateQueue()
        with self.assertRaises(CandidateQueueError):
            queue.transition("asc-missing", "TRIAGED")

    def test_add_is_idempotent(self):
        queue = CandidateQueue()
        queue.add(self._candidate())
        queue.transition("asc-0000000000000001", "TRIAGED")
        queue.add(self._candidate())
        self.assertEqual(
            queue.get("asc-0000000000000001").status, "TRIAGED"
        )

    def test_summary_by_status(self):
        queue = CandidateQueue()
        queue.add_many([self._candidate("asc-1"), self._candidate("asc-2")])
        queue.transition("asc-1", "TRIAGED")
        summary = queue.summary()
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_status"]["NEW"], 1)
        self.assertEqual(summary["by_status"]["TRIAGED"], 1)
        self.assertEqual(set(summary["by_status"]), set(CANDIDATE_STATUSES))

    def test_persistence_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "queue.json"
            queue = CandidateQueue(path=path)
            queue.add(self._candidate())
            queue.transition("asc-0000000000000001", "TRIAGED")
            queue.save()
            self.assertTrue(path.is_file())
            reloaded = CandidateQueue(path=path)
            self.assertEqual(
                reloaded.get("asc-0000000000000001").status, "TRIAGED"
            )

    def test_in_memory_queue_writes_nothing(self):
        base = Path(__file__).resolve().parents[1] / "ai_data"
        before = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        queue = CandidateQueue()
        queue.add(self._candidate())
        queue.transition("asc-0000000000000001", "TRIAGED")
        after = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        self.assertEqual(before, after)


class TestRealCorpus(unittest.TestCase):
    def test_live_projection_degrades_honestly(self):
        repo.clear_cache()
        snap = repo.load_snapshot("dell")
        self.assertIsInstance(snap, AttackSurfaceSnapshot)
        if snap.available:
            self.assertGreaterEqual(snap.url_count, 0)
            self.assertGreaterEqual(snap.endpoint_count, 0)
            self.assertGreaterEqual(snap.parameter_count, 0)
            payload = svc.attack_surface_payload(snapshot=snap)
            self.assertIn("priority_queue", payload)
        else:
            self.assertFalse(snap.records)
            self.assertTrue(snap.generated_from)

    def test_unknown_program_is_not_invented(self):
        repo.clear_cache()
        snap = repo.load_snapshot("definitely-not-a-real-program-xyz")
        if snap.available:
            self.assertEqual(snap.records, ())
        else:
            self.assertEqual(snap.records, ())


if __name__ == "__main__":
    unittest.main(verbosity=2)
