"""
tests/test_research_agent.py — Stage R23 autonomous research scheduler tests.

Research-only, offline. Covers scheduler policy (disabled/window/bounds),
deterministic plan selection, locking, source URL validation (SSRF guard),
bounded sourcing, evidence provenance + trusted hashes, LLM grounding,
persistence idempotency, CLI dry-run, and the safety invariants (no target
interaction, no Nuclei execution, no active validation, no findings).

No network, no LLM, no Mongo, no subprocess.
"""
import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.research_agent import storage
from ai.research_agent.agent import ResearchAgent
from ai.research_agent.prompts import build_research_prompt
from ai.research_agent.scheduler import (
    RUN_STATUS_BLOCKED,
    RUN_STATUS_COMPLETED,
    RUN_STATUS_PARTIAL,
    ResearchScheduler,
    SchedulerConfig,
    acquire_lock,
    in_window,
    next_window_start,
    parse_hhmm,
    priority_rank,
    select_plans,
)
from ai.research_agent.sources import (
    ResearchSourceCollector,
    SourceValidationError,
    classify_source,
    validate_source_url,
)
from ai.schemas.research_agent import (
    RESEARCH_AGENT_RULE_VERSION,
    ResearchAgentEvidence,
    ResearchAgentNucleiCandidate,
    ResearchAgentResult,
    find_forbidden_terms,
    result_id_for,
)


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


class FakeDoc:
    def __init__(self, url, content, title="Title", source_type="nvd"):
        self.url = url
        self.content = content
        self.title = title
        self.source_type = source_type


class FakeFetcher:
    def __init__(self, content=None, error=None, docs=None):
        self.content = content or "Public advisory body text."
        self.error = error
        self.docs = docs
        self.calls = []

    def fetch(self, url):
        self.calls.append(url)
        if self.error:
            raise self.error
        if self.docs is not None:
            return self.docs.get(url)
        return FakeDoc(url, self.content)

    def close(self):
        pass


class FakeLLM:
    def __init__(self, payload):
        self.payload = payload
        self.prompts = []

    def generate(self, prompt):
        self.prompts.append(prompt)
        if isinstance(self.payload, Exception):
            raise self.payload
        if isinstance(self.payload, str):
            return self.payload
        return json.dumps(self.payload)


class ExplodingAgent:
    def run_plans(self, *args, **kwargs):  # pragma: no cover - must not be called
        raise AssertionError("agent must not run in dry-run")


class FakeResult:
    def __init__(self, plan_id, status="RESEARCH_COMPLETED", evidence=0, sources=1):
        self.plan_id = plan_id
        self.result_id = "ra-" + plan_id[-4:]
        self.cve_id = "CVE-2026-1557"
        self.program = "dell"
        self.status = status
        self.evidence = [object()] * evidence
        self.sources = [object()] * sources


class FakeAgent:
    def __init__(self, *, expire_result=False):
        self.seen_plan_ids = []
        self.expire_result = expire_result

    def run_plans(
        self,
        plans,
        *,
        run_id,
        deadline,
        dry_run,
        network,
        persist,
        per_plan_timeout=None,
    ):
        results = []
        failures = []
        for plan in plans:
            if per_plan_timeout is not None and per_plan_timeout():
                failures.append(
                    {"plan_id": plan.get("plan_id"), "error": "time budget expired"}
                )
                break
            self.seen_plan_ids.append(plan["plan_id"])
            if self.expire_result:
                failures.append({"plan_id": plan.get("plan_id"), "error": "boom"})
                continue
            results.append(FakeResult(plan["plan_id"]))
        return results, failures


def make_plan(
    plan_id,
    *,
    cve="CVE-2026-1557",
    program="dell",
    priority="HIGH_RESEARCH",
    priority_score=70,
    relevance_score=50,
    recommended_start="REVIEW_PUBLIC_POC",
    status="RESEARCH_PLAN_READY",
):
    return {
        "plan_id": plan_id,
        "lead_id": "rl-0000000000000000",
        "cve_id": cve,
        "program": program,
        "priority_score": priority_score,
        "relevance_score": relevance_score,
        "recommended_start": recommended_start,
        "status": status,
        "metadata": {"priority_level": priority},
        "unknowns": ["affected version unknown"],
        "steps": [],
        "blockers": [],
    }


def payload_loader_factory(references, **research):
    base = {"vulnerability_type": "Cross-Site Scripting", "severity": "High"}
    base.update(research)

    def loader(cve):
        return {"research": {**base, "references": references}}

    return loader


def intel_loader_factory(program="dell", **exploitability):
    expl = {"public_poc": "true", "exploit_available": "true"}
    expl.update(exploitability)

    def loader(cve):
        return {
            "available": True,
            "exploitability": expl,
            "relevance": [{"program": program, "reasons": ["technology match"]}],
        }

    return loader


@contextmanager
def temp_agent(tmpdir=None):
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


# ---------------------------------------------------------------------------
# scheduler config + window
# ---------------------------------------------------------------------------


class TestSchedulerConfig(unittest.TestCase):
    def test_disabled_by_default(self):
        self.assertFalse(SchedulerConfig.from_env({}).enabled)

    def test_conservative_defaults(self):
        config = SchedulerConfig.from_env({})
        self.assertEqual(config.window_start, "12:00")
        self.assertEqual(config.window_end, "00:00")
        self.assertEqual(config.max_minutes, 300)
        self.assertEqual(config.max_plans, 5)
        self.assertEqual(config.timezone, "Asia/Tehran")
        # bounded network fetching is on by default; LLM stays opt-in
        self.assertTrue(config.network)
        self.assertFalse(config.llm)
        self.assertFalse(config.kb_ingest)

    def test_env_overrides(self):
        config = SchedulerConfig.from_env(
            {
                "WATCH_RESEARCH_ENABLED": "true",
                "WATCH_RESEARCH_WINDOW_START": "22:30",
                "WATCH_RESEARCH_WINDOW_END": "02:00",
                "WATCH_RESEARCH_MAX_MINUTES": "45",
                "WATCH_RESEARCH_MAX_PLANS": "2",
                "WATCH_RESEARCH_TIMEZONE": "UTC",
                "WATCH_RESEARCH_NETWORK": "1",
                "WATCH_RESEARCH_LLM": "yes",
            }
        )
        self.assertTrue(config.enabled)
        self.assertEqual(config.window_start, "22:30")
        self.assertEqual(config.window_end, "02:00")
        self.assertEqual(config.max_minutes, 45)
        self.assertEqual(config.max_plans, 2)
        self.assertEqual(config.timezone, "UTC")
        self.assertTrue(config.network)
        self.assertTrue(config.llm)

    def test_malformed_ints_fall_back(self):
        config = SchedulerConfig.from_env(
            {"WATCH_RESEARCH_MAX_MINUTES": "abc", "WATCH_RESEARCH_MAX_PLANS": ""}
        )
        self.assertEqual(config.max_minutes, 300)
        self.assertEqual(config.max_plans, 5)


class TestWindow(unittest.TestCase):
    def test_parse_hhmm(self):
        self.assertEqual(parse_hhmm("18:00"), 18 * 60)
        self.assertEqual(parse_hhmm("00:00"), 0)
        with self.assertRaises(ValueError):
            parse_hhmm("25:00")
        with self.assertRaises(ValueError):
            parse_hhmm("bad")

    def test_in_window_same_day(self):
        self.assertTrue(in_window(datetime(2026, 1, 1, 19, 0), "18:00", "23:00"))
        self.assertFalse(in_window(datetime(2026, 1, 1, 10, 0), "18:00", "23:00"))

    def test_in_window_crossing_midnight(self):
        self.assertTrue(in_window(datetime(2026, 1, 1, 23, 30), "22:00", "06:00"))
        self.assertTrue(in_window(datetime(2026, 1, 1, 3, 0), "22:00", "06:00"))
        self.assertFalse(in_window(datetime(2026, 1, 1, 12, 0), "22:00", "06:00"))

    def test_window_end_exclusive_at_midnight(self):
        # 18:00-00:00 excludes exactly 00:00
        self.assertFalse(in_window(datetime(2026, 1, 1, 0, 0), "18:00", "00:00"))
        self.assertTrue(in_window(datetime(2026, 1, 1, 23, 59), "18:00", "00:00"))

    def test_zero_length_window_closed(self):
        self.assertFalse(in_window(datetime(2026, 1, 1, 12, 0), "12:00", "12:00"))

    def test_timezone_not_system_clock(self):
        cfg = SchedulerConfig(timezone="Asia/Tehran", enabled=True)
        # An aware UTC instant that is inside the Tehran window.
        from datetime import timezone as _tz

        utc_now = datetime(2026, 9, 10, 16, 0, tzinfo=_tz.utc)  # 19:30 Tehran
        sch = ResearchScheduler(cfg, plan_loader=lambda: [], now_fn=lambda: utc_now)
        self.assertTrue(sch.in_window())

    def test_next_window_start(self):
        now = datetime(2026, 1, 1, 10, 0)
        nxt = next_window_start(now, "18:00", "00:00")
        self.assertEqual((nxt.hour, nxt.minute), (18, 0))
        self.assertEqual(nxt.day, 1)
        later = next_window_start(datetime(2026, 1, 1, 19, 0), "18:00", "00:00")
        self.assertEqual(later.day, 2)

    def test_production_window_tehran_boundaries(self):
        # 12:00-00:00 Asia/Tehran: start inclusive, end exclusive.
        from zoneinfo import ZoneInfo

        tehran = ZoneInfo("Asia/Tehran")

        def at(hour, minute):
            return datetime(2026, 9, 11, hour, minute, tzinfo=tehran)

        self.assertFalse(in_window(at(11, 59), "12:00", "00:00"))
        self.assertTrue(in_window(at(12, 0), "12:00", "00:00"))
        self.assertTrue(in_window(at(23, 59), "12:00", "00:00"))
        self.assertFalse(in_window(at(0, 0), "12:00", "00:00"))

    def test_production_default_window_tehran(self):
        # The shipped default window is 12:00-00:00 Asia/Tehran.
        from zoneinfo import ZoneInfo

        tehran = ZoneInfo("Asia/Tehran")
        cfg = SchedulerConfig.from_env({})
        self.assertEqual(cfg.window_start, "12:00")
        self.assertEqual(cfg.window_end, "00:00")
        sch = ResearchScheduler(cfg, plan_loader=lambda: [])
        self.assertFalse(
            sch.in_window(
                datetime(2026, 9, 11, 11, 59, tzinfo=tehran)
            )
        )
        self.assertTrue(
            sch.in_window(
                datetime(2026, 9, 11, 12, 0, tzinfo=tehran)
            )
        )
        self.assertTrue(
            sch.in_window(
                datetime(2026, 9, 11, 23, 59, tzinfo=tehran)
            )
        )
        self.assertFalse(
            sch.in_window(datetime(2026, 9, 11, 0, 0, tzinfo=tehran))
        )


# ---------------------------------------------------------------------------
# plan selection
# ---------------------------------------------------------------------------


class TestPlanSelection(unittest.TestCase):
    def test_priority_ordering(self):
        plans = [
            make_plan("r22-0000000000000001", priority="LOW_RESEARCH"),
            make_plan("r22-0000000000000002", priority="CRITICAL_RESEARCH"),
            make_plan("r22-0000000000000003", priority="MEDIUM_RESEARCH"),
            make_plan("r22-0000000000000004", priority="HIGH_RESEARCH"),
        ]
        selected = select_plans(plans, 10)
        self.assertEqual(
            [p["plan_id"][-1] for p in selected], ["2", "4", "3", "1"]
        )

    def test_same_priority_recommended_start_then_scores(self):
        plans = [
            make_plan("r22-0000000000000001", recommended_start="REVIEW_REFERENCES"),
            make_plan("r22-0000000000000002", recommended_start="REVIEW_CVE_SUMMARY"),
            make_plan(
                "r22-0000000000000003",
                recommended_start="REVIEW_REFERENCES",
                relevance_score=90,
            ),
        ]
        selected = select_plans(plans, 10)
        # REVIEW_CVE_SUMMARY sorts before REVIEW_REFERENCES; within the latter,
        # the higher relevance score wins.
        self.assertEqual(
            [p["plan_id"][-1] for p in selected], ["2", "3", "1"]
        )

    def test_priority_rank_values(self):
        self.assertEqual(priority_rank("CRITICAL_RESEARCH"), 0)
        self.assertEqual(priority_rank("HIGH_RESEARCH"), 1)
        self.assertEqual(priority_rank("NOPE"), 5)

    def test_completed_plans_excluded(self):
        plans = [
            make_plan("r22-0000000000000001", status="RESEARCH_PLAN_COMPLETED"),
            make_plan("r22-0000000000000002"),
        ]
        self.assertEqual(
            [p["plan_id"] for p in select_plans(plans, 10)],
            ["r22-0000000000000002"],
        )

    def test_max_plans_bound(self):
        plans = [make_plan(f"r22-{i:016x}") for i in range(10)]
        self.assertEqual(len(select_plans(plans, 3)), 3)
        self.assertEqual(len(select_plans(plans, 0)), 0)

    def test_deterministic_regardless_of_input_order(self):
        plans = [make_plan(f"r22-{i:016x}") for i in range(8)]
        forward = [p["plan_id"] for p in select_plans(plans, 8)]
        backward = [p["plan_id"] for p in select_plans(list(reversed(plans)), 8)]
        self.assertEqual(forward, backward)


# ---------------------------------------------------------------------------
# locking + scheduler policy
# ---------------------------------------------------------------------------


class TestLocking(unittest.TestCase):
    def test_acquire_lock_excludes_second(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "l.lock")
            with acquire_lock(path) as first:
                self.assertTrue(first)
                with acquire_lock(path) as second:
                    self.assertFalse(second)

    def test_unwritable_lock_path_returns_false(self):
        with acquire_lock("/proc/definitely/not/writable.lock") as locked:
            self.assertFalse(locked)

    def test_scheduler_skips_when_locked(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = os.path.join(tmp, "l.lock")
            cfg = SchedulerConfig(
                enabled=True,
                window_start="00:00",
                window_end="23:59",
                lock_path=lock,
                agent_dir=tmp,
            )
            plan = make_plan("r22-0000000000000001")
            sch = ResearchScheduler(
                cfg, agent=FakeAgent(), plan_loader=lambda: [plan]
            )
            with acquire_lock(lock) as held:
                self.assertTrue(held)
                record = sch.run_once(force=True)
            self.assertEqual(record["skipped"], "locked")
            self.assertEqual(record["plans_processed"], 0)


class TestSchedulerPolicy(unittest.TestCase):
    def _scheduler(self, tmp, **cfg_kwargs):
        cfg_kwargs.setdefault("enabled", False)
        cfg_kwargs.setdefault("window_start", "00:00")
        cfg_kwargs.setdefault("window_end", "23:59")
        cfg = SchedulerConfig(
            lock_path=os.path.join(tmp, "l.lock"),
            agent_dir=tmp,
            **cfg_kwargs,
        )
        agent = FakeAgent()
        plan = make_plan("r22-0000000000000001")
        return ResearchScheduler(cfg, agent=agent, plan_loader=lambda: [plan]), agent

    def test_disabled_does_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            sch, agent = self._scheduler(tmp, enabled=False)
            record = sch.run_once()
            self.assertEqual(record["skipped"], "disabled")
            self.assertEqual(record["status"], RUN_STATUS_BLOCKED)
            self.assertEqual(agent.seen_plan_ids, [])
            self.assertFalse(os.path.exists(os.path.join(tmp, "runs")))

    def test_outside_window_does_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            sch, agent = self._scheduler(
                tmp, enabled=True, window_start="18:00", window_end="00:00"
            )
            outside = datetime(2026, 1, 1, 12, 0)
            record = sch.run_once(now=outside)
            self.assertEqual(record["skipped"], "outside_window")
            self.assertEqual(agent.seen_plan_ids, [])

    def test_force_ignores_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            sch, agent = self._scheduler(tmp, enabled=False)
            record = sch.run_once(force=True)
            self.assertIsNone(record["skipped"])
            self.assertEqual(agent.seen_plan_ids, ["r22-0000000000000001"])

    def test_disabled_default_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            sch, _ = self._scheduler(tmp, enabled=False)
            self.assertEqual(sch.run_once()["skipped"], "disabled")

    def test_max_plans_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            plans = [make_plan(f"r22-{i:016x}") for i in range(6)]
            cfg = SchedulerConfig(
                enabled=True,
                window_start="00:00",
                window_end="23:59",
                max_plans=2,
                lock_path=os.path.join(tmp, "l.lock"),
                agent_dir=tmp,
            )
            agent = FakeAgent()
            sch = ResearchScheduler(cfg, agent=agent, plan_loader=lambda: plans)
            record = sch.run_once()
            self.assertEqual(record["plans_selected"], 2)
            self.assertEqual(len(agent.seen_plan_ids), 2)

    def test_max_runtime_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            plans = [make_plan(f"r22-{i:016x}") for i in range(3)]
            cfg = SchedulerConfig(
                enabled=True,
                window_start="00:00",
                window_end="23:59",
                max_plans=3,
                max_minutes=1,
                lock_path=os.path.join(tmp, "l.lock"),
                agent_dir=tmp,
            )
            ticks = iter([0.0, 0.0, 10_000.0, 10_000.0, 10_000.0])
            sch = ResearchScheduler(
                cfg,
                agent=FakeAgent(),
                plan_loader=lambda: plans,
                monotonic_fn=lambda: next(ticks),
            )
            record = sch.run_once()
            # first plan processed, remaining stop on the time budget
            self.assertEqual(record["plans_processed"], 1)
            self.assertTrue(
                any("time budget" in f.get("error", "") for f in record["failures"])
            )

    def test_fail_soft_per_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            plans = [make_plan(f"r22-{i:016x}") for i in range(3)]
            cfg = SchedulerConfig(
                enabled=True,
                window_start="00:00",
                window_end="23:59",
                lock_path=os.path.join(tmp, "l.lock"),
                agent_dir=tmp,
            )
            sch = ResearchScheduler(
                cfg, agent=FakeAgent(expire_result=True), plan_loader=lambda: plans
            )
            record = sch.run_once()
            self.assertEqual(record["plans_processed"], 0)
            self.assertEqual(len(record["failures"]), 3)
            self.assertEqual(record["status"], "RESEARCH_FAILED")

    def test_dry_run_has_zero_agent_activity(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = make_plan("r22-0000000000000001")
            cfg = SchedulerConfig(
                enabled=True,
                window_start="00:00",
                window_end="23:59",
                lock_path=os.path.join(tmp, "l.lock"),
                agent_dir=tmp,
            )
            sch = ResearchScheduler(
                cfg, agent=ExplodingAgent(), plan_loader=lambda: [plan]
            )
            record = sch.run_once(dry_run=True)
            self.assertEqual(record["skipped"], "dry_run")
            self.assertEqual(record["plans_selected"], 1)
            # no writes at all
            self.assertFalse(os.path.exists(os.path.join(tmp, "runs")))

    def test_run_uses_agent_and_writes_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = make_plan("r22-0000000000000001")
            cfg = SchedulerConfig(
                enabled=True,
                window_start="00:00",
                window_end="23:59",
                lock_path=os.path.join(tmp, "l.lock"),
                agent_dir=tmp,
            )
            agent = FakeAgent()
            sch = ResearchScheduler(cfg, agent=agent, plan_loader=lambda: [plan])
            record = sch.run_once()
            self.assertEqual(record["status"], RUN_STATUS_COMPLETED)
            self.assertEqual(record["plans_processed"], 1)
            self.assertTrue(storage.latest_run(base=tmp))

    def test_preview_lists_eligible_without_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = make_plan("r22-0000000000000001")
            cfg = SchedulerConfig(
                lock_path=os.path.join(tmp, "l.lock"), agent_dir=tmp
            )
            sch = ResearchScheduler(
                cfg, agent=ExplodingAgent(), plan_loader=lambda: [plan]
            )
            preview = sch.preview()
            self.assertEqual(len(preview["plans"]), 1)


# ---------------------------------------------------------------------------
# source validation (SSRF guard)
# ---------------------------------------------------------------------------


class TestSourceValidation(unittest.TestCase):
    def test_allows_public_https(self):
        url = "https://nvd.nist.gov/vuln/detail/CVE-2026-1557"
        self.assertEqual(validate_source_url(url), url)

    def test_rejects_scheme(self):
        for bad in ("ftp://nvd.nist.gov/x", "file:///etc/passwd", "javascript:x"):
            with self.assertRaises(SourceValidationError):
                validate_source_url(bad)

    def test_rejects_localhost(self):
        for bad in ("http://localhost/x", "http://localhost.localdomain/x"):
            with self.assertRaises(SourceValidationError):
                validate_source_url(bad)

    def test_rejects_loopback(self):
        for bad in ("http://127.0.0.1/x", "http://127.1.2.3/x", "http://[::1]/x"):
            with self.assertRaises(SourceValidationError):
                validate_source_url(bad)

    def test_rejects_rfc1918(self):
        for bad in (
            "http://10.0.0.5/x",
            "http://172.16.3.4/x",
            "http://192.168.1.1/x",
        ):
            with self.assertRaises(SourceValidationError):
                validate_source_url(bad)

    def test_rejects_metadata_endpoints(self):
        for bad in (
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://instance-data/latest/",
        ):
            with self.assertRaises(SourceValidationError):
                validate_source_url(bad)

    def test_rejects_internal_suffix(self):
        with self.assertRaises(SourceValidationError):
            validate_source_url("http://service.internal/x")

    def test_rejects_program_host(self):
        for bad in (
            "https://dell.com/security",
            "https://www.dell.com/security",
        ):
            with self.assertRaises(SourceValidationError):
                validate_source_url(bad, program="dell")

    def test_rejects_forbidden_hosts(self):
        with self.assertRaises(SourceValidationError):
            validate_source_url(
                "https://example.org/x", forbidden_hosts={"example.org"}
            )

    def test_classify_sources(self):
        self.assertEqual(classify_source("https://nvd.nist.gov/x"), "nvd")
        self.assertEqual(classify_source("https://github.com/a/b"), "github")
        self.assertEqual(classify_source("https://wordfence.com/x"), "wordfence")
        self.assertEqual(classify_source("https://wpscan.com/x"), "wpscan")
        self.assertEqual(classify_source("https://example.org/x"), "other")


# ---------------------------------------------------------------------------
# source collector
# ---------------------------------------------------------------------------


class TestSourceCollector(unittest.TestCase):
    def _collector(self, **kwargs):
        return ResearchSourceCollector(research_dir="/tmp/nope", **kwargs)

    def test_url_only_stored_reference_has_no_hash(self):
        col = self._collector()
        sources = col.collect_stored("CVE-2026-1557", ["https://example.org/a"])
        self.assertEqual(len(sources), 1)
        self.assertIsNone(sources[0].content_hash)
        self.assertEqual(sources[0].status, "STORED_ONLY")

    def test_archive_body_yields_trusted_hash(self):
        from ai.collectors.body_extraction import normalize_text, sha256_text

        body = "Some advisory body about the affected component."
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "CVE-2026-1557.references.json").write_text(
                json.dumps(
                    {
                        "cve_id": "CVE-2026-1557",
                        "records": [
                            {
                                "source_url": "https://nvd.nist.gov/x",
                                "source_type": "nvd",
                                "title": "NVD",
                                "body": body,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            col = ResearchSourceCollector(research_dir=tmp)
            sources = col.collect_stored(
                "CVE-2026-1557", ["https://nvd.nist.gov/x"]
            )
        self.assertEqual(sources[0].status, "AVAILABLE")
        self.assertEqual(sources[0].content_hash, sha256_text(normalize_text(body)))

    def test_fetch_records_hash_and_bounds_content(self):
        body = "A" * 50000
        col = self._collector(fetcher=FakeFetcher(content=body), max_doc_chars=100)
        sources = col.collect_stored("CVE-2026-1557", ["https://nvd.nist.gov/x"])
        fetched = col.fetch_sources(sources)
        self.assertEqual(fetched[0].status, "AVAILABLE")
        self.assertLessEqual(fetched[0].char_count, 100)
        self.assertTrue(fetched[0].content_hash)

    def test_fetch_rejects_program_url(self):
        col = self._collector(fetcher=FakeFetcher())
        sources = col.collect_stored("CVE-2026-1557", ["https://dell.com/x"])
        fetched = col.fetch_sources(sources, program="dell")
        self.assertEqual(fetched[0].status, "REJECTED")
        self.assertEqual(col._get_fetcher().calls, [])

    def test_fetch_failure_is_soft(self):
        col = self._collector(fetcher=FakeFetcher(error=RuntimeError("boom")))
        sources = col.collect_stored("CVE-2026-1557", ["https://nvd.nist.gov/x"])
        fetched = col.fetch_sources(sources)
        self.assertEqual(fetched[0].status, "FAILED")

    def test_dedupes_by_url(self):
        col = self._collector()
        sources = col.collect_stored(
            "CVE-2026-1557",
            ["https://nvd.nist.gov/x", "https://nvd.nist.gov/x#frag"],
        )
        self.assertEqual(len(sources), 1)

    def test_content_for_returns_bounded_body(self):
        col = self._collector(fetcher=FakeFetcher(content="hello world"))
        sources = col.collect_stored("CVE-2026-1557", ["https://nvd.nist.gov/x"])
        fetched = col.fetch_sources(sources)
        self.assertIn("hello world", col.content_for(fetched[0]))


# ---------------------------------------------------------------------------
# prompt bounds
# ---------------------------------------------------------------------------


class TestPrompt(unittest.TestCase):
    def test_prompt_is_bounded(self):
        docs = [
            {"url": f"https://nvd.nist.gov/{i}", "content": "x" * 100000,
             "content_hash": "h", "source_type": "nvd", "title": "t"}
            for i in range(50)
        ]
        prompt = build_research_prompt({"cve_id": "CVE-2026-1557"}, docs)
        self.assertLessEqual(len(prompt), 60000)

    def test_prompt_states_research_only_rules(self):
        prompt = build_research_prompt(
            {"cve_id": "CVE-2026-1557"},
            [{"url": "https://nvd.nist.gov/x", "content": "body",
              "content_hash": "h", "source_type": "nvd", "title": "t"}],
        )
        self.assertIn("RESEARCH-ONLY", prompt)
        self.assertIn("Do NOT perform or suggest active validation", prompt)
        self.assertIn("Do NOT output a content_hash", prompt)

    def test_only_hashed_documents_are_supplied(self):
        prompt = build_research_prompt(
            {"cve_id": "CVE-2026-1557"},
            [
                {"url": "https://nvd.nist.gov/hashed", "content": "body",
                 "content_hash": "h", "source_type": "nvd", "title": "t"},
                {"url": "https://nvd.nist.gov/urlonly", "content": "",
                 "content_hash": None, "source_type": "nvd", "title": "t"},
            ],
        )
        self.assertIn("https://nvd.nist.gov/hashed", prompt)
        self.assertNotIn("https://nvd.nist.gov/urlonly\n", prompt + "\n")


# ---------------------------------------------------------------------------
# agent: evidence grounding + safety
# ---------------------------------------------------------------------------


class TestAgentEvidence(unittest.TestCase):
    def _agent(self, tmp, *, llm_payload=None, llm_enabled=True, references=None,
               fetcher=None, **kwargs):
        collector = ResearchSourceCollector(
            research_dir="/tmp/nope", fetcher=fetcher or FakeFetcher()
        )
        return ResearchAgent(
            sources=collector,
            llm=FakeLLM(llm_payload) if llm_payload is not None else None,
            llm_enabled=llm_enabled,
            network_enabled=True,
            agent_dir=tmp,
            payload_loader=payload_loader_factory(
                references or ["https://nvd.nist.gov/x"]
            ),
            intel_loader=intel_loader_factory(),
            lead_loader=lambda lid: {},
            **kwargs,
        )

    def test_grounded_evidence_keeps_source_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(
                tmp,
                llm_payload={
                    "evidence": [
                        {"claim": "Affected version is <=1.0",
                         "source_url": "https://nvd.nist.gov/x",
                         "quote": "<=1.0", "confidence": "HIGH"}
                    ]
                },
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertEqual(len(result.evidence), 1)
        self.assertTrue(result.evidence[0].content_hash)
        self.assertEqual(result.evidence[0].content_hash, result.sources[0].content_hash)

    def test_uncited_source_dropped_to_unknowns(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(
                tmp,
                llm_payload={
                    "evidence": [
                        {"claim": "claim", "source_url": "https://evil.example/x",
                         "quote": "", "confidence": "HIGH"}
                    ]
                },
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertEqual(result.evidence, [])
        self.assertTrue(any("not supplied" in u for u in result.unknowns))

    def test_forbidden_verdict_claim_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(
                tmp,
                llm_payload={
                    "evidence": [
                        {"claim": "the target is VULNERABLE",
                         "source_url": "https://nvd.nist.gov/x",
                         "quote": "", "confidence": "HIGH"}
                    ]
                },
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertEqual(result.evidence, [])
        self.assertTrue(any("unsupported verdict" in u for u in result.unknowns))

    def test_llm_cannot_set_content_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(
                tmp,
                llm_payload={
                    "evidence": [
                        {"claim": "grounded", "source_url": "https://nvd.nist.gov/x",
                         "quote": "q", "confidence": "HIGH",
                         "content_hash": "f" * 64}
                    ]
                },
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        # the hash comes from the source layer, not the model's value
        self.assertNotEqual(result.evidence[0].content_hash, "f" * 64)

    def test_llm_provider_error_reports_exact_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(
                tmp,
                llm_payload=RuntimeError("OpenRouter returned HTTP 429"),
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertEqual(result.status, "RESEARCH_PARTIAL")
        self.assertTrue(any("429" in u for u in result.unknowns), result.unknowns)

    def test_model_unknown_with_verdict_language_scrubbed(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(
                tmp,
                llm_payload={
                    "unknowns": [
                        "the endpoint is vulnerable on target assets",
                        "whether the plugin is installed",
                    ]
                },
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertFalse(any(find_forbidden_terms(u) for u in result.unknowns))
        self.assertTrue(
            any("unsupported verdict" in u for u in result.unknowns)
        )
        self.assertIn("whether the plugin is installed", result.unknowns)

    def test_model_summary_with_verdict_language_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(
                tmp,
                llm_payload={"exploitability_summary": "the target is VULNERABLE"},
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertNotIn("VULNERABLE", result.exploitability_summary.upper())
        self.assertTrue(result.exploitability_summary)

    def test_inferences_marked_model_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(
                tmp,
                llm_payload={
                    "inferences": [
                        {"statement": "Likely relevant to the stack",
                         "basis": "tech", "confidence": "LOW"}
                    ]
                },
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        model_inferences = [i for i in result.inferences if i.model_generated]
        self.assertTrue(model_inferences)

    def test_unknowns_preserved_from_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(tmp, llm_enabled=False)
            plan = make_plan("r22-0000000000000001")
            plan["unknowns"] = ["affected version unknown", "asset version unknown"]
            result = agent.run_plan(plan, run_id="run-x", persist=False)
        for expected in ("affected version unknown", "asset version unknown"):
            self.assertIn(expected, result.unknowns)

    def test_deterministic_offline_has_no_llm_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(tmp, llm_enabled=False)
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertEqual(result.evidence, [])
        self.assertIn(result.status, ("RESEARCH_COMPLETED", "RESEARCH_PARTIAL"))

    def test_nuclei_candidate_never_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(
                tmp,
                llm_payload={
                    "nuclei_candidates": [
                        {"product": "WP Responsive Images",
                         "template_source": "research", "request_shape": "GET /x",
                         "matcher_logic": "version"}
                    ]
                },
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertTrue(result.nuclei_candidates)
        for candidate in result.nuclei_candidates:
            self.assertFalse(candidate.executed)
            self.assertIsNone(candidate.target_url)

    def test_status_blocked_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = ResearchSourceCollector(
                research_dir="/tmp/nope", fetcher=FakeFetcher()
            )
            agent = ResearchAgent(
                sources=collector, llm=None, llm_enabled=False, network_enabled=False,
                agent_dir=tmp,
                payload_loader=payload_loader_factory([]),
                intel_loader=intel_loader_factory(), lead_loader=lambda lid: {},
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertEqual(result.status, "RESEARCH_BLOCKED")

    def test_status_partial_when_fetch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(
                tmp, llm_enabled=False,
                fetcher=FakeFetcher(error=RuntimeError("boom")),
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertEqual(result.status, "RESEARCH_PARTIAL")

    def test_no_vulnerability_vocabulary_in_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(tmp, llm_enabled=False)
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x", persist=False
            )
        self.assertNotIn(result.status, ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING"))

    def test_dry_run_agent_does_not_touch_fetcher_or_llm(self):
        class ExplodingLLM:
            def generate(self, prompt):  # pragma: no cover
                raise AssertionError("LLM must not run in dry-run")

        class ExplodingFetcher:
            def fetch(self, url):  # pragma: no cover
                raise AssertionError("network must not run in dry-run")

        with tempfile.TemporaryDirectory() as tmp:
            collector = ResearchSourceCollector(
                research_dir="/tmp/nope", fetcher=ExplodingFetcher()
            )
            agent = ResearchAgent(
                sources=collector, llm=ExplodingLLM(), llm_enabled=True,
                network_enabled=True, agent_dir=tmp,
                payload_loader=payload_loader_factory(["https://nvd.nist.gov/x"]),
                intel_loader=intel_loader_factory(), lead_loader=lambda lid: {},
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-x",
                dry_run=True, persist=False,
            )
            self.assertFalse(os.path.exists(os.path.join(tmp, "runs")))
        self.assertIsNotNone(result)


class TestResultSchemaSafety(unittest.TestCase):
    def _base(self, **overrides):
        data = {
            "result_id": "ra-0000000000000000",
            "run_id": "run-x",
            "plan_id": "r22-0000000000000001",
            "cve_id": "CVE-2026-1557",
            "program": "dell",
        }
        data.update(overrides)
        return data

    def test_rejects_forbidden_status(self):
        for bad in ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING"):
            with self.assertRaises(Exception):
                ResearchAgentResult(**self._base(status=bad))

    def test_accepts_research_statuses(self):
        for status in ("RESEARCH_COMPLETED", "RESEARCH_PARTIAL",
                       "RESEARCH_BLOCKED", "RESEARCH_FAILED"):
            result = ResearchAgentResult(**self._base(status=status))
            self.assertEqual(result.status, status)

    def test_evidence_requires_hash(self):
        with self.assertRaises(Exception):
            ResearchAgentEvidence(
                evidence_id="ev-1", source_url="https://nvd.nist.gov/x",
                claim="c", content_hash="",
            )

    def test_evidence_requires_source_url(self):
        with self.assertRaises(Exception):
            ResearchAgentEvidence(
                evidence_id="ev-1", source_url="", claim="c", content_hash="h"
            )

    def test_nuclei_candidate_forces_safety(self):
        with self.assertRaises(Exception):
            ResearchAgentNucleiCandidate(product="p", executed=True)
        with self.assertRaises(Exception):
            ResearchAgentNucleiCandidate(product="p", target_url="https://dell.com")

    def test_production_finding_always_false(self):
        with self.assertRaises(Exception):
            ResearchAgentResult(**self._base(production_finding=True))

    def test_result_id_deterministic(self):
        self.assertEqual(
            result_id_for("r22-0000000000000001"),
            result_id_for("r22-0000000000000001"),
        )
        self.assertNotEqual(
            result_id_for("r22-0000000000000001"),
            result_id_for("r22-0000000000000002"),
        )

    def test_find_forbidden_terms(self):
        self.assertEqual(find_forbidden_terms("the target is VULNERABLE"),
                         ["VULNERABLE"])
        self.assertEqual(find_forbidden_terms("not verified yet"), ["VERIFIED"])
        self.assertEqual(find_forbidden_terms("no verdict here"), [])


# ---------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------


class TestPersistence(unittest.TestCase):
    def _result(self, tmp, plan_id="r22-0000000000000001"):
        return ResearchAgentResult(
            result_id=result_id_for(plan_id),
            run_id="run-x",
            plan_id=plan_id,
            cve_id="CVE-2026-1557",
            program="dell",
            status="RESEARCH_PARTIAL",
        )

    def test_store_result_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._result(tmp)
            path, written = storage.store_result(result, base=tmp)
            self.assertTrue(written)
            first = Path(path).read_text(encoding="utf-8")
            path2, written2 = storage.store_result(result, base=tmp)
            self.assertFalse(written2)
            self.assertEqual(first, Path(path2).read_text(encoding="utf-8"))

    def test_no_overwrite_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._result(tmp)
            path, _ = storage.store_result(result, base=tmp)
            changed = result.model_copy(update={"status": "RESEARCH_COMPLETED"})
            storage.store_result(changed, base=tmp)
            loaded = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(loaded["status"], "RESEARCH_PARTIAL")

    def test_report_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._result(tmp)
            p1, w1 = storage.write_report(result, base=tmp)
            text1 = Path(p1).read_text(encoding="utf-8")
            p2, w2 = storage.write_report(result, base=tmp)
            self.assertTrue(w1)
            self.assertFalse(w2)
            self.assertEqual(text1, Path(p2).read_text(encoding="utf-8"))
            self.assertIn("Research Agent Result", text1)

    def test_run_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage.store_run({"run_id": "run-a", "started_at": "2026-01-01T00:00:00"}, base=tmp)
            storage.store_run({"run_id": "run-b", "started_at": "2026-01-02T00:00:00"}, base=tmp)
            runs = storage.list_runs(base=tmp)
            self.assertEqual([r["run_id"] for r in runs], ["run-a", "run-b"])
            self.assertEqual(storage.latest_run(base=tmp)["run_id"], "run-b")

    def test_invalid_plan_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                storage.result_path("../../etc/passwd", RESEARCH_AGENT_RULE_VERSION, base=tmp)

    def test_optional_kb_ingest_is_idempotent(self):
        from ai.knowledge.store import KnowledgeStore

        with tempfile.TemporaryDirectory() as tmp:
            store = KnowledgeStore(root_dir=os.path.join(tmp, "kb"))
            agent = ResearchAgent(
                sources=ResearchSourceCollector(
                    research_dir="/tmp/nope", fetcher=FakeFetcher()
                ),
                llm=None, llm_enabled=False, network_enabled=False,
                agent_dir=os.path.join(tmp, "agent"),
                payload_loader=payload_loader_factory(["https://nvd.nist.gov/x"]),
                intel_loader=intel_loader_factory(), lead_loader=lambda lid: {},
                kb_ingest=True, kb_store=store,
            )
            agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-a", persist=True
            )
            first = list(agent.last_kb_ids)
            agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-b", persist=True
            )
            second = list(agent.last_kb_ids)
        self.assertTrue(first)
        self.assertEqual(first, second)

    def test_full_run_persists_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = ResearchAgent(
                sources=ResearchSourceCollector(
                    research_dir="/tmp/nope", fetcher=FakeFetcher()
                ),
                llm=None, llm_enabled=False, network_enabled=False, agent_dir=tmp,
                payload_loader=payload_loader_factory(["https://nvd.nist.gov/x"]),
                intel_loader=intel_loader_factory(), lead_loader=lambda lid: {},
            )
            result = agent.run_plan(
                make_plan("r22-0000000000000001"), run_id="run-z", persist=True
            )
            files = sorted(os.listdir(tmp))
            self.assertTrue(
                any(f.endswith(".json") and f != "runs" for f in files)
            )
            self.assertTrue(any(f.endswith(".md") for f in files))
            self.assertTrue(result.report_path.endswith(".md"))


# ---------------------------------------------------------------------------
# real corpus (CVE-2026-1557 -> dell), controlled source layer
# ---------------------------------------------------------------------------


class TestRealCorpus(unittest.TestCase):
    def _real_plan(self):
        from backend import research_execution

        plans = research_execution.build_plans()
        return next(
            (
                p
                for p in plans
                if p.get("cve_id") == "CVE-2026-1557"
                and p.get("program") == "dell"
            ),
            None,
        )

    def test_real_plan_selected_and_researched(self):
        plan = self._real_plan()
        self.assertIsNotNone(plan, "CVE-2026-1557 -> dell plan must exist")
        self.assertEqual(plan["plan_id"], "r22-38d26f10681e9a0f")

        from ai.research_agent.agent import ResearchAgent

        class GroundedLLM:
            def generate(self, prompt):
                # cite a supplied wordpress trac reference
                return json.dumps(
                    {
                        "evidence": [
                            {
                                "claim": "The image_handler.php file is part of "
                                "the affected plugin",
                                "source_url": "https://plugins.trac.wordpress.org/"
                                "browser/wp-responsive-images/tags/1.0/"
                                "image_handler.php#L28",
                                "quote": "image_handler",
                                "confidence": "MEDIUM",
                            }
                        ],
                        "inferences": [
                            {"statement": "The plugin is present in the "
                             "persisted research references",
                             "basis": "reference list", "confidence": "LOW"}
                        ],
                        "unknowns": ["whether the program actually runs the plugin"],
                        "nuclei_candidates": [],
                        "recommended_next_step": "REVIEW_PUBLIC_POC",
                    }
                )

        with tempfile.TemporaryDirectory() as tmp:
            collector = ResearchSourceCollector(
                research_dir="ai_data/research", fetcher=FakeFetcher()
            )
            agent = ResearchAgent(
                sources=collector,
                llm=GroundedLLM(),
                llm_enabled=True,
                network_enabled=True,
                agent_dir=tmp,
            )
            result = agent.run_plan(plan, run_id="run-real", persist=True)
            stored = list(Path(tmp).glob("r22-*.json"))

        # plan selected -> sources processed -> evidence generated
        self.assertGreaterEqual(len(result.sources), 1)
        self.assertGreaterEqual(len(result.evidence), 1)
        # unknowns preserved
        self.assertTrue(result.unknowns)
        # result stored
        self.assertTrue(stored)
        # no target interaction: no source URL is a program host
        for source in result.sources:
            self.assertNotIn("dell.com", source.url)
        # research-only: never a finding / forbidden status
        self.assertFalse(result.production_finding)
        self.assertNotIn(
            result.status, ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING")
        )

    def test_real_corpus_offline_is_fail_soft(self):
        plan = self._real_plan()
        self.assertIsNotNone(plan)
        with tempfile.TemporaryDirectory() as tmp:
            collector = ResearchSourceCollector(
                research_dir="ai_data/research", fetcher=FakeFetcher()
            )
            agent = ResearchAgent(
                sources=collector, llm=None, llm_enabled=False,
                network_enabled=False, agent_dir=tmp,
            )
            result = agent.run_plan(plan, run_id="run-real-off", persist=True)
        self.assertIn(result.status, ("RESEARCH_PARTIAL", "RESEARCH_BLOCKED"))
        self.assertFalse(result.production_finding)


# ---------------------------------------------------------------------------
# CLI + API (read-only)
# ---------------------------------------------------------------------------


class TestCli(unittest.TestCase):
    def test_parser_has_agent_subcommands(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        for sub in ("status", "run", "dry-run", "report"):
            args = parser.parse_args(["agent", sub])
            self.assertEqual(args.command, "agent")
            self.assertEqual(args.agent_command, sub)

    def test_dry_run_cli_zero_activity(self):
        from ai import research_cli

        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "WATCH_RESEARCH_ENABLED": "true",
                "WATCH_RESEARCH_LOCK": os.path.join(tmp, "l.lock"),
                "WATCH_RESEARCH_AGENT_DIR": tmp,
            }
            with mock.patch.dict(os.environ, env, clear=False):
                rc = research_cli.main(["agent", "dry-run", "--json"])
            self.assertEqual(rc, 0)
            self.assertFalse(os.path.exists(os.path.join(tmp, "runs")))

    def test_status_cli(self):
        from ai import research_cli

        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "WATCH_RESEARCH_LOCK": os.path.join(tmp, "l.lock"),
                "WATCH_RESEARCH_AGENT_DIR": tmp,
            }
            with mock.patch.dict(os.environ, env, clear=False):
                rc = research_cli.main(["agent", "status", "--json"])
            self.assertEqual(rc, 0)


class TestSafetyScan(unittest.TestCase):
    """Static scan: the R23 package must not reach any execution surface."""

    def _sources(self):
        root = Path("/opt/watch/ai/research_agent")
        files = [root / "agent.py", root / "scheduler.py", root / "sources.py",
                 root / "storage.py", root / "prompts.py"]
        files.append(Path("/opt/watch/ai/schemas/research_agent.py"))
        return [(p, p.read_text(encoding="utf-8")) for p in files]

    def test_no_execution_imports(self):
        banned = (
            "subprocess", "socket", "browser", "live_validation",
            "ai.execution", "ai.verification", "ai.finding", "ai.resolver",
            "nuclei_runner", "ai.authorizer", "ai.persistence",
        )
        for path, text in self._sources():
            lowered = text.lower()
            for needle in banned:
                self.assertNotIn(
                    f"import {needle}", lowered, f"{path.name} imports {needle}"
                )
                self.assertNotIn(
                    f"from {needle} import", lowered,
                    f"{path.name} imports from {needle}",
                )
            self.assertNotIn('import httpx', lowered, f"{path.name} imports httpx")

    def test_no_finding_api(self):
        for path, text in self._sources():
            for needle in ("create_finding", "materialize_finding", "alert("):
                self.assertNotIn(needle, text.lower(), f"{path.name}: {needle}")

    def test_result_statuses_are_research_only(self):
        from ai.schemas.research_agent import AGENT_STATUSES

        self.assertEqual(
            set(AGENT_STATUSES),
            {
                "RESEARCH_COMPLETED",
                "RESEARCH_PARTIAL",
                "RESEARCH_BLOCKED",
                "RESEARCH_FAILED",
            },
        )
        for forbidden in ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING"):
            self.assertNotIn(forbidden, AGENT_STATUSES)


class TestApiAndUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from config import config
        from fastapi.testclient import TestClient

        from api import app

        cls.key = config().get("API_KEY", "")
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if self.key:
            params["api_key"] = self.key
        return self.client.get(path, params=params)

    def test_status_api(self):
        r = self._get("/api/research/agent/status")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("enabled", body)
        self.assertIn("window", body)

    def test_runs_api(self):
        r = self._get("/api/research/agent/runs")
        self.assertEqual(r.status_code, 200)
        self.assertIn("items", r.json())

    def test_agent_page_and_sidebar_link(self):
        r = self._get("/ui/research/agent")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research Agent", r.text)
        self.assertIn("/ui/research/agent", r.text)

    def test_agent_page_takes_precedence_over_cve_route(self):
        r = self._get("/ui/research/agent")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("Invalid CVE identifier", r.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
