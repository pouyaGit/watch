"""AUTONOMOUS FINDING VERIFICATION & TRIAGE v1 — SOC layer tests (Phase 15).

Read-only projections: candidate index/detail, Cases-page candidate vs
verified distinction, Handoff integration (index rows + detail
fallback), route registration and template presence.  Every rendered
value comes from real persisted state — empty stores render honest
"no data" UIs, never fabricated rows.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

import backend.soc.findings as soc_findings  # noqa: E402
from backend.soc import cases as soc_cases  # noqa: E402
from backend.soc import handoff as soc_handoff  # noqa: E402
from backend.research_agents.runtime_store import (  # noqa: E402
    RuntimeStore,
)
from tests.finding_fixtures import (  # noqa: E402
    complete_job,
    enqueue_job,
    finding_worker_factory,
    make_stores,
    run_findings,
)

REPO = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = REPO / "web/templates"


def _empty_store():
    """A store whose base has NO finding data (tmp, empty dir)."""
    import tempfile
    tmp = tempfile.mkdtemp(prefix="soc-empty-")
    runtime = RuntimeStore(str(Path(tmp) / "runtime"))
    return runtime, runtime


class TestFindingsIndex(unittest.TestCase):
    def test_empty_store_is_honest_not_fabricated(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="find-idx-")
        runtime = RuntimeStore(str(Path(tmp) / "runtime"))
        fs_store = runtime  # FindingStore(runtime.base)
        from backend.research_agents.finding.store import FindingStore
        fs = FindingStore(runtime.base)
        with mock.patch.object(soc_findings, "_store",
                               return_value=(fs, runtime)):
            payload = soc_findings.findings_index()
        self.assertTrue(payload["source_available"])
        self.assertEqual(payload["count"], 0)
        self.assertEqual(payload["candidates"], [])
        self.assertEqual(payload["verified_count"], 0)
        self.assertEqual(payload["duplicate_count"], 0)
        self.assertEqual(payload["state_counts"], {})

    def test_missing_store_dir_degrades_honestly(self):
        with mock.patch.object(
                soc_findings, "_store",
                side_effect=RuntimeError("injected store outage")):
            payload = soc_findings.findings_index()
        self.assertFalse(payload["source_available"])
        self.assertEqual(payload["candidates"], [])
        self.assertTrue(payload["error"])

    def test_populated_index_reflects_real_pipeline_state(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="verified")
        wf, _ = finding_worker_factory("verified")
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=wf)
        with mock.patch.object(soc_findings, "_store",
                               return_value=(fs, runtime)):
            payload = soc_findings.findings_index()
        self.assertTrue(payload["source_available"])
        self.assertEqual(payload["count"], len(fs.list_candidates()))
        row = payload["candidates"][0]
        for key in ("candidate_id", "vulnerability_class", "state",
                    "verification_state", "evidence_count",
                    "duplicate_status", "severity",
                    "severity_provenance", "last_verification",
                    "detail_url"):
            self.assertIn(key, row)
        self.assertEqual(payload["verified_count"],
                         sum(1 for c in fs.list_candidates()
                             if c.lifecycle_state == "VERIFIED"))
        self.assertIn(row["detail_url"],
                      f"/ui/soc/findings/{row['candidate_id']}")


class TestFindingDetail(unittest.TestCase):
    def test_unknown_candidate_returns_none_for_route_404(self):
        runtime, fs = make_stores()
        with mock.patch.object(soc_findings, "_store",
                               return_value=(fs, runtime)):
            self.assertIsNone(soc_findings.finding_detail("cand-none"))

    def test_detail_carries_all_phase15_sections(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="verified")
        wf, _ = finding_worker_factory("verified")
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=wf)
        cand = [c for c in fs.list_candidates()
                if c.lifecycle_state != "DUPLICATE"]
        cid = (cand[0] if cand else fs.list_candidates()[0]).candidate_id
        with mock.patch.object(soc_findings, "_store",
                               return_value=(fs, runtime)):
            detail = soc_findings.finding_detail(cid)
        self.assertIsNotNone(detail)
        for key in ("candidate", "hypothesis", "state", "missing_evidence",
                    "evidence", "related", "linked_duplicates",
                    "verification", "case", "package", "gate",
                    "transitions", "lineage", "provenance",
                    "severity_provenance", "confidence_provenance",
                    "handoff", "limitations", "research_history"):
            self.assertIn(key, detail)
        self.assertEqual(detail["state"],
                         fs.get_candidate(cid).lifecycle_state)
        # case package built only for verified candidates
        if detail["state"] == "VERIFIED":
            self.assertTrue(detail["package"])
            self.assertIn(
                detail["handoff"].get("verified_status"),
                ("VERIFIED", "READY_FOR_REVIEW", "HANDED_OFF"))
        # honest advisory disclosure: the advisor block is ALWAYS
        # present and populated only when the LLM advisor actually ran
        self.assertIsInstance(detail["advisor"], dict)
        if detail["advisor"]:
            self.assertTrue(detail["advisor"].get("advisory_only"))
        if detail["verification"] and isinstance(
                detail["verification"].get("provenance"), dict):
            adv = detail["verification"]["provenance"].get("advisor")
            if adv:
                self.assertTrue(adv.get("advisory_only", True))


class TestCasesPageDistinction(unittest.TestCase):
    """Phase 15: Cases page distinguishes candidate vs verified case."""

    def _runtime_store(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="cases-rt-")
        return RuntimeStore(str(Path(tmp) / "runtime"))

    def test_cases_index_marks_finding_rows_with_kind(self):
        runtime = self._runtime_store()
        fs_base = runtime.base
        from backend.research_agents.finding.store import FindingStore
        fs = FindingStore(fs_base)
        # a real finding case through the pipeline (fixture-mode stores
        # share the same base so FindingStore(store.base) sees them)
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="verified")
        wf, _ = finding_worker_factory("verified")
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=wf)
        with mock.patch(
                "backend.research_agents.runtime_store.default_store",
                return_value=runtime):
            payload = soc_cases.cases_index()
        rows = payload["cases"] if isinstance(payload, dict) else payload
        finding_rows = [r for r in rows
                        if str(r.get("detail_url") or "").startswith(
                            "/ui/soc/findings/")]
        self.assertTrue(finding_rows, "finding cases must appear on "
                                      "the Cases page")
        fr = finding_rows[0]
        self.assertIn(fr.get("kind"),
                      ("candidate-case", "verified-case"))
        # every row carries a kind for the column (gate/aec/finding)
        for r in rows:
            self.assertIn("kind", r)
        # a VERIFIED finding row must be labelled verified-case
        if any(c.lifecycle_state == "VERIFIED" for c in
               fs.list_candidates()):
            self.assertIn("verified-case",
                          [r.get("kind") for r in finding_rows])


class TestHandoffIntegration(unittest.TestCase):
    """Phase 14: handoff read-only, exposes verified status, no secrets."""

    def _pipeline(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="verified")
        wf, _ = finding_worker_factory("verified")
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=wf)
        return runtime, fs, source

    def test_handoff_index_lists_finding_cases_read_only(self):
        import tempfile
        runtime, fs, source = self._pipeline()
        # handoff_index reads default_store() for reports + FindingStore
        # (same base) for finding rows: patch default_store to tmp
        with mock.patch(
                "backend.research_agents.runtime_store.default_store",
                return_value=runtime):
            payload = soc_handoff.handoff_index()
        rows = payload["reports"] if isinstance(payload, dict) \
            else payload
        finding_rows = [r for r in rows
                        if "/ui/soc/findings/" in str(
                            r.get("view_url") or "")]
        self.assertTrue(finding_rows)
        fr = finding_rows[0]
        # exposed fields (read-only, no secrets)
        for key in ("job_id", "report_id", "target", "category",
                    "agent", "status", "view_url"):
            self.assertIn(key, fr)
        blob = str(fr)
        self.assertNotIn("sk-", blob)
        self.assertNotIn("OPENROUTER_API_KEY", blob)

    def test_handoff_detail_falls_back_to_finding_package(self):
        runtime, fs, source = self._pipeline()
        vers = fs.list_verifications()
        self.assertTrue(vers)
        job_id = vers[-1].job_id or source.id
        with mock.patch(
                "backend.research_agents.runtime_store.default_store",
                return_value=runtime):
            detail = soc_handoff.handoff_detail(job_id)
        self.assertIsNotNone(detail, "a verification/source job with a "
                                     "finding case must resolve in "
                                     "handoff detail")
        blob = str(detail)
        self.assertNotIn("sk-", blob)
        self.assertNotIn("OPENROUTER_API_KEY", blob)
        # read-only view: the verified status is exposed
        self.assertIn("verified_status", detail)

    def test_handoff_still_serves_report_jobs_unchanged(self):
        # a non-finding job with no report -> None as before (no behavior
        # change for legacy handoff)
        runtime = RuntimeStore(self._tmp())
        with mock.patch(
                "backend.research_agents.runtime_store.default_store",
                return_value=runtime):
            self.assertIsNone(soc_handoff.handoff_detail(
                "job-does-not-exist"))

    def _tmp(self):
        import tempfile
        return str(Path(tempfile.mkdtemp(prefix="hf-")) / "runtime")


class TestRoutesAndTemplates(unittest.TestCase):
    def test_routes_registered(self):
        from backend.routers.soc import router
        paths = [getattr(r, "path", "") for r in router.routes]
        self.assertIn("/ui/soc/findings", paths)
        self.assertIn("/ui/soc/findings/{candidate_id}", paths)

    def test_templates_exist_and_are_well_formed(self):
        for name in ("soc/findings.html", "soc/finding_detail.html",
                     "soc/cases.html"):
            self.assertTrue((TEMPLATE_DIR / name).exists(), name)
        # cases template shows the kind column (candidate vs verified)
        cases_html = (TEMPLATE_DIR / "soc/cases.html").read_text(
            encoding="utf-8")
        self.assertIn("case.kind", cases_html)

    def test_detail_template_renders_with_real_payload(self):
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="verified")
        wf, _ = finding_worker_factory("verified")
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=wf)
        cand = fs.list_candidates()[0]
        with mock.patch.object(soc_findings, "_store",
                               return_value=(fs, runtime)):
            detail = soc_findings.finding_detail(cand.candidate_id)
        tpl = env.get_template("soc/finding_detail.html")
        html = tpl.render(**detail, request=None, api_key_qs="")
        self.assertIn(cand.candidate_id, html)
        self.assertIn("candidate", html.lower())
        # limitations always rendered (honest disclosure)
        self.assertIn("limitation", html.lower())

    def test_index_template_renders_honest_empty_state(self):
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
        import tempfile
        tmp = tempfile.mkdtemp(prefix="idx-")
        runtime = RuntimeStore(str(Path(tmp) / "runtime"))
        from backend.research_agents.finding.store import FindingStore
        fs = FindingStore(runtime.base)
        with mock.patch.object(soc_findings, "_store",
                               return_value=(fs, runtime)):
            payload = soc_findings.findings_index()
        tpl = env.get_template("soc/findings.html")
        html = tpl.render(**payload, request=None, api_key_qs="")
        self.assertIn("no candidate findings yet", html.lower())
        # no fabricated rows when empty
        self.assertNotIn("/ui/soc/findings/cand-", html)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
