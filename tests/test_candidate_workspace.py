"""Candidate / Finding detail — analyst workspace (UX + data contract).

Covers the authoritative-state contract: one current-state projection,
stale LLM advisory never presented as current state, evidence
deduplication (presentation only), related-candidate deduplication,
navigation without API-key leakage, honest not_recorded/unavailable
rendering, and HTML escaping for every candidate lifecycle state.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.soc import candidate_workspace as cw
from backend.soc.findings import finding_detail
from tests.finding_fixtures import make_candidate

TEMPLATES = Path(__file__).resolve().parents[1] / "web" / "templates"

# credential-shaped literals must be assembled, never stored contiguous
def _secret_shape() -> str:
    return "sk" + "-or" + "-" + "v1-TESTKEY"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def render(detail: dict, *, api_key_qs: str = "") -> str:
    payload = {k: v for k, v in detail.items() if k != "api_key_qs"}
    if not payload.get("workspace"):
        payload["workspace"] = cw.build_workspace(payload)
    return _env().get_template("soc/finding_detail.html").render(
        **payload, request=None, api_key_qs=api_key_qs)


def evidence_row(i: int, obs: str = "urls:obs-1",
                 signal: str = "xss_parameter_inventory",
                 created: str = "2026-09-23T04:38:49Z",
                 job: str = "job-verify") -> dict:
    return {
        "id": f"ev-{i:04d}", "job_id": job, "type": "evidence",
        "observation_ref": obs, "detail": "https://host/x?p=1",
        "reliability": "observed", "directness": "direct",
        "stance": "supporting", "created_at": created, "signal": signal,
    }


def base_detail(**over) -> dict:
    """Synthetic but shape-accurate finding_detail payload."""
    d: dict = {
        "candidate_id": "cand-unit0000000001",
        "candidate": {
            "candidate_id": "cand-unit0000000001",
            "source_job": "job-src-1",
            "scope_ref": "watch:scope:unit/example.com",
            "vulnerability_class": "XSS",
            "hypothesis": "stored inputs present; payload testing out of scope",
            "specialist": "xss-agent",
            "target": "example.com",
            "lifecycle_state": "VERIFIED",
            "duplicate_of": "",
            "endpoint": {"url": "https://example.com/support",
                         "method": "GET", "parameter": ""},
            "parameter": "",
            "confidence": "high",
            "severity": "UNASSESSED",
            "severity_provenance": "unassessed_no_authoritative_rule",
            "provenance": "research_result",
            "created_at": "2026-09-23T04:38:49Z",
            "updated_at": "2026-09-23T04:39:51Z",
            "supporting_signals": ["research_result:high"],
            "missing_evidence": [],
        },
        "evidence": [evidence_row(1), evidence_row(2, obs="urls:obs-2")],
        "related": [],
        "correlations": [],
        "linked_duplicates": [],
        "plans": [],
        "advices": [],
        "lineage": [],
        "transitions": [],
        "case": None,
        "verification": {
            "verification_id": "ver-unit0000001", "state": "VERIFIED",
            "rule_version": "xss-evidence-rules",
            "gate_reason": "evidence_rules_met",
            "created_at": "2026-09-23T04:39:22Z",
            "updated_at": "2026-09-23T04:39:51Z",
            "required_evidence": ["evidence_rules_met"],
            "current_evidence": ["evidence_rules_met"],
            "authorization_ids": [], "plan_ids": [],
            "job_id": "job-verify"},
        "gate": {
            "case_id": "case-gate0001",
            "finding_case_id": "fcase-unit0001",
            "decision": "VERIFIED",
            "gate_reason": "evidence_rules_met",
            "decided_at": "2026-09-23T04:39:51Z"},
        "gate_case": None,
        "package": {},
        "handoff": {},
        "hunt": {},
        "plan_ids": [],
        "authorization_ids": [],
        "advisor": {},
        "model": "",
        "used": False,
        "prompt_version": "",
        "mistakes": [],
        "limitations": [],
        "advisor_provenance": {},
        "provenance": "signal",
        "confidence": "high",
        "confidence_provenance": "research_result",
        "severity": "UNASSESSED",
        "severity_provenance": "unassessed_no_authoritative_rule",
        "hypothesis": "stored inputs present; payload testing out of scope",
        "missing_evidence": [],
        "state": "VERIFIED",
        "duplicate_of": "",
        "api_key_qs": "",
        "evidence_count": 2,
        "evidence_truncated": 0,
        "evidence_model_limit": 300,
        "missing": [],
        "llm": {},
        "model_name": "",
        "used": False,
        "prompt_version": "",
        "advisor_mistakes": [],
        "advisor_provenance": {},
        "limitations": [],
        "handoff_ready": False,
    }
    d.update(over)
    return d


class AuthoritativeStateTest(unittest.TestCase):
    """§1 — one authoritative current-state projection."""

    def test_header_uses_persisted_candidate_state(self):
        ws = cw.build_workspace(base_detail())
        self.assertTrue(ws["available"])
        self.assertEqual(ws["summary"]["candidate_state"], "VERIFIED")
        self.assertEqual(ws["states"]["source"],
                         "candidate + verification + finding case "
                         "(persisted rows only; LLM advisory excluded)")

    def test_stale_llm_state_never_becomes_current_state(self):
        advisor = {"used": True, "confidence": "medium",
                   "candidate_interpretation":
                       "The XSS candidate is in VERIFICATION_PENDING state.",
                   "model_resolved": "openrouter/free",
                   "prompt_version": "finding-verification-advisor-v1"}
        ws = cw.build_workspace(base_detail(advisor=advisor, used=True))
        self.assertEqual(ws["states"]["candidate"], "VERIFIED")
        self.assertEqual(ws["llm"]["current_authoritative_state"], "VERIFIED")
        self.assertEqual(ws["llm"]["state_in_advisory_text"],
                         "VERIFICATION_PENDING")
        self.assertTrue(ws["llm"]["stale"])
        self.assertTrue(ws["llm"]["historical"])
        # no persisted generation-time state field exists — say so
        self.assertEqual(ws["llm"]["state_at_generation"], "not_recorded")
        self.assertEqual(ws["llm"]["model"], "openrouter/free")
        self.assertEqual(ws["llm"]["role"], "ADVISORY ONLY")
        self.assertEqual(ws["llm"]["authority"], "Evidence Gate")

    def test_current_state_is_rendered_as_current_not_stale(self):
        advisor = {"used": True, "confidence": "medium",
                   "candidate_interpretation":
                       "state is VERIFICATION_PENDING",
                   "model_resolved": "openrouter/free"}
        html = render(base_detail(advisor=advisor, used=True))
        head, _, tail = html.partition('id="llm-advisory"')
        self.assertIn(">VERIFIED<", head)            # header = current
        self.assertNotIn("VERIFICATION_PENDING", head)
        self.assertIn("Historical LLM Advisory", tail)
        self.assertIn("VERIFICATION_PENDING", tail)  # only as history
        self.assertIn("Current authoritative state", html)
        self.assertIn("ADVISORY ONLY", html)

    def test_verified_candidate_is_not_called_unconfirmed(self):
        ws = cw.build_workspace(base_detail())
        notice = ws["summary"]["notice"]
        self.assertNotIn("not a confirmed vulnerability", notice)
        self.assertIn("evidence_rules_met", notice)
        html = render(base_detail())
        self.assertNotIn("not a confirmed vulnerability", html)

    def test_undecided_candidate_still_gets_a_truthful_pending_notice(self):
        d = base_detail(lifecycle_state="DETECTED", state="DETECTED",
                        verification=None, gate=None, case=None,
                        transitions=[{
                            "kind": "candidate",
                            "id": "cand-unit0000000001",
                            "old": "", "new": "DETECTED",
                            "reason": "candidate_detected",
                            "created_at": "2026-09-23T04:38:49Z"}])
        ws = cw.build_workspace(d)
        self.assertIn("under review", ws["summary"]["notice"])
        self.assertNotIn("evidence_rules_met", ws["summary"]["notice"])

    def test_candidate_and_case_states_are_both_shown(self):
        case = {"case_id": "fcase-unit1", "state": "READY_FOR_REVIEW",
                "recommended_next_step": "review the timeline"}
        ws = cw.build_workspace(base_detail(case=case))
        self.assertEqual(ws["summary"]["case_state"], "READY_FOR_REVIEW")
        self.assertTrue(ws["case_package"]["exists"])
        html = render(base_detail(case=case))
        self.assertIn(">VERIFIED<", html)
        self.assertIn(">READY_FOR_REVIEW<", html)

    def test_missing_case_and_verification_render_not_recorded(self):
        ws = cw.build_workspace(base_detail(
            lifecycle_state="TRIAGED", state="TRIAGED",
            case=None, verification=None, gate=None, gate_case=None))
        self.assertEqual(ws["summary"]["case_state"], "not_recorded")
        self.assertEqual(ws["verification"]["status"], "not_recorded")
        self.assertEqual(ws["verification"]["verification_id"], "not_recorded")
        self.assertFalse(ws["case_package"]["exists"])
        html = render(base_detail(
            lifecycle_state="TRIAGED", state="TRIAGED",
            case=None, verification=None, gate=None, gate_case=None))
        self.assertIn("not_recorded", html)


class AffectedResourceTest(unittest.TestCase):
    """§4 — exact affected resource + real navigation."""

    def test_affected_url_and_method_from_persisted_endpoint(self):
        ws = cw.build_workspace(base_detail())
        aff = ws["affected"]
        self.assertEqual(aff["url"], "https://example.com/support")
        self.assertEqual(aff["method"], "GET")
        self.assertEqual(aff["path"], "/support")
        self.assertEqual(aff["host"], "example.com")
        self.assertTrue(aff["url_is_link"])

    def test_method_not_recorded_when_endpoint_is_bare_string(self):
        ws = cw.build_workspace(base_detail(
            candidate={**base_detail()["candidate"],
                       "endpoint": "https://example.com/support"}))
        self.assertEqual(ws["affected"]["method"], "not_recorded")

    def test_parameter_not_recorded_when_no_linked_record_has_it(self):
        ws = cw.build_workspace(base_detail())
        self.assertEqual(ws["why"]["parameter_display"],
                         "Not recorded in candidate context")
        checked = ws["why"]["parameter_sources_checked"]
        self.assertTrue(checked)
        joined = " ".join(checked)
        for token in ("candidate", "endpoint record", "url record"):
            self.assertIn(token, joined)

    def test_endpoint_and_url_record_links_when_records_exist(self):
        records = {
            "state": "ok",
            "url_records": {"urls:obs-1": {
                "id": "urls:obs-1",
                "url": "https://example.com/support?q=1",
                "path": "/support", "params": ["q"],
                "program_name": "unit", "sources": ["katana"]}},
            "affected_url": {"id": "urls:aff1",
                             "url": "https://example.com/support",
                             "path": "/support", "params": [],
                             "program_name": "unit"},
            "endpoint": {"id": "endp1", "program_name": "unit",
                         "path": "/support", "http_method": "GET",
                         "params": ["q"]},
            "program_exists": True,
            "reason": "",
        }
        with mock.patch.object(cw, "mongo_records",
                               return_value=records):
            ws = cw.build_workspace(base_detail())
        ep = ws["links"]["endpoint_record"]["href"]
        self.assertTrue(ep.startswith("/ui/endpoints?"), ep)
        self.assertIn("q=%2Fsupport", ep)
        self.assertIn("program=unit", ep)
        ur = ws["links"]["url_record"]["href"]
        self.assertTrue(ur.startswith("/ui/urls?"), ur)
        self.assertIn("program=unit", ur)
        self.assertIn("q=", ur)
        self.assertEqual(ws["links"]["program"]["href"], "/ui/program/unit")
        self.assertTrue(
            ws["links"]["parameter_record"]["href"].startswith(
                "/ui/parameters?"))

    def test_external_affected_url_never_carries_api_key(self):
        detail = base_detail()
        with_key = render(detail, api_key_qs="FIXTUREKEY")
        for href in re.findall(r'href="(https://example\.com[^"]*)"',
                               with_key):
            self.assertNotIn("api_key", href)
        ws = cw.build_workspace(detail)
        self.assertNotIn("api_key", ws["links"]["affected_url"]["href"])

    def test_source_record_state_is_honest_when_lookup_unavailable(self):
        with mock.patch.object(cw, "mongo_records",
                               side_effect=RuntimeError("no mongo")):
            ws = cw.build_workspace(base_detail())
        self.assertEqual(ws["affected"]["records"]["lookup_state"],
                         "unavailable")
        # the program link cannot be claimed without a record
        self.assertEqual(ws["links"]["program"]["kind"], "none")
        self.assertEqual(ws["links"]["program"]["href"], "")
        # filtered index links remain honest navigation (no existence claim)
        self.assertEqual(ws["links"]["endpoint_record"]["kind"], "ui")


class ObservationGroupingTest(unittest.TestCase):
    """§5/§6 — grouped presentation, storage untouched."""

    def _detail(self) -> dict:
        rows = []
        n = 0
        for obs in ("urls:obs-1", "urls:obs-2"):
            for _ in range(3):
                n += 1
                rows.append(evidence_row(n, obs=obs,
                                         signal="xss_parameter_inventory"))
        rows.append(evidence_row(99, obs="job-verify:url-inventory:42",
                                 signal="url_inventory",
                                 created="2026-09-23T04:40:00Z"))
        return base_detail(evidence=rows, evidence_count=len(rows))

    def test_grouping_counts_unique_observations_and_events(self):
        ws = cw.build_workspace(self._detail())
        obs = ws["observations"]
        self.assertEqual(obs["event_count"], 7)
        self.assertEqual(obs["unique_count"], 3)
        self.assertEqual(len(obs["groups"]), 3)

    def test_group_fields_are_complete_and_deterministic(self):
        ws = cw.build_workspace(self._detail())
        grp = ws["observations"]["groups"][0]
        for field in ("observation_id", "type", "signal_quality", "role",
                      "first_observed", "last_observed", "event_count",
                      "jobs", "parameters", "affected_resource"):
            self.assertIn(field, grp)
        self.assertEqual(grp["event_count"], 3)     # two obs + one dup
        self.assertEqual(grp["first_observed"][:19], "2026-09-23T04:38:49")
        self.assertEqual(grp["last_observed"][:19], "2026-09-23T04:38:49")

    def test_dedup_keeps_every_persisted_event(self):
        d = self._detail()
        ws = cw.build_workspace(d)
        grouped_ids = [g["event_count"] for g in ws["observations"]["groups"]]
        self.assertEqual(sum(grouped_ids), len(d["evidence"]))
        # presentation grouping must not mutate the input read model
        self.assertEqual(len(d["evidence"]), 7)
        raw_ids = ws["raw"]["evidence_event_ids"]
        self.assertEqual(len(raw_ids), 7)
        self.assertEqual(len(set(raw_ids)), 7)

    def test_same_observation_across_jobs_groups_once(self):
        rows = [evidence_row(1, obs="urls:obs-1", job="job-a"),
                evidence_row(2, obs="urls:obs-1", job="job-b")]
        ws = cw.build_workspace(base_detail(evidence=rows,
                                            evidence_count=2))
        self.assertEqual(ws["observations"]["unique_count"], 1)
        self.assertEqual(ws["observations"]["event_count"], 2)
        self.assertEqual(
            sorted(ws["observations"]["groups"][0]["jobs"]),
            ["job-a", "job-b"])


class RelatedCandidatesTest(unittest.TestCase):
    """§12 — deduplicate by candidate id, honest current states."""

    def _fs(self, states: dict) -> object:
        class _Cand:
            def __init__(self, state):
                self.lifecycle_state = state

        class _FS:
            def get_candidate(self, cid):
                if cid in states:
                    return _Cand(states[cid])
                return None
        return _FS()

    def _detail(self) -> dict:
        corr = [
            {"candidate_id": "cand-unit0000000001",
             "other_candidate_id": "cand-dup1", "relation": "POSSIBLE_DUPLICATE",
             "reasons": ["same endpoint"], "canonical_id": "", "revisions": 1},
            {"candidate_id": "cand-unit0000000001",
             "other_candidate_id": "cand-dup1", "relation": "RELATED_CANDIDATE",
             "reasons": ["same target"], "canonical_id": "", "revisions": 1},
            {"candidate_id": "cand-unit0000000001",
             "other_candidate_id": "cand-old1", "relation": "POSSIBLE_DUPLICATE",
             "reasons": ["older duplicate"], "canonical_id":
                 "cand-unit0000000001", "revisions": 1},
        ]
        return base_detail(correlations=corr,
                           related=list(corr),
                           linked_duplicates=["cand-old1"])

    def test_each_related_candidate_appears_exactly_once(self):
        ws = cw.build_workspace(self._detail(),
                                fs=self._fs({"cand-dup1": "TRIAGED",
                                             "cand-old1": "DUPLICATE"}))
        rows = ws["related"]["rows"]
        ids = [r["candidate_id"] for r in rows]
        self.assertEqual(sorted(ids), ["cand-dup1", "cand-old1"])
        self.assertEqual(len(ids), len(set(ids)))

    def test_reasons_and_relations_merge_per_candidate(self):
        ws = cw.build_workspace(self._detail(),
                                fs=self._fs({"cand-dup1": "TRIAGED",
                                             "cand-old1": "DUPLICATE"}))
        dup1 = next(r for r in ws["related"]["rows"]
                    if r["candidate_id"] == "cand-dup1")
        self.assertEqual(dup1["relations"],
                         ["POSSIBLE_DUPLICATE", "RELATED_CANDIDATE"])
        self.assertEqual(sorted(dup1["reasons"]),
                         ["same endpoint", "same target"])

    def test_current_states_are_read_from_persisted_candidates(self):
        ws = cw.build_workspace(self._detail(),
                                fs=self._fs({"cand-dup1": "TRIAGED",
                                             "cand-old1": "DUPLICATE"}))
        states = {r["candidate_id"]: r["state"]
                  for r in ws["related"]["rows"]}
        self.assertEqual(states["cand-dup1"], "TRIAGED")
        self.assertEqual(states["cand-old1"], "DUPLICATE")

    def test_missing_related_candidate_state_is_not_invented(self):
        ws = cw.build_workspace(self._detail(), fs=self._fs({}))
        for row in ws["related"]["rows"]:
            self.assertEqual(row["state"], "not_found")
        self.assertEqual(ws["related"]["lookup_state"], "ok")

    def test_canonical_candidate_and_preserved_evidence_shown(self):
        ws = cw.build_workspace(self._detail(), fs=self._fs({}))
        self.assertEqual(ws["related"]["canonical_candidate"],
                         "cand-unit0000000001")
        self.assertTrue(ws["related"]["canonical_is_self"])
        self.assertEqual(ws["related"]["preserved_evidence_from"],
                         ["cand-old1"])

    def test_related_section_renders_each_candidate_once(self):
        ws = cw.build_workspace(self._detail(),
                                fs=self._fs({"cand-dup1": "TRIAGED",
                                             "cand-old1": "DUPLICATE"}))
        html = render({**self._detail(), "workspace": ws})
        section = html.split('id="related-candidates"')[1].split(
            'id="llm-advisory"')[0]
        self.assertEqual(section.count('href="/ui/soc/findings/cand-dup1"'), 1)
        self.assertEqual(section.count('href="/ui/soc/findings/cand-old1"'), 1)


class TimelineAndNextStepTest(unittest.TestCase):
    """§11/§13 — human timeline + persisted analyst next step."""

    def _transitions(self) -> list:
        base = [("04:38:49", "", "DETECTED", "candidate_detected"),
                ("04:38:49", "DETECTED", "TRIAGED",
                 "triage:verify_via_hunt_planner"),
                ("04:38:49", "TRIAGED", "VERIFICATION_PLANNED",
                 "triage_recommends_verification"),
                ("04:38:50", "VERIFICATION_PLANNED",
                 "VERIFICATION_PENDING", "authorization_granted"),
                ("04:39:22", "VERIFICATION_PENDING", "VERIFYING",
                 "verification_started"),
                ("04:39:51", "VERIFYING", "VERIFIED", "evidence_rules_met")]
        return [{"kind": "candidate", "id": "cand-unit0000000001",
                 "old": old, "new": new, "reason": reason,
                 "created_at": f"2026-09-23T{t}Z"}
                for t, old, new, reason in base]

    def _lineage(self) -> list:
        return [
            {"kind": "verification", "stage": "verification:CREATED",
             "created_at": "2026-09-23T04:38:49Z"},
            {"kind": "verification", "stage": "verification:AUTHORIZED",
             "created_at": "2026-09-23T04:38:50Z"},
            {"kind": "verification", "stage": "verification:VERIFIED",
             "created_at": "2026-09-23T04:39:51Z"},
            {"kind": "case", "stage": "case:READY_FOR_REVIEW",
             "created_at": "2026-09-23T04:39:51Z"},
            {"kind": "candidate", "stage": "candidate:VERIFICATION_PENDING",
             "created_at": "2026-09-23T04:38:50Z"},
        ]

    def test_timeline_is_human_readable_ordered_and_complete(self):
        ws = cw.build_workspace(base_detail(
            transitions=self._transitions(), lineage=self._lineage()))
        labels = [e["label"] for e in ws["timeline"]["entries"]]
        self.assertEqual(labels, [
            "Candidate detected", "Triaged", "Verification planned",
            "Authorization granted", "Verification started",
            "Verification completed", "Candidate VERIFIED",
            "Case READY_FOR_REVIEW",
        ])
        times = [e["at"][11:19] for e in ws["timeline"]["entries"]]
        self.assertEqual(times, sorted(times))

    def test_timeline_does_not_dump_raw_engineering_stage_names(self):
        ws = cw.build_workspace(base_detail(
            transitions=self._transitions(), lineage=self._lineage()))
        joined = " ".join(e["label"] for e in ws["timeline"]["entries"])
        self.assertNotIn("verification:CREATED", joined)
        self.assertNotIn("triage:verify_via_hunt_planner", joined)

    def test_raw_lineage_still_available_below_the_fold(self):
        ws = cw.build_workspace(base_detail(
            transitions=self._transitions(), lineage=self._lineage()))
        stages = [r["stage"] for r in ws["raw"]["lineage"]]
        self.assertIn("verification:CREATED", stages)

    def test_analyst_next_step_comes_from_persisted_case_package(self):
        case = {"case_id": "fcase-unit1", "state": "READY_FOR_REVIEW",
                "recommended_next_step": "Review the persisted evidence."}
        ws = cw.build_workspace(base_detail(case=case))
        self.assertEqual(ws["next_step"]["display"],
                         "Review the persisted evidence.")
        self.assertEqual(ws["next_step"]["source"], "case.recommended_next_step")
        self.assertIn("authorized scope", ws["next_step"]["scope_note"])

    def test_next_step_falls_back_to_package_then_not_recorded(self):
        case = {"case_id": "fcase-unit1", "state": "READY_FOR_REVIEW"}
        pkg = {"recommended_analyst_next_step": "step from package"}
        ws = cw.build_workspace(base_detail(case=case, package=pkg))
        self.assertEqual(ws["next_step"]["display"], "step from package")
        ws2 = cw.build_workspace(base_detail(case=None, package={}))
        self.assertIn("No persisted analyst next step",
                      ws2["next_step"]["display"])


class VerifiedAndNotVerifiedTest(unittest.TestCase):
    """§7/§8 — distinguish gate verification / exploitability / severity."""

    def test_what_was_verified_only_uses_persisted_gate_facts(self):
        ver = {"verification_id": "ver-unit1", "state": "VERIFIED",
               "rule_version": "xss", "gate_reason": "evidence_rules_met",
               "created_at": "2026-09-23T04:39:22Z",
               "updated_at": "2026-09-23T04:39:51Z"}
        gate = {"case_id": "case-gate1", "finding_case_id": "fcase-unit1",
                "decision": "VERIFIED", "gate_reason": "evidence_rules_met",
                "decided_at": "2026-09-23T04:39:51Z"}
        pkg = {"evidence_ids": [f"ev-{i}" for i in range(40)],
               "authoritative_verification": {
                   "gate_authoritative": True,
                   "gate_reason": "evidence_rules_met",
                   "evidence_used": [f"ev-{i}" for i in range(10)],
                   "detail": "", "limitations": []}}
        ws = cw.build_workspace(base_detail(verification=ver, gate=gate,
                                            package=pkg))
        self.assertEqual(ws["verification"]["status"], "VERIFIED")
        self.assertEqual(ws["verification"]["rule"], "evidence_rules_met")
        texts = " ".join(p["text"] for p in ws["verified"]["points"])
        self.assertIn("Evidence Gate requirements were satisfied", texts)
        self.assertIn("40 persisted evidence", texts)

    def test_what_was_not_verified_separates_the_four_dimensions(self):
        ver = {"verification_id": "ver-unit1", "state": "VERIFIED",
               "gate_reason": "evidence_rules_met",
               "created_at": "t", "updated_at": "t"}
        gate = {"case_id": "case-gate1", "finding_case_id": "fcase-unit1",
                "decision": "VERIFIED", "gate_reason": "evidence_rules_met",
                "decided_at": "2026-09-23T04:39:51Z"}
        ws = cw.build_workspace(base_detail(verification=ver, gate=gate))
        texts = " ".join(p["text"] for p in ws["not_verified"]["points"])
        self.assertIn("No exploit or payload execution is recorded", texts)
        self.assertIn("Severity remains UNASSESSED", texts)
        self.assertIn("no authoritative severity rule", texts)
        self.assertIn("CVE applicability is not established", texts)
        dims = {d["dimension"] for d in ws["not_verified"]["distinctions"]}
        self.assertEqual(dims, {
            "Evidence Gate verification",
            "Exploitability confirmation",
            "Severity assessment",
            "External-report readiness"})

    def test_no_false_nothing_missing_claim_without_gate(self):
        ws = cw.build_workspace(base_detail(
            verification=None, gate=None, case=None))
        texts = " ".join(p["text"] for p in ws["verified"]["points"])
        self.assertIn("No completed Evidence Gate decision is recorded", texts)

    def test_case_package_counts_match_persisted_package(self):
        pkg = {"evidence_ids": ["ev-1", "ev-2", "ev-3"],
               "evidence_timeline": [{"event": "a", "at": "1"},
                                     {"event": "b", "at": "2"}],
               "limitations": ["l1", "l2", "l3"]}
        case = {"case_id": "fcase-unit1", "state": "READY_FOR_REVIEW"}
        ws = cw.build_workspace(base_detail(case=case, package=pkg))
        cp = ws["case_package"]
        self.assertEqual(cp["evidence_count"], 3)
        self.assertEqual(cp["timeline_count"], 2)
        self.assertEqual(cp["limitations_count"], 3)
        self.assertEqual(cp["handoff_state"], "READY_FOR_REVIEW")


class SecretAndNavigationTest(unittest.TestCase):
    """§16/§15 — no API keys in page content; real routes only."""

    def test_page_contains_no_credential_material(self):
        html = render(base_detail(), api_key_qs="")
        self.assertNotIn(_secret_shape(), html)
        self.assertNotIn("Bearer ", html)
        self.assertNotIn("Authorization:", html)
        self.assertNotIn("OPENROUTER", html)
        # no href may carry an api key when the caller supplied none
        self.assertEqual(
            re.findall(r'href="[^"]*api_key=', html), [])

    def test_server_side_api_key_is_never_injected(self):
        with mock.patch.dict(os.environ, {"API_KEY": _secret_shape()}):
            html = render(base_detail(), api_key_qs="")
        self.assertNotIn(_secret_shape(), html)

    def test_internal_navigation_keeps_existing_auth_propagation(self):
        html = render(base_detail(), api_key_qs="FIXTUREKEY")
        self.assertIn("api_key=FIXTUREKEY", html)   # existing app mechanism
        self.assertNotIn("sk-", html)

    def test_links_only_reference_existing_routes(self):
        ws = cw.build_workspace(base_detail())
        allowed_prefix = ("/ui/", "/api/")
        for name, link in ws["links"].items():
            with self.subTest(link=name):
                href = link["href"]
                if link["kind"] == "external":
                    self.assertTrue(href.startswith("http"), f"{name}: {href}")
                    self.assertNotIn("api_key", href)
                    continue
                self.assertTrue(href.startswith(allowed_prefix)
                                or link["kind"] == "none",
                                f"{name}: {href}")
                self.assertNotIn("api_key", href)

    def test_links_have_notes_when_no_ui_route_exists(self):
        ws = cw.build_workspace(base_detail(
            hunt={"objective_id": "hunt-obj1", "state": "RESOLVED"}))
        obj = ws["links"].get("hunt_objective")
        if obj is not None:
            self.assertEqual(obj["href"], "")
            self.assertIn("no dedicated UI route", obj["note"])


class CandidateStateRenderingTest(unittest.TestCase):
    """§18 — every existing candidate state renders truthfully."""

    STATES = ("DETECTED", "TRIAGED", "VERIFICATION_PLANNED",
              "VERIFICATION_PENDING", "VERIFYING", "VERIFIED",
              "REJECTED", "BLOCKED", "DUPLICATE")

    def test_every_state_renders_with_its_badge_and_honest_notice(self):
        for state in self.STATES:
            with self.subTest(state=state):
                detail = base_detail(
                    lifecycle_state=state, state=state,
                    verification=None, gate=None,
                    case=None if state != "VERIFIED" else {
                        "case_id": "fcase-unit1",
                        "state": "READY_FOR_REVIEW"},
                    transitions=[{
                        "kind": "candidate", "id": "cand-unit0000000001",
                        "old": "", "new": state,
                        "reason": "candidate_detected",
                        "created_at": "2026-09-23T04:38:49Z"}])
                ws = cw.build_workspace(detail)
                html = render(detail)
                self.assertIn(f">{state}<", html)
                self.assertTrue(ws["summary"]["notice"])
                if state != "VERIFIED":
                    self.assertNotIn("not a confirmed vulnerability", html)

    def test_verified_state_gets_gate_wording_not_pending_wording(self):
        ws = cw.build_workspace(base_detail())
        self.assertIn("Evidence Gate decision recorded",
                      ws["summary"]["notice"])
        self.assertNotIn("await", ws["summary"]["notice"].lower())


class StoreBackedRenderingTest(unittest.TestCase):
    """Fixture-store rendering: real FindingStore + template."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        from backend.research_agents.finding.store import FindingStore
        self.fs = FindingStore(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_store_backed_candidate_renders_workspace(self):
        cand = make_candidate(self.fs, cls="XSS")
        self.fs.transition_candidate(cand.candidate_id, "TRIAGED",
                                     reason="triage:verify_via_hunt_planner")
        from tests.finding_fixtures import make_case
        make_case(self.fs, cand, state="READY_FOR_REVIEW")
        with mock.patch("backend.soc.findings._store",
                        return_value=(self.fs, None)):
            detail = finding_detail(cand.candidate_id)
        self.assertTrue(detail["workspace"]["available"])
        html = render(detail)
        self.assertIn(cand.candidate_id, html)
        self.assertIn(">TRIAGED<", html)
        self.assertIn("Why this candidate exists", html)
        self.assertIn("Affected resource", html)
        self.assertIn("Analyst package", html)
        self.assertIn("candidate", html.lower())

    def test_store_backed_stale_case_state_not_shown_as_candidate_state(self):
        cand = make_candidate(self.fs, cls="XSS")
        self.fs.transition_candidate(
            cand.candidate_id, "TRIAGED",
            reason="triage:verify_via_hunt_planner")
        from tests.finding_fixtures import make_case
        make_case(self.fs, cand, state="READY_FOR_REVIEW")
        with mock.patch("backend.soc.findings._store",
                        return_value=(self.fs, None)):
            detail = finding_detail(cand.candidate_id)
        ws = detail["workspace"]
        # candidate lifecycle and case state stay separate, both current
        self.assertEqual(ws["states"]["candidate"], "TRIAGED")
        self.assertEqual(ws["states"]["case"], "READY_FOR_REVIEW")
        self.assertEqual(ws["summary"]["candidate_state"], "TRIAGED")

    def test_workspace_failure_degrades_honestly(self):
        cand = make_candidate(self.fs, cls="XSS")
        with mock.patch("backend.soc.findings._store",
                        return_value=(self.fs, None)), \
             mock.patch("backend.soc.candidate_workspace.build_workspace",
                        side_effect=RuntimeError("boom")):
            detail = finding_detail(cand.candidate_id)
        ws = detail["workspace"]
        self.assertFalse(ws["available"])
        self.assertTrue(ws["error"].startswith("RuntimeError"),
                        ws["error"])
        html = render(detail)
        self.assertIn("Workspace unavailable", html)
        self.assertIn(cand.candidate_id, html)


class HtmlSafetyTest(unittest.TestCase):
    """§18 — XSS/HTML escaping of every user-influenced field."""

    def test_hypothesis_and_target_are_escaped(self):
        payload = '<script>alert("x")</script>'
        detail = base_detail(
            hypothesis=payload,
            candidate={**base_detail()["candidate"],
                       "target": payload,
                       "hypothesis": payload})
        html = render(detail)
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)

    def test_evidence_detail_is_escaped(self):
        rows = [dict(evidence_row(1),
                     detail='<img src=x onerror=alert(1)>')]
        html = render(base_detail(evidence=rows, evidence_count=1))
        self.assertNotIn("<img src=x", html)

    def test_related_candidate_ids_are_escaped(self):
        corr = [{"candidate_id": "cand-unit0000000001",
                 "other_candidate_id": '"><script>x</script>',
                 "relation": "RELATED_CANDIDATE", "reasons": ["r"],
                 "canonical_id": "", "revisions": 1}]
        html = render(base_detail(
            correlations=[{**corr[0], "other_candidate_id":
                           '"><script>x</script>'}],
            related=[corr[0]]))
        self.assertNotIn("<script>x</script>", html)


class ProjectionShapeTest(unittest.TestCase):
    """The projection is JSON-serializable and never carries secrets."""

    def test_projection_serializes_cleanly(self):
        ws = cw.build_workspace(base_detail())
        blob = json.dumps(ws, default=str)
        self.assertNotIn(_secret_shape(), blob)
        self.assertNotIn("Bearer ", blob)
        self.assertTrue(ws["available"])

    def test_projection_has_no_dict_method_name_keys(self):
        # `.items` on a dict payload resolves to dict.items in Jinja
        ws = cw.build_workspace(base_detail())
        self.assertNotIn("items", ws["verified"])
        self.assertNotIn("items", ws["not_verified"])


if __name__ == "__main__":
    unittest.main()
