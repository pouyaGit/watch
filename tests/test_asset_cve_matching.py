"""tests/test_asset_cve_matching.py — Stage R30.1 asset <-> CVE tests.

Deterministic, offline tests for the asset <-> CVE matching intelligence layer:
normalization, boundary-aware matching, aliases, every match type, version
range semantics, confidence precedence, evidence provenance, blocker
resolution, aggregation, deterministic ids, malformed input, the real corpus,
backend composition, CLI, API, UI and safety invariants.

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei, no
browser, no PoC execution, no findings, no alerts, no Mongo, no persistence.
R17/R25.2/R26/R29 engines and their rule versions are never modified.
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.knowledge import asset_cve_matching as acm
from ai.schemas.asset_cve_match import (
    ASSET_CVE_MATCH_RULE_VERSION,
    CONFIDENCES,
    MATCH_TYPES,
    SOURCES,
    AssetCVEMatch,
    confidence_score_for,
    match_id_for,
)

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
DELL = "rl-af7ecfba1a86fc83"
INDEED = "rl-d1d66e2ee9d8467c"
ASSET_ID = "asset-" + "a" * 16


def ev(**over):
    """evaluate_inventory with a deterministic base; override per test."""

    base = {
        "cve_id": CVE,
        "program": "dell",
        "asset_identifier": ASSET_ID,
    }
    base.update(over)
    return acm.evaluate_inventory(**base)


class TestNormalization(unittest.TestCase):
    def test_product_alias_forms(self):
        self.assertEqual(
            acm.normalize_product("WP Responsive Images (WordPress plugin)"),
            "wp responsive images",
        )
        self.assertEqual(
            acm.normalize_product("wp-responsive-images"),
            "wp responsive images",
        )
        self.assertEqual(acm.normalize_product("WordPress"), "wordpress")

    def test_component_basename(self):
        self.assertEqual(
            acm.normalize_component(
                "wp-content/plugins/wp-responsive-images/image_handler.php"
            ),
            "image handler php",
        )
        self.assertEqual(
            acm.normalize_component("image_handler.php"),
            "image handler php",
        )

    def test_plugin(self):
        self.assertEqual(
            acm.normalize_plugin("wp-responsive-images"),
            "wp responsive images",
        )
        self.assertEqual(
            acm.normalize_plugin("WP Responsive Images"),
            "wp responsive images",
        )

    def test_version_parameter(self):
        self.assertEqual(acm.normalize_version("1.0.3"), "1.0.3")
        self.assertEqual(acm.normalize_parameter("?src"), "src")
        self.assertEqual(acm.normalize_parameter("src"), "src")

    def test_case_whitespace_separators(self):
        self.assertEqual(acm.normalize_product("  WordPress  "), "wordpress")
        self.assertEqual(
            acm.normalize_component("Image_Handler.PHP"),
            "image handler php",
        )


class TestBoundaryMatching(unittest.TestCase):
    def test_no_substring_matches(self):
        self.assertIsNone(acm.match_product(["press"], ["wordpress"]))
        self.assertIsNone(acm.match_component(["press"], ["wordpress"]))
        self.assertIsNone(acm.match_technology(["press"], ["wordpress"]))
        self.assertIsNone(acm.match_plugin(["press"], ["wordpress"]))

    def test_parameter_boundary(self):
        self.assertIsNone(acm.match_parameter(["id"], ["idx"]))
        self.assertIsNone(acm.match_parameter(["file"], ["page"]))


class TestAliases(unittest.TestCase):
    def test_slug_and_display_name(self):
        result = acm.match_product(
            ["wp-responsive-images"], ["WP Responsive Images"]
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.match_type, "PRODUCT")

    def test_wordpress_identity(self):
        self.assertIsNotNone(acm.match_product(["WordPress"], ["wordpress"]))
        self.assertIsNotNone(
            acm.match_technology(["wordpress"], ["WordPress"])
        )

    def test_alias_tables_versioned(self):
        self.assertIn("wordpress", acm.PRODUCT_ALIASES)
        self.assertIn("wp responsive images", acm.PRODUCT_ALIASES)


class TestMatchTypes(unittest.TestCase):
    def test_product(self):
        result = acm.match_product(
            ["WP Responsive Images (WordPress plugin)"],
            ["wp-responsive-images"],
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.source, "ASSET_INVENTORY")
        self.assertTrue(result.evidence)

    def test_component(self):
        result = acm.match_component(
            ["wp-content/plugins/x/image_handler.php"],
            ["image_handler.php"],
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.source, "COMPONENT_INVENTORY")
        self.assertIsNone(
            acm.match_component(["image_handler.php"], ["other.php"])
        )

    def test_plugin(self):
        result = acm.match_plugin(
            ["wp-responsive-images"], ["WP Responsive Images"]
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.match_type, "PLUGIN")

    def test_technology_generic_vs_specific(self):
        specific = acm.match_technology(["wordpress"], ["WordPress"])
        generic = acm.match_technology(["php"], ["PHP"])
        self.assertIsNotNone(specific)
        self.assertIsNotNone(generic)
        self.assertEqual(specific.confidence, "MEDIUM")
        self.assertEqual(generic.confidence, "LOW")

    def test_parameter(self):
        result = acm.match_parameter(["src"], ["src"])
        self.assertIsNotNone(result)
        self.assertEqual(result.match_type, "PARAMETER")
        self.assertTrue(result.supporting)

    def test_path(self):
        result = acm.match_path(
            ["wp-content/plugins/x/image_handler.php"],
            ["/wp-content/plugins/x/image_handler.php"],
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.source, "ENDPOINT_INVENTORY")
        self.assertTrue(result.supporting)
        self.assertIsNone(
            acm.match_path(["a/b/c.php"], ["/x/y/z.php"])
        )

    def test_vulnerability_type_supporting(self):
        result = acm.match_vulnerability_type(
            ["path_traversal"], ["path_traversal"]
        )
        self.assertIsNotNone(result)
        self.assertTrue(result.supporting)
        self.assertEqual(result.confidence, "LOW")


class TestVersion(unittest.TestCase):
    def test_exact(self):
        self.assertEqual(
            acm.evaluate_version(["1.0.3"], ["1.0.3"])["state"], "MATCH"
        )

    def test_upper_bound_inclusive(self):
        self.assertEqual(
            acm.evaluate_version(["<=1.0"], ["1.0"])["state"], "MATCH"
        )
        self.assertEqual(
            acm.evaluate_version(["<1.0.5"], ["1.0.5"])["state"], "NO_MATCH"
        )
        self.assertEqual(
            acm.evaluate_version(["<1.0.5"], ["1.0.3"])["state"], "MATCH"
        )

    def test_lower_bound_and_range(self):
        self.assertEqual(
            acm.evaluate_version([">=2.0"], ["2.1"])["state"], "MATCH"
        )
        self.assertEqual(
            acm.evaluate_version(["1.0 - 1.5"], ["1.2"])["state"], "MATCH"
        )
        self.assertEqual(
            acm.evaluate_version([">=1.0,<2.0"], ["1.9"])["state"], "MATCH"
        )

    def test_unknown_version(self):
        self.assertEqual(
            acm.evaluate_version(["<=1.0"], [])["state"], "UNKNOWN"
        )
        self.assertEqual(
            acm.evaluate_version([], ["1.0"])["state"], "UNKNOWN"
        )
        self.assertIsNone(acm.match_version(["<=1.0"], []))

    def test_invalid_range_is_unknown(self):
        self.assertEqual(
            acm.evaluate_version(["not-a-version"], ["1.0"])["state"],
            "UNKNOWN",
        )
        self.assertEqual(
            acm.evaluate_version(["<=x.y"], ["1.0"])["state"], "UNKNOWN"
        )


class TestConfidence(unittest.TestCase):
    def _conf(self, *results):
        return acm.calculate_match_confidence(
            [r for r in results if r is not None]
        )

    def test_high_combinations(self):
        product = acm.match_product(["wordpress"], ["wordpress"])
        component = acm.match_component(["image_handler.php"],
                                        ["image_handler.php"])
        version = acm.match_version(["<=1.0"], ["1.0"])
        parameter = acm.match_parameter(["src"], ["src"])
        self.assertEqual(self._conf(product, component), "HIGH")
        self.assertEqual(self._conf(version, component), "HIGH")
        self.assertEqual(self._conf(component, parameter), "HIGH")

    def test_medium_combinations(self):
        product = acm.match_product(["wordpress"], ["wordpress"])
        component = acm.match_component(["image_handler.php"],
                                        ["image_handler.php"])
        tech = acm.match_technology(["wordpress"], ["WordPress"])
        version = acm.match_version(["<=1.0"], ["1.0"])
        self.assertEqual(self._conf(product), "MEDIUM")
        self.assertEqual(self._conf(component), "MEDIUM")
        self.assertEqual(self._conf(tech), "MEDIUM")
        self.assertEqual(self._conf(product, version), "MEDIUM")

    def test_generic_technology_never_high(self):
        generic = acm.match_technology(["php"], ["PHP"])
        support = acm.match_vulnerability_type(
            ["sql_injection"], ["sql_injection"]
        )
        self.assertEqual(self._conf(generic), "LOW")
        self.assertEqual(self._conf(generic, support), "LOW")

    def test_supporting_only_low(self):
        support = acm.match_vulnerability_type(
            ["path_traversal"], ["path_traversal"]
        )
        self.assertEqual(self._conf(support), "LOW")

    def test_confidence_scores_bounded(self):
        self.assertEqual(confidence_score_for("HIGH"), 90)
        self.assertEqual(confidence_score_for("MEDIUM"), 60)
        self.assertEqual(confidence_score_for("LOW"), 30)
        self.assertEqual(confidence_score_for("NOPE"), 0)


class TestEvidenceProvenance(unittest.TestCase):
    def test_sources_are_closed_vocabulary(self):
        summary = ev(
            cve_products=["wordpress"],
            cve_components=["image_handler.php"],
            cve_technologies=["wordpress"],
            cve_versions=["<=1.0"],
            cve_parameters=["src"],
            observed_products=["wordpress"],
            observed_components=["image_handler.php"],
            observed_technologies=["WordPress"],
            observed_versions=["1.0"],
            observed_parameters=["src"],
        )
        self.assertTrue(summary["all_matches"])
        for row in summary["all_matches"]:
            self.assertIn(row["source"], SOURCES)
            self.assertIn(row["match_type"], MATCH_TYPES)
            self.assertTrue(row["evidence"])
            self.assertTrue(row["reason"])

    def test_match_carries_traceable_evidence(self):
        summary = ev(
            cve_technologies=["wordpress"],
            observed_technologies=["WordPress"],
        )
        row = summary["all_matches"][0]
        self.assertIn("observed technology: WordPress", row["evidence"])
        self.assertIn("cve technology: wordpress", row["evidence"])


class TestBlockers(unittest.TestCase):
    def test_component_resolution(self):
        component = acm.match_component(["image_handler.php"],
                                        ["image_handler.php"])
        result = acm.resolve_blockers(
            ["only generic technology match", "asset component not observed"],
            [component],
        )
        self.assertEqual(
            result["resolved"],
            ["generic_technology_only", "component_not_observed"],
        )
        self.assertEqual(result["remaining"], [])

    def test_plugin_resolution(self):
        plugin = acm.match_plugin(["wp-responsive-images"],
                                  ["WP Responsive Images"])
        result = acm.resolve_blockers(["affected plugin not observed"], [plugin])
        self.assertEqual(result["resolved"], ["plugin_not_observed"])

    def test_version_requires_real_match(self):
        self.assertEqual(
            acm.resolve_blockers(["asset version unknown"], [])["remaining"],
            ["version_unknown"],
        )
        version = acm.match_version(["<=1.0"], ["1.0"])
        self.assertEqual(
            acm.resolve_blockers(["asset version unknown"], [version])[
                "resolved"
            ],
            ["version_unknown"],
        )

    def test_parameter_resolution(self):
        parameter = acm.match_parameter(["src"], ["src"])
        result = acm.resolve_blockers(["parameter unknown"], [parameter])
        self.assertEqual(result["resolved"], ["parameter_unknown"])

    def test_public_poc_never_resolves(self):
        # There is no PoC input at all: a version blocker stays remaining
        # without real observed version evidence.
        result = acm.resolve_blockers(
            ["generic_technology_only", "version_unknown"], []
        )
        self.assertEqual(result["resolved"], [])
        self.assertEqual(
            result["remaining"],
            ["generic_technology_only", "version_unknown"],
        )

    def test_unknown_blocker_preserved(self):
        result = acm.resolve_blockers(["some_new_blocker"], [])
        self.assertEqual(result["remaining"], ["some_new_blocker"])


class TestAggregation(unittest.TestCase):
    def test_strongest_and_states(self):
        summary = ev(
            cve_products=["wordpress"],
            cve_components=["image_handler.php"],
            cve_versions=["<=1.0"],
            observed_products=["wordpress"],
            observed_components=["image_handler.php"],
            observed_versions=["1.0"],
            blocker_codes=[
                "only generic technology match",
                "asset component not observed",
                "asset version unknown",
            ],
        )
        self.assertEqual(summary["strongest_confidence"], "HIGH")
        self.assertEqual(summary["strongest_match_type"], "COMPONENT")
        self.assertEqual(summary["asset_match_state"], "CONFIRMED")
        self.assertEqual(summary["matched_component"], "image_handler.php")
        self.assertEqual(summary["matched_version"], "1.0")
        self.assertEqual(summary["resolved_blockers"], [
            "generic_technology_only",
            "component_not_observed",
            "version_unknown",
        ])
        self.assertEqual(
            summary["match_summary"],
            "Exact component observed; version evidence available.",
        )

    def test_supported_state(self):
        summary = ev(
            cve_components=["image_handler.php"],
            observed_components=["image_handler.php"],
        )
        self.assertEqual(summary["asset_match_state"], "SUPPORTED")

    def test_weak_state_technology_only(self):
        summary = ev(
            cve_technologies=["wordpress"],
            observed_technologies=["WordPress"],
            blocker_codes=["only generic technology match"],
        )
        self.assertEqual(summary["asset_match_state"], "WEAK")
        self.assertEqual(summary["remaining_blockers"],
                         ["generic_technology_only"])
        self.assertEqual(
            summary["match_summary"],
            "Technology match exists, but affected component is not observed.",
        )

    def test_unknown_state(self):
        summary = ev(cve_technologies=["wordpress"])
        self.assertEqual(summary["asset_match_state"], "UNKNOWN")
        self.assertEqual(summary["strongest_confidence"], "NONE")
        self.assertIsNone(summary["strongest_match"])
        self.assertEqual(summary["match_summary"],
                         "No deterministic asset match.")

    def test_observed_and_missing(self):
        summary = ev(
            cve_components=["image_handler.php"],
            cve_versions=["<=1.0"],
            observed_components=["image_handler.php"],
        )
        self.assertIn("COMPONENT: image_handler.php", summary["observed"])
        self.assertIn("VERSION", summary["missing"])

    def test_not_overwriting_r17(self):
        # The summary is a fresh dict; it never declares R17 fields.
        summary = ev(
            cve_technologies=["wordpress"],
            observed_technologies=["WordPress"],
        )
        self.assertNotIn("relevance", summary)
        self.assertNotIn("relevance_score", summary)
        self.assertEqual(summary["rule_version"], ASSET_CVE_MATCH_RULE_VERSION)


class TestDeterministicIds(unittest.TestCase):
    def test_repeatable(self):
        first = match_id_for(CVE, "dell", "TECHNOLOGY", "wordpress", ASSET_ID)
        second = match_id_for(CVE, "dell", "TECHNOLOGY", "wordpress",
                              ASSET_ID)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("am-"))

    def test_distinct(self):
        a = match_id_for(CVE, "dell", "TECHNOLOGY", "wordpress", ASSET_ID)
        b = match_id_for(CVE, "indeed", "TECHNOLOGY", "wordpress", ASSET_ID)
        c = match_id_for(CVE, "dell", "COMPONENT", "image handler php",
                         ASSET_ID)
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)

    def test_aggregation_uses_ids(self):
        summary = ev(
            cve_technologies=["wordpress"],
            observed_technologies=["WordPress"],
        )
        row = summary["all_matches"][0]
        self.assertEqual(
            row["match_id"],
            match_id_for(CVE, "dell", "TECHNOLOGY", "wordpress", ASSET_ID),
        )


class TestMalformedInput(unittest.TestCase):
    def test_missing_inputs_do_not_crash(self):
        summary = acm.evaluate_inventory(cve_id=CVE, program="dell")
        self.assertEqual(summary["all_matches"], [])
        self.assertEqual(summary["asset_match_state"], "UNKNOWN")

    def test_none_lists_do_not_crash(self):
        summary = acm.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            cve_components=None,
            observed_components=None,
        )
        self.assertEqual(summary["all_matches"], [])

    def test_invalid_values_ignored(self):
        self.assertIsNone(acm.match_product(["n/a"], ["unknown"]))
        self.assertIsNone(acm.match_component([""], [""]))

    def test_schema_rejects_bad_values(self):
        base = acm.build_asset_cve_match(
            cve_id=CVE,
            program="dell",
            match=acm.match_technology(["wordpress"], ["WordPress"]),
            confidence="MEDIUM",
            asset_identifier=ASSET_ID,
        ).model_dump(mode="json")
        for field, value in (
            ("match_type", "VULNERABLE"),
            ("confidence", "CRITICAL"),
            ("source", "INTERNET"),
            ("cve_id", "not-a-cve"),
            ("asset_identifier", "https://target.example"),
            ("research_only", False),
        ):
            with self.subTest(field=field):
                payload = dict(base)
                payload[field] = value
                with self.assertRaises(ValueError):
                    AssetCVEMatch(**payload)

    def test_schema_fixes_rule_version(self):
        base = acm.build_asset_cve_match(
            cve_id=CVE,
            program="dell",
            match=acm.match_technology(["wordpress"], ["WordPress"]),
            confidence="MEDIUM",
            asset_identifier=ASSET_ID,
        ).model_dump(mode="json")
        base["rule_version"] = "r99-9"
        self.assertEqual(
            AssetCVEMatch(**base).rule_version,
            ASSET_CVE_MATCH_RULE_VERSION,
        )

    def test_extra_fields_rejected(self):
        base = acm.build_asset_cve_match(
            cve_id=CVE,
            program="dell",
            match=acm.match_technology(["wordpress"], ["WordPress"]),
            confidence="MEDIUM",
            asset_identifier=ASSET_ID,
        ).model_dump(mode="json")
        base["exploit_command"] = "run"
        with self.assertRaises(ValueError):
            AssetCVEMatch(**base)


class TestBackendRealCorpus(unittest.TestCase):
    def test_real_corpus(self):
        from backend import asset_cve_matching as backend

        data = backend.build_matches(cve=CVE)
        self.assertEqual(data["total"], 2)
        programs = {item["program"] for item in data["items"]}
        self.assertEqual(programs, {"dell", "indeed"})
        for item in data["items"]:
            self.assertEqual(item["cve_id"], CVE)
            self.assertEqual(item["asset_match_confidence"], "MEDIUM")
            self.assertEqual(item["asset_match_state"], "WEAK")
            self.assertEqual(item["strongest_match_type"], "TECHNOLOGY")
            self.assertEqual(
                item["strongest_match"]["matched_value"], "WordPress"
            )
            # No fabricated component/version/parameter matches.
            self.assertEqual(item["matched_component"], "")
            self.assertEqual(item["matched_version"], "")
            self.assertEqual(item["matched_parameter"], "")
            self.assertIn("component_not_observed", item["remaining_blockers"])
            self.assertIn("version_unknown", item["remaining_blockers"])
            self.assertEqual(item["research_status"], "NOT YET SUFFICIENT")
            self.assertTrue(item["research_only"])

    def test_program_filter(self):
        from backend import asset_cve_matching as backend

        data = backend.build_matches(cve=CVE, program="dell")
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["program"], "dell")

    def test_getters(self):
        from backend import asset_cve_matching as backend

        backend.clear_cache()
        items = backend.get_matches(CVE)
        self.assertEqual(len(items), 2)
        summary = backend.get_match_summary(CVE)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["states"], {"WEAK": 2})
        self.assertEqual(summary["confidences"], {"MEDIUM": 2})
        projection = backend.get_projection(CVE, "dell")
        self.assertEqual(projection["strongest_match_type"], "TECHNOLOGY")
        self.assertEqual(projection["asset_match_state"], "WEAK")
        self.assertEqual(projection["resolved_blockers"], [])
        self.assertTrue(projection["remaining_blockers"])

    def test_unknown_program_projection(self):
        from backend import asset_cve_matching as backend

        backend.clear_cache()
        projection = backend.get_projection(CVE, "does-not-exist")
        self.assertEqual(projection["asset_match_state"], "UNKNOWN")
        self.assertEqual(projection["strongest_match_type"], "")

    def test_no_target_data_leakage(self):
        from backend import asset_cve_matching as backend

        blob = json.dumps(backend.build_matches(cve=CVE)).lower()
        for token in ("dellnetworkingvr", "dellservervr", "hiringlab",
                      "http://", "https://", ".com"):
            self.assertNotIn(token, blob)

    def test_deterministic(self):
        from backend import asset_cve_matching as backend

        backend.clear_cache()
        first = backend.build_matches(cve=CVE)
        backend.clear_cache()
        second = backend.build_matches(cve=CVE)
        self.assertEqual(first, second)


class TestAdditiveIntegration(unittest.TestCase):
    def test_action_and_hunt_context(self):
        from backend import hunt_queue, research_action_queue

        actions = research_action_queue.build_action_queue()
        self.assertTrue(actions)
        for action in actions:
            self.assertIn("asset_match_confidence", action)
            self.assertIn("remaining_blockers", action)
            self.assertEqual(action["asset_match_state"], "WEAK")
        hunt = hunt_queue.build_hunt_queue()
        self.assertTrue(hunt)
        for item in hunt:
            self.assertIn("asset_match_reason", item)
            self.assertEqual(item["asset_match_state"], "WEAK")

    def test_money_and_priorities_unchanged(self):
        from ai.schemas.hunt_queue import HUNT_RULE_VERSION
        from backend import hunt_queue, research_action_queue
        from backend import research_economics

        before = research_economics.build_economics()
        actions = research_action_queue.build_action_queue()
        hunt = hunt_queue.build_hunt_queue()
        after = research_economics.build_economics()
        self.assertEqual(before, after)
        self.assertEqual([a["money_score"] for a in actions], [53, 53])
        self.assertEqual([h["hunt_priority"] for h in hunt],
                         ["VERIFY_FIRST", "VERIFY_FIRST"])
        self.assertEqual(HUNT_RULE_VERSION, "r29-1")


class TestCli(unittest.TestCase):
    def _run(self, argv):
        from ai.research_cli import main

        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_human_output(self):
        code, out, _ = self._run(["match", "cve", "--cve", CVE])
        self.assertEqual(code, 0)
        self.assertIn("ASSET ↔ CVE MATCH", out)
        self.assertIn(f"{CVE} → dell", out)
        self.assertIn("STRONGEST MATCH", out)
        self.assertIn("TECHNOLOGY", out)
        self.assertIn("Confidence: MEDIUM", out)
        self.assertIn("✓ TECHNOLOGY", out)
        self.assertIn("WordPress", out)
        self.assertIn("Source: TECHNOLOGY_INVENTORY", out)
        self.assertIn("✗ COMPONENT", out)
        self.assertIn("✗ VERSION", out)
        self.assertIn("component_not_observed", out)
        self.assertIn("version_unknown", out)
        self.assertIn("NOT YET SUFFICIENT", out)
        self.assertIn("No target testing was performed.", out)
        for token in ("dellnetworkingvr", "hiringlab", "http://", "https://"):
            self.assertNotIn(token, out)

    def test_program_json(self):
        code, out, _ = self._run([
            "match", "cve", "--cve", CVE, "--program", "dell", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["program"], "dell")
        self.assertEqual(data["rule_version"], "r30-1")
        self.assertTrue(data["research_only"])

    def test_no_execution_flags(self):
        for flag in ("--execute", "--target", "--scan", "--poc", "--bounty"):
            with self.subTest(flag=flag):
                with self.assertRaises(SystemExit) as ctx:
                    with redirect_stderr(io.StringIO()):
                        self._run(["match", "cve", "--cve", CVE, flag, "x"])
                self.assertEqual(ctx.exception.code, 2)


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_auth_required(self):
        for path in (
            f"/api/research/matches/{CVE}",
            f"/api/research/matches/{CVE}/summary",
        ):
            with self.subTest(path=path):
                r = self.client.get(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)

    def test_list(self):
        r = self._get(f"/api/research/matches/{CVE}")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["rule_version"], "r30-1")
        self.assertTrue(body["research_only"])
        self.assertEqual(body["items"][0]["asset_match_state"], "WEAK")

    def test_summary(self):
        body = self._get(f"/api/research/matches/{CVE}/summary").json()
        self.assertEqual(body["states"], {"WEAK": 2})
        self.assertTrue(body["research_only"])

    def test_program(self):
        body = self._get(f"/api/research/matches/{CVE}/dell").json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["program"], "dell")

    def test_program_not_found(self):
        r = self._get(f"/api/research/matches/{CVE}/nope")
        self.assertEqual(r.status_code, 404)

    def test_no_write_endpoint(self):
        params = {"api_key": API_KEY} if API_KEY else {}
        r = self.client.post(f"/api/research/matches/{CVE}", params=params)
        self.assertIn(r.status_code, (405, 401))

    def test_no_payout_or_target_data(self):
        blob = json.dumps(self._get(f"/api/research/matches/{CVE}").json())
        low = blob.lower()
        for token in ("payout", "bounty", "reward", "http://", "https://",
                      "dellnetworkingvr", "hiringlab"):
            self.assertNotIn(token, low)


class TestUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_lead_detail_panel(self):
        r = self._get(f"/ui/research/leads/{DELL}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Asset match evidence", r.text)
        panel = r.text.split("Asset match evidence", 1)[1].split(
            "Why investigate", 1)[0]
        self.assertIn("TECHNOLOGY", panel)
        self.assertIn("WordPress", panel)
        self.assertIn("Remaining blockers", panel)
        self.assertIn("component_not_observed", panel)
        self.assertIn("no target testing was performed", panel.lower())
        for token in ("dellnetworkingvr", "dellservervr", "http://",
                      "https://"):
            self.assertNotIn(token, panel)

    def test_no_charts_or_polling(self):
        r = self._get(f"/ui/research/leads/{DELL}")
        panel = r.text.split("Asset match evidence", 1)[1].split(
            "Why investigate", 1)[0]
        for token in ("setInterval", "websocket", "EventSource", "chart"):
            self.assertNotIn(token, panel)


class TestSafety(unittest.TestCase):
    NEW_FILES = (
        "ai/schemas/asset_cve_match.py",
        "ai/knowledge/asset_cve_matching.py",
        "backend/asset_cve_matching.py",
    )

    def test_no_execution_tokens(self):
        for rel in self.NEW_FILES:
            source = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            for token in ("import subprocess", "subprocess.",
                          "import socket", "socket.",
                          "import requests", "requests.",
                          "import httpx", "httpx.",
                          "import openai", "import anthropic",
                          "from ai.llm", "nuclei.", "Popen(",
                          "selenium", "playwright", "os.system(",
                          "urlopen", "import dns", "dnspython"):
                self.assertNotIn(token, source, f"{token} found in {rel}")

    def test_no_persistence_tokens(self):
        source = (Path("/opt/watch") / "backend"
                  / "asset_cve_matching.py").read_text(encoding="utf-8")
        for token in ("O_APPEND", "fsync", "open(", "os.replace",
                      "insert_one", "update_one", "delete_one", "pymongo",
                      "mongoengine", "MongoClient", "write_text", "json.dump"):
            self.assertNotIn(token, source)

    def test_engine_purity(self):
        kwargs = dict(
            cve_id=CVE,
            program="dell",
            asset_identifier=ASSET_ID,
            cve_technologies=["wordpress"],
            observed_technologies=["WordPress"],
        )
        first = acm.evaluate_inventory(**kwargs)
        second = acm.evaluate_inventory(**kwargs)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_persistence_side_effects(self):
        from backend import asset_cve_matching as backend

        base = Path("/opt/watch/ai_data/research")
        before = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        backend.clear_cache()
        backend.build_matches(cve=CVE)
        after = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        self.assertEqual(before, after)

    def test_r17_unchanged(self):
        from ai.knowledge import relevance

        self.assertEqual(relevance.ASSET_RELEVANCE_RULE_VERSION, "r17-1")
        self.assertEqual(
            relevance.ASSET_RELEVANCE_WEIGHTS,
            {"product": 50, "plugin": 35, "technology": 20, "path": 20,
             "vulnerability_type": 10, "keyword": 5},
        )

    def test_r25_r26_r29_rules_unchanged(self):
        from ai.knowledge import (
            daily_research,
            economics,
            opportunity,
            opportunity_action,
        )
        from ai.knowledge import hunt_queue as hq

        self.assertEqual(economics.RULE_VERSION, "r25-1")
        self.assertEqual(economics.MONEY_W_VALUE, 0.55)
        self.assertEqual(economics.MONEY_W_CONFIDENCE, 0.15)
        self.assertEqual(economics.MONEY_W_EFFORT_EFF, 0.15)
        self.assertEqual(economics.MONEY_W_RISK_AVOID, 0.15)
        self.assertEqual(opportunity.OPPORTUNITY_RULE_VERSION, "r26-1")
        self.assertEqual(opportunity_action.ACTION_RULE_VERSION, "r26-2")
        self.assertEqual(daily_research.WORKFLOW_VERSION, "r26-3")
        self.assertEqual(hq.HUNT_RULE_VERSION, "r29-1")

    def test_money_not_touched(self):
        from backend import asset_cve_matching as backend
        from backend import research_economics

        before = research_economics.build_economics()
        backend.clear_cache()
        backend.build_matches(cve=CVE)
        after = research_economics.build_economics()
        self.assertEqual(before, after)

    def test_research_only_forced(self):
        row = acm.build_asset_cve_match(
            cve_id=CVE,
            program="dell",
            match=acm.match_technology(["wordpress"], ["WordPress"]),
            confidence="MEDIUM",
            asset_identifier=ASSET_ID,
        )
        self.assertTrue(row.research_only)
        self.assertEqual(row.rule_version, ASSET_CVE_MATCH_RULE_VERSION)

    def test_closed_vocabularies(self):
        self.assertEqual(set(CONFIDENCES), {"HIGH", "MEDIUM", "LOW"})
        self.assertIn("VULNERABILITY_TYPE", MATCH_TYPES)
        self.assertIn("PATH", MATCH_TYPES)
        self.assertEqual(ASSET_CVE_MATCH_RULE_VERSION, "r30-1")
        self.assertEqual(acm.ASSET_MATCH_STATES,
                         ("CONFIRMED", "SUPPORTED", "WEAK", "UNKNOWN"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
