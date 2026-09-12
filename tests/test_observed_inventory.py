"""tests/test_observed_inventory.py — Stage R30.2 observed inventory tests.

Deterministic, offline tests for the observed component/plugin/version/
parameter/path inventory derived from existing Watch recon records: extraction,
provenance, dedup, normalization, malformed records, missing sources,
deterministic ids, privacy, real corpus, R30.1 integration, blocker resolution
through R30.1, CLI, API, UI and safety invariants.

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei, no
browser, no PoC execution, no findings, no alerts, no Mongo writes, no
persistence. R17/R25.2/R26/R29 and the R30.1 matching semantics are unchanged.
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.knowledge import observed_inventory as oi
from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    ParamRecord,
    SubdomainRecord,
)
from ai.schemas.observed_inventory import (
    EVIDENCE_TYPES,
    INVENTORY_SOURCES,
    OBSERVED_INVENTORY_RULE_VERSION,
    ObservedAssetInventory,
    ObservedItem,
    inventory_id_for,
    observed_item_values,
)

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
DELL = "rl-af7ecfba1a86fc83"
INDEED = "rl-d1d66e2ee9d8467c"


def http(subdomain, tech, *, program="dell", record_id=None):
    return HttpRecord(
        program_name=program,
        subdomain=subdomain,
        scope="dell.com",
        tech=tuple(tech),
        record_id=record_id or f"http-{subdomain}",
    )


def endpoint(subdomain, path, params=(), records=(), *, program="dell",
             record_id=None):
    return EndpointRecord(
        program_name=program,
        subdomain=subdomain,
        path=path,
        example_url=f"https://{subdomain}{path}",
        params=tuple(params),
        param_records=tuple(records),
        record_id=record_id or f"ep-{subdomain}-{path}",
    )


def param(name, method="GET", location="query", source="crawl"):
    return ParamRecord(name=name, method=method, location=location,
                       source=source)


def subdomain(name, *, program="dell"):
    return SubdomainRecord(
        program_name=program, subdomain=name, scope="dell.com",
        record_id=f"sub-{name}",
    )


def build(program="dell", **over):
    records = {
        "http_records": [],
        "endpoint_records": [],
        "subdomain_records": [],
    }
    records.update(over)
    return oi.build_observed_inventory(program, **records)


class TestTechnologyExtraction(unittest.TestCase):
    def test_technologies(self):
        inv = build(
            http_records=[
                http("a.dell.com", ["WordPress", "nginx:1.24.0"]),
                http("b.dell.com", ["jQuery:3.7.1"]),
            ],
            subdomain_records=[subdomain("a.dell.com"),
                               subdomain("b.dell.com")],
        )
        self.assertEqual(
            observed_item_values(inv.technologies),
            ["WordPress", "jQuery", "nginx"],
        )
        for item in inv.technologies:
            self.assertEqual(item.source, "TECHNOLOGY_INVENTORY")
            self.assertEqual(item.evidence_type, "STRUCTURED_TECHNOLOGY")

    def test_dedup_across_subdomains(self):
        inv = build(
            http_records=[
                http("a.dell.com", ["WordPress"]),
                http("b.dell.com", ["WordPress"]),
            ],
            subdomain_records=[subdomain("a.dell.com"),
                               subdomain("b.dell.com")],
        )
        self.assertEqual(observed_item_values(inv.technologies), ["WordPress"])

    def test_dedup_normalized_case(self):
        inv = build(
            http_records=[
                http("a.dell.com", ["WordPress"]),
                http("b.dell.com", ["wordpress"]),
            ],
            subdomain_records=[subdomain("a.dell.com"),
                               subdomain("b.dell.com")],
        )
        self.assertEqual(len(inv.technologies), 1)

    def test_source_row_without_subdomain_record(self):
        inv = build(http_records=[http("orphan.dell.com", ["WordPress"])])
        self.assertEqual(observed_item_values(inv.technologies), ["WordPress"])


class TestVersionExtraction(unittest.TestCase):
    def test_versions_only_when_explicit(self):
        inv = build(
            http_records=[
                http("a.dell.com", ["WordPress", "nginx:1.24.0"]),
            ],
            subdomain_records=[subdomain("a.dell.com")],
        )
        self.assertEqual(observed_item_values(inv.versions), ["1.24.0"])
        for item in inv.versions:
            self.assertEqual(item.evidence_type, "STRUCTURED_TECHNOLOGY")

    def test_no_version_never_inferred(self):
        inv = build(
            http_records=[http("a.dell.com", ["WordPress"])],
            subdomain_records=[subdomain("a.dell.com")],
        )
        self.assertEqual(inv.versions, [])


class TestParameterExtraction(unittest.TestCase):
    def test_parameters_with_provenance(self):
        inv = build(
            endpoint_records=[
                endpoint("a.dell.com", "/search", params=("q",),
                         records=(param("q"),)),
                endpoint("b.dell.com", "/user", params=("id",),
                         records=(param("id", "POST", "body", "x8"),)),
            ],
            subdomain_records=[subdomain("a.dell.com"),
                               subdomain("b.dell.com")],
        )
        self.assertEqual(observed_item_values(inv.parameters), ["id", "q"])
        joined = " ".join(inv.evidence)
        self.assertIn("method=POST location=body source=x8", joined)
        self.assertIn("method=GET location=query source=crawl", joined)

    def test_dedup_and_normalization(self):
        inv = build(
            endpoint_records=[
                endpoint("a.dell.com", "/x", params=("src",),
                         records=(param("src"),)),
                endpoint("b.dell.com", "/y", params=("?src",)),
            ],
            subdomain_records=[subdomain("a.dell.com"),
                               subdomain("b.dell.com")],
        )
        self.assertEqual(observed_item_values(inv.parameters), ["src"])

    def test_arbitrary_strings_are_not_parameters(self):
        inv = build(
            endpoint_records=[endpoint("a.dell.com", "/x")],
            subdomain_records=[subdomain("a.dell.com")],
        )
        self.assertEqual(inv.parameters, [])


class TestPathExtraction(unittest.TestCase):
    def test_paths(self):
        inv = build(
            endpoint_records=[
                endpoint("a.dell.com", "/search"),
                endpoint("b.dell.com", "/user/{id}/profile"),
            ],
            subdomain_records=[subdomain("a.dell.com"),
                               subdomain("b.dell.com")],
        )
        self.assertEqual(
            observed_item_values(inv.paths),
            ["/search", "/user/{id}/profile"],
        )
        for item in inv.paths:
            self.assertEqual(item.source, "ENDPOINT_INVENTORY")
            self.assertEqual(item.evidence_type, "STRUCTURED_ENDPOINT")

    def test_path_dedup(self):
        inv = build(
            endpoint_records=[
                endpoint("a.dell.com", "/search"),
                endpoint("b.dell.com", "/search"),
            ],
            subdomain_records=[subdomain("a.dell.com"),
                               subdomain("b.dell.com")],
        )
        self.assertEqual(observed_item_values(inv.paths), ["/search"])


class TestExplicitCategories(unittest.TestCase):
    def test_products_only_when_explicit(self):
        inv = build(product_records=[{"value": "WordPress"}])
        self.assertEqual(observed_item_values(inv.products), ["WordPress"])
        self.assertEqual(inv.products[0].source, "ASSET_INVENTORY")
        self.assertEqual(inv.products[0].evidence_type, "EXPLICIT_FIELD")

    def test_components_explicit(self):
        inv = build(component_records=[
            ObservedItem(value="image_handler.php", source="COMPONENT_INVENTORY",
                         evidence_type="STRUCTURED_COMPONENT"),
        ])
        self.assertEqual(
            observed_item_values(inv.components), ["image_handler.php"]
        )

    def test_plugins_never_inferred_from_paths(self):
        inv = build(
            endpoint_records=[
                endpoint("a.dell.com",
                         "/wp-content/plugins/wp-responsive-images/")
            ],
            subdomain_records=[subdomain("a.dell.com")],
        )
        self.assertEqual(inv.plugins, [])
        self.assertEqual(inv.components, [])

    def test_products_never_inferred_from_technology(self):
        inv = build(
            http_records=[http("a.dell.com", ["WordPress"])],
            subdomain_records=[subdomain("a.dell.com")],
        )
        self.assertEqual(inv.products, [])
        self.assertEqual(inv.components, [])
        self.assertEqual(inv.plugins, [])


class TestProvenanceAndPrivacy(unittest.TestCase):
    def test_every_item_has_valid_provenance(self):
        inv = build(
            http_records=[http("a.dell.com", ["WordPress:6.4"])],
            endpoint_records=[
                endpoint("a.dell.com", "/x", params=("src",),
                         records=(param("src"),))
            ],
            subdomain_records=[subdomain("a.dell.com")],
            product_records=[{"value": "WordPress"}],
        )
        for key in ("technologies", "products", "components", "plugins",
                    "versions", "parameters", "paths"):
            for item in getattr(inv, key):
                with self.subTest(category=key):
                    self.assertIn(item.source, INVENTORY_SOURCES)
                    self.assertIn(item.evidence_type, EVIDENCE_TYPES)
                    self.assertTrue(item.value)

    def test_evidence_types_closed_no_inference(self):
        self.assertNotIn("INFERRED", EVIDENCE_TYPES)
        self.assertNotIn("GUESSED", EVIDENCE_TYPES)
        self.assertNotIn("LLM_DERIVED", EVIDENCE_TYPES)

    def test_schema_rejects_inferred_evidence(self):
        with self.assertRaises(ValueError):
            ObservedItem(value="x", source="TECHNOLOGY_INVENTORY",
                         evidence_type="INFERRED")

    def test_no_target_identifiers_in_projection(self):
        inv = build(
            http_records=[http("a.dell.com", ["WordPress"])],
            endpoint_records=[endpoint("a.dell.com", "/x", params=("src",))],
            subdomain_records=[subdomain("a.dell.com")],
        )
        blob = json.dumps(inv.model_dump(mode="json")).lower()
        for token in ("dell.com", "http://", "https://", "127.0.0.1",
                      "a.dell.com"):
            self.assertNotIn(token, blob)

    def test_no_example_url_exposed(self):
        inv = build(
            endpoint_records=[endpoint("a.dell.com", "/x")],
            subdomain_records=[subdomain("a.dell.com")],
        )
        blob = json.dumps(inv.model_dump(mode="json"))
        self.assertNotIn("example_url", blob)
        self.assertNotIn("https://a.dell.com", blob)


class TestMalformedAndMissing(unittest.TestCase):
    def test_one_malformed_endpoint_does_not_erase_inventory(self):
        bad = endpoint("a.dell.com", "/bad\npath", record_id="ep-bad")
        good = endpoint("a.dell.com", "/good")
        inv = build(
            endpoint_records=[bad, good],
            subdomain_records=[subdomain("a.dell.com")],
        )
        self.assertEqual(observed_item_values(inv.paths), ["/good"])

    def test_missing_sources_empty(self):
        inv = build()
        self.assertEqual(inv.technologies, [])
        self.assertEqual(inv.parameters, [])
        self.assertEqual(inv.sources, [])
        self.assertEqual(inv.generated_from["http_records"], 0)

    def test_empty_inventory(self):
        inv = build(program="ghost")
        self.assertEqual(inv.program, "ghost")
        self.assertEqual(inv.evidence, [])
        self.assertEqual(inv.paths, [])
        self.assertTrue(inv.research_only)

    def test_none_inputs(self):
        inv = oi.build_observed_inventory(
            "dell", http_records=None, endpoint_records=None,
            subdomain_records=None,
        )
        self.assertEqual(inv.technologies, [])


class TestDeterministicIds(unittest.TestCase):
    def test_inventory_id(self):
        first = inventory_id_for("dell")
        self.assertEqual(first, inventory_id_for("dell"))
        self.assertNotEqual(first, inventory_id_for("indeed"))
        self.assertTrue(first.startswith("inv-"))

    def test_build_deterministic(self):
        kwargs = dict(
            http_records=[http("a.dell.com", ["WordPress"])],
            subdomain_records=[subdomain("a.dell.com")],
        )
        first = build(**kwargs).model_dump(mode="json")
        second = build(**kwargs).model_dump(mode="json")
        self.assertEqual(first, second)

    def test_schema_fixes_rule_version(self):
        inv = build().model_dump(mode="json")
        inv["rule_version"] = "r99-9"
        self.assertEqual(
            ObservedAssetInventory(**inv).rule_version,
            OBSERVED_INVENTORY_RULE_VERSION,
        )

    def test_schema_rejects_bad_program(self):
        with self.assertRaises(ValueError):
            ObservedAssetInventory(
                inventory_id=inventory_id_for("dell"), program="bad program!"
            )

    def test_summary(self):
        inv = build(
            http_records=[http("a.dell.com", ["WordPress:6.4"])],
            endpoint_records=[endpoint("a.dell.com", "/x", params=("src",))],
            subdomain_records=[subdomain("a.dell.com")],
        )
        summary = oi.build_inventory_summary([inv])
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["programs"], ["dell"])
        self.assertEqual(summary["by_program"]["dell"]["technologies"], 1)
        self.assertEqual(summary["rule_version"], "r30-2")
        self.assertTrue(summary["research_only"])


class TestBackendRealCorpus(unittest.TestCase):
    def test_real_inventory_shape(self):
        from backend import observed_inventory as backend

        backend.clear_cache()
        entries = backend.build_inventory()
        programs = {item["program"] for item in entries}
        self.assertIn("dell", programs)
        self.assertIn("indeed", programs)
        for item in entries:
            self.assertEqual(item["rule_version"], "r30-2")
            self.assertTrue(item["research_only"])
            for key in ("technologies", "products", "components", "plugins",
                        "versions", "parameters", "paths"):
                for row in item[key]:
                    self.assertIn(row["source"], INVENTORY_SOURCES)
                    self.assertIn(row["evidence_type"], EVIDENCE_TYPES)
            for row in item.get("version_associations") or []:
                self.assertIn(row["source"], INVENTORY_SOURCES)
                self.assertIn(row["evidence_type"], EVIDENCE_TYPES)
                self.assertTrue(row["version"])
            blob = json.dumps(item).lower()
            # ``.com`` alone is not a valid privacy token: persisted
            # path-only values may legitimately contain host-like segments
            # (e.g. ``/%5c/afcs.dellcdn.com%5c/...``). The projection must not
            # carry raw URL/host fields or schemes instead.
            for token in ("http://", "https://", "dellnetworkingvr",
                          "hiringlab", "example_url"):
                self.assertNotIn(token, blob)

    def test_unknown_program_is_none(self):
        from backend import observed_inventory as backend

        backend.clear_cache()
        self.assertIsNone(backend.get_inventory("definitely-not-a-program"))

    def test_known_program_returns_inventory(self):
        from backend import observed_inventory as backend

        backend.clear_cache()
        inventory = backend.get_inventory("dell")
        self.assertIsNotNone(inventory)
        self.assertEqual(inventory["program"], "dell")
        self.assertEqual(inventory["rule_version"], "r30-2")

    def test_summary_shape(self):
        from backend import observed_inventory as backend

        summary = backend.get_inventory_summary()
        self.assertEqual(summary["rule_version"], "r30-2")
        self.assertTrue(summary["research_only"])
        self.assertIn("dell", summary["programs"])

    def test_injected_records(self):
        from backend import observed_inventory as backend

        records = {
            "http_records": [http("a.dell.com", ["WordPress:6.4"])],
            "endpoint_records": [
                endpoint("a.dell.com", "/x", params=("src",),
                         records=(param("src"),))
            ],
            "subdomain_records": [subdomain("a.dell.com")],
        }
        inventory = backend.get_inventory("dell", records=records)
        self.assertEqual(
            observed_item_values(inventory["technologies"]), ["WordPress"]
        )
        self.assertEqual(
            observed_item_values(inventory["parameters"]), ["src"]
        )
        self.assertEqual(
            observed_item_values(inventory["versions"]), ["6.4"]
        )

    def test_no_persistence(self):
        from backend import observed_inventory as backend

        base = Path("/opt/watch/ai_data/research")
        before = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        backend.clear_cache()
        backend.build_inventory()
        backend.get_inventory_summary()
        after = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        self.assertEqual(before, after)


class TestR301Integration(unittest.TestCase):
    def setUp(self):
        from backend import asset_cve_matching

        asset_cve_matching.clear_cache()

    def tearDown(self):
        from backend import asset_cve_matching

        asset_cve_matching.clear_cache()

    def _fake_inventory(self):
        def fake_get_inventory(program, records=None):
            if program != "dell":
                return None
            return {
                "program": "dell",
                "technologies": [
                    {"value": "WordPress", "source": "TECHNOLOGY_INVENTORY",
                     "evidence_type": "STRUCTURED_TECHNOLOGY"},
                ],
                "products": [
                    {"value": "WP Responsive Images",
                     "source": "ASSET_INVENTORY",
                     "evidence_type": "EXPLICIT_FIELD"},
                ],
                "components": [
                    {"value": "image_handler.php",
                     "source": "COMPONENT_INVENTORY",
                     "evidence_type": "STRUCTURED_COMPONENT"},
                ],
                "plugins": [
                    {"value": "wp-responsive-images",
                     "source": "COMPONENT_INVENTORY",
                     "evidence_type": "STRUCTURED_COMPONENT"},
                ],
                "versions": [
                    {"value": "1.0", "source": "TECHNOLOGY_INVENTORY",
                     "evidence_type": "STRUCTURED_TECHNOLOGY"},
                ],
                "version_associations": [
                    {"version": "1.0", "technology_family": "WordPress",
                     "component": "wp-responsive-images",
                     "source": "COMPONENT_INVENTORY",
                     "evidence_type": "STRUCTURED_COMPONENT"},
                ],
                "parameters": [
                    {"value": "src", "source": "PARAMETER_INVENTORY",
                     "evidence_type": "STRUCTURED_PARAMETER"},
                ],
                "paths": [
                    {"value":
                     "/wp-content/plugins/wp-responsive-images/image_handler.php",
                     "source": "ENDPOINT_INVENTORY",
                     "evidence_type": "STRUCTURED_ENDPOINT"},
                ],
            }

        return fake_get_inventory

    def test_inventory_upgrades_match_through_r301(self):
        from backend import asset_cve_matching

        asset_cve_matching.clear_cache()
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            side_effect=self._fake_inventory(),
        ):
            data = asset_cve_matching.build_matches(cve=CVE, program="dell")
        item = data["items"][0]
        self.assertEqual(item["asset_match_state"], "CONFIRMED")
        self.assertEqual(item["asset_match_confidence"], "HIGH")
        self.assertEqual(item["strongest_match_type"], "COMPONENT")
        self.assertIn("component_not_observed", item["resolved_blockers"])
        self.assertIn("version_unknown", item["resolved_blockers"])
        self.assertEqual(item["remaining_blockers"], [])
        self.assertEqual(item["matched_component"], "image_handler.php")
        self.assertEqual(item["matched_version"], "1.0")
        self.assertEqual(item["matched_parameter"], "src")
        self.assertEqual(
            item["version_association_state"],
            "VERSION_MATCH_WITHIN_SAME_FAMILY",
        )

    def test_unassociated_version_does_not_resolve_version_blocker(self):
        from backend import asset_cve_matching

        base = self._fake_inventory()

        def without_associations(program, records=None):
            inventory = base(program, records)
            if inventory is not None:
                inventory["version_associations"] = []
            return inventory

        asset_cve_matching.clear_cache()
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            side_effect=without_associations,
        ):
            data = asset_cve_matching.build_matches(cve=CVE, program="dell")
        item = data["items"][0]
        self.assertEqual(item["matched_version"], "")
        self.assertIn("version_unknown", item["remaining_blockers"])
        self.assertNotIn("version_unknown", item["resolved_blockers"])
        self.assertEqual(
            item["version_association_state"],
            "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION",
        )

    def test_blockers_resolve_only_through_r301(self):
        from ai.knowledge import asset_cve_matching as engine

        # R30.2 never removes a blocker itself: the engine maps evidence.
        result = engine.resolve_blockers(
            ["component_not_observed"], []
        )
        self.assertEqual(result["remaining"], ["component_not_observed"])
        self.assertEqual(result["resolved"], [])

    def test_r301_matching_semantics_unchanged(self):
        from ai.knowledge import asset_cve_matching as engine
        from ai.schemas.asset_cve_match import ASSET_CVE_MATCH_RULE_VERSION

        self.assertEqual(ASSET_CVE_MATCH_RULE_VERSION, "r30-1")
        self.assertEqual(engine.RULE_VERSION, "r30-1")
        self.assertEqual(
            engine.ASSET_MATCH_STATES,
            ("CONFIRMED", "SUPPORTED", "WEAK", "UNKNOWN"),
        )
        summary = engine.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            asset_identifier="asset-" + "a" * 16,
            cve_technologies=["wordpress"],
            observed_technologies=["WordPress"],
        )
        self.assertEqual(summary["asset_match_state"], "WEAK")
        self.assertEqual(summary["strongest_confidence"], "MEDIUM")

    def test_no_stronger_evidence_stays_weak(self):
        from backend import asset_cve_matching

        asset_cve_matching.clear_cache()
        with mock.patch(
            "backend.observed_inventory.get_inventory", return_value=None
        ):
            data = asset_cve_matching.build_matches(cve=CVE, program="dell")
        item = data["items"][0]
        self.assertEqual(item["asset_match_state"], "WEAK")
        self.assertEqual(item["strongest_match_type"], "TECHNOLOGY")
        self.assertIn("component_not_observed", item["remaining_blockers"])
        self.assertIn("version_unknown", item["remaining_blockers"])


class TestCli(unittest.TestCase):
    def _run(self, argv):
        from ai.research_cli import main

        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_human_output(self):
        from backend import observed_inventory as backend

        fake = [{
            "inventory_id": "inv-" + "a" * 16,
            "program": "dell",
            "technologies": [
                {"value": "WordPress", "source": "TECHNOLOGY_INVENTORY",
                 "evidence_type": "STRUCTURED_TECHNOLOGY"},
            ],
            "products": [],
            "components": [],
            "plugins": [],
            "versions": [
                {"value": "6.4", "source": "TECHNOLOGY_INVENTORY",
                 "evidence_type": "STRUCTURED_TECHNOLOGY"},
            ],
            "parameters": [
                {"value": "src", "source": "PARAMETER_INVENTORY",
                 "evidence_type": "STRUCTURED_PARAMETER"},
            ],
            "paths": [
                {"value": "/x", "source": "ENDPOINT_INVENTORY",
                 "evidence_type": "STRUCTURED_ENDPOINT"},
            ],
            "sources": ["TECHNOLOGY_INVENTORY", "PARAMETER_INVENTORY",
                        "ENDPOINT_INVENTORY"],
            "evidence": [],
            "generated_from": {},
            "rule_version": "r30-2",
            "research_only": True,
        }]
        with mock.patch.object(backend, "build_inventory", return_value=fake):
            code, out, _ = self._run(["inventory", "--program", "dell"])
        self.assertEqual(code, 0)
        self.assertIn("OBSERVED ASSET INVENTORY", out)
        self.assertIn("dell", out)
        self.assertIn("TECHNOLOGIES", out)
        self.assertIn("✓ WordPress", out)
        self.assertIn("PRODUCTS", out)
        self.assertIn("none", out)
        self.assertIn("PATHS", out)
        self.assertIn("1 available records", out)
        self.assertIn("TECHNOLOGY_INVENTORY", out)
        self.assertIn("Research-only: true", out)
        self.assertIn("No target testing was performed.", out)
        for token in ("http://", "https://", "dell.com"):
            self.assertNotIn(token, out)

    def test_json_output(self):
        from backend import observed_inventory as backend

        fake = [{
            "inventory_id": "inv-" + "a" * 16,
            "program": "dell",
            "technologies": [], "products": [], "components": [],
            "plugins": [], "versions": [], "parameters": [], "paths": [],
            "sources": [], "evidence": [], "generated_from": {},
            "rule_version": "r30-2", "research_only": True,
        }]
        with mock.patch.object(backend, "build_inventory", return_value=fake):
            code, out, _ = self._run([
                "inventory", "--program", "dell", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["program"], "dell")
        self.assertEqual(payload["rule_version"], "r30-2")

    def test_no_execution_flags(self):
        for flag in ("--scan", "--execute", "--target", "--nuclei"):
            with self.subTest(flag=flag):
                with self.assertRaises(SystemExit) as ctx:
                    with redirect_stderr(io.StringIO()):
                        self._run(["inventory", flag, "x"])
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
        for path in ("/api/research/inventory/dell",
                     "/api/research/inventory/summary"):
            with self.subTest(path=path):
                r = self.client.get(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)

    def test_program_route(self):
        r = self._get("/api/research/inventory/dell")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["program"], "dell")
        self.assertEqual(body["rule_version"], "r30-2")
        self.assertTrue(body["research_only"])
        for key in ("technologies", "products", "components", "plugins",
                    "versions", "parameters", "paths"):
            self.assertIn(key, body)

    def test_unknown_program_404(self):
        r = self._get("/api/research/inventory/definitely-not-a-program")
        self.assertEqual(r.status_code, 404)

    def test_summary_route(self):
        body = self._get("/api/research/inventory/summary").json()
        self.assertEqual(body["rule_version"], "r30-2")
        self.assertIn("dell", body["programs"])

    def test_no_write_endpoint(self):
        params = {"api_key": API_KEY} if API_KEY else {}
        r = self.client.post("/api/research/inventory/dell", params=params)
        self.assertIn(r.status_code, (405, 401))

    def test_no_target_data(self):
        blob = json.dumps(self._get("/api/research/inventory/dell").json())
        low = blob.lower()
        for token in ("http://", "https://", "dellnetworkingvr",
                      "hiringlab", "example_url"):
            self.assertNotIn(token, low)


class TestUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def setUp(self):
        from backend import asset_cve_matching

        asset_cve_matching.clear_cache()

    def tearDown(self):
        from backend import asset_cve_matching
        from backend import observed_inventory as backend

        asset_cve_matching.clear_cache()
        backend.clear_cache()

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_lead_detail_inventory_panel(self):
        from backend import observed_inventory as backend

        fake = {
            "inventory_id": "inv-" + "a" * 16,
            "program": "dell",
            "technologies": [
                {"value": "WordPress", "source": "TECHNOLOGY_INVENTORY",
                 "evidence_type": "STRUCTURED_TECHNOLOGY"},
            ],
            "products": [],
            "components": [
                {"value": "image_handler.php",
                 "source": "COMPONENT_INVENTORY",
                 "evidence_type": "STRUCTURED_COMPONENT"},
            ],
            "plugins": [],
            "versions": [
                {"value": "6.4", "source": "TECHNOLOGY_INVENTORY",
                 "evidence_type": "STRUCTURED_TECHNOLOGY"},
            ],
            "parameters": [
                {"value": "src", "source": "PARAMETER_INVENTORY",
                 "evidence_type": "STRUCTURED_PARAMETER"},
            ],
            "paths": [
                {"value": "/x", "source": "ENDPOINT_INVENTORY",
                 "evidence_type": "STRUCTURED_ENDPOINT"},
            ],
            "sources": ["TECHNOLOGY_INVENTORY"],
            "evidence": [],
            "generated_from": {},
            "rule_version": "r30-2",
            "research_only": True,
        }
        with mock.patch.object(backend, "get_inventory", return_value=fake):
            r = self._get(f"/ui/research/leads/{DELL}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Observed asset inventory", r.text)
        panel = r.text.split("Observed asset inventory", 1)[1].split(
            "Why investigate", 1)[0]
        self.assertIn("WordPress", panel)
        self.assertIn("image_handler.php", panel)
        self.assertIn("src", panel)
        self.assertIn("1 path record(s)", panel)
        for token in ("http://", "https://", "dell.com",
                      "dellnetworkingvr"):
            self.assertNotIn(token, panel)

    def test_no_charts_or_polling(self):
        r = self._get(f"/ui/research/leads/{DELL}")
        panel = r.text.split("Observed asset inventory", 1)[1].split(
            "Why investigate", 1)[0]
        for token in ("setInterval", "websocket", "EventSource", "chart"):
            self.assertNotIn(token, panel)


class TestSafety(unittest.TestCase):
    NEW_FILES = (
        "ai/schemas/observed_inventory.py",
        "ai/knowledge/observed_inventory.py",
        "backend/observed_inventory.py",
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
                          "urlopen"):
                self.assertNotIn(token, source, f"{token} found in {rel}")

    def test_no_persistence_tokens(self):
        source = (Path("/opt/watch") / "backend"
                  / "observed_inventory.py").read_text(encoding="utf-8")
        for token in ("insert_one", "update_one", "delete_one", "delete_many",
                      "insert_many", "pymongo.MongoClient(",
                      "write_text", "json.dump", "os.replace", "fsync"):
            self.assertNotIn(token, source)

    def test_no_hardcoded_credentials(self):
        source = (Path("/opt/watch") / "backend"
                  / "observed_inventory.py").read_text(encoding="utf-8")
        for token in ("YourStrongPassword", "password=", "mongodb://pouya"):
            self.assertNotIn(token, source)

    def test_no_fabrication_on_empty_input(self):
        inv = build()
        self.assertEqual(inv.technologies, [])
        self.assertEqual(inv.products, [])
        self.assertEqual(inv.components, [])
        self.assertEqual(inv.plugins, [])
        self.assertEqual(inv.versions, [])
        self.assertEqual(inv.parameters, [])
        self.assertEqual(inv.paths, [])
        self.assertEqual(inv.sources, [])
        self.assertEqual(inv.evidence, [])
        self.assertTrue(inv.inventory_id.startswith("inv-"))

    def test_no_persistence_side_effects(self):
        from backend import observed_inventory as backend

        base = Path("/opt/watch/ai_data/research")
        before = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        backend.clear_cache()
        backend.build_inventory()
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

    def test_r25_r26_r29_unchanged(self):
        from ai.knowledge import (
            daily_research,
            economics,
            opportunity,
            opportunity_action,
        )
        from ai.knowledge import hunt_queue as hq

        self.assertEqual(economics.RULE_VERSION, "r25-1")
        self.assertEqual(opportunity.OPPORTUNITY_RULE_VERSION, "r26-1")
        self.assertEqual(opportunity_action.ACTION_RULE_VERSION, "r26-2")
        self.assertEqual(daily_research.WORKFLOW_VERSION, "r26-3")
        self.assertEqual(hq.HUNT_RULE_VERSION, "r29-1")

    def test_money_not_touched(self):
        from backend import observed_inventory as backend
        from backend import research_economics

        before = research_economics.build_economics()
        backend.clear_cache()
        backend.build_inventory()
        after = research_economics.build_economics()
        self.assertEqual(before, after)

    def test_schema_closed_vocabularies(self):
        self.assertEqual(OBSERVED_INVENTORY_RULE_VERSION, "r30-2")
        self.assertEqual(
            set(INVENTORY_SOURCES),
            {"ASSET_INVENTORY", "TECHNOLOGY_INVENTORY",
             "COMPONENT_INVENTORY", "PARAMETER_INVENTORY",
             "ENDPOINT_INVENTORY"},
        )
        self.assertNotIn("CVE_METADATA", INVENTORY_SOURCES)

    def test_research_only_forced(self):
        inv = build()
        self.assertTrue(inv.research_only)
        payload = inv.model_dump(mode="json")
        payload["research_only"] = False
        with self.assertRaises(ValueError):
            ObservedAssetInventory(**payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
