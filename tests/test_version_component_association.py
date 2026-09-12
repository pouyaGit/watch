"""tests/test_version_component_association.py — Stage R30.3 tests.

Deterministic, offline tests for observed version <-> component/family
association: owning-family extraction from persisted technology observations,
explicit component ownership only, the two required version-association
states, no component promotion without association, fail-soft malformed input,
the backend adapter, and safety invariants.

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no browser, no PoC execution, no findings, no alerts, no Mongo writes, no
persistence. R17/R25.2/R26/R29 and the R30.1 matching engine are unchanged.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.knowledge import asset_cve_matching as acm
from ai.knowledge import observed_inventory as oi
from ai.knowledge import version_component_association as vca
from ai.researcher.target_intelligence import (
    HttpRecord,
    SubdomainRecord,
)
from ai.schemas.asset_cve_match import ASSET_CVE_MATCH_RULE_VERSION
from ai.schemas.observed_inventory import (
    OBSERVED_INVENTORY_RULE_VERSION,
    ObservedVersionAssociation,
    VERSION_ASSOCIATION_RULE_VERSION,
)

CVE = "CVE-2026-1557"
DELL_ASSET = "asset-" + "a" * 16


def http(subdomain, tech, *, program="dell"):
    return HttpRecord(
        program_name=program,
        subdomain=subdomain,
        scope="dell.com",
        tech=tuple(tech),
        record_id=f"http-{subdomain}",
    )


def subdomain(name, *, program="dell"):
    return SubdomainRecord(
        program_name=program,
        subdomain=name,
        scope="dell.com",
        record_id=f"sub-{name}",
    )


def assoc(version, family="", component="", **over):
    base = {
        "version": version,
        "technology_family": family,
        "component": component,
    }
    base.update(over)
    return base


def evaluate(**over):
    base = {
        "cve_families": ["WordPress"],
        "cve_components": [],
        "cve_plugins": ["XYZ"],
        "cve_versions": ["<=1.2.3"],
        "observed_versions": [],
    }
    base.update(over)
    return vca.evaluate_version_association(**base)


class TestSameFamilySameComponent(unittest.TestCase):
    """Case 1: same technology + same component + matching version."""

    def test_within_same_family_allowed(self):
        result = evaluate(
            observed_versions=[
                assoc("1.2.3", "WordPress", "XYZ"),
            ],
        )
        self.assertEqual(
            result.state, "VERSION_MATCH_WITHIN_SAME_FAMILY"
        )
        self.assertEqual(result.engine_versions, ("1.2.3",))
        self.assertEqual(result.matched_version, "1.2.3")
        self.assertEqual(result.family, "WordPress")
        self.assertEqual(result.component, "XYZ")
        self.assertTrue(result.component_available)

    def test_engine_combines_component_and_version(self):
        result = evaluate(
            observed_versions=[assoc("1.2.3", "WordPress", "XYZ")],
        )
        summary = acm.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            asset_identifier=DELL_ASSET,
            cve_plugins=["XYZ"],
            cve_versions=["<=1.2.3"],
            observed_plugins=["XYZ"],
            observed_versions=list(result.engine_versions),
        )
        self.assertEqual(summary["asset_match_state"], "CONFIRMED")
        self.assertEqual(summary["strongest_confidence"], "HIGH")
        self.assertEqual(summary["matched_version"], "1.2.3")

    def test_component_record_reported_when_available(self):
        result = evaluate(
            observed_versions=[
                ObservedVersionAssociation(
                    version="1.2.3",
                    technology_family="WordPress",
                    component="wp-responsive-images",
                    source="COMPONENT_INVENTORY",
                    evidence_type="STRUCTURED_COMPONENT",
                )
            ],
            cve_plugins=["WP Responsive Images (WordPress plugin)"],
        )
        self.assertEqual(
            result.state, "VERSION_MATCH_WITHIN_SAME_FAMILY"
        )
        self.assertEqual(result.component, "wp-responsive-images")


class TestDifferentComponent(unittest.TestCase):
    """Case 2: same technology + different component -> no component match."""

    def test_different_component_not_component_associated(self):
        result = evaluate(
            observed_versions=[assoc("1.2.3", "WordPress", "ABC")],
            cve_plugins=["XYZ"],
        )
        self.assertEqual(
            result.state, "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION"
        )
        self.assertEqual(result.engine_versions, ())
        self.assertFalse(result.component_available)
        self.assertEqual(result.component, "")

    def test_no_component_promotion_through_engine(self):
        result = evaluate(
            observed_versions=[assoc("1.2.3", "WordPress", "ABC")],
            cve_plugins=["XYZ"],
        )
        summary = acm.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            asset_identifier=DELL_ASSET,
            cve_plugins=["XYZ"],
            cve_versions=["<=1.2.3"],
            observed_plugins=["ABC"],
            observed_versions=list(result.engine_versions),
        )
        self.assertIsNone(
            next(
                (
                    row
                    for row in summary["all_matches"]
                    if row["match_type"] == "VERSION"
                ),
                None,
            )
        )
        self.assertNotEqual(summary["strongest_confidence"], "HIGH")


class TestTechnologyVersionOnly(unittest.TestCase):
    """Case 3: technology version only + CVE for a plugin."""

    def test_component_unavailable_not_inferred(self):
        result = evaluate(
            cve_versions=["<=7.0"],
            observed_versions=[assoc("6.8.3", "WordPress", "")],
        )
        self.assertEqual(
            result.state, "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION"
        )
        self.assertEqual(result.engine_versions, ())
        self.assertEqual(result.matched_version, "6.8.3")
        self.assertFalse(result.component_available)

    def test_version_not_passed_into_engine(self):
        result = evaluate(
            cve_versions=["<=7.0"],
            observed_versions=[assoc("6.8.3", "WordPress", "")],
        )
        summary = acm.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            asset_identifier=DELL_ASSET,
            cve_technologies=["wordpress"],
            cve_plugins=["XYZ"],
            cve_versions=["<=7.0"],
            observed_technologies=["WordPress"],
            observed_versions=list(result.engine_versions),
            blocker_codes=["asset version unknown", "affected plugin not observed"],
        )
        self.assertEqual(summary["strongest_match_type"], "TECHNOLOGY")
        self.assertEqual(summary["matched_version"], "")
        self.assertEqual(summary["matched_component"], "")
        self.assertIn("version_unknown", summary["remaining_blockers"])
        self.assertIn("plugin_not_observed", summary["remaining_blockers"])


class TestComponentWithoutVersion(unittest.TestCase):
    """Case 4: component present but version absent."""

    def test_component_match_possible_version_unavailable(self):
        result = evaluate(
            observed_versions=[],
            observed_plugins=["XYZ"],
        )
        self.assertEqual(
            result.state, "COMPONENT_ASSOCIATED_VERSION_UNKNOWN"
        )
        self.assertEqual(result.engine_versions, ())
        self.assertEqual(result.matched_version, "")
        self.assertTrue(result.component_available)

    def test_engine_component_only_medium(self):
        result = evaluate(
            observed_versions=[],
            observed_plugins=["XYZ"],
        )
        summary = acm.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            asset_identifier=DELL_ASSET,
            cve_plugins=["XYZ"],
            cve_versions=["<=1.2.3"],
            observed_plugins=["XYZ"],
            observed_versions=list(result.engine_versions),
        )
        self.assertEqual(summary["strongest_match_type"], "PLUGIN")
        self.assertEqual(summary["asset_match_state"], "SUPPORTED")
        self.assertEqual(summary["matched_version"], "")


class TestVersionWithoutOwner(unittest.TestCase):
    """Case 5: version present but owning component unavailable."""

    def test_version_retained_component_unavailable(self):
        result = evaluate(
            cve_versions=["<=7.0"],
            observed_versions=[assoc("6.8.3", "WordPress", "")],
        )
        self.assertEqual(
            result.state, "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION"
        )
        self.assertEqual(result.matched_version, "6.8.3")
        self.assertEqual(result.family, "WordPress")
        self.assertEqual(result.component, "")
        self.assertTrue(
            any("observed component: unavailable" in line
                for line in result.evidence)
        )

    def test_unassociated_metadata_version_not_promoted(self):
        # A version with no owner at all (persisted research metadata).
        result = evaluate(
            cve_versions=["<=1.0"],
            observed_versions=[assoc("1.0", "", "")],
        )
        self.assertEqual(
            result.state, "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION"
        )
        self.assertEqual(result.engine_versions, ())
        self.assertEqual(result.matched_version, "1.0")


class TestDifferentFamilies(unittest.TestCase):
    """Case 6: different technology families -> no association."""

    def test_family_mismatch(self):
        result = evaluate(
            cve_versions=["<=4.0"],
            observed_versions=[assoc("3.7.1", "jQuery", "")],
        )
        self.assertEqual(result.state, "FAMILY_MISMATCH")
        self.assertEqual(result.engine_versions, ())

    def test_family_mismatch_even_when_range_matches(self):
        result = evaluate(
            cve_versions=["<=7.0"],
            observed_versions=[assoc("6.8.3", "Drupal", "")],
        )
        self.assertEqual(result.state, "FAMILY_MISMATCH")
        self.assertEqual(result.engine_versions, ())

    def test_unrelated_family_component(self):
        result = evaluate(
            cve_versions=["<=1.2.3"],
            observed_versions=[assoc("1.2.3", "Joomla", "ABC")],
        )
        self.assertEqual(result.state, "FAMILY_MISMATCH")
        self.assertFalse(result.component_available)


class TestMalformedAndEmpty(unittest.TestCase):
    """Case 7: empty/malformed observations fail soft, deterministically."""

    def test_empty_inputs(self):
        result = vca.evaluate_version_association()
        self.assertEqual(result.state, "NO_VERSION_OBSERVATION")
        self.assertEqual(result.engine_versions, ())

    def test_none_inputs(self):
        result = vca.evaluate_version_association(
            cve_families=None,
            cve_components=None,
            cve_plugins=None,
            cve_versions=None,
            observed_versions=None,
            observed_components=None,
            observed_plugins=None,
        )
        self.assertEqual(result.state, "NO_VERSION_OBSERVATION")

    def test_malformed_records_skipped(self):
        result = evaluate(
            observed_versions=[
                None,
                "",
                {},
                {"version": ""},
                {"version": "1.2.3", "source": "NOT_A_SOURCE"},
                "not-a-record",
                assoc("1.2.3", "WordPress", "XYZ"),
            ],
        )
        self.assertEqual(
            result.state, "VERSION_MATCH_WITHIN_SAME_FAMILY"
        )
        self.assertEqual(result.engine_versions, ("1.2.3",))

    def test_garbage_version_token_is_unknown(self):
        result = evaluate(
            cve_versions=["<=7.0"],
            observed_versions=[assoc("not-a-version", "WordPress", "")],
        )
        self.assertEqual(result.state, "VERSION_ASSOCIATION_UNKNOWN")
        self.assertEqual(result.engine_versions, ())

    def test_unparseable_range_is_unknown(self):
        result = evaluate(
            cve_versions=["<=x.y"],
            observed_versions=[assoc("6.8.3", "WordPress", "XYZ")],
        )
        self.assertEqual(
            result.state, "COMPONENT_ASSOCIATED_VERSION_UNKNOWN"
        )
        self.assertEqual(result.engine_versions, ())

    def test_deterministic(self):
        kwargs = dict(
            cve_families=["WordPress"],
            cve_plugins=["XYZ"],
            cve_versions=["<=1.2.3"],
            observed_versions=[
                assoc("1.2.3", "WordPress", "XYZ"),
                assoc("0.9", "WordPress", ""),
            ],
        )
        first = vca.association_projection(
            vca.evaluate_version_association(**kwargs)
        )
        second = vca.association_projection(
            vca.evaluate_version_association(**kwargs)
        )
        self.assertEqual(first, second)


class TestVocabulary(unittest.TestCase):
    def test_states_closed_and_distinct(self):
        self.assertEqual(VERSION_ASSOCIATION_RULE_VERSION, "r30-3")
        self.assertEqual(vca.RULE_VERSION, "r30-3")
        self.assertIn(
            "VERSION_MATCH_WITHIN_SAME_FAMILY",
            vca.VERSION_ASSOCIATION_STATES,
        )
        self.assertIn(
            "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION",
            vca.VERSION_ASSOCIATION_STATES,
        )
        self.assertEqual(
            len(set(vca.VERSION_ASSOCIATION_STATES)),
            len(vca.VERSION_ASSOCIATION_STATES),
        )

    def test_research_only(self):
        result = vca.evaluate_version_association()
        self.assertTrue(result.research_only)
        self.assertEqual(result.rule_version, "r30-3")

    def test_projection_shape(self):
        payload = vca.association_projection(
            evaluate(observed_versions=[assoc("1.2.3", "WordPress", "XYZ")])
        )
        for key in (
            "state",
            "engine_versions",
            "matched_version",
            "family",
            "component",
            "component_available",
            "evidence",
            "reason",
            "rule_version",
            "research_only",
        ):
            self.assertIn(key, payload)


class TestCollector(unittest.TestCase):
    def test_http_tech_owner_recorded(self):
        inventory = oi.build_observed_inventory(
            "dell",
            http_records=[http("a.dell.com", ["WordPress:6.8.3"])],
            subdomain_records=[subdomain("a.dell.com")],
        )
        self.assertEqual(len(inventory.version_associations), 1)
        item = inventory.version_associations[0]
        self.assertEqual(item.version, "6.8.3")
        self.assertEqual(item.technology_family, "WordPress")
        self.assertEqual(item.component, "")
        self.assertEqual(item.source, "TECHNOLOGY_INVENTORY")

    def test_flat_versions_unchanged_for_compatibility(self):
        inventory = oi.build_observed_inventory(
            "dell",
            http_records=[http("a.dell.com", ["WordPress:6.8.3"])],
            subdomain_records=[subdomain("a.dell.com")],
        )
        self.assertEqual(
            [item.value for item in inventory.versions], ["6.8.3"]
        )

    def test_component_owner_only_when_explicit(self):
        inventory = oi.build_observed_inventory(
            "dell",
            version_records=[
                ObservedVersionAssociation(
                    version="1.0",
                    technology_family="WordPress",
                    component="wp-responsive-images",
                    source="COMPONENT_INVENTORY",
                    evidence_type="STRUCTURED_COMPONENT",
                )
            ],
        )
        self.assertEqual(len(inventory.version_associations), 1)
        self.assertEqual(
            inventory.version_associations[0].component,
            "wp-responsive-images",
        )
        self.assertEqual(
            inventory.sources, ["COMPONENT_INVENTORY"]
        )

    def test_paths_never_create_component_ownership(self):
        from ai.researcher.target_intelligence import EndpointRecord

        inventory = oi.build_observed_inventory(
            "dell",
            endpoint_records=[
                EndpointRecord(
                    program_name="dell",
                    subdomain="a.dell.com",
                    path="/wp-content/plugins/wp-responsive-images/x.php",
                    example_url=(
                        "https://a.dell.com/wp-content/plugins/"
                        "wp-responsive-images/x.php"
                    ),
                    record_id="ep-1",
                )
            ],
            subdomain_records=[subdomain("a.dell.com")],
        )
        self.assertEqual(inventory.components, [])
        self.assertEqual(inventory.plugins, [])
        self.assertEqual(inventory.version_associations, [])

    def test_deterministic(self):
        kwargs = dict(
            http_records=[http("a.dell.com", ["WordPress:6.8.3"])],
            subdomain_records=[subdomain("a.dell.com")],
        )
        first = oi.build_observed_inventory("dell", **kwargs)
        second = oi.build_observed_inventory("dell", **kwargs)
        self.assertEqual(
            first.model_dump(mode="json"), second.model_dump(mode="json")
        )

    def test_malformed_version_records_skipped(self):
        inventory = oi.build_observed_inventory(
            "dell",
            version_records=[
                None,
                {},
                {"value": ""},
                {"version": "1.0"},  # owner unavailable is valid
            ],
        )
        self.assertEqual(len(inventory.version_associations), 1)
        self.assertEqual(
            inventory.version_associations[0].technology_family, ""
        )


def _fake_inventory(version=None, associations=(), versions=()):
    item = {
        "inventory_id": "inv-" + "a" * 16,
        "program": "dell",
        "technologies": [
            {"value": "WordPress", "source": "TECHNOLOGY_INVENTORY",
             "evidence_type": "STRUCTURED_TECHNOLOGY"},
        ],
        "products": [],
        "components": [
            {"value": "image_handler.php", "source": "COMPONENT_INVENTORY",
             "evidence_type": "STRUCTURED_COMPONENT"},
        ],
        "plugins": [
            {"value": "wp-responsive-images",
             "source": "COMPONENT_INVENTORY",
             "evidence_type": "STRUCTURED_COMPONENT"},
        ],
        "versions": [
            {"value": v, "source": "TECHNOLOGY_INVENTORY",
             "evidence_type": "STRUCTURED_TECHNOLOGY"} for v in versions
        ],
        "version_associations": list(associations),
        "parameters": [],
        "paths": [],
        "sources": ["TECHNOLOGY_INVENTORY", "COMPONENT_INVENTORY"],
        "evidence": [],
        "generated_from": {},
        "rule_version": "r30-2",
        "research_only": True,
    }
    if version is not None:
        item["versions"].append(
            {"value": version, "source": "TECHNOLOGY_INVENTORY",
             "evidence_type": "STRUCTURED_TECHNOLOGY"}
        )
    return item


class TestBackendAdapter(unittest.TestCase):
    def setUp(self):
        from backend import asset_cve_matching

        asset_cve_matching.clear_cache()

    def tearDown(self):
        from backend import asset_cve_matching
        from backend import observed_inventory as backend_oi

        asset_cve_matching.clear_cache()
        backend_oi.clear_cache()

    def _build(self, inventory):
        from backend import asset_cve_matching

        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=inventory,
        ):
            return asset_cve_matching.build_matches(
                cve=CVE, program="dell"
            )["items"][0]

    def test_unassociated_version_does_not_promote(self):
        item = self._build(_fake_inventory(version="1.0"))
        self.assertEqual(
            item["version_association_state"],
            "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION",
        )
        self.assertEqual(item["version_association_rule_version"], "r30-3")
        self.assertEqual(item["matched_component"], "image_handler.php")
        self.assertEqual(item["matched_version"], "")
        self.assertEqual(item["asset_match_state"], "SUPPORTED")
        self.assertEqual(item["asset_match_confidence"], "MEDIUM")
        self.assertNotEqual(item["strongest_confidence"], "HIGH")
        self.assertIn("version_unknown", item["remaining_blockers"])
        self.assertNotIn("version_unknown", item["resolved_blockers"])

    def test_associated_version_promotes(self):
        item = self._build(
            _fake_inventory(
                associations=[
                    {
                        "version": "1.0",
                        "technology_family": "WordPress",
                        "component": "wp-responsive-images",
                        "source": "COMPONENT_INVENTORY",
                        "evidence_type": "STRUCTURED_COMPONENT",
                    }
                ],
            )
        )
        self.assertEqual(
            item["version_association_state"],
            "VERSION_MATCH_WITHIN_SAME_FAMILY",
        )
        self.assertEqual(item["version_association_family"], "WordPress")
        self.assertEqual(
            item["version_association_component"], "wp-responsive-images"
        )
        self.assertEqual(item["matched_version"], "1.0")
        self.assertEqual(item["asset_match_state"], "CONFIRMED")
        self.assertEqual(item["asset_match_confidence"], "HIGH")
        self.assertIn("version_unknown", item["resolved_blockers"])

    def test_component_without_version(self):
        item = self._build(_fake_inventory())
        self.assertEqual(
            item["version_association_state"],
            "COMPONENT_ASSOCIATED_VERSION_UNKNOWN",
        )
        self.assertEqual(item["matched_version"], "")
        self.assertEqual(item["asset_match_state"], "SUPPORTED")
        self.assertIn("version_unknown", item["remaining_blockers"])

    def test_association_fields_on_every_item(self):
        from backend import asset_cve_matching

        data = asset_cve_matching.build_matches(cve=CVE)
        self.assertTrue(data["items"])
        for item in data["items"]:
            self.assertIn("version_association_state", item)
            self.assertIn(
                item["version_association_state"],
                vca.VERSION_ASSOCIATION_STATES,
            )
            self.assertIn("version_association_evidence", item)
            self.assertEqual(
                item["version_association_rule_version"], "r30-3"
            )

    def test_deterministic(self):
        from backend import asset_cve_matching

        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=_fake_inventory(version="1.0"),
        ):
            first = asset_cve_matching.build_matches(cve=CVE)
            asset_cve_matching.clear_cache()
            second = asset_cve_matching.build_matches(cve=CVE)
        self.assertEqual(first, second)


class TestSafety(unittest.TestCase):
    NEW_FILES = (
        "ai/schemas/observed_inventory.py",
        "ai/knowledge/observed_inventory.py",
        "ai/knowledge/version_component_association.py",
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
        for rel in (
            "ai/knowledge/version_component_association.py",
            "backend/asset_cve_matching.py",
        ):
            source = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            for token in ("insert_one", "update_one", "delete_one",
                          "pymongo.MongoClient(", "open(", "write_text",
                          "json.dump", "os.replace", "fsync"):
                self.assertNotIn(token, source, f"{token} found in {rel}")

    def test_r301_engine_semantics_unchanged(self):
        self.assertEqual(ASSET_CVE_MATCH_RULE_VERSION, "r30-1")
        self.assertEqual(acm.RULE_VERSION, "r30-1")
        # Called directly (no association layer), the engine still combines
        # component + version into HIGH: R30.3 is additive, not a rewrite.
        summary = acm.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            asset_identifier=DELL_ASSET,
            cve_plugins=["XYZ"],
            cve_versions=["<=1.2.3"],
            observed_plugins=["XYZ"],
            observed_versions=["1.2.3"],
        )
        self.assertEqual(summary["asset_match_state"], "CONFIRMED")
        self.assertEqual(summary["strongest_confidence"], "HIGH")

    def test_r30_2_rule_version_unchanged(self):
        self.assertEqual(OBSERVED_INVENTORY_RULE_VERSION, "r30-2")
        self.assertEqual(oi.RULE_VERSION, "r30-2")

    def test_r17_r25_r26_r29_unchanged(self):
        from ai.knowledge import (
            daily_research,
            economics,
            opportunity,
            opportunity_action,
            relevance,
        )
        from ai.knowledge import hunt_queue as hq

        self.assertEqual(relevance.ASSET_RELEVANCE_RULE_VERSION, "r17-1")
        self.assertEqual(economics.RULE_VERSION, "r25-1")
        self.assertEqual(opportunity.OPPORTUNITY_RULE_VERSION, "r26-1")
        self.assertEqual(opportunity_action.ACTION_RULE_VERSION, "r26-2")
        self.assertEqual(daily_research.WORKFLOW_VERSION, "r26-3")
        self.assertEqual(hq.HUNT_RULE_VERSION, "r29-1")

    def test_no_global_score_fields(self):
        payload = vca.association_projection(
            evaluate(observed_versions=[assoc("1.2.3", "WordPress", "XYZ")])
        )
        for token in ("score", "money", "payout", "bounty", "priority"):
            self.assertNotIn(token, json.dumps(payload).lower())

    def test_no_target_identifiers_in_association(self):
        result = evaluate(
            observed_versions=[assoc("1.2.3", "WordPress", "XYZ")],
        )
        blob = json.dumps(vca.association_projection(result)).lower()
        for token in ("http://", "https://", ".com", "dell"):
            self.assertNotIn(token, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
