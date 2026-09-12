"""tests/test_component_inference.py — Stage R31.2 tests.

Deterministic, offline tests for path-rule based component/plugin inference:
initial rules (CKEditor, WordPress plugins/themes), extended rules, record
sources (URL / endpoint / HTTP), negatives and malformed input, determinism,
inventory merge behavior, the real inventory loader and safety invariants.

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no browser, no PoC execution, no Mongo writes, no persistence.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.knowledge import component_inference as ci
from ai.knowledge.observed_inventory import build_observed_inventory
from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    SubdomainRecord,
    UrlRecord,
)
from ai.schemas.observed_inventory import (
    EVIDENCE_TYPES,
    ObservedAssetInventory,
    ObservedItem,
    OBSERVED_INVENTORY_RULE_VERSION,
    inventory_id_for,
)


def infer(url=(), endpoint=(), http=()):
    return ci.infer_inventory_items(
        url_records=url,
        endpoint_records=endpoint,
        http_records=http,
    )


def values(items):
    return [item.value for item in items]


def url_record(path=None, url=None, program="dell", subdomain="a.dell.com"):
    return UrlRecord(
        program_name=program,
        subdomain=subdomain,
        url=url or "",
        path=path or "",
        record_id="u-1",
    )


def endpoint_record(path=None, example_url=None, program="dell",
                    subdomain="a.dell.com"):
    return EndpointRecord(
        program_name=program,
        subdomain=subdomain,
        path=path or "",
        example_url=example_url or "",
        record_id="e-1",
    )


def http_record(url=None, final_url=None, program="dell",
                subdomain="a.dell.com"):
    return HttpRecord(
        program_name=program,
        subdomain=subdomain,
        url=url or "",
        final_url=final_url or "",
        record_id="h-1",
    )


class TestInitialRules(unittest.TestCase):
    def test_ckeditor(self):
        out = infer(endpoint=[endpoint_record("/assets/ckeditor/plugins/")])
        self.assertEqual(values(out["components"]), ["CKEditor"])
        item = out["components"][0]
        self.assertEqual(item.source, "COMPONENT_INVENTORY")
        self.assertEqual(item.evidence_type, "INFERRED_COMPONENT")
        self.assertEqual(out["plugins"], [])

    def test_wordpress_plugin(self):
        out = infer(
            endpoint=[endpoint_record("/wp-content/plugins/contact-form-7/")]
        )
        self.assertEqual(values(out["plugins"]), ["contact-form-7"])
        self.assertEqual(out["plugins"][0].evidence_type,
                         "INFERRED_PLUGIN")
        self.assertEqual(out["components"], [])

    def test_wordpress_plugin_nested_path(self):
        out = infer(endpoint=[endpoint_record(
            "/wp-content/plugins/contact-form-7/includes/js/scripts.js"
        )])
        self.assertEqual(values(out["plugins"]), ["contact-form-7"])

    def test_wordpress_plugin_single_file(self):
        out = infer(endpoint=[endpoint_record(
            "/wp-content/plugins/hello.php"
        )])
        self.assertEqual(values(out["plugins"]), ["hello.php"])

    def test_wordpress_mu_plugin(self):
        out = infer(endpoint=[endpoint_record(
            "/wp-content/mu-plugins/force-ssl.php"
        )])
        self.assertEqual(values(out["plugins"]), ["force-ssl.php"])

    def test_wordpress_theme(self):
        out = infer(endpoint=[endpoint_record(
            "/wp-content/themes/twentytwentyfour/style.css"
        )])
        self.assertEqual(values(out["components"]), ["twentytwentyfour"])
        self.assertEqual(out["components"][0].evidence_type,
                         "INFERRED_COMPONENT")

    def test_wordpress_no_slug_no_inference(self):
        out = infer(endpoint=[endpoint_record("/wp-content/plugins/")])
        self.assertEqual(out["plugins"], [])
        self.assertEqual(out["components"], [])


class TestExtendedRules(unittest.TestCase):
    def test_ckeditor_variants(self):
        out = infer(endpoint=[
            endpoint_record("/assets/fckeditor/editor.js"),
            endpoint_record("/assets/ckfinder/core/connector.php"),
        ])
        self.assertEqual(values(out["components"]),
                         ["CKFinder", "FCKeditor"])

    def test_tinymce(self):
        out = infer(endpoint=[endpoint_record("/assets/tinymce/plugins/")])
        self.assertEqual(values(out["components"]), ["TinyMCE"])

    def test_drupal_modules(self):
        out = infer(endpoint=[
            endpoint_record("/sites/all/modules/views/"),
            endpoint_record("/modules/contrib/token/token.module"),
        ])
        self.assertEqual(values(out["components"]), ["token", "views"])

    def test_joomla(self):
        out = infer(endpoint=[
            endpoint_record("/components/com_users/router.php"),
            endpoint_record("/modules/mod_menu/mod_menu.php"),
        ])
        self.assertEqual(values(out["components"]),
                         ["com_users", "mod_menu"])

    def test_jquery_asset(self):
        out = infer(endpoint=[
            endpoint_record("/assets/js/jquery-3.6.0.min.js"),
            endpoint_record("/assets/js/jquery.min.js"),
            endpoint_record("/assets/js/jquery.1.12.4.min.js"),
        ])
        self.assertEqual(values(out["components"]), ["jQuery"])


class TestRecordSources(unittest.TestCase):
    def test_endpoint_path(self):
        out = infer(endpoint=[endpoint_record(
            "/wp-content/plugins/akismet/readme.txt"
        )])
        self.assertEqual(values(out["plugins"]), ["akismet"])

    def test_url_path(self):
        out = infer(url=[url_record(
            "/wp-content/plugins/akismet/readme.txt"
        )])
        self.assertEqual(values(out["plugins"]), ["akismet"])

    def test_http_url(self):
        out = infer(http=[http_record(
            "https://a.dell.com/wp-content/plugins/akismet/readme.txt"
        )])
        self.assertEqual(values(out["plugins"]), ["akismet"])

    def test_http_final_url_fallback(self):
        out = infer(http=[http_record(
            final_url="https://a.dell.com/assets/ckeditor/plugins/"
        )])
        self.assertEqual(values(out["components"]), ["CKEditor"])

    def test_url_fallback_to_full_url(self):
        out = infer(url=[url_record(
            url="https://a.dell.com/wp-content/themes/twentytwentyfour/a.css"
        )])
        self.assertEqual(values(out["components"]), ["twentytwentyfour"])

    def test_endpoint_fallback_to_example_url(self):
        out = infer(endpoint=[endpoint_record(
            example_url=(
                "https://a.dell.com/wp-content/plugins/akismet/a.txt"
            )
        )])
        self.assertEqual(values(out["plugins"]), ["akismet"])

    def test_dict_records_supported(self):
        out = infer(endpoint=[{"path": "/assets/ckeditor/plugins/"}])
        self.assertEqual(values(out["components"]), ["CKEditor"])

    def test_relative_path_normalized(self):
        out = infer(url=[url_record(path="wp-content/plugins/akismet/")])
        self.assertEqual(values(out["plugins"]), ["akismet"])

    def test_query_string_ignored(self):
        out = infer(endpoint=[endpoint_record(
            "/wp-content/plugins/akismet/?ver=1.0"
        )])
        self.assertEqual(values(out["plugins"]), ["akismet"])

    def test_no_hostname_in_output(self):
        out = infer(http=[http_record(
            "https://secret-host.dell.com/wp-content/plugins/akismet/a.txt"
        )])
        blob = json.dumps(
            [item.model_dump(mode="json")
             for item in out["components"] + out["plugins"]]
            + out["evidence"]
        ).lower()
        for token in ("secret-host", "dell.com", "http://", "https://"):
            self.assertNotIn(token, blob)


class TestNegatives(unittest.TestCase):
    def test_generic_plugins_path_not_inferred(self):
        out = infer(endpoint=[endpoint_record("/products/plugins/")])
        self.assertEqual(out["plugins"], [])
        self.assertEqual(out["components"], [])

    def test_keyword_lookalike_not_inferred(self):
        out = infer(endpoint=[
            endpoint_record("/blog/ckeditor-guide/"),
            endpoint_record("/docs/tinymce-history/"),
        ])
        self.assertEqual(out["components"], [])

    def test_generic_modules_path_not_inferred(self):
        out = infer(endpoint=[endpoint_record("/modules/user/")])
        self.assertEqual(out["components"], [])

    def test_traversal_segments_rejected(self):
        out = infer(endpoint=[
            endpoint_record("/wp-content/plugins/../x/"),
            endpoint_record("/wp-content/plugins/..%2fetc/"),
        ])
        self.assertEqual(out["plugins"], [])

    def test_encoded_or_spaced_slug_rejected(self):
        out = infer(endpoint=[
            endpoint_record("/wp-content/plugins/bad%20slug/"),
            endpoint_record("/wp-content/plugins/bad slug/"),
        ])
        self.assertEqual(out["plugins"], [])

    def test_empty_inputs(self):
        out = infer()
        self.assertEqual(out["components"], [])
        self.assertEqual(out["plugins"], [])
        self.assertEqual(out["evidence"], [])

    def test_none_and_malformed_records(self):
        out = infer(
            url=[None, "", 0, {"path": None}, {"path": 123}],
            endpoint=[None, {}, {"path": ""}],
            http=[None],
        )
        self.assertEqual(out["components"], [])
        self.assertEqual(out["plugins"], [])

    def test_newline_path_fail_soft(self):
        out = infer(endpoint=[endpoint_record(
            "/wp-content/plugins/bad\nslug/"
        )])
        self.assertEqual(out["plugins"], [])

    def test_long_path_truncated_fail_soft(self):
        out = infer(endpoint=[
            endpoint_record("/wp-content/plugins/" + "a" * 5000 + "/")
        ])
        self.assertEqual(out["plugins"], [])


class TestDeterminism(unittest.TestCase):
    def test_repeatable(self):
        kwargs = dict(endpoint=[
            endpoint_record("/assets/ckeditor/plugins/"),
            endpoint_record("/wp-content/plugins/akismet/"),
        ])
        first = infer(**kwargs)
        second = infer(**kwargs)
        self.assertEqual(
            json.dumps([i.model_dump() for i in first["components"]],
                       sort_keys=True),
            json.dumps([i.model_dump() for i in second["components"]],
                       sort_keys=True),
        )
        self.assertEqual(first["evidence"], second["evidence"])

    def test_input_order_does_not_matter(self):
        a = url_record(path="/wp-content/plugins/akismet/")
        b = endpoint_record(path="/assets/ckeditor/plugins/")
        first = infer(url=[a], endpoint=[b])
        second = infer(url=[b], endpoint=[a])
        self.assertEqual(first, second)

    def test_dedup_same_slug_many_paths(self):
        out = infer(endpoint=[
            endpoint_record("/wp-content/plugins/akismet/a.php"),
            endpoint_record("/wp-content/plugins/akismet/b.php"),
            endpoint_record("/wp-content/plugins/akismet/"),
        ])
        self.assertEqual(values(out["plugins"]), ["akismet"])
        inferred = [line for line in out["evidence"]
                    if "inferred" in line]
        self.assertEqual(len(inferred), 1)

    def test_case_insensitive_rule(self):
        out = infer(endpoint=[endpoint_record(
            "/WP-CONTENT/PLUGINS/Akismet/"
        )])
        self.assertEqual(values(out["plugins"]), ["Akismet"])

    def test_rules_have_unique_ids(self):
        ids = [rule.rule_id for rule in ci.RULES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(ids)


class TestApplyInferred(unittest.TestCase):
    def _inventory(self, **over):
        kwargs = {
            "http_records": [
                HttpRecord(
                    program_name="dell",
                    subdomain="a.dell.com",
                    tech=("WordPress:6.8.3",),
                    record_id="h-1",
                )
            ],
            "subdomain_records": [
                SubdomainRecord(
                    program_name="dell",
                    subdomain="a.dell.com",
                    scope="dell.com",
                    record_id="s-1",
                )
            ],
        }
        kwargs.update(over)
        return build_observed_inventory("dell", **kwargs)

    def test_merge_preserves_existing_categories(self):
        inventory = self._inventory()
        inferred = infer(endpoint=[
            endpoint_record("/assets/ckeditor/plugins/"),
            endpoint_record("/wp-content/plugins/akismet/"),
        ])
        merged = ci.apply_inferred_items(inventory, inferred)
        self.assertEqual(values(merged.components), ["CKEditor"])
        self.assertEqual(values(merged.plugins), ["akismet"])
        self.assertEqual(values(merged.technologies), ["WordPress"])
        self.assertEqual(values(merged.versions), ["6.8.3"])
        self.assertEqual(
            [(a.version, a.technology_family)
             for a in merged.version_associations],
            [("6.8.3", "WordPress")],
        )
        self.assertIn("COMPONENT_INVENTORY", merged.sources)
        self.assertEqual(merged.generated_from["inferred_components"], 1)
        self.assertEqual(merged.generated_from["inferred_plugins"], 1)
        self.assertEqual(
            merged.generated_from["component_inference_rule_version"],
            "r31-2",
        )
        self.assertTrue(
            any("inferred from path" in line for line in merged.evidence)
        )

    def test_explicit_item_wins_over_inferred(self):
        inventory = self._inventory(component_records=[
            ObservedItem(
                value="CKEditor",
                source="COMPONENT_INVENTORY",
                evidence_type="STRUCTURED_COMPONENT",
            )
        ])
        inferred = infer(endpoint=[
            endpoint_record("/assets/ckeditor/plugins/")
        ])
        merged = ci.apply_inferred_items(inventory, inferred)
        self.assertIs(merged, inventory)
        self.assertEqual(len(merged.components), 1)
        self.assertEqual(
            merged.components[0].evidence_type, "STRUCTURED_COMPONENT"
        )

    def test_noop_returns_same_object(self):
        inventory = self._inventory()
        self.assertIs(ci.apply_inferred_items(inventory, {}), inventory)
        self.assertIs(
            ci.apply_inferred_items(
                inventory, {"components": [], "plugins": []}
            ),
            inventory,
        )

    def test_non_dict_inferred_is_noop(self):
        inventory = self._inventory()
        self.assertIs(ci.apply_inferred_items(inventory, None), inventory)

    def test_merged_inventory_is_valid_schema(self):
        inventory = self._inventory()
        inferred = infer(endpoint=[
            endpoint_record("/wp-content/themes/twentytwentyfour/")
        ])
        merged = ci.apply_inferred_items(inventory, inferred)
        self.assertIsInstance(merged, ObservedAssetInventory)
        for item in merged.components:
            self.assertIn(item.source, ("COMPONENT_INVENTORY",))
            self.assertIn(item.evidence_type, EVIDENCE_TYPES)
        payload = merged.model_dump(mode="json")
        rebuilt = ObservedAssetInventory(**payload)
        self.assertEqual(rebuilt.components[0].value, "twentytwentyfour")


class TestLoaderIntegration(unittest.TestCase):
    def _records(self):
        return {
            "http_records": [
                HttpRecord(
                    program_name="dell",
                    subdomain="a.dell.com",
                    tech=("WordPress:6.8.3",),
                    url="https://a.dell.com/wp-content/plugins/akismet/",
                    record_id="h-1",
                )
            ],
            "url_records": [
                UrlRecord(
                    program_name="dell",
                    subdomain="a.dell.com",
                    path="/assets/ckeditor/plugins/",
                    record_id="u-1",
                )
            ],
            "endpoint_records": [
                EndpointRecord(
                    program_name="dell",
                    subdomain="a.dell.com",
                    path="/wp-content/plugins/contact-form-7/a.php",
                    record_id="e-1",
                )
            ],
            "subdomain_records": [
                SubdomainRecord(
                    program_name="dell",
                    subdomain="a.dell.com",
                    scope="dell.com",
                    record_id="s-1",
                )
            ],
        }

    def test_build_real_observed_inventory_infers(self):
        import ai.knowledge.inventory_loader as loader

        with mock.patch.object(
            loader, "load_program_inventory_records",
            return_value=self._records(),
        ):
            inventory = loader.build_real_observed_inventory("dell")

        self.assertEqual(values(inventory.technologies), ["WordPress"])
        self.assertEqual(values(inventory.versions), ["6.8.3"])
        self.assertEqual(values(inventory.components), ["CKEditor"])
        self.assertEqual(
            values(inventory.plugins),
            ["akismet", "contact-form-7"],
        )
        for item in inventory.components + inventory.plugins:
            self.assertIn(
                item.evidence_type,
                ("INFERRED_COMPONENT", "INFERRED_PLUGIN"),
            )
            self.assertEqual(item.source, "COMPONENT_INVENTORY")

    def test_loader_deterministic(self):
        import ai.knowledge.inventory_loader as loader

        with mock.patch.object(
            loader, "load_program_inventory_records",
            return_value=self._records(),
        ):
            first = loader.build_real_observed_inventory("dell")
            second = loader.build_real_observed_inventory("dell")
        self.assertEqual(first, second)

    def test_inference_failure_never_breaks_inventory(self):
        import ai.knowledge.inventory_loader as loader

        with mock.patch.object(
            loader, "load_program_inventory_records",
            return_value=self._records(),
        ), mock.patch.object(
            loader, "infer_inventory_items",
            side_effect=RuntimeError("boom"),
        ):
            inventory = loader.build_real_observed_inventory("dell")
        self.assertEqual(values(inventory.technologies), ["WordPress"])
        self.assertEqual(inventory.components, [])
        self.assertEqual(inventory.plugins, [])


class TestSafety(unittest.TestCase):
    NEW_FILES = (
        "ai/knowledge/component_inference.py",
        "ai/knowledge/inventory_loader.py",
    )

    def test_no_execution_or_network_tokens(self):
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
        source = (Path("/opt/watch")
                  / "ai/knowledge/component_inference.py"
                  ).read_text(encoding="utf-8")
        for token in ("insert_one", "update_one", "delete_one",
                      "pymongo.MongoClient(", "write_text", "json.dump",
                      "os.replace", "fsync"):
            self.assertNotIn(token, source)

    def test_evidence_vocabulary(self):
        self.assertIn("INFERRED_COMPONENT", EVIDENCE_TYPES)
        self.assertIn("INFERRED_PLUGIN", EVIDENCE_TYPES)
        self.assertNotIn("GUESSED", EVIDENCE_TYPES)
        self.assertNotIn("LLM_DERIVED", EVIDENCE_TYPES)
        with self.assertRaises(ValueError):
            ObservedItem(
                value="x",
                source="COMPONENT_INVENTORY",
                evidence_type="INFERRED",
            )

    def test_rule_version(self):
        self.assertEqual(ci.RULE_VERSION, "r31-2")

    def test_r30_rules_unchanged(self):
        self.assertEqual(OBSERVED_INVENTORY_RULE_VERSION, "r30-2")
        self.assertEqual(
            inventory_id_for("dell"),
            inventory_id_for("dell"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
