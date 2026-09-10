"""Stage R14 tests: deterministic parameter and component intelligence.

Pure unit tests. No LLM, no network, no active validation.
"""

from __future__ import annotations

import unittest

from ai.knowledge.intelligence import (
    ExtractedIntelligence,
    extract_research_intelligence,
)


def _payload(text: str, cve_id: str = "CVE-2024-5376") -> dict:
    """Structural research payload carrying one body text."""

    return {
        "cve": {"id": cve_id},
        "research": {
            "description": text,
        },
    }


def _extract(text: str, cve_id: str = "CVE-2024-5376") -> ExtractedIntelligence:
    return extract_research_intelligence(cve_id, _payload(text, cve_id), [])


class ParameterExtractionTests(unittest.TestCase):
    def test_id_parameter_before_of_file(self):
        result = _extract(
            "XSS injection vulnerability exists in id parameter of "
            "view_each_faculty.php file."
        )
        self.assertEqual(result.parameters, ["id"])

    def test_parameter_id_reversed_form(self):
        result = _extract("The injection occurs via parameter id in the page.")
        self.assertIn("id", result.parameters)

    def test_the_id_parameter(self):
        result = _extract("The the id parameter is reflected without encoding.")
        self.assertIn("id", result.parameters)

    def test_vulnerable_parameter_labeled(self):
        result = _extract("vulnerable parameter: id")
        self.assertEqual(result.parameters, ["id"])

    def test_quoted_parameter(self):
        result = _extract('parameter "id" is affected')
        self.assertIn("id", result.parameters)
        result2 = _extract("parameter 'id' is affected")
        self.assertIn("id", result2.parameters)

    def test_get_post_query_url_parameter(self):
        for phrase in (
            "GET parameter id",
            "POST parameter user_id",
            "query parameter search",
            "URL parameter q",
        ):
            result = _extract(f"Injection via {phrase} was confirmed.")
            self.assertEqual(len(result.parameters), 1, phrase)

    def test_common_parameter_names(self):
        for name in ("user_id", "redirect_url", "q", "search", "callback",
                     "file", "path"):
            result = _extract(f"XSS injection in {name} parameter of app.")
            self.assertIn(name, result.parameters, name)

    def test_generic_input_without_label_rejected(self):
        result = _extract("The input was reflected in the response.")
        self.assertEqual(result.parameters, [])

    def test_generic_user_page_rejected_without_parameter_wording(self):
        result = _extract("The user page renders content from the request.")
        self.assertEqual(result.parameters, [])

    def test_url_query_string_not_treated_as_parameter(self):
        result = _extract(
            "Injection at https://example.com/view.php?id=1&user=2 was "
            "reported in the write-up."
        )
        for value in result.parameters:
            self.assertNotIn("?", value)
            self.assertNotIn("=", value)
            self.assertNotIn("&", value)

    def test_html_attribute_not_extracted(self):
        result = _extract(
            'The page uses <div class="container"> markup; the layout file '
            "index.html is unrelated."
        )
        self.assertEqual(result.parameters, [])

    def test_duplicate_parameter_mentions_single_claim(self):
        result = _extract(
            "id parameter is vulnerable. Later the id parameter of the same "
            "file is described again in the advisory text."
        )
        self.assertEqual(result.parameters, ["id"])
        param_evidence = [
            e for e in result.evidence if e.field == "parameter"
        ]
        self.assertEqual(len(param_evidence), 1)

    def test_multiple_parameters_stable_ordering(self):
        text = (
            "XSS injection exists in the search parameter and the q "
            "parameter of finder.php. Also the callback parameter of "
            "finder.php is affected."
        )
        result = _extract(text)
        self.assertEqual(result.parameters, ["search", "q", "callback"])
        self.assertEqual(result.parameters, _extract(text).parameters)

    def test_quoted_and_plain_forms_converge(self):
        result = _extract(
            'parameter "id" is affected; the id parameter is exploitable.'
        )
        self.assertEqual(result.parameters, ["id"])

    def test_empty_and_garbage_no_claims(self):
        self.assertEqual(_extract("").parameters, [])
        self.assertEqual(_extract("!!! ??? ###").parameters, [])
        self.assertEqual(_extract("").components, [])


class ComponentExtractionTests(unittest.TestCase):
    def test_id_parameter_of_file_extracts_component(self):
        result = _extract(
            "XSS injection vulnerability exists in id parameter of "
            "view_each_faculty.php file."
        )
        self.assertEqual(result.components, ["view_each_faculty.php"])

    def test_leading_slash_converges(self):
        a = _extract(
            "SQL injection in the /admin/login.php endpoint is possible."
        )
        b = _extract(
            "SQL injection in the admin/login.php endpoint is possible."
        )
        self.assertEqual(a.components, b.components)
        self.assertEqual(a.components, ["admin/login.php"])

    def test_vulnerable_file_label(self):
        result = _extract("vulnerable file: foo.php")
        self.assertEqual(result.components, ["foo.php"])

    def test_affected_endpoint_label(self):
        result = _extract("the affected endpoint is /api/users")
        self.assertEqual(result.components, ["api/users"])

    def test_plugin_path(self):
        result = _extract(
            "XSS in wp-content/plugins/foo/bar.php allows injection."
        )
        self.assertEqual(result.components, ["wp-content/plugins/foo/bar.php"])

    def test_unrelated_filename_mention_no_claim(self):
        result = _extract(
            "The repository contains readme.md, LICENSE and setup.py files "
            "for the project build. Contributions are welcome in utils.py."
        )
        self.assertEqual(result.components, [])

    def test_code_block_unrelated_filenames_conservative(self):
        result = _extract(
            "Project layout:\nsrc/main.py\nsrc/helpers.py\nsrc/app.py\n"
            "See the docs for details."
        )
        self.assertEqual(result.components, [])

    def test_duplicate_component_mentions_single_claim(self):
        result = _extract(
            "XSS injection in view_each_faculty.php; view_each_faculty.php "
            "is the affected script of the app."
        )
        self.assertEqual(result.components, ["view_each_faculty.php"])
        comp_evidence = [
            e for e in result.evidence if e.field == "component"
        ]
        self.assertEqual(len(comp_evidence), 1)

    def test_multiple_components_stable_ordering(self):
        text = (
            "XSS injection in admin/login.php and in user/profile.php; "
            "also api/export.php is affected."
        )
        result = _extract(text)
        self.assertEqual(
            result.components,
            ["admin/login.php", "user/profile.php", "api/export.php"],
        )
        self.assertEqual(result.components, _extract(text).components)

    def test_oversized_capture_rejected(self):
        result = _extract(
            "XSS injection in " + "a" * 400 + ".php file was reported."
        )
        self.assertEqual(result.components, [])


class ProvenanceAndAttributionTests(unittest.TestCase):
    def test_parameter_provenance_fields(self):
        result = _extract(
            "XSS injection vulnerability exists in id parameter of "
            "view_each_faculty.php file."
        )
        records = [e for e in result.evidence if e.field == "parameter"]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.value, "id")
        self.assertEqual(record.rule_id, "parameter-name-bare")
        self.assertEqual(record.rule_version, "r15-1")
        self.assertEqual(record.source_artifact, "CVE-2024-5376.cli.json")
        self.assertIn("id parameter", record.evidence)

    def test_component_provenance_fields(self):
        result = _extract(
            "XSS injection vulnerability exists in id parameter of "
            "view_each_faculty.php file."
        )
        records = [e for e in result.evidence if e.field == "component"]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.value, "view_each_faculty.php")
        self.assertTrue(record.rule_id)
        self.assertIn("view_each_faculty.php", record.evidence)

    def test_multi_cve_reference_nearest_attribution(self):
        payload = {
            "cve": {"id": "CVE-2024-5376"},
            "research": {"description": "base"},
        }
        records = [
            {
                "url": "https://example.com/a",
                "body": (
                    "CVE-2024-5376: XSS injection in id parameter of "
                    "view_each_faculty.php. Related coverage of this issue "
                    "is extensive across several feeds. Another advisory "
                    "CVE-2024-99999 describes a different product."
                ),
            }
        ]
        result = extract_research_intelligence(
            "CVE-2024-5376", payload, records
        )
        self.assertEqual(result.parameters, ["id"])
        self.assertEqual(result.components, ["view_each_faculty.php"])

    def test_other_cve_section_not_attributed(self):
        payload = {
            "cve": {"id": "CVE-2024-5376"},
            "research": {"description": "base"},
        }
        records = [
            {
                "url": "https://example.com/a",
                "body": (
                    "Unrelated advisory CVE-2024-99999: SQL injection in "
                    "the password parameter of admin/login.php. "
                    "This feed aggregates many advisories."
                ),
            }
        ]
        result = extract_research_intelligence(
            "CVE-2024-5376", payload, records
        )
        self.assertEqual(result.parameters, [])
        self.assertEqual(result.components, [])

    def test_cve_silent_reference_with_product_term(self):
        payload = {
            "cve": {"id": "CVE-2024-5376"},
            "research": {"description": "base"},
        }
        records = [
            {
                "url": "https://example.com/blog",
                "body": (
                    "School management system advisory: XSS injection in id "
                    "parameter of view_each_faculty.php."
                ),
            }
        ]
        result = extract_research_intelligence(
            "CVE-2024-5376", payload, records, product_terms=("school",)
        )
        self.assertEqual(result.parameters, ["id"])

    def test_empty_records_no_claims(self):
        result = extract_research_intelligence(
            "CVE-2024-5376", {"cve": {"id": "CVE-2024-5376"}}, []
        )
        self.assertEqual(result.parameters, [])
        self.assertEqual(result.components, [])
        self.assertEqual(result.evidence, [])


class AcceptanceTests(unittest.TestCase):
    def test_cve_2024_5376_wording(self):
        result = _extract(
            "XSS injection vulnerability exists in id parameter of "
            "view_each_faculty.php file. The reflected payload executes."
        )
        self.assertIn("xss", result.vulnerability_types)
        self.assertEqual(result.parameters, ["id"])
        self.assertEqual(result.components, ["view_each_faculty.php"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


