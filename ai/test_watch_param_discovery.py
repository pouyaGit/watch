"""Focused tests for the x8 provenance mapping in
``crawl/watch_param_discovery.py``.

Only the pure mapping/parsing contract is tested here
(the x8 binary itself is NOT invoked): injection-place →
internal-location conversion must preserve GET/query,
POST/body, PUT/body provenance and must NEVER silently
convert unsupported injection places (Headers, HeaderValue,
non-GET Path, unknown) into a case location.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from unittest import mock

from crawl.watch_param_discovery import (
    build_x8_target_url,
    main,
    map_x8_location,
    run_x8,
)


class X8LocationMappingTests(unittest.TestCase):
    def test_query_maps_to_query(self):
        self.assertEqual(map_x8_location("Query", "GET"), "query")

    def test_body_maps_to_body_for_post(self):
        self.assertEqual(map_x8_location("Body", "POST"), "body")

    def test_body_maps_to_body_for_put(self):
        self.assertEqual(map_x8_location("Body", "PUT"), "body")

    def test_get_path_maps_to_query(self):
        # x8 4.3.1 labels the default GET query-string injection
        # "Path"; with our -u URL template that means query.
        self.assertEqual(map_x8_location("Path", "GET"), "query")

    def test_headers_never_map(self):
        self.assertIsNone(map_x8_location("Headers", "GET"))
        self.assertIsNone(map_x8_location("Headers", "POST"))

    def test_headervalue_never_maps(self):
        self.assertIsNone(map_x8_location("HeaderValue", "GET"))

    def test_non_get_path_never_maps(self):
        # A POST/PUT "Path" injection is not a supported location
        # and must not be converted.
        self.assertIsNone(map_x8_location("Path", "POST"))
        self.assertIsNone(map_x8_location("Path", "PUT"))

    def test_unknown_and_empty_never_map(self):
        self.assertIsNone(map_x8_location("Cookie", "GET"))
        self.assertIsNone(map_x8_location("", "GET"))
        self.assertIsNone(map_x8_location(None, "GET"))

    def test_missing_method_does_not_default_unsupported_to_query(self):
        # No method context, no mapping for Path/Headers.
        self.assertIsNone(map_x8_location("Path", None))
        self.assertIsNone(map_x8_location("Headers", ""))

    def test_case_insensitive_labels(self):
        self.assertEqual(map_x8_location("path", "get"), "query")
        self.assertEqual(map_x8_location("body", "post"), "body")
        self.assertIsNone(map_x8_location("headers", "get"))


# Synthetic x8 4.3.1 JSON payload used to exercise run_x8()'s parser
# without ever invoking the real binary.
SYNTHETIC_X8_JSON = [
    {"method": "POST", "injection_place": "Body", "found_params": [{"name": "foo"}]},
    {"method": "PUT", "injection_place": "Body", "found_params": [{"name": "bar"}]},
    {"method": "PATCH", "injection_place": "Body", "found_params": [{"name": "baz"}]},
    {"method": "GET", "injection_place": "Query", "found_params": [{"name": "q"}]},
]


class X8RunParserTests(unittest.TestCase):
    """run_x8() must preserve raw x8 provenance and never invent a
    default HTTP method. The x8 binary is NOT invoked: subprocess is
    faked so the temporary ``-o`` JSON file is populated with a
    synthetic payload that run_x8() then reads back."""

    def _run_payload(self, mock_subprocess, payload):
        # x8 present in PATH.
        mock_subprocess.call.return_value = 0
        # Keep the real exception class so the ``except`` clause stays
        # a valid catch target even though subprocess is a MagicMock.
        mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired

        def _fake_run(cmd, *args, **kwargs):
            out_path = cmd[cmd.index("-o") + 1]
            with open(out_path, "w") as f:
                json.dump(payload, f)
            return subprocess.CompletedProcess(cmd, 0)

        mock_subprocess.run.side_effect = _fake_run
        return run_x8("https://example.test/api", "/tmp/wordlist.txt")

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_run_x8_preserves_methods_and_places(self, mock_subprocess):
        records = self._run_payload(mock_subprocess, SYNTHETIC_X8_JSON)
        self.assertEqual(
            records,
            [
                {"name": "foo", "method": "POST", "injection_place": "Body"},
                {"name": "bar", "method": "PUT", "injection_place": "Body"},
                {"name": "baz", "method": "PATCH", "injection_place": "Body"},
                {"name": "q", "method": "GET", "injection_place": "Query"},
            ],
        )

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_run_x8_maps_to_expected_locations(self, mock_subprocess):
        # End-to-end contract: run_x8() raw records feed map_x8_location()
        # (called by the caller, never inside run_x8) to the internal
        # location vocabulary without any POST/PUT/PATCH downgrade to GET.
        records = self._run_payload(mock_subprocess, SYNTHETIC_X8_JSON)
        mapped = {
            rec["name"]: map_x8_location(rec["injection_place"], rec["method"])
            for rec in records
        }
        self.assertEqual(
            mapped,
            {"foo": "body", "bar": "body", "baz": "body", "q": "query"},
        )

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_missing_method_is_discarded(self, mock_subprocess):
        payload = [{"injection_place": "Body", "found_params": [{"name": "foo"}]}]
        self.assertEqual(self._run_payload(mock_subprocess, payload), [])

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_blank_method_is_discarded(self, mock_subprocess):
        payload = [
            {"method": "   ", "injection_place": "Body", "found_params": [{"name": "foo"}]}
        ]
        self.assertEqual(self._run_payload(mock_subprocess, payload), [])

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_missing_injection_place_is_discarded(self, mock_subprocess):
        payload = [{"method": "POST", "found_params": [{"name": "foo"}]}]
        self.assertEqual(self._run_payload(mock_subprocess, payload), [])

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_blank_injection_place_is_discarded(self, mock_subprocess):
        payload = [
            {"method": "POST", "injection_place": "  ", "found_params": [{"name": "foo"}]}
        ]
        self.assertEqual(self._run_payload(mock_subprocess, payload), [])

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_post_never_becomes_get(self, mock_subprocess):
        payload = [{"method": "POST", "injection_place": "Body", "found_params": [{"name": "foo"}]}]
        records = self._run_payload(mock_subprocess, payload)
        self.assertEqual([r["method"] for r in records], ["POST"])

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_put_never_becomes_get(self, mock_subprocess):
        payload = [{"method": "PUT", "injection_place": "Body", "found_params": [{"name": "bar"}]}]
        records = self._run_payload(mock_subprocess, payload)
        self.assertEqual([r["method"] for r in records], ["PUT"])

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_patch_never_becomes_get(self, mock_subprocess):
        payload = [{"method": "PATCH", "injection_place": "Body", "found_params": [{"name": "baz"}]}]
        records = self._run_payload(mock_subprocess, payload)
        self.assertEqual([r["method"] for r in records], ["PATCH"])

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_bare_param_names_still_supported(self, mock_subprocess):
        # Older x8 formats may emit bare name strings in found_params.
        payload = [{"method": "GET", "injection_place": "Query", "found_params": ["q", "r"]}]
        records = self._run_payload(mock_subprocess, payload)
        self.assertEqual(
            records,
            [
                {"name": "q", "method": "GET", "injection_place": "Query"},
                {"name": "r", "method": "GET", "injection_place": "Query"},
            ],
        )

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_valid_and_invalid_items_mixed(self, mock_subprocess):
        payload = [
            {"method": "POST", "injection_place": "Body", "found_params": [{"name": "keep"}]},
            {"injection_place": "Body", "found_params": [{"name": "no_method"}]},
            {"method": "GET", "found_params": [{"name": "no_place"}]},
            {"method": "GET", "injection_place": "Query", "found_params": [{"name": ""}]},
        ]
        records = self._run_payload(mock_subprocess, payload)
        self.assertEqual(
            records,
            [{"name": "keep", "method": "POST", "injection_place": "Body"}],
        )


class X8TargetConstructionTests(unittest.TestCase):
    """build_x8_target_url() normalizes the endpoint URL used for x8
    discovery, and main() must derive the target from the *current*
    endpoint before logging/passing it to run_x8(). No real x8 binary,
    no HTTP, no MongoDB: everything external is faked."""

    def test_strips_query_and_fragment(self):
        self.assertEqual(
            build_x8_target_url("https://shop.example.test/path?a=1#frag"),
            "https://shop.example.test/path",
        )

    def test_empty_path_becomes_root(self):
        self.assertEqual(
            build_x8_target_url("https://shop.example.test"),
            "https://shop.example.test/",
        )

    def test_unparseable_url_returned_unchanged(self):
        # No scheme/netloc -> returned as-is (no invented target).
        self.assertEqual(build_x8_target_url("not a url"), "not a url")

    @mock.patch("crawl.watch_param_discovery.export_wordlists")
    @mock.patch("crawl.watch_param_discovery.time.sleep")
    @mock.patch("crawl.watch_param_discovery.send_telegram")
    @mock.patch("crawl.watch_param_discovery.run_x8")
    @mock.patch("crawl.watch_param_discovery.get_pending_endpoints")
    @mock.patch("crawl.watch_param_discovery.os.path.exists", return_value=True)
    def test_main_passes_endpoint_derived_target_to_run_x8(
        self, _exists, get_pending, run_x8_mock, _sleep, _telegram, _export
    ):
        ep = mock.Mock()
        ep.example_url = "https://shop.example.test/path?token=abc"
        ep.program_name = "dell"
        ep.param_records = []
        run_x8_mock.return_value = []
        get_pending.return_value = [ep]

        # Regression guard: previously main() logged target={x8_target}
        # before x8_target was assigned, raising NameError on the first
        # iteration. Driving main() here proves the ordering is correct.
        with mock.patch.object(sys, "argv", ["watch_param_discovery.py"]):
            main()

        run_x8_mock.assert_called_once()
        called_url = run_x8_mock.call_args[0][0]
        self.assertEqual(called_url, "https://shop.example.test/path")
        self.assertEqual(called_url, build_x8_target_url(ep.example_url))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()