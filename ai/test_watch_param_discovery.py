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
    normalize_param_record,
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

    @mock.patch("crawl.watch_param_discovery.subprocess")
    def test_success_with_zero_findings_returns_empty_list(self, mock_subprocess):
        # A clean, successful x8 run that found nothing must return []
        # (NOT None) so the caller can still mark the endpoint checked.
        records = self._run_payload(mock_subprocess, [])
        self.assertEqual(records, [])
        self.assertIsNotNone(records)


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


class NormalizeParamRecordTests(unittest.TestCase):
    """normalize_param_record() must produce the canonical
    param_records schema and reject anything it cannot attribute."""

    def test_crawl_get_query(self):
        self.assertEqual(
            normalize_param_record("q", "GET", "query", "crawl"),
            {"name": "q", "method": "GET", "location": "query", "source": "crawl"},
        )

    def test_crawl_post_body(self):
        self.assertEqual(
            normalize_param_record("foo", "post", "body", "crawl"),
            {"name": "foo", "method": "POST", "location": "body", "source": "crawl"},
        )

    def test_crawl_put_body(self):
        self.assertEqual(
            normalize_param_record("bar", "PUT", "Body", "crawl"),
            {"name": "bar", "method": "PUT", "location": "body", "source": "crawl"},
        )

    def test_crawl_patch_body(self):
        self.assertEqual(
            normalize_param_record("baz", "patch", "BODY", "crawl"),
            {"name": "baz", "method": "PATCH", "location": "body", "source": "crawl"},
        )

    def test_name_and_vocabulary_are_normalized(self):
        rec = normalize_param_record("  spaced  ", " get ", " QUERY ", " x8 ")
        self.assertEqual(
            rec,
            {"name": "spaced", "method": "GET", "location": "query", "source": "x8"},
        )

    def test_empty_name_rejected(self):
        self.assertIsNone(normalize_param_record("", "GET", "query", "crawl"))
        self.assertIsNone(normalize_param_record("   ", "GET", "query", "crawl"))
        self.assertIsNone(normalize_param_record(None, "GET", "query", "crawl"))

    def test_missing_method_rejected_never_invented(self):
        self.assertIsNone(normalize_param_record("q", "", "query", "crawl"))
        self.assertIsNone(normalize_param_record("q", None, "query", "crawl"))
        self.assertIsNone(normalize_param_record("q", "   ", "query", "crawl"))

    def test_unsupported_method_rejected(self):
        self.assertIsNone(normalize_param_record("q", "OPTIONS", "query", "x8"))
        self.assertIsNone(normalize_param_record("q", "DELETE", "body", "x8"))
        self.assertIsNone(normalize_param_record("q", "HEAD", "query", "x8"))

    def test_unsupported_location_rejected(self):
        # The raw x8 "Path" label is NOT a valid location here; only
        # mapped query/body values may pass through.
        self.assertIsNone(normalize_param_record("q", "GET", "Path", "x8"))
        self.assertIsNone(normalize_param_record("q", "GET", "headers", "x8"))
        self.assertIsNone(normalize_param_record("q", "GET", "HeaderValue", "x8"))
        self.assertIsNone(normalize_param_record("q", "GET", "cookie", "x8"))
        self.assertIsNone(normalize_param_record("q", "GET", "totally-unknown", "x8"))

    def test_missing_location_rejected(self):
        self.assertIsNone(normalize_param_record("q", "GET", "", "x8"))
        self.assertIsNone(normalize_param_record("q", "GET", None, "x8"))

    def test_unsupported_source_rejected(self):
        self.assertIsNone(normalize_param_record("q", "GET", "query", "manual"))

    def test_x8_path_get_maps_to_query_then_normalizes(self):
        # Full x8 pipeline: Path+GET maps to query, then normalizes.
        location = map_x8_location("Path", "GET")
        self.assertEqual(location, "query")
        self.assertEqual(
            normalize_param_record("q", "GET", location, "x8"),
            {"name": "q", "method": "GET", "location": "query", "source": "x8"},
        )

    def test_x8_path_non_get_rejected_end_to_end(self):
        # Path + POST/PUT/PATCH: map_x8_location rejects, so no
        # normalized record can ever be produced.
        for method in ("POST", "PUT", "PATCH"):
            self.assertIsNone(map_x8_location("Path", method))


class X8MainPersistenceTests(unittest.TestCase):
    """main() must persist x8 records through the normalized schema,
    deduplicate by full provenance, keep the union fields consistent,
    and only mark x8_checked when x8 actually completed."""

    class _FakeEndpoint:
        def __init__(self, **kw):
            self.program_name = kw.get("program_name", "dell")
            self.example_url = kw.get(
                "example_url", "https://shop.example.test/path?token=abc"
            )
            self.params = list(kw.get("params", []))
            self.params_from_crawl = list(kw.get("params_from_crawl", []))
            self.params_from_x8 = list(kw.get("params_from_x8", []))
            self.param_records = list(kw.get("param_records", []))
            self.x8_checked = kw.get("x8_checked", False)
            self.x8_last_checked = None
            self.last_update = None
            self.saved = 0

        def save(self):
            self.saved += 1

    def _run_main(self, ep, run_x8_result):
        with mock.patch(
            "crawl.watch_param_discovery.get_pending_endpoints",
            return_value=[ep],
        ), mock.patch(
            "crawl.watch_param_discovery.run_x8", return_value=run_x8_result
        ), mock.patch(
            "crawl.watch_param_discovery.send_telegram"
        ), mock.patch(
            "crawl.watch_param_discovery.export_wordlists", return_value=[]
        ), mock.patch(
            "crawl.watch_param_discovery.time.sleep"
        ), mock.patch(
            "crawl.watch_param_discovery.os.path.exists", return_value=True
        ), mock.patch.object(
            sys, "argv", ["watch_param_discovery.py"]
        ):
            main()
        return ep

    def test_successful_x8_with_no_findings_marks_checked(self):
        ep = self._FakeEndpoint()
        self._run_main(ep, [])
        self.assertTrue(ep.x8_checked)
        self.assertGreaterEqual(ep.saved, 1)

    def test_x8_failure_does_not_mark_checked(self):
        # None means x8 did not complete (timeout/error/parse fail):
        # the endpoint must stay unchecked and not be saved.
        ep = self._FakeEndpoint(x8_checked=False)
        self._run_main(ep, None)
        self.assertFalse(ep.x8_checked)
        self.assertEqual(ep.saved, 0)

    def test_x8_records_persisted_normalized_and_deduped(self):
        ep = self._FakeEndpoint(
            params=["c"],
            params_from_crawl=["c"],
            param_records=[
                {"name": "c", "method": "GET", "location": "query", "source": "crawl"},
            ],
        )
        raw = [
            {"name": "foo", "method": "POST", "injection_place": "Body"},
            {"name": " foo ", "method": "POST", "injection_place": "Body"},  # dup
            {"name": "hdr", "method": "GET", "injection_place": "Headers"},  # dropped
            {"name": "q", "method": "GET", "injection_place": "Query"},
        ]
        self._run_main(ep, raw)

        self.assertEqual(
            sorted(
                (r["name"], r["method"], r["location"], r["source"])
                for r in ep.param_records
            ),
            [
                ("c", "GET", "query", "crawl"),
                ("foo", "POST", "body", "x8"),
                ("q", "GET", "query", "x8"),
            ],
        )
        # Union fields derived from the records:
        self.assertEqual(ep.params_from_x8, ["foo", "q"])
        self.assertEqual(ep.params_from_crawl, ["c"])
        self.assertEqual(ep.params, ["c", "foo", "q"])
        self.assertTrue(ep.x8_checked)

    def test_x8_duplicate_against_existing_records_not_readded(self):
        ep = self._FakeEndpoint(
            param_records=[
                {"name": "q", "method": "GET", "location": "query", "source": "x8"},
            ],
            params_from_x8=["q"],
            params=["q"],
        )
        self._run_main(
            ep,
            [{"name": "q", "method": "GET", "injection_place": "Query"}],
        )
        x8_records = [
            r for r in ep.param_records
            if r.get("source") == "x8" and r.get("name") == "q"
        ]
        self.assertEqual(len(x8_records), 1)

    def test_run_x8_returns_none_when_binary_missing(self):
        with mock.patch("crawl.watch_param_discovery.subprocess") as ms:
            ms.call.return_value = 1  # which x8 -> not found
            self.assertIsNone(run_x8("https://example.test/api", "/tmp/wl.txt"))

    def test_run_x8_returns_none_on_timeout(self):
        with mock.patch("crawl.watch_param_discovery.subprocess") as ms:
            ms.call.return_value = 0
            ms.TimeoutExpired = subprocess.TimeoutExpired
            ms.run.side_effect = subprocess.TimeoutExpired(cmd="x8", timeout=1)
            self.assertIsNone(run_x8("https://example.test/api", "/tmp/wl.txt"))

    def test_run_x8_returns_none_on_execution_error(self):
        with mock.patch("crawl.watch_param_discovery.subprocess") as ms:
            ms.call.return_value = 0
            ms.TimeoutExpired = subprocess.TimeoutExpired
            ms.run.side_effect = OSError("spawn failed")
            self.assertIsNone(run_x8("https://example.test/api", "/tmp/wl.txt"))

    def test_run_x8_returns_none_on_unparseable_output(self):
        with mock.patch("crawl.watch_param_discovery.subprocess") as ms:
            ms.call.return_value = 0
            ms.TimeoutExpired = subprocess.TimeoutExpired

            def _garbage(cmd, *args, **kwargs):
                out_path = cmd[cmd.index("-o") + 1]
                with open(out_path, "w") as f:
                    f.write("{not json")
                return subprocess.CompletedProcess(cmd, 0)

            ms.run.side_effect = _garbage
            self.assertIsNone(run_x8("https://example.test/api", "/tmp/wl.txt"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()