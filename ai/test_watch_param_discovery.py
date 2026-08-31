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

import unittest

from crawl.watch_param_discovery import map_x8_location


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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()