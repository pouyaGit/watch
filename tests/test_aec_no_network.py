"""No-network proof for the AEC-1 offline half (S1).

The plan's guarantee is that the preparation phase cannot talk to a target. The
strongest cheap proof available offline is confrontational: deny socket
primitives at the process level and then run the rest of the AEC-1 test suite
inside that denial. If any module (or any transitive import a module triggers)
reaches for a transport, the suite fails right there.

The sub-suites are loaded and run in-process, so an attempt to resolve a name or
open a connection raises immediately instead of being silently deferred.
"""

from __future__ import annotations

import io
import socket
import sys
import unittest

sys.dont_write_bytecode = True

SUITES_UNDER_DENIAL = (
    "tests.test_aec_selection",
    "tests.test_aec_redaction",
    "tests.test_aec_budget_ledger",
    "tests.test_aec_case_compiler",
    "tests.test_aec_observation_plan",
    "tests.test_aec_authorization_gate",
    "tests.test_aec_import_guard",
    "tests.test_aec_constants",
    "tests.test_aec_readonly_guard",
)

DENIED = ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex")


class _NetworkDenied(Exception):
    pass


def _deny(*args, **kwargs):
    raise _NetworkDenied("AEC-1 offline half attempted network access")


class TestNoNetwork(unittest.TestCase):
    def test_socket_primitives_are_denied_for_the_whole_suite(self):
        originals = {name: getattr(socket, name, None) for name in DENIED}
        stream = io.StringIO()
        try:
            for name in DENIED:
                if originals[name] is not None:
                    setattr(socket, name, _deny)
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromNames(list(SUITES_UNDER_DENIAL))
            result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
        finally:
            for name, original in originals.items():
                if original is not None:
                    setattr(socket, name, original)

        self.assertGreaterEqual(result.testsRun, 100, "expected the AEC-1 suites to run")
        self.assertEqual(
            [],
            [str(item[0]) for item in result.failures] + [str(item[0]) for item in result.errors],
            f"sub-suite failed under network denial:\n{stream.getvalue()[-2000:]}",
        )
        self.assertTrue(result.wasSuccessful())

    def test_denial_actually_bites(self):
        originals = socket.create_connection
        try:
            socket.create_connection = _deny
            with self.assertRaises(_NetworkDenied):
                socket.create_connection(("example.invalid", 80))
        finally:
            socket.create_connection = originals

    def test_offline_modules_import_without_network(self):
        import importlib

        for name in ("aec", "aec.errors", "aec.models", "aec.redaction", "aec.selection"):
            with self.subTest(module=name):
                self.assertIsNotNone(importlib.import_module(name))


if __name__ == "__main__":
    unittest.main()
