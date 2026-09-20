"""tests/test_command_center_operations.py — Command Center Live Operations v1.

Focused tests for the live operations layer:

- ``backend.operations_status`` — ``systemctl show`` parsing, service/timer
  status mapping, last-execution projection, missing-unit handling, an
  unavailable-systemd path, resource collection with an injected collector,
  uptime formatting and timeline event normalization.
- ``GET /api/command/operations`` — deterministic JSON response.
- ``GET /ui/command`` — System Operations / Resource Status / Live Timeline
  panels render.

Fully offline: the systemctl invocation and resource collector are injected
fakes, so the real system is never queried. No network, no writes, no LLM.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


def _fake_runner(unit_outputs, *, version_rc=0):
    """Build an injectable ``systemctl`` runner from canned unit outputs.

    ``unit_outputs`` maps a unit name to a ``(returncode, stdout)`` pair. The
    reachability probe is answered separately via ``version_rc``.
    """

    def runner(args, timeout=5.0):
        if "--property=Version" in args:
            return version_rc, "255.4-1ubuntu8.17\n", ""
        unit = args[1] if len(args) > 1 else ""
        code, out = unit_outputs.get(unit, (1, ""))
        return code, out, ""

    return runner


def _fake_collector():
    return {
        "cpu_percent": 12.0,
        "ram_used_mb": 1024.0,
        "ram_total_mb": 2048.0,
        "ram_percent": 50.0,
        "disk_used_gb": 10.0,
        "disk_total_gb": 20.0,
        "disk_percent": 50.0,
        "load_avg": [0.1, 0.2, 0.3],
    }


SERVICE_OUTPUT = "\n".join([
    "Result=success",
    "ExecMainStatus=0",
    "ExecMainStartTimestamp=Sun 2026-09-20 08:30:13 UTC",
    "ExecMainStartTimestampMonotonic=427894972507",
    "ExecMainExitTimestamp=Sun 2026-09-20 08:30:47 UTC",
    "ExecMainExitTimestampMonotonic=427929007619",
    "LoadState=loaded",
    "ActiveState=inactive",
    "SubState=dead",
    "UnitFileState=disabled",
])

API_SERVICE_OUTPUT = "\n".join([
    "Result=success",
    "ExecMainStatus=0",
    "ExecMainStartTimestamp=Sat 2026-09-19 06:29:32 UTC",
    "ExecMainStartTimestampMonotonic=1000000000",
    "LoadState=loaded",
    "ActiveState=active",
    "SubState=running",
    "UnitFileState=enabled",
])

TIMER_OUTPUT = "\n".join([
    "NextElapseUSecRealtime=Sun 2026-09-20 14:30:00 UTC",
    "LastTriggerUSec=Sun 2026-09-20 08:30:13 UTC",
    "LastTriggerUSecMonotonic=4d 22h",
    "LoadState=loaded",
    "ActiveState=active",
    "SubState=waiting",
    "UnitFileState=enabled",
])

MISSING_OUTPUT = "\n".join([
    "LoadState=not-found",
    "ActiveState=inactive",
    "UnitFileState=",
])


class TestSystemdParsing(unittest.TestCase):
    def test_parse_show(self):
        from backend import operations_status as ops

        parsed = ops._parse_show("A=1\nB=hello world\nignored\nC=\n")
        self.assertEqual(parsed, {"A": "1", "B": "hello world", "C": ""})

    def test_parse_when_valid_and_invalid(self):
        from backend import operations_status as ops

        parsed = ops._parse_when("Sun 2026-09-20 08:30:13 UTC")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.isoformat(), "2026-09-20T08:30:13+00:00")
        self.assertIsNone(ops._parse_when("n/a"))
        self.assertIsNone(ops._parse_when(""))
        self.assertIsNone(ops._parse_when("not a timestamp"))

    def test_duration_and_format(self):
        from backend import operations_status as ops

        self.assertEqual(ops._duration_seconds(1_000_000, 3_500_000), 2.5)
        self.assertIsNone(ops._duration_seconds(None, 5))
        self.assertIsNone(ops._duration_seconds(5, 1))
        self.assertEqual(ops._format_duration(34), "34s")
        self.assertEqual(ops._format_duration(90), "1m 30s")
        self.assertEqual(ops._format_duration(3600), "1h")
        self.assertEqual(ops._format_uptime(90000), "1d 1h 0m")


class TestServiceStatusMapping(unittest.TestCase):
    def test_service_states(self):
        from backend import operations_status as ops

        self.assertEqual(ops._service_status({"ActiveState": "active",
                                              "SubState": "running"}), "RUNNING")
        self.assertEqual(ops._service_status({"ActiveState": "inactive",
                                              "Result": "success"}),
                         "LAST RUN SUCCESS")
        self.assertEqual(ops._service_status({"ActiveState": "failed",
                                              "Result": "exit-code"}), "FAILED")
        self.assertEqual(ops._service_status({"ActiveState": "activating"}),
                         "STARTING")
        self.assertEqual(ops._service_status({"LoadState": "not-found"}),
                         "NOT INSTALLED")
        self.assertEqual(ops._service_status({"LoadState": "masked"}), "MASKED")

    def test_timer_states(self):
        from backend import operations_status as ops

        self.assertEqual(ops._timer_status({"ActiveState": "active",
                                            "SubState": "waiting"}), "SCHEDULED")
        self.assertEqual(ops._timer_status({"ActiveState": "failed"}), "FAILED")
        self.assertEqual(ops._timer_status({"LoadState": "not-found"}),
                         "NOT INSTALLED")


class TestCollectOperations(unittest.TestCase):
    def test_service_and_timer_projection(self):
        from backend import operations_status as ops

        runner = _fake_runner({
            "watch-api.service": (0, API_SERVICE_OUTPUT),
            "watch-dell-watchlist.service": (0, SERVICE_OUTPUT),
            "watch-dell-watchlist.timer": (0, TIMER_OUTPUT),
        })
        payload = ops.collect_operations(runner=runner)
        self.assertTrue(payload["available"])
        units = {u["unit"]: u for u in payload["units"]}
        self.assertEqual(units["watch-api.service"]["status"], "RUNNING")
        self.assertTrue(units["watch-api.service"]["enabled"])
        service = units["watch-dell-watchlist.service"]
        self.assertEqual(service["status"], "LAST RUN SUCCESS")
        self.assertFalse(service["enabled"])
        self.assertEqual(service["last_run"]["exit_status"], 0)
        self.assertAlmostEqual(
            service["last_run"]["duration_seconds"], 34.035, places=3)
        self.assertEqual(service["last_run"]["duration_label"], "34s")
        timer = units["watch-dell-watchlist.timer"]
        self.assertEqual(timer["status"], "SCHEDULED")
        self.assertIsNotNone(timer["last_trigger"])
        self.assertIsNotNone(timer["next_elapse"])

    def test_missing_service_is_not_installed(self):
        from backend import operations_status as ops

        runner = _fake_runner({
            "watch-api.service": (0, MISSING_OUTPUT),
        })
        payload = ops.collect_operations(
            units=[("watch-api.service", "service")], runner=runner)
        self.assertTrue(payload["available"])
        unit = payload["units"][0]
        self.assertEqual(unit["status"], "NOT INSTALLED")
        self.assertFalse(unit["installed"])
        self.assertIsNone(unit["last_run"])

    def test_unavailable_systemd_is_honest(self):
        from backend import operations_status as ops

        def runner(args, timeout=5.0):
            return 1, "", "System has not been booted with systemd as init system"

        payload = ops.collect_operations(
            units=[("watch-api.service", "service")], runner=runner)
        self.assertFalse(payload["available"])
        self.assertEqual(payload["units"][0]["status"], "UNAVAILABLE")

    def test_missing_systemctl_binary_is_honest(self):
        from backend import operations_status as ops

        def runner(args, timeout=5.0):
            raise FileNotFoundError("systemctl")

        payload = ops.collect_operations(
            units=[("watch-api.service", "service")], runner=runner)
        self.assertFalse(payload["available"])
        self.assertEqual(payload["units"][0]["status"], "UNAVAILABLE")
        self.assertIn("not installed", payload["note"])

    def test_operation_events(self):
        from backend import operations_status as ops

        runner = _fake_runner({
            "watch-dell-watchlist.service": (0, SERVICE_OUTPUT),
            "watch-dell-watchlist.timer": (0, TIMER_OUTPUT),
        })
        payload = ops.collect_operations(
            units=[("watch-dell-watchlist.service", "service"),
                   ("watch-dell-watchlist.timer", "timer")],
            runner=runner,
        )
        events = ops.operation_events(payload)
        kinds = [e["kind"] for e in events]
        self.assertIn("SERVICE_RUN", kinds)
        self.assertIn("TIMER_TRIGGER", kinds)
        service_event = [e for e in events if e["kind"] == "SERVICE_RUN"][0]
        self.assertEqual(service_event["at"].isoformat(),
                         "2026-09-20T08:30:13+00:00")
        self.assertIn("exit=0", service_event["detail"])


class TestCollectResources(unittest.TestCase):
    def test_resources_with_injected_collector(self):
        from backend import operations_status as ops

        with mock.patch("backend.operations_status.uptime_status",
                        return_value={"uptime_seconds": 3600,
                                      "boot_time": None,
                                      "uptime_label": "1h 0m"}):
            payload = ops.collect_resources(_fake_collector)
        self.assertTrue(payload["available"])
        self.assertEqual(payload["cpu_percent"], 12.0)
        self.assertEqual(payload["uptime_label"], "1h 0m")

    def test_resources_empty_collector_is_honest(self):
        from backend import operations_status as ops

        with mock.patch("backend.operations_status.uptime_status",
                        return_value={"uptime_seconds": None,
                                      "boot_time": None,
                                      "uptime_label": ""}):
            payload = ops.collect_resources(lambda: {})
        self.assertFalse(payload["available"])


class _Fixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        (root / "watch").mkdir()
        agent = root / "agent"
        agent.mkdir()
        self._env = mock.patch.dict(os.environ, {
            "WATCH_RESEARCH_WATCHLIST_DIR": str(root / "watch"),
            "WATCH_AGENT_DIR": str(agent),
        })
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()


class TestOperationsRoutes(_Fixture):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    def _system_ops(self):
        from backend import operations_status as ops

        runner = _fake_runner({
            "watch-api.service": (0, API_SERVICE_OUTPUT),
            "watch-dell-watchlist.service": (0, SERVICE_OUTPUT),
            "watch-dell-watchlist.timer": (0, TIMER_OUTPUT),
        })
        with mock.patch("backend.operations_status.uptime_status",
                        return_value={"uptime_seconds": 3600,
                                      "boot_time": None,
                                      "uptime_label": "1h 0m"}):
            return ops.snapshot(runner=runner, collector=_fake_collector)

    def test_operations_endpoint_shape(self):
        system_ops = self._system_ops()
        with mock.patch("backend.operations_status.snapshot",
                        return_value=system_ops):
            r = self._get("/api/command/operations")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        for key in ("operations", "resources", "events"):
            self.assertIn(key, body)
        units = {u["unit"]: u for u in body["operations"]["units"]}
        self.assertEqual(units["watch-dell-watchlist.service"]["status"],
                         "LAST RUN SUCCESS")
        self.assertTrue(body["resources"]["available"])
        self.assertIn("uptime_label", body["resources"])
        self.assertTrue(body["events"])

    def test_page_renders_live_operations_panels(self):
        system_ops = self._system_ops()
        with mock.patch("backend.operations_status.snapshot",
                        return_value=system_ops), \
             mock.patch("backend.dashboard.latest_runs", return_value=[]), \
             mock.patch("backend.research_data.has_report", return_value=False):
            r = self._get("/ui/command")
        self.assertEqual(r.status_code, 200)
        text = r.text
        self.assertIn("System Operations", text)
        self.assertIn("Resource Status", text)
        self.assertIn("watch-dell-watchlist.service", text)
        self.assertIn("LAST RUN SUCCESS", text)
        self.assertIn("Live Timeline", text)
        self.assertIn("Uptime", text)
        self.assertNotIn("Vulnerable", text)
        self.assertNotIn("Exploitable", text)

    def test_unavailable_systemd_panel_is_honest(self):
        def runner(args, timeout=5.0):
            return 1, "", "System has not been booted with systemd"

        from backend import operations_status as ops

        unavailable = ops.collect_operations(
            units=[("watch-api.service", "service")], runner=runner)
        system_ops = {"operations": unavailable,
                      "resources": {"available": False},
                      "events": []}
        with mock.patch("backend.operations_status.snapshot",
                        return_value=system_ops), \
             mock.patch("backend.dashboard.latest_runs", return_value=[]), \
             mock.patch("backend.research_data.has_report", return_value=False):
            r = self._get("/ui/command")
        self.assertEqual(r.status_code, 200)
        self.assertIn("System operations unavailable", r.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
