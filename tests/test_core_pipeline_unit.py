#!/usr/bin/env python3
"""core watch.service runtime-environment regression tests (offline).

Locks the Systemd runtime hardening for the core pipeline installer
(``setup-core-pipeline.sh``):

  - explicit Go-tool PATH on ``watch.service`` (mirrors setup-weekly-jobs.sh)
  - a real timeout that actually applies to ``Type=oneshot``
    (``TimeoutStartSec=``, NOT the ignored ``RuntimeMaxSec=``)
  - unchanged ExecStart / KillMode / TimeoutStopSec
  - unchanged timer cadence (00:00/12:00 Asia/Tehran, Persistent=false)

No service is installed, started, or contacted; the unit text is parsed out of
the installer script and (when available) checked with ``systemd-analyze
verify``.
"""

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "setup-core-pipeline.sh"

EXPECTED_PATH = (
    "/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:"
    "/home/pouya_behnia/go/bin:/usr/local/bin:/usr/bin:/bin"
)
EXPECTED_TIMEOUT = "6h"


def _extract_unit(script_text, unit_name):
    """Return the heredoc body written to <unit_name> (without the UNIT line)."""
    lines = []
    capturing = False
    for line in script_text.splitlines():
        if not capturing and unit_name in line and "<< 'UNIT'" in line:
            capturing = True
            continue
        if capturing:
            if line.strip() == "UNIT":
                break
            lines.append(line)
    return "\n".join(lines) + "\n"


class TestCoreServiceUnit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = SCRIPT.read_text()
        cls.service = _extract_unit(text, "watch.service")
        cls.timer = _extract_unit(text, "watch.timer")

    def test_service_heredoc_extracted(self):
        self.assertIn("[Service]", self.service)
        self.assertIn("Type=oneshot", self.service)

    def test_explicit_go_tool_path_present(self):
        self.assertIn(f'Environment="PATH={EXPECTED_PATH}"', self.service)
        for directory in EXPECTED_PATH.split(":"):
            self.assertIn(directory, self.service)

    def test_real_oneshot_timeout_present(self):
        self.assertRegex(self.service, r"(?m)^TimeoutStartSec=" + re.escape(EXPECTED_TIMEOUT) + r"$")

    def test_runtimemaxsec_directive_absent(self):
        # RuntimeMaxSec= is ignored for Type=oneshot and must not be used.
        self.assertIsNone(
            re.search(r"(?m)^\s*RuntimeMaxSec=", self.service),
            "RuntimeMaxSec= must not be set on a Type=oneshot service",
        )

    def test_killmode_and_stop_preserved(self):
        self.assertRegex(self.service, r"(?m)^KillMode=control-group$")
        self.assertRegex(self.service, r"(?m)^TimeoutStopSec=30s$")

    def test_execstart_unchanged(self):
        self.assertRegex(
            self.service,
            r"(?m)^ExecStart=/usr/bin/flock -n /run/watch-pipeline\.lock "
            r"/opt/watch/run-pipeline\.sh$",
        )

    def test_timer_cadence_unchanged(self):
        self.assertRegex(self.timer, r"(?m)^Unit=watch\.service$")
        self.assertRegex(
            self.timer, r"(?m)^OnCalendar=\*-\*-\* 00:00:00 Asia/Tehran$"
        )
        self.assertRegex(
            self.timer, r"(?m)^OnCalendar=\*-\*-\* 12:00:00 Asia/Tehran$"
        )
        self.assertRegex(self.timer, r"(?m)^Persistent=false$")
        self.assertNotIn("RandomizedDelaySec", self.timer)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze not available")
    def test_systemd_analyze_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            unit = Path(tmp) / "watch.service"
            unit.write_text(self.service)
            result = subprocess.run(
                ["systemd-analyze", "verify", str(unit)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(
            result.returncode, 0,
            msg=f"systemd-analyze verify failed:\n{result.stdout}\n{result.stderr}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
