#!/usr/bin/env python3
"""Smoke-test platform CLI output when Windows stdout defaults to cp1252."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLATFORM_SCRIPTS = ROOT / "adapters"


class WindowsUtf8OutputTest(unittest.TestCase):
    def run_script(
        self,
        script_name: str,
        args: tuple[str, ...] = (),
        *,
        expected_returncode: int = 0,
        stdin: bytes | None = None,
    ) -> tuple[str, str]:
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "cp1252"
        result = subprocess.run(
            [sys.executable, str(PLATFORM_SCRIPTS / script_name), *args],
            cwd=ROOT,
            env=environment,
            input=stdin,
            capture_output=True,
            timeout=20,
            check=False,
        )
        stdout = result.stdout.decode("utf-8")
        stderr = result.stderr.decode("utf-8")
        self.assertEqual(
            result.returncode,
            expected_returncode,
            f"{script_name} failed under cp1252: {stderr}",
        )
        self.assertNotIn("UnicodeEncodeError", stderr)
        return stdout, stderr

    def test_platform_scripts_survive_cp1252_stdio(self):
        cases = (
            ("cloud_usage.py", ("--help",), 0, None),
            ("cloudflare_r2_usage.py", ("--help",), 0, None),
            ("github_actions_usage.py", ("--help",), 0, None),
            ("paas_execute.py", (), 2, b"{}"),
            ("paas_inventory.py", (), 0, None),
            ("render_preflight.py", ("--help",), 0, None),
            ("paas_health.py", ("--catalog", "--json"), 0, None),
            ("paas_action.py", ("--help",), 0, None),
            ("vercel_billing.py", ("--help",), 0, None),
        )
        for script_name, args, expected_returncode, stdin in cases:
            with self.subTest(script=script_name):
                stdout, _ = self.run_script(
                    script_name,
                    args,
                    expected_returncode=expected_returncode,
                    stdin=stdin,
                )
                self.assertTrue(stdout or expected_returncode == 2)

    def test_catalog_unicode_is_emitted_as_utf8(self):
        stdout, _ = self.run_script("paas_health.py", ("--catalog", "--json"))
        self.assertIn("🚂", stdout)


if __name__ == "__main__":
    unittest.main()
