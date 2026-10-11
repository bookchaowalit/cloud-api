#!/usr/bin/env python3
"""Contract tests for the read-only multi-PaaS control plane."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "adapters" / "paas_health.py"
SPEC = importlib.util.spec_from_file_location("paas_health", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {MODULE_PATH}")
paas_health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(paas_health)


class PaaSControlPlaneTest(unittest.TestCase):
    def test_catalog_is_read_only_and_covers_target_providers(self):
        registry = paas_health._load_registry()
        self.assertEqual(
            {provider["id"] for provider in registry["providers"] if provider["paas"]},
            {"vercel", "render", "railway", "fly-io", "heroku"},
        )
        self.assertEqual(len(registry["providers"]), 17)
        self.assertFalse(registry["deployment_enabled"])
        self.assertFalse(registry["write_actions_enabled"])
        self.assertEqual(registry["write_entrypoint"], "paas:action:propose")
        self.assertTrue(
            all(
                provider["write_policy"] == "proposal_only"
                and (not provider["paas"] or provider["write_capabilities"] == [])
                for provider in registry["providers"]
            )
        )

    def test_offline_health_does_not_require_credentials(self):
        with patch.object(paas_health, "get_env", return_value=None):
            payload = paas_health.run_health_check(live=False)

        self.assertEqual(payload["mode"], "offline")
        self.assertEqual(payload["summary"]["total"], 5)
        self.assertEqual(payload["summary"]["not_configured"], 5)
        self.assertEqual(payload["summary"]["errors"], 0)
        self.assertFalse(payload["write_actions_enabled"])

    def test_live_check_is_bounded_and_never_returns_provider_payload(self):
        def fake_get_env(name: str, required: bool = False):
            values = {
                "RENDER_API_KEY": "test-render-token",
                "FLY_API_TOKEN": "test-fly-token",
                "FLY_ORG_SLUG": "test-org",
                "HEROKU_TOKEN": "test-heroku-token",
            }
            return values.get(name)

        def fake_auth(provider):
            token = {
                "render": "test-render-token",
                "fly-io": "test-fly-token",
                "heroku": "test-heroku-token",
            }[provider["id"]]
            return paas_health.AuthResolution(
                status="configured",
                credential=token,
                auth_source="env",
            )

        with patch.object(paas_health, "get_env", side_effect=fake_get_env), patch.object(
            paas_health, "resolve_provider_auth", side_effect=fake_auth
        ), patch.object(
            paas_health, "_get_json", return_value={"items": [], "total_apps": 0}
        ):
            render = paas_health.check_paas_provider("render", live=True)
            fly = paas_health.check_paas_provider("fly-io", live=True)
            heroku = paas_health.check_paas_provider("heroku", live=True)

        self.assertEqual(render["status"], "healthy")
        self.assertEqual(fly["status"], "healthy")
        self.assertEqual(heroku["status"], "healthy")
        serialized = json.dumps([render, fly, heroku])
        self.assertNotIn("test-render-token", serialized)
        self.assertNotIn("test-fly-token", serialized)
        self.assertNotIn("test-heroku-token", serialized)
        self.assertNotIn("items", serialized)


if __name__ == "__main__":
    unittest.main()
