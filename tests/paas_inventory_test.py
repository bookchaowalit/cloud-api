#!/usr/bin/env python3
"""Contract tests for bounded read-only PaaS inventory."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "adapters" / "paas_inventory.py"
SPEC = importlib.util.spec_from_file_location("paas_inventory", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {MODULE_PATH}")
paas_inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(paas_inventory)


class PaaSInventoryTest(unittest.TestCase):
    def test_bounded_inventory_marks_partial_pages(self):
        resources = [
            {"id": f"resource-{index}"} for index in range(paas_inventory.MAX_ITEMS + 1)
        ]
        result = paas_inventory._finish(
            {}, resources, source_count=len(resources), has_more=True
        )

        self.assertEqual(result["summary"]["resources"], paas_inventory.MAX_ITEMS)
        self.assertEqual(len(result["resources"]), paas_inventory.MAX_ITEMS)
        self.assertTrue(result["partial"])
        self.assertTrue(result["has_more"])
        self.assertFalse(result["summary"]["total_known"])
        self.assertTrue(
            paas_inventory._pagination_has_more({"pagination": {"next": "cursor-2"}}, 1)
        )
        self.assertTrue(
            paas_inventory._pagination_has_more(
                {}, paas_inventory.MAX_ITEMS, request_limited=True
            )
        )

    def test_offline_inventory_does_not_call_providers(self):
        with (
            patch.object(paas_inventory, "resolve_provider_auth") as resolver,
            patch.object(paas_inventory, "_get_json") as get_json,
            patch.object(paas_inventory, "_post_json") as post_json,
        ):
            payload = paas_inventory.run_inventory(live=False)

        self.assertEqual(payload["mode"], "offline")
        self.assertEqual(payload["summary"]["providers"], 5)
        self.assertEqual(payload["summary"]["not_configured"], 5)
        self.assertEqual(payload["summary"]["resources"], 0)
        resolver.assert_not_called()
        get_json.assert_not_called()
        post_json.assert_not_called()

    def test_live_inventory_is_sanitized_and_query_only(self):
        def fake_auth(provider):
            return paas_inventory.AuthResolution(
                status="configured",
                credential=f"token-for-{provider['id']}",
                auth_source="env",
            )

        def fake_env(name, required=False):
            return "workspace-1" if name == "RAILWAY_WORKSPACE_ID" else "personal"

        def fake_get_json(url, headers=None):
            if "vercel.com" in url:
                return {
                    "projects": [
                        {"id": "prj-1", "name": "frontend", "secretPayload": "hidden"}
                    ]
                }
            if "render.com" in url:
                return {
                    "items": [
                        {
                            "service": {
                                "id": "srv-1",
                                "name": "api",
                                "secretPayload": "hidden",
                            }
                        }
                    ]
                }
            if "machines.dev" in url:
                return {"apps": [{"id": "app-1", "name": "worker", "machine_count": 1}]}
            return [{"id": "app-1", "name": "heroku-app", "secretPayload": "hidden"}]

        def fake_post_json(url, body, headers=None):
            self.assertTrue(body["query"].lstrip().lower().startswith("query"))
            return {
                "data": {
                    "workspace": {
                        "projects": {
                            "edges": [
                                {
                                    "node": {
                                        "id": "rail-1",
                                        "name": "railway-app",
                                        "secretPayload": "hidden",
                                    }
                                }
                            ]
                        }
                    }
                }
            }

        with (
            patch.object(
                paas_inventory, "resolve_provider_auth", side_effect=fake_auth
            ),
            patch.object(paas_inventory, "get_env", side_effect=fake_env),
            patch.object(paas_inventory, "_get_json", side_effect=fake_get_json),
            patch.object(paas_inventory, "_post_json", side_effect=fake_post_json),
        ):
            payload = paas_inventory.run_inventory(live=True)

        self.assertEqual(payload["summary"]["healthy"], 5)
        self.assertEqual(payload["summary"]["resources"], 5)
        serialized = json.dumps(payload)
        self.assertNotIn("token-for", serialized)
        self.assertNotIn("secretPayload", serialized)
        self.assertNotIn("mutation", serialized.lower())
        self.assertTrue(payload["read_only"])
        self.assertFalse(payload["execution_enabled"])
        self.assertFalse(payload["write_attempted"])

    def test_secret_provider_failure_uses_public_error_class(self):
        auth_failure = paas_inventory.AuthResolution(
            status="error",
            auth_source="secret_manager",
            error_class="secret_provider_unreachable",
        )
        with (
            patch.object(
                paas_inventory, "resolve_provider_auth", return_value=auth_failure
            ),
            patch.object(paas_inventory, "_get_json") as get_json,
            patch.object(paas_inventory, "_post_json") as post_json,
        ):
            payload = paas_inventory.run_inventory(live=True)

        self.assertEqual(payload["summary"]["errors"], 5)
        self.assertEqual(
            {provider["error_class"] for provider in payload["providers"]},
            {"secret_provider_unreachable"},
        )
        self.assertNotIn("private details", json.dumps(payload))
        get_json.assert_not_called()
        post_json.assert_not_called()


if __name__ == "__main__":
    unittest.main()
