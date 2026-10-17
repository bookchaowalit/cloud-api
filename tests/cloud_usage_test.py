#!/usr/bin/env python3
"""Contract tests for the sanitized cloud usage/cost snapshot."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "adapters" / "cloud_usage.py"
SPEC = importlib.util.spec_from_file_location("cloud_usage", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {MODULE_PATH}")
cloud_usage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cloud_usage)


class CloudUsageTest(unittest.TestCase):
    def test_snapshot_is_read_only_and_does_not_return_provider_payloads(self):
        runner = Mock(
            return_value={
                "schema_version": "solo-empire.paas-inventory.v1",
                "providers": [
                    {
                        "id": "vercel",
                        "name": "Vercel",
                        "status": "healthy",
                        "dashboard_url": "https://vercel.com/dashboard",
                        "resources": [
                            {"id": "secret-resource-id", "name": "private-app"}
                        ],
                        "summary": {"resources": 1, "returned": 1},
                    }
                ],
                "summary": {
                    "providers": 1,
                    "healthy": 1,
                    "configured": 0,
                    "not_configured": 0,
                    "errors": 0,
                    "resources": 1,
                },
            }
        )
        payload = cloud_usage.build_snapshot(
            live=False,
            inventory_runner=runner,
        )

        runner.assert_called_once_with(live=False)
        self.assertTrue(payload["read_only"])
        self.assertFalse(payload["execution_enabled"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(payload["usage"]["resource_count"], 1)
        self.assertFalse(payload["usage"]["r2_connected"])
        self.assertIn("free_quota", payload["usage"])
        self.assertGreater(payload["usage"]["free_quota"]["summary"]["total"], 0)
        self.assertEqual(payload["costs"]["status"], "unavailable")
        self.assertEqual(payload["costs"]["planned_monthly_equivalent"], {})
        serialized = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("secret-resource-id", serialized)
        self.assertNotIn("private-app", serialized)
        self.assertNotIn("credential_refs", serialized)
        self.assertNotIn("account_id", serialized)

    def test_live_mode_is_explicit_and_provider_usage_cost_stays_false(self):
        runner = Mock(
            return_value={
                "schema_version": "solo-empire.paas-inventory.v1",
                "providers": [],
                "summary": {
                    "providers": 0,
                    "healthy": 0,
                    "configured": 0,
                    "not_configured": 0,
                    "errors": 0,
                    "resources": 0,
                },
            }
        )
        r2_runner = Mock(return_value=cloud_usage.empty_r2_result(live=True))
        billing_runner = Mock(
            return_value=cloud_usage.empty_vercel_billing_result(live=True)
        )
        actions_runner = Mock(
            return_value=cloud_usage.empty_github_actions_result(live=True)
        )
        payload = cloud_usage.build_snapshot(
            live=True,
            inventory_runner=runner,
            r2_metrics_runner=r2_runner,
            vercel_billing_runner=billing_runner,
            github_actions_runner=actions_runner,
        )

        runner.assert_called_once_with(live=True)
        r2_runner.assert_called_once_with(live=True)
        billing_runner.assert_called_once_with(live=True)
        actions_runner.assert_called_once_with(live=True)
        self.assertEqual(payload["mode"], "live")
        self.assertFalse(payload["usage"]["billing_api_connected"])
        self.assertFalse(payload["usage"]["provider_usage_cost_connected"])

    def test_snapshot_preserves_partial_inventory_signal(self):
        runner = Mock(
            return_value={
                "schema_version": "solo-empire.paas-inventory.v1",
                "providers": [
                    {
                        "id": "render",
                        "name": "Render",
                        "status": "healthy",
                        "dashboard_url": "https://dashboard.render.com",
                        "partial": True,
                        "has_more": True,
                        "summary": {
                            "resources": 20,
                            "returned": 20,
                            "partial": True,
                            "has_more": True,
                            "total_known": False,
                        },
                    }
                ],
                "summary": {
                    "providers": 1,
                    "healthy": 1,
                    "configured": 0,
                    "not_configured": 0,
                    "errors": 0,
                    "resources": 20,
                    "partial_providers": 1,
                    "has_more": True,
                    "total_known": False,
                },
            }
        )
        payload = cloud_usage.build_snapshot(live=False, inventory_runner=runner)

        provider = payload["inventory"]["providers"][0]
        self.assertTrue(provider["partial"])
        self.assertTrue(provider["has_more"])
        self.assertFalse(provider["total_known"])
        self.assertEqual(payload["inventory"]["summary"]["partial_providers"], 1)
        self.assertTrue(payload["inventory"]["summary"]["has_more"])
        self.assertFalse(payload["inventory"]["summary"]["total_known"])

    def test_snapshot_includes_sanitized_cloudflare_r2_signal(self):
        runner = Mock(
            return_value={
                "schema_version": "solo-empire.paas-inventory.v1",
                "providers": [],
                "summary": {
                    "providers": 0,
                    "healthy": 0,
                    "configured": 0,
                    "not_configured": 0,
                    "errors": 0,
                    "resources": 0,
                },
            }
        )
        r2_runner = Mock(
            return_value={
                "schema_version": "solo-empire.cloudflare-r2-usage.v1",
                "status": "healthy",
                "credential_state": "verified_read_only",
                "object_count": 7,
                "payload_bytes": 2048,
                "payload_gib": 0.000002,
                "metadata_bytes": 128,
                "uploaded_object_count": 1,
                "uploaded_payload_bytes": 32,
                "uploaded_payload_gib": 0.00000003,
                "storage_cost_estimate": {
                    "status": "estimate_only",
                    "estimated_usd": 0.06,
                    "standard": {
                        "payload_gb": 12.0,
                        "free_gb_month": 10.0,
                        "billable_gb_month": 2.0,
                        "rate_usd_per_gb_month": 0.015,
                        "estimated_usd": 0.03,
                    },
                    "infrequent_access": {
                        "payload_gb": 3.0,
                        "free_gb_month": 0.0,
                        "billable_gb_month": 3.0,
                        "rate_usd_per_gb_month": 0.01,
                        "estimated_usd": 0.03,
                    },
                },
                "storage_classes": {
                    "standard": {"published": {}, "uploaded": {}},
                    "infrequent_access": {"published": {}, "uploaded": {}},
                },
            }
        )
        actions_runner = Mock(
            return_value=cloud_usage.empty_github_actions_result(live=True)
        )
        billing_runner = Mock(
            return_value=cloud_usage.empty_vercel_billing_result(live=True)
        )

        payload = cloud_usage.build_snapshot(
            live=True,
            inventory_runner=runner,
            r2_metrics_runner=r2_runner,
            vercel_billing_runner=billing_runner,
            github_actions_runner=actions_runner,
        )

        r2_runner.assert_called_once_with(live=True)
        billing_runner.assert_called_once_with(live=True)
        actions_runner.assert_called_once_with(live=True)
        self.assertTrue(payload["usage"]["r2_connected"])
        self.assertEqual(payload["usage"]["r2_object_count"], 7)
        self.assertEqual(payload["summary"]["r2_status"], "healthy")
        self.assertEqual(payload["usage"]["cloudflare_r2"]["object_count"], 7)
        self.assertEqual(
            payload["usage"]["cloudflare_r2"]["storage_cost_estimate"]["estimated_usd"],
            0.06,
        )
        self.assertFalse(payload["usage"]["billing_api_connected"])

    def test_snapshot_includes_sanitized_vercel_billing_aggregates(self):
        runner = Mock(
            return_value={
                "schema_version": "solo-empire.paas-inventory.v1",
                "providers": [],
                "summary": {
                    "providers": 0,
                    "healthy": 0,
                    "configured": 0,
                    "not_configured": 0,
                    "errors": 0,
                    "resources": 0,
                },
            }
        )
        r2_runner = Mock(return_value=cloud_usage.empty_r2_result(live=True))
        actions_runner = Mock(
            return_value=cloud_usage.empty_github_actions_result(live=True)
        )
        billing_runner = Mock(
            return_value={
                "schema_version": "solo-empire.vercel-billing.v1",
                "status": "healthy",
                "credential_state": "verified_read_only",
                "auth_source": "secret_manager",
                "window": {
                    "from": "2026-09-01T00:00:00.000Z",
                    "to": "2026-10-01T00:00:00.000Z",
                },
                "charge_count": 4,
                "billed_cost_by_currency": {"USD": 29.99},
                "effective_cost_by_currency": {"USD": 28.5},
                "service_breakdown": [
                    {
                        "service_name": "Vercel Functions",
                        "charge_category": "Usage",
                        "currency": "USD",
                        "charge_count": 4,
                        "billed_cost": 29.99,
                        "effective_cost": 28.5,
                    }
                ],
            }
        )

        payload = cloud_usage.build_snapshot(
            live=True,
            inventory_runner=runner,
            r2_metrics_runner=r2_runner,
            vercel_billing_runner=billing_runner,
            github_actions_runner=actions_runner,
        )

        self.assertTrue(payload["usage"]["billing_api_connected"])
        self.assertTrue(payload["usage"]["provider_usage_cost_connected"])
        self.assertTrue(payload["usage"]["vercel_billing_connected"])
        self.assertEqual(
            payload["usage"]["vercel_billing"]["auth_source"], "secret_manager"
        )
        self.assertEqual(payload["usage"]["vercel_charge_count"], 4)
        self.assertEqual(
            payload["usage"]["vercel_billed_cost_by_currency"], {"USD": 29.99}
        )
        self.assertEqual(payload["summary"]["vercel_billing_status"], "healthy")
        self.assertEqual(
            payload["usage"]["vercel_billing"]["service_breakdown"][0]["service_name"],
            "Vercel Functions",
        )

    def test_snapshot_includes_sanitized_github_actions_usage_and_free_quota(self):
        runner = Mock(
            return_value={
                "schema_version": "solo-empire.paas-inventory.v1",
                "providers": [],
                "summary": {
                    "providers": 0,
                    "healthy": 0,
                    "configured": 0,
                    "not_configured": 0,
                    "errors": 0,
                    "resources": 0,
                },
            }
        )
        actions_runner = Mock(
            return_value={
                "schema_version": "solo-empire.github-actions-usage.v1",
                "status": "healthy",
                "credential_state": "verified_read_only",
                "auth_source": "cli_session",
                "owner_type": "user",
                "owner_configured": False,
                "plan": "free",
                "free_allowance": {
                    "minutes": 2000,
                    "artifact_storage_gb": 0.5,
                    "cache_storage_gb": 10,
                },
                "window": {
                    "year": 2026,
                    "month": 9,
                    "from": "2026-09-01",
                    "to": "2026-09-30",
                },
                "actions_minutes": 123,
                "actions_artifact_storage_gb_hours": 4,
                "actions_cache_storage_gb_hours": 1,
                "actions_rows": 3,
                "usage_items_count": 3,
                "next_action": "none",
            }
        )

        payload = cloud_usage.build_snapshot(
            live=True,
            inventory_runner=runner,
            r2_metrics_runner=Mock(return_value=cloud_usage.empty_r2_result(live=True)),
            vercel_billing_runner=Mock(
                return_value=cloud_usage.empty_vercel_billing_result(live=True)
            ),
            github_actions_runner=actions_runner,
        )

        self.assertTrue(payload["usage"]["github_actions_connected"])
        self.assertEqual(
            payload["usage"]["github_actions"]["auth_source"], "cli_session"
        )
        self.assertEqual(payload["usage"]["github_actions_minutes"], 123)
        actions_row = next(
            row
            for row in payload["usage"]["free_quota"]["services"]
            if row["id"] == "github-actions"
        )
        self.assertEqual(actions_row["status"], "usage_available")
        self.assertEqual(actions_row["observed"]["remaining"], 1877)
        self.assertEqual(actions_row["quota"]["limit"], 2000)


if __name__ == "__main__":
    unittest.main()
