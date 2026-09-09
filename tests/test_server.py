from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server import CloudApi  # noqa: E402


class CloudApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.api = CloudApi(allowed_origins=("http://localhost:3200",))
        self.owner_headers = {
            "Host": "127.0.0.1:3440",
            "Origin": "http://localhost:3200",
            "Content-Type": "application/json",
            "X-Solo-PaaS-Command": "1",
        }

    def test_health_is_available_without_authentication(self) -> None:
        response = self.api.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.payload["service"], "solo-empire-cloud-api")
        self.assertEqual(response.payload["schema_version"], "solo-empire.cloud-api.v1")

    def test_request_target_is_bounded(self) -> None:
        response = self.api.handle("GET", "/health?x=" + ("a" * 4096))
        self.assertEqual(response.status, 414)
        self.assertEqual(response.payload["error"]["code"], "target_too_large")

    def test_read_routes_delegate_to_sanitized_platform_adapters(self) -> None:
        usage = {"schema_version": "solo-empire.cloud-usage.v1", "read_only": True}
        inventory = {"schema_version": "solo-empire.paas-inventory.v1", "read_only": True}
        policy = {"schema_version": "solo-empire.paas-action-policy.v1", "providers": []}
        with (
            patch("server.cloud_usage.build_snapshot", return_value=usage) as usage_mock,
            patch("server.paas_inventory.run_inventory", return_value=inventory) as inventory_mock,
            patch("server.paas_action.load_policy", return_value=policy) as policy_mock,
        ):
            usage_response = self.api.handle("GET", "/api/v1/cloud/usage?live=false")
            inventory_response = self.api.handle("GET", "/api/v1/paas/inventory?live=true&provider_id=render")
            policy_response = self.api.handle("GET", "/api/v1/paas/actions")
        self.assertEqual(usage_response.status, 200)
        self.assertEqual(inventory_response.status, 200)
        self.assertEqual(policy_response.status, 200)
        self.assertEqual(usage_response.payload["contract"], "solo-empire.cloud-api.v1")
        self.assertEqual(inventory_response.payload["route"], "paas_inventory")
        self.assertEqual(policy_response.payload["route"], "paas_actions")
        usage_mock.assert_called_once_with(live=False)
        inventory_mock.assert_called_once_with(live=True, provider_id="render")
        policy_mock.assert_called_once_with()

    def test_configured_token_protects_read_routes(self) -> None:
        api = CloudApi(token="unit-test-token", allowed_origins=("http://localhost:3200",))
        with patch("server.cloud_usage.build_snapshot", return_value={"read_only": True}):
            denied = api.handle("GET", "/api/v1/cloud/usage")
            allowed = api.handle(
                "GET",
                "/api/v1/cloud/usage",
                headers={"Authorization": "Bearer unit-test-token"},
            )
        self.assertEqual(denied.status, 401)
        self.assertEqual(denied.payload["error"]["code"], "cloud_api_auth_required")
        self.assertEqual(allowed.status, 200)

    def test_production_without_token_fails_closed(self) -> None:
        api = CloudApi(environment="production")
        response = api.handle("GET", "/api/v1/paas/actions")
        self.assertEqual(response.status, 401)
        self.assertEqual(response.payload["error"]["code"], "cloud_api_auth_required")

    def test_command_requires_local_owner_boundary(self) -> None:
        denied = self.api.handle(
            "POST",
            "/api/v1/paas/commands",
            body=b'{"operation":"status","decision_id":1}',
        )
        self.assertEqual(denied.status, 403)
        self.assertEqual(denied.payload["error"]["code"], "local_owner_request_required")

        with patch("server.paas_execute.dispatch", return_value={"decision_id": 1, "status": "queued"}) as dispatch:
            allowed = self.api.handle(
                "POST",
                "/api/v1/paas/commands",
                headers=self.owner_headers,
                body=json.dumps({"operation": "status", "decision_id": 1}).encode(),
                remote_address="127.0.0.1",
            )
        self.assertEqual(allowed.status, 200)
        dispatch.assert_called_once_with({"operation": "status", "decision_id": 1})

    def test_command_rejects_forwarded_headers_and_oversized_body(self) -> None:
        forwarded = self.api.handle(
            "POST",
            "/api/v1/paas/commands",
            headers={**self.owner_headers, "X-Forwarded-For": "127.0.0.1"},
            body=b'{"operation":"status","decision_id":1}',
            remote_address="127.0.0.1",
        )
        self.assertEqual(forwarded.status, 403)
        self.assertEqual(forwarded.payload["error"]["code"], "forwarded_request_rejected")

        oversized = self.api.handle(
            "POST",
            "/api/v1/paas/commands",
            headers=self.owner_headers,
            body=b"{" + b"a" * (16 * 1024) + b"}",
            remote_address="127.0.0.1",
        )
        self.assertEqual(oversized.status, 413)
        self.assertEqual(oversized.payload["error"]["code"], "command_too_large")

        malformed_origin = self.api.handle(
            "POST",
            "/api/v1/paas/commands",
            headers={**self.owner_headers, "Origin": "http://[invalid"},
            body=b'{"operation":"status","decision_id":1}',
            remote_address="127.0.0.1",
        )
        self.assertEqual(malformed_origin.status, 403)
        self.assertEqual(malformed_origin.payload["error"]["code"], "local_owner_request_required")

    def test_command_gate_errors_are_safe(self) -> None:
        with patch("server.paas_execute.dispatch", side_effect=RuntimeError("provider token=never-return")):
            response = self.api.handle(
                "POST",
                "/api/v1/paas/commands",
                headers=self.owner_headers,
                body=b'{"operation":"status","decision_id":1}',
                remote_address="127.0.0.1",
            )
        self.assertEqual(response.status, 503)
        self.assertEqual(response.payload["error"]["code"], "command_result_unknown")
        self.assertNotIn("token", json.dumps(response.payload))


if __name__ == "__main__":
    unittest.main()
