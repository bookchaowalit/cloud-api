#!/usr/bin/env python3
"""Contract tests for Render read-only discovery and rollback preflight."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "adapters" / "render_preflight.py"
SPEC = importlib.util.spec_from_file_location("render_preflight", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {MODULE_PATH}")
render_preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(render_preflight)


class RenderPreflightTest(unittest.TestCase):
    def test_health_host_only_accepts_provider_owned_render_url(self):
        self.assertEqual(
            render_preflight._render_health_host({"serviceDetails": {"url": "https://api.onrender.com/"}}),
            "api.onrender.com",
        )
        self.assertIsNone(
            render_preflight._render_health_host({"serviceDetails": {"url": "https://user:pass@evil.example/"}})
        )
        self.assertIsNone(
            render_preflight._render_health_host({"serviceDetails": {"url": "https://api.onrender.com/path"}})
        )

    def test_clean_health_path_is_bounded_and_provider_supplied(self):
        self.assertEqual(render_preflight._clean_health_path(" /healthz "), "/healthz")
        self.assertEqual(render_preflight._clean_service({"healthCheckPath": "/readyz"})["health_path"], "/readyz")
        self.assertIsNone(render_preflight._clean_health_path("/health?token=x"))
        self.assertIsNone(render_preflight._clean_health_path("//evil.example"))

    def test_offline_discovery_never_calls_render(self):
        with patch.object(render_preflight, "resolve_provider_auth") as resolve_auth, patch.object(
            render_preflight, "_get_json"
        ) as get_json:
            payload = render_preflight.discover(live=False)

        self.assertEqual(payload["status"], "not_checked")
        self.assertEqual(payload["auth_source"], "not_checked")
        self.assertEqual(payload["credentials"]["status"], "not_checked")
        self.assertEqual(payload["external_calls"], 0)
        self.assertEqual(payload["services"], [])
        resolve_auth.assert_not_called()
        get_json.assert_not_called()

    def test_live_discovery_unwraps_items_and_recent_deploys_without_payload_leak(self):
        responses = [
            {
                "cursor": "cursor-next",
                "items": [
                    {
                        "service": {
                            "id": "srv-staging",
                            "name": "staging-api",
                            "type": "web_service",
                            "environmentId": "env-staging",
                            "autoDeploy": "no",
                            "branch": "main",
                            "healthCheckPath": "/healthz",
                            "serviceDetails": {"url": "https://staging-api.onrender.com/"},
                            "secretPayload": "should-not-appear",
                        }
                    }
                ],
            },
            {
                "items": [
                    {
                        "deploy": {
                            "id": "dep-previous",
                            "serviceId": "srv-staging",
                            "status": "deactivated",
                            "commit": {"id": "abc123"},
                            "secretPayload": "should-not-appear",
                        }
                    }
                ]
            },
        ]
        with patch.object(render_preflight, "resolve_provider_auth", return_value=self._configured_auth()), patch.object(
            render_preflight, "_get_json", side_effect=responses
        ):
            payload = render_preflight.discover(live=True, service_id="srv-staging", environment_id="env-staging")

        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["auth_source"], "secret_manager")
        self.assertEqual(payload["external_calls"], 2)
        self.assertEqual(payload["summary"], {"services": 1, "deploys": 1})
        self.assertEqual(payload["services"][0]["id"], "srv-staging")
        self.assertEqual(payload["services"][0]["health_host"], "staging-api.onrender.com")
        self.assertEqual(payload["services"][0]["health_path"], "/healthz")
        self.assertEqual(payload["deploys"][0]["service_id"], "srv-staging")
        self.assertEqual(payload["deploys"][0]["status"], "deactivated")
        serialized = json.dumps(payload)
        self.assertNotIn("test-render-token", serialized)
        self.assertNotIn("secretPayload", serialized)
        self.assertNotIn("cursor-next", serialized)

    def test_cli_discovery_uses_logged_in_session_and_sanitizes_output(self):
        responses = [
            [
                {
                    "service": {
                        "id": "srv-cli",
                        "name": "cli-service",
                        "type": "web_service",
                        "environmentId": "env-production",
                        "autoDeploy": "yes",
                        "secretPayload": "should-not-appear",
                    },
                    "environment": {
                        "id": "env-production",
                        "name": "Production",
                        "ownerEmail": "private@example.com",
                    },
                }
            ],
            [
                {
                    "id": "dep-cli",
                    "serviceId": "srv-cli",
                    "status": "deactivated",
                    "commit": {"id": "abc123"},
                    "secretPayload": "should-not-appear",
                }
            ],
        ]
        with patch.object(render_preflight, "_run_cli", side_effect=responses):
            payload = render_preflight.discover(live=True, source="cli", service_id="srv-cli")

        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["auth_source"], "cli_session")
        self.assertEqual(payload["credentials"]["status"], "cli_session")
        self.assertEqual(payload["external_calls"], 2)
        self.assertEqual(payload["services"][0]["environment_name"], "Production")
        serialized = json.dumps(payload)
        self.assertNotIn("private@example.com", serialized)
        self.assertNotIn("secretPayload", serialized)

    def test_api_discovery_fetches_only_selected_service_detail_for_health_origin(self):
        responses = [
            {"items": [{"service": {"id": "srv-api", "name": "api-service", "type": "web_service", "environmentId": "env-production"}}]},
            {"service": {"id": "srv-api", "serviceDetails": {"url": "https://api-service.onrender.com"}, "healthCheckPath": "/healthz", "environmentId": "env-production"}},
            {"items": [{"deploy": {"id": "dep-api", "serviceId": "srv-api", "status": "live"}}]},
        ]
        with patch.object(render_preflight, "resolve_provider_auth", return_value=self._configured_auth()), patch.object(
            render_preflight, "_get_json", side_effect=responses
        ):
            payload = render_preflight.discover(live=True, service_id="srv-api")

        self.assertEqual(payload["external_calls"], 3)
        self.assertEqual(payload["services"][0]["health_host"], "api-service.onrender.com")
        self.assertEqual(payload["services"][0]["health_path"], "/healthz")
        self.assertEqual(payload["deploys"][0]["service_id"], "srv-api")
        self.assertNotIn("test-render-token", json.dumps(payload))

    def test_cli_preflight_reports_real_production_blockers_without_writes(self):
        responses = [
            [
                {
                    "service": {
                        "id": "srv-cli",
                        "name": "cli-service",
                        "type": "web_service",
                        "environmentId": "env-production",
                        "autoDeploy": "yes",
                        "serviceDetails": {"url": "https://cli-service.onrender.com/"},
                    },
                    "environment": {"id": "env-production", "name": "Production"},
                }
            ],
            [
                {
                    "id": "dep-cli",
                    "serviceId": "srv-cli",
                    "status": "deactivated",
                    "commit": {"id": "abc123"},
                }
            ],
        ]
        with patch.object(render_preflight, "_run_cli", side_effect=responses), patch.object(
            render_preflight, "_probe_url", return_value={"status": "passed", "http_status": 200}
        ):
            payload = render_preflight.preflight(
                live=True,
                source="cli",
                service_id="srv-cli",
                environment_id="env-production",
                target_deploy_id="dep-cli",
                health_url="https://production.example.com/health",
                environment="production",
            )

        self.assertFalse(payload["preflight_passed"])
        self.assertIn("auto-deploy-enabled", payload["blockers"])
        self.assertNotIn("environment-name-mismatch", payload["blockers"])
        self.assertEqual(payload["external_calls"], 3)
        self.assertFalse(payload["execution_allowed"])
        self.assertFalse(payload["write_attempted"])

    def test_staging_preflight_passes_but_never_allows_execution(self):
        responses = {
            "https://api.render.com/v1/services/srv-staging": {
                "id": "srv-staging",
                "name": "staging-api",
                "type": "web_service",
                "environmentId": "env-staging",
                "autoDeploy": "no",
            },
            "https://api.render.com/v1/environments/env-staging": {
                "id": "env-staging",
                "name": "staging",
                "projectId": "proj-example",
            },
            "https://api.render.com/v1/services/srv-staging/deploys/dep-previous": {
                "id": "dep-previous",
                "serviceId": "srv-staging",
                "status": "deactivated",
                "commit": {"id": "abc123"},
            },
        }

        def fake_get_json(url, headers=None):
            return responses[url]

        with patch.object(render_preflight, "resolve_provider_auth", return_value=self._configured_auth()), patch.object(
            render_preflight, "_get_json", side_effect=fake_get_json
        ), patch.object(render_preflight, "_probe_url", return_value={"status": "passed", "http_status": 200}):
            payload = render_preflight.preflight(
                live=True,
                service_id="srv-staging",
                environment_id="env-staging",
                target_deploy_id="dep-previous",
                health_url="https://staging.example.com/health",
            )

        self.assertTrue(payload["preflight_passed"])
        self.assertEqual(payload["status"], "preflight_passed")
        self.assertFalse(payload["execution_allowed"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(payload["external_calls"], 4)
        self.assertEqual(payload["checks"]["health_endpoint"]["http_status"], 200)
        self.assertNotIn("test-render-token", json.dumps(payload))

    def test_action_preflight_covers_deploy_without_provider_writes(self):
        discovery = {
            "status": "ready",
            "external_calls": 2,
            "credentials": {"status": "cli_session", "missing": []},
            "services": [{
                "id": "srv-production",
                "type": "web_service",
                "environment_id": "env-production",
                "environment_name": "Production",
                "auto_deploy": "no",
                "health_host": "production.onrender.com",
                "health_path": "/healthz",
            }],
            "deploys": [{"id": "dep-live", "status": "live", "service_id": "srv-production"}],
        }
        with patch.object(render_preflight, "discover", return_value=discovery), patch.object(
            render_preflight, "_probe_url", return_value={"status": "passed", "http_status": 200}
        ) as probe:
            payload = render_preflight.action_preflight(
                live=True,
                source="cli",
                action="deploy",
                service_id="srv-production",
                environment_id="env-production",
                environment="production",
                target_revision="a" * 40,
                health_path="/healthz",
            )

        self.assertTrue(payload["preflight_passed"])
        self.assertEqual(payload["status"], "preflight_passed")
        self.assertEqual(payload["external_calls"], 3)
        self.assertEqual(payload["checks"]["current_deploy"]["deploy"]["id"], "dep-live")
        probe.assert_called_once_with("https://production.onrender.com/healthz")
        self.assertFalse(payload["execution_allowed"])
        self.assertFalse(payload["write_attempted"])

    def test_action_preflight_set_auto_deploy_skips_health_probe(self):
        discovery = {
            "status": "ready",
            "external_calls": 2,
            "credentials": {"status": "cli_session", "missing": []},
            "services": [{
                "id": "srv-production",
                "type": "web_service",
                "environment_id": "env-production",
                "environment_name": "Production",
                "auto_deploy": "yes",
                "health_host": "production.onrender.com",
            }],
            "deploys": [],
        }
        with patch.object(render_preflight, "discover", return_value=discovery), patch.object(
            render_preflight, "_probe_url"
        ) as probe:
            payload = render_preflight.action_preflight(
                live=True,
                source="cli",
                action="set-auto-deploy",
                service_id="srv-production",
                environment_id="env-production",
                environment="production",
                auto_deploy="no",
            )

        self.assertTrue(payload["preflight_passed"])
        self.assertEqual(payload["checks"]["service"]["auto_deploy"], "yes")
        self.assertEqual(payload["external_calls"], 2)
        probe.assert_not_called()

    def test_action_preflight_offline_does_not_discover(self):
        with patch.object(render_preflight, "discover") as discover:
            payload = render_preflight.action_preflight(
                live=False,
                source="cli",
                action="restart",
                service_id="srv-production",
                environment_id="env-production",
                target_revision=None,
            )

        self.assertFalse(payload["preflight_passed"])
        self.assertIn("live-check-required", payload["blockers"])
        discover.assert_not_called()

    def test_action_preflight_does_not_echo_an_invalid_health_secret(self):
        with patch.object(render_preflight, "discover") as discover:
            payload = render_preflight.action_preflight(
                live=True,
                source="cli",
                action="restart",
                service_id="srv-production",
                environment_id="env-production",
                environment="production",
                health_path="/health?token=private-value",
            )

        self.assertIn("invalid-health-path", payload["blockers"])
        self.assertNotIn("private-value", json.dumps(payload))
        discover.assert_not_called()

    def test_preflight_blocks_autodeploy_and_failed_target(self):
        responses = {
            "https://api.render.com/v1/services/srv-production": {
                "id": "srv-production",
                "type": "web_service",
                "environmentId": "env-production",
                "autoDeploy": "yes",
            },
            "https://api.render.com/v1/environments/env-production": {
                "id": "env-production",
                "name": "production",
            },
            "https://api.render.com/v1/services/srv-production/deploys/dep-failed": {
                "id": "dep-failed",
                "serviceId": "srv-production",
                "status": "build_failed",
            },
        }

        with patch.object(render_preflight, "resolve_provider_auth", return_value=self._configured_auth()), patch.object(
            render_preflight, "_get_json", side_effect=lambda url, headers=None: responses[url]
        ), patch.object(render_preflight, "_probe_url", return_value={"status": "passed", "http_status": 200}):
            payload = render_preflight.preflight(
                live=True,
                service_id="srv-production",
                environment_id="env-production",
                target_deploy_id="dep-failed",
                health_url="https://production.example.com/health",
                environment="production",
            )

        self.assertFalse(payload["preflight_passed"])
        self.assertIn("auto-deploy-enabled", payload["blockers"])
        self.assertIn("target-deploy-not-successful", payload["blockers"])

    def test_production_preflight_passes_when_guardrails_pass(self):
        responses = {
            "https://api.render.com/v1/services/srv-production": {
                "id": "srv-production",
                "name": "production-api",
                "type": "web_service",
                "environmentId": "env-production",
                "autoDeploy": "no",
            },
            "https://api.render.com/v1/environments/env-production": {
                "id": "env-production",
                "name": "production",
                "projectId": "proj-example",
            },
            "https://api.render.com/v1/services/srv-production/deploys/dep-previous": {
                "id": "dep-previous",
                "serviceId": "srv-production",
                "status": "deactivated",
                "commit": {"id": "abc123"},
            },
        }

        with patch.object(render_preflight, "resolve_provider_auth", return_value=self._configured_auth()), patch.object(
            render_preflight, "_get_json", side_effect=lambda url, headers=None: responses[url]
        ), patch.object(render_preflight, "_probe_url", return_value={"status": "passed", "http_status": 200}):
            payload = render_preflight.preflight(
                live=True,
                service_id="srv-production",
                environment_id="env-production",
                target_deploy_id="dep-previous",
                health_url="https://production.example.com/health",
                environment="production",
            )

        self.assertTrue(payload["preflight_passed"])
        self.assertEqual(payload["status"], "preflight_passed")
        self.assertFalse(payload["execution_allowed"])
        self.assertFalse(payload["write_attempted"])
        self.assertNotIn("test-render-token", json.dumps(payload))

    @staticmethod
    def _configured_auth():
        return render_preflight.AuthResolution(
            status="configured",
            credential="test-render-token",
            auth_source="secret_manager",
        )


if __name__ == "__main__":
    unittest.main()
