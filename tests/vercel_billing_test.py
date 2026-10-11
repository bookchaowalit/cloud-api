#!/usr/bin/env python3
"""Contract tests for the read-only Vercel billing adapter."""

from __future__ import annotations

import importlib.util
import json
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "adapters" / "vercel_billing.py"
SPEC = importlib.util.spec_from_file_location("vercel_billing", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {MODULE_PATH}")
vercel_billing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vercel_billing)


class VercelBillingTest(unittest.TestCase):
    def test_offline_mode_does_not_read_secrets_or_call_provider(self):
        secret_getter = Mock(side_effect=AssertionError("offline must not resolve secrets"))
        env_getter = Mock(side_effect=AssertionError("offline must not read provider scope"))
        fetcher = Mock(side_effect=AssertionError("offline must not call provider"))

        payload = vercel_billing.run_billing(
            live=False,
            secret_getter=secret_getter,
            env_getter=env_getter,
            fetcher=fetcher,
        )

        self.assertEqual(payload["status"], "not_checked")
        self.assertEqual(payload["credential_state"], "not_checked")
        self.assertFalse(payload["billing_connected"])
        self.assertEqual(payload["focus_version"], "1.3")
        self.assertEqual(payload["response_format"], "jsonl")
        self.assertEqual(payload["required_secret_names"], ["VERCEL_TOKEN"])
        self.assertEqual(payload["next_action"], "run_live_check")
        secret_getter.assert_not_called()
        env_getter.assert_not_called()
        fetcher.assert_not_called()

    def test_live_mode_aggregates_allow_listed_focus_costs_without_raw_records(self):
        secret_getter = Mock(return_value="vercel-secret-token")
        env_values = {"VERCEL_TEAM_ID": "team_123", "VERCEL_TEAM_SLUG": "solo-team"}
        env_getter = Mock(side_effect=lambda name: env_values.get(name))
        records = [
            {
                "BillingAccountId": "private-account-id",
                "ResourceId": "private-resource-id",
                "Tags": {"private": "value"},
                "BillingCurrency": "USD",
                "ServiceName": "Vercel Functions",
                "ChargeCategory": "Usage",
                "BilledCost": "12.50",
                "EffectiveCost": "11.75",
            },
            {
                "BillingCurrency": "USD",
                "ServiceName": "Vercel Functions",
                "ChargeCategory": "Usage",
                "BilledCost": -1.25,
                "EffectiveCost": -1.25,
            },
            {
                "BillingCurrency": "EUR",
                "ServiceName": "Vercel Blob",
                "ChargeCategory": "Usage",
                "BilledCost": 4,
                "EffectiveCost": 4,
            },
        ]
        fetcher = Mock(return_value=[json.dumps(record) for record in records])

        payload = vercel_billing.run_billing(
            live=True,
            from_date="2026-09-01",
            to_date="2026-10-01",
            secret_getter=secret_getter,
            env_getter=env_getter,
            fetcher=fetcher,
        )

        self.assertEqual(payload["status"], "healthy")
        self.assertEqual(payload["credential_state"], "verified_read_only")
        self.assertEqual(payload["auth_source"], "secret_manager")
        self.assertTrue(payload["billing_connected"])
        self.assertEqual(payload["account_scope"], "configured_team")
        self.assertTrue(payload["team_scope_configured"])
        self.assertEqual(payload["billing_access_scope"], "pro_or_enterprise_team")
        self.assertEqual(payload["next_action"], "none")
        self.assertEqual(payload["window"], {"from": "2026-09-01T00:00:00.000Z", "to": "2026-10-01T00:00:00.000Z"})
        self.assertEqual(payload["charge_count"], 3)
        self.assertEqual(payload["billed_cost_by_currency"], {"EUR": 4.0, "USD": 11.25})
        self.assertEqual(payload["effective_cost_by_currency"], {"EUR": 4.0, "USD": 10.5})
        self.assertEqual(len(payload["service_breakdown"]), 2)
        functions = next(row for row in payload["service_breakdown"] if row["service_name"] == "Vercel Functions")
        self.assertEqual(functions["charge_count"], 2)
        self.assertEqual(functions["billed_cost"], 11.25)
        self.assertEqual(functions["effective_cost"], 10.5)

        fetcher.assert_called_once()
        called_url, called_headers = fetcher.call_args.args
        parsed = urllib.parse.urlparse(called_url)
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(parsed.path, "/v1/billing/charges")
        self.assertEqual(query["teamId"], ["team_123"])
        self.assertEqual(query["slug"], ["solo-team"])
        self.assertEqual(query["from"], ["2026-09-01T00:00:00.000Z"])
        self.assertEqual(query["to"], ["2026-10-01T00:00:00.000Z"])
        self.assertEqual(called_headers, {"Authorization": "Bearer vercel-secret-token"})

        serialized = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("vercel-secret-token", serialized)
        self.assertNotIn("private-account-id", serialized)
        self.assertNotIn("private-resource-id", serialized)
        self.assertNotIn("private", serialized)
        self.assertNotIn("BillingAccountId", serialized)

    def test_cli_session_without_api_token_does_not_call_provider(self):
        auth = vercel_billing.AuthResolution(status="configured", auth_source="cli_session")
        fetcher = Mock(side_effect=AssertionError("billing API must not be called without an API token"))
        with patch.object(vercel_billing, "resolve_provider_auth", return_value=auth):
            payload = vercel_billing.run_billing(
                live=True,
                env_getter=Mock(return_value=None),
                fetcher=fetcher,
            )

        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["credential_state"], "error")
        self.assertEqual(payload["error_class"], "cli_session_token_unavailable")
        self.assertEqual(payload["auth_source"], "cli_session")
        fetcher.assert_not_called()

    def test_missing_token_does_not_call_provider(self):
        fetcher = Mock()
        payload = vercel_billing.run_billing(
            live=True,
            secret_getter=Mock(return_value=None),
            env_getter=Mock(return_value=None),
            fetcher=fetcher,
        )

        self.assertEqual(payload["status"], "not_configured")
        self.assertEqual(payload["error_class"], "credentials_not_configured")
        self.assertEqual(payload["next_action"], "configure_vercel_token")
        self.assertFalse(payload["billing_connected"])
        fetcher.assert_not_called()

    def test_secret_provider_failure_is_sanitized_and_actionable(self):
        SecretResolutionError = type("SecretResolutionError", (RuntimeError,), {})
        payload = vercel_billing.run_billing(
            live=True,
            secret_getter=Mock(side_effect=SecretResolutionError("private provider details")),
            env_getter=Mock(return_value=None),
            fetcher=Mock(side_effect=AssertionError("provider must not be called")),
        )

        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["credential_state"], "error")
        self.assertEqual(payload["error_class"], "secret_provider_unreachable")
        self.assertEqual(payload["next_action"], "restore_secret_provider_session")
        self.assertNotIn("private provider details", json.dumps(payload))

    def test_invalid_jsonl_fails_closed_without_returning_provider_content(self):
        payload = vercel_billing.run_billing(
            live=True,
            secret_getter=Mock(return_value="token"),
            env_getter=Mock(return_value=None),
            fetcher=Mock(return_value=['{"BillingCurrency":"USD","BilledCost":1}', "not-json"]),
        )

        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_class"], "invalid_focus_jsonl")
        self.assertEqual(payload["charge_count"], 0)
        self.assertNotIn("not-json", json.dumps(payload))

    def test_invalid_scope_is_rejected_before_provider_call(self):
        fetcher = Mock()
        env_values = {"VERCEL_TEAM_ID": "team/with-invalid-slash", "VERCEL_TEAM_SLUG": None}
        payload = vercel_billing.run_billing(
            live=True,
            secret_getter=Mock(return_value="token"),
            env_getter=Mock(side_effect=lambda name: env_values.get(name)),
            fetcher=fetcher,
        )

        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_class"], "invalid_team_scope")
        fetcher.assert_not_called()


if __name__ == "__main__":
    unittest.main()
