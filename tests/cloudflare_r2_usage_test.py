#!/usr/bin/env python3
"""Contract tests for the read-only Cloudflare R2 metrics adapter."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "adapters" / "cloudflare_r2_usage.py"
SPEC = importlib.util.spec_from_file_location("cloudflare_r2_usage", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {MODULE_PATH}")
cloudflare_r2_usage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cloudflare_r2_usage)


class CloudflareR2UsageTest(unittest.TestCase):
    def test_offline_mode_does_not_read_secrets_or_call_provider(self):
        secret_getter = Mock(
            side_effect=AssertionError("offline must not resolve secrets")
        )
        fetcher = Mock(side_effect=AssertionError("offline must not call provider"))

        payload = cloudflare_r2_usage.run_metrics(
            live=False,
            secret_getter=secret_getter,
            fetcher=fetcher,
        )

        self.assertEqual(payload["status"], "not_checked")
        self.assertEqual(payload["credential_state"], "not_checked")
        self.assertFalse(payload["billing_connected"])
        self.assertEqual(payload["storage_cost_estimate"]["status"], "not_checked")
        secret_getter.assert_not_called()
        fetcher.assert_not_called()

    def test_live_mode_normalizes_aggregate_metrics_without_raw_payload(self):
        secret_values = {
            "CLOUDFLARE_API_TOKEN": "secret-token-value",
            "CLOUDFLARE_ACCOUNT_ID": "0123456789abcdef0123456789abcdef",
        }
        secret_getter = Mock(side_effect=lambda name: secret_values[name])
        fetcher = Mock(
            return_value={
                "success": True,
                "result": {
                    "standard": {
                        "published": {
                            "metadataSize": 100,
                            "objects": 2,
                            "payloadSize": 12_000_000_000,
                        },
                        "uploaded": {
                            "metadataSize": 10,
                            "objects": 1,
                            "payloadSize": 512,
                        },
                    },
                    "infrequentAccess": {
                        "published": {
                            "metadataSize": 50,
                            "objects": 3,
                            "payloadSize": 3_000_000_000,
                        },
                        "uploaded": {
                            "metadataSize": 5,
                            "objects": 1,
                            "payloadSize": 256,
                        },
                    },
                },
            }
        )

        payload = cloudflare_r2_usage.run_metrics(
            live=True,
            secret_getter=secret_getter,
            fetcher=fetcher,
        )

        self.assertEqual(payload["status"], "healthy")
        self.assertEqual(payload["credential_state"], "verified_read_only")
        self.assertEqual(payload["object_count"], 5)
        self.assertEqual(payload["payload_bytes"], 15_000_000_000)
        self.assertEqual(payload["uploaded_object_count"], 2)
        self.assertEqual(
            payload["storage_classes"]["standard"]["published"]["object_count"], 2
        )
        self.assertEqual(
            payload["storage_classes"]["infrequent_access"]["published"][
                "payload_bytes"
            ],
            3_000_000_000,
        )
        self.assertFalse(payload["billing_connected"])
        estimate = payload["storage_cost_estimate"]
        self.assertEqual(estimate["status"], "estimate_only")
        self.assertEqual(estimate["standard"]["billable_gb_month"], 2.0)
        self.assertEqual(estimate["infrequent_access"]["billable_gb_month"], 3.0)
        self.assertEqual(estimate["estimated_usd"], 0.06)
        self.assertFalse(estimate["includes_operations"])
        fetcher.assert_called_once()
        called_url, called_headers = fetcher.call_args.args
        self.assertEqual(
            called_url,
            "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/r2/metrics",
        )
        self.assertEqual(called_headers, {"Authorization": "Bearer secret-token-value"})

        serialized = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("secret-token-value", serialized)
        self.assertNotIn("0123456789abcdef0123456789abcdef", serialized)
        self.assertNotIn("bucket-name", serialized)
        self.assertNotIn("payloadSize", serialized)

    def test_missing_credentials_is_not_configured_and_does_not_call_provider(self):
        fetcher = Mock()
        payload = cloudflare_r2_usage.run_metrics(
            live=True,
            secret_getter=Mock(return_value=None),
            fetcher=fetcher,
        )

        self.assertEqual(payload["status"], "not_configured")
        self.assertEqual(payload["error_class"], "credentials_not_configured")
        self.assertEqual(payload["storage_cost_estimate"]["status"], "unavailable")
        fetcher.assert_not_called()

    def test_secret_provider_failure_uses_public_error_class(self):
        SecretResolutionError = type("SecretResolutionError", (RuntimeError,), {})
        payload = cloudflare_r2_usage.run_metrics(
            live=True,
            secret_getter=Mock(side_effect=SecretResolutionError("private details")),
            fetcher=Mock(side_effect=AssertionError("provider must not be called")),
        )

        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_class"], "secret_provider_unreachable")
        self.assertNotIn("private details", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
