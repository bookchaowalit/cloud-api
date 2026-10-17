#!/usr/bin/env python3
"""Contract tests for the read-only GitHub Actions usage adapter."""

from __future__ import annotations

import importlib.util
import json
import urllib.error
import urllib.parse
import unittest
from datetime import datetime, UTC
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "adapters" / "github_actions_usage.py"
SPEC = importlib.util.spec_from_file_location("github_actions_usage", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {MODULE_PATH}")
github_actions_usage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(github_actions_usage)


class GitHubActionsUsageTest(unittest.TestCase):
    def test_offline_mode_does_not_read_secrets_or_call_provider(self):
        secret_getter = Mock(
            side_effect=AssertionError("offline must not resolve secrets")
        )
        env_getter = Mock(
            side_effect=AssertionError("offline must not read provider config")
        )
        fetcher = Mock(side_effect=AssertionError("offline must not call provider"))

        payload = github_actions_usage.run_usage(
            live=False,
            secret_getter=secret_getter,
            env_getter=env_getter,
            fetcher=fetcher,
        )

        self.assertEqual(payload["status"], "not_checked")
        self.assertEqual(payload["credential_state"], "not_checked")
        self.assertIsNone(payload["actions_minutes"])
        self.assertEqual(payload["next_action"], "run_live_check")
        secret_getter.assert_not_called()
        env_getter.assert_not_called()
        fetcher.assert_not_called()

    def test_user_report_aggregates_actions_and_plan_allowance_without_raw_records(
        self,
    ):
        secret_getter = Mock(return_value="github-secret-token")
        env_values = {
            "GITHUB_BILLING_OWNER_TYPE": "user",
            "GITHUB_BILLING_OWNER": None,
            "GITHUB_ACTIONS_PLAN": None,
        }
        env_getter = Mock(side_effect=lambda name: env_values.get(name))

        def fetcher(url, headers):
            self.assertEqual(headers, {"Authorization": "Bearer github-secret-token"})
            if url == "https://api.github.com/user":
                return {"login": "private-user", "plan": {"name": "Free"}}
            parsed = urllib.parse.urlparse(url)
            self.assertEqual(parsed.path, "/users/private-user/settings/billing/usage")
            self.assertEqual(
                urllib.parse.parse_qs(parsed.query), {"year": ["2026"], "month": ["9"]}
            )
            return {
                "usageItems": [
                    {
                        "product": "Actions",
                        "sku": "Actions Linux",
                        "unitType": "minutes",
                        "quantity": 120,
                    },
                    {
                        "product": "Actions",
                        "sku": "Actions Storage",
                        "unitType": "GB-Hours",
                        "quantity": 10.5,
                    },
                    {
                        "product": "Actions",
                        "sku": "Actions Cache Storage",
                        "unitType": "GB-Hours",
                        "grossQuantity": 2,
                    },
                    {
                        "product": "Other",
                        "sku": "Other",
                        "unitType": "minutes",
                        "quantity": 999,
                    },
                ]
            }

        payload = github_actions_usage.run_usage(
            live=True,
            secret_getter=secret_getter,
            env_getter=env_getter,
            fetcher=fetcher,
            now=datetime(2026, 9, 14, tzinfo=UTC),
        )

        self.assertEqual(payload["status"], "healthy")
        self.assertEqual(payload["credential_state"], "verified_read_only")
        self.assertEqual(payload["auth_source"], "secret_manager")
        self.assertEqual(payload["owner_type"], "user")
        self.assertFalse(payload["owner_configured"])
        self.assertEqual(payload["plan"], "free")
        self.assertEqual(payload["free_allowance"]["minutes"], 2000)
        self.assertEqual(payload["actions_minutes"], 120)
        self.assertEqual(payload["actions_artifact_storage_gb_hours"], 10.5)
        self.assertEqual(payload["actions_cache_storage_gb_hours"], 2)
        self.assertEqual(payload["actions_rows"], 3)
        self.assertEqual(payload["window"]["from"], "2026-09-01")
        self.assertEqual(payload["window"]["to"], "2026-09-30")
        self.assertEqual(payload["next_action"], "none")

        serialized = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("github-secret-token", serialized)
        self.assertNotIn("private-user", serialized)
        self.assertNotIn("Other", serialized)

    def test_cli_token_is_used_and_reported_without_exposing_it(self):
        auth = github_actions_usage.AuthResolution(
            status="configured",
            credential="github-cli-token",
            auth_source="cli_session",
        )
        fetcher = Mock(
            side_effect=[
                {"login": "private-user", "plan": {"name": "Free"}},
                {
                    "usageItems": [
                        {"product": "Actions", "unitType": "minutes", "quantity": 1}
                    ]
                },
            ]
        )
        with patch.object(
            github_actions_usage, "resolve_provider_auth", return_value=auth
        ) as resolver:
            payload = github_actions_usage.run_usage(
                live=True,
                env_getter=Mock(return_value=None),
                fetcher=fetcher,
                now=datetime(2026, 9, 14, tzinfo=UTC),
            )

        resolver.assert_called_once_with(github_actions_usage.GITHUB_PROVIDER)
        self.assertEqual(payload["status"], "healthy")
        self.assertEqual(payload["auth_source"], "cli_session")
        self.assertEqual(
            fetcher.call_args_list[0].args[1]["Authorization"],
            f"Bearer {auth.credential}",
        )
        self.assertNotIn(auth.credential, json.dumps(payload))

    def test_cli_session_without_token_does_not_call_billing_api(self):
        auth = github_actions_usage.AuthResolution(
            status="configured", auth_source="cli_session"
        )
        fetcher = Mock(
            side_effect=AssertionError("billing API must not be called without a token")
        )
        with patch.object(
            github_actions_usage, "resolve_provider_auth", return_value=auth
        ):
            payload = github_actions_usage.run_usage(
                live=True,
                env_getter=Mock(return_value=None),
                fetcher=fetcher,
            )

        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_class"], "cli_session_token_unavailable")
        self.assertEqual(payload["auth_source"], "cli_session")
        fetcher.assert_not_called()

    def test_organization_requires_owner_without_calling_provider(self):
        fetcher = Mock(
            side_effect=AssertionError("missing owner must fail before provider call")
        )
        env_values = {
            "GITHUB_BILLING_OWNER_TYPE": "organization",
            "GITHUB_BILLING_OWNER": None,
            "GITHUB_ACTIONS_PLAN": None,
        }
        payload = github_actions_usage.run_usage(
            live=True,
            secret_getter=Mock(return_value="token"),
            env_getter=Mock(side_effect=lambda name: env_values.get(name)),
            fetcher=fetcher,
        )

        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_class"], "missing_billing_owner")
        self.assertEqual(payload["next_action"], "configure_github_billing_owner")
        fetcher.assert_not_called()

    def test_billing_forbidden_is_sanitized(self):
        error = urllib.error.HTTPError(
            "https://api.github.com/users/user/settings/billing/usage",
            403,
            "private provider body",
            {},
            None,
        )

        def fetcher(url, headers):
            if url == "https://api.github.com/user":
                return {"login": "user", "plan": {"name": "Free"}}
            raise error

        payload = github_actions_usage.run_usage(
            live=True,
            secret_getter=Mock(return_value="token"),
            env_getter=Mock(side_effect=lambda name: None),
            fetcher=fetcher,
        )

        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_class"], "github_billing_forbidden")
        self.assertEqual(payload["next_action"], "verify_github_billing_scope")
        self.assertNotIn("private provider body", json.dumps(payload))
        error.close()


if __name__ == "__main__":
    unittest.main()
