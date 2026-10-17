"""Fixture-backed management reads, bounded fan-out and output contracts."""

import json
import sys
import unittest
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters"))
from auth_resolver import AuthResolution
import cloud_read_adapters as adapters
from paas_inventory import run_inventory


def authenticated(_):
    return AuthResolution("configured", credential="fixture-key", auth_source="env")


def config(name):
    return (
        {
            "CLOUDFLARE_ACCOUNT_ID": "account1",
            "UPSTASH_EMAIL": "fixture@example.com",
        }.get(name),
        "env",
    )


class CloudReadAdaptersTest(unittest.TestCase):
    def collect(self, provider, fixture):
        calls = []

        def read(provider_id, path, headers):
            calls.append((provider_id, path))
            self.assertEqual(provider_id, provider)
            value = fixture[path]
            if isinstance(value, BaseException):
                raise value
            return value

        return adapters.collect_provider(
            provider,
            live=True,
            auth_resolver=authenticated,
            secret_getter=config,
            json_getter=read,
        ), calls

    def test_all_offline_adapters_never_resolve_auth_or_read_api(self):
        resolver = Mock()
        getter = Mock()
        for provider in adapters.READ_PROVIDERS:
            with self.subTest(provider=provider):
                report = adapters.collect_provider(
                    provider, auth_resolver=resolver, json_getter=getter
                )
                self.assertTrue(
                    all(
                        value["credential_state"] == "not_checked"
                        for value in report.values()
                    )
                )
        resolver.assert_not_called()
        getter.assert_not_called()

    def test_neon_projects_branches_and_billing_period_usage(self):
        report, calls = self.collect(
            "neon",
            {
                "/projects?limit=20": {
                    "projects": [{"id": "quiet-river", "name": "Fixture"}],
                    "pagination": {"cursor": "next"},
                },
                "/projects/quiet-river/branches?limit=20": {
                    "branches": [
                        {
                            "id": "br-one",
                            "name": "main",
                            "connection_uri": "PRIVATE_SENTINEL",
                        }
                    ]
                },
                "/projects/quiet-river": {
                    "project": {
                        "compute_time_seconds": 7200,
                        "synthetic_storage_size": 100,
                        "data_storage_bytes_hour": 2400,
                        "data_transfer_bytes": 40,
                        "consumption_period_start": "2026-06-01",
                        "consumption_period_end": "2026-07-01",
                        "cpu_used_sec": 999999,
                        "api_key": "PRIVATE_SENTINEL",
                    }
                },
            },
        )
        self.assertEqual(len(calls), 3)
        self.assertTrue(report["inventory"]["partial"])
        self.assertEqual(report["usage"]["projects"][0]["compute_hours"], 2)
        self.assertEqual(report["usage"]["projects"][0]["storage_byte_hours"], 2400)
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(report))

    def test_neon_detail_fanout_capped_and_missing_metrics_not_zero(self):
        fixture = {
            "/projects?limit=20": {
                "projects": [{"id": f"project-{i}"} for i in range(25)]
            }
        }
        for i in range(5):
            fixture[f"/projects/project-{i}/branches?limit=20"] = {"branches": []}
            fixture[f"/projects/project-{i}"] = {"project": {}}
        report, calls = self.collect("neon", fixture)
        self.assertEqual(len(calls), 11)
        self.assertEqual(report["inventory"]["returned"], 20)
        self.assertTrue(report["usage"]["partial"])
        self.assertIsNone(report["usage"]["projects"][0]["compute_hours"])
        self.assertFalse(report["inventory"]["total_known"])

    def test_cloudflare_metadata_only_and_production_deployment(self):
        report, _ = self.collect(
            "cloudflare",
            {
                "/accounts/account1/workers/scripts": {
                    "success": True,
                    "result": [{"id": "worker-one", "env": "PRIVATE_SENTINEL"}],
                },
                "/accounts/account1/pages/projects?page=1&per_page=20": {
                    "success": True,
                    "result_info": {"total_count": 2},
                    "result": [
                        {
                            "id": "pages-one",
                            "name": "site",
                            "env_vars": "PRIVATE_SENTINEL",
                            "canonical_deployment": {
                                "id": "deploy-1",
                                "created_on": "2026-06-29",
                                "latest_stage": {"status": "success"},
                            },
                        }
                    ],
                },
            },
        )
        self.assertEqual(report["inventory"]["returned"], 2)
        self.assertTrue(report["inventory"]["partial"])
        self.assertEqual(
            report["inventory"]["items"][1]["production_deployment"]["id"], "deploy-1"
        )
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(report))
        self.assertNotIn("usage", report)

    def test_cloudflare_http200_error_envelope_is_not_success(self):
        report, _ = self.collect(
            "cloudflare",
            {
                "/accounts/account1/workers/scripts": {
                    "success": False,
                    "errors": [{"message": "PRIVATE_SENTINEL"}],
                },
                "/accounts/account1/pages/projects?page=1&per_page=20": {
                    "success": True,
                    "result": [],
                },
            },
        )
        self.assertEqual(report["inventory"]["status"], "error")
        self.assertEqual(report["health"]["status"], "error")
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(report))

    def test_runpod_rates_not_billed_spend_and_desired_not_actual_state(self):
        report, _ = self.collect(
            "runpod",
            {
                "/pods": [
                    {
                        "id": "pod1",
                        "name": "GPU",
                        "desiredStatus": "RUNNING",
                        "costPerHr": 2,
                        "adjustedCostPerHr": 1.5,
                        "env": {"PRIVATE_SENTINEL": "PRIVATE_SENTINEL"},
                        "publicIp": "PRIVATE_SENTINEL",
                    }
                ],
                "/endpoints": [
                    {
                        "id": "endpoint1",
                        "name": "Inference",
                        "template": "PRIVATE_SENTINEL",
                    }
                ],
            },
        )
        self.assertEqual(report["usage"]["pods"][0]["credits_per_hour"], 1.5)
        self.assertEqual(report["usage"]["pods"][0]["desired_status"], "RUNNING")
        serialized = json.dumps(report)
        self.assertNotIn("PRIVATE_SENTINEL", serialized)
        self.assertNotIn("estimated_usd", serialized)
        self.assertNotIn("billing", report)

    def test_supabase_database_status_without_database_host_or_keys(self):
        report, calls = self.collect(
            "supabase",
            {
                "/projects": [
                    {
                        "id": "abcdefghijklmnopqrst",
                        "ref": "abcdefghijklmnopqrst",
                        "name": "DB",
                        "region": "ap-southeast-1",
                        "status": "ACTIVE_HEALTHY",
                        "database": {"host": "PRIVATE_SENTINEL"},
                        "keys": "PRIVATE_SENTINEL",
                    }
                ]
            },
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            report["inventory"]["items"][0]["database_status"], "ACTIVE_HEALTHY"
        )
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(report))
        self.assertNotIn("usage", report)

    def test_upstash_uses_developer_basic_auth_and_excludes_currency_guess(self):
        read = Mock(
            side_effect=[
                [
                    {
                        "database_id": "db1",
                        "database_name": "Cache",
                        "region": "global",
                        "state": "active",
                        "rest_token": "PRIVATE_SENTINEL",
                    }
                ],
                {
                    "total_monthly_requests": 10,
                    "current_storage": 5,
                    "total_monthly_billing": 123,
                    "rest_token": "PRIVATE_SENTINEL",
                },
            ]
        )
        report = adapters.collect_provider(
            "upstash",
            live=True,
            auth_resolver=authenticated,
            secret_getter=config,
            json_getter=read,
        )
        self.assertTrue(
            read.call_args_list[0].args[2]["Authorization"].startswith("Basic ")
        )
        self.assertEqual(report["usage"]["databases"][0]["monthly_requests"], 10)
        self.assertIsNone(report["usage"]["databases"][0]["monthly_bandwidth_bytes"])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(report))
        self.assertNotIn("total_monthly_billing", json.dumps(report))

    def test_usage_error_preserves_inventory_and_exposes_no_zero(self):
        report, _ = self.collect(
            "upstash",
            {
                "/redis/databases": [{"database_id": "db1"}],
                "/redis/stats/db1": adapters.CloudReadError("rate_limited"),
            },
        )
        self.assertEqual(report["inventory"]["status"], "healthy")
        self.assertEqual(report["usage"]["status"], "error")
        self.assertEqual(
            report["usage"]["errors"], [{"id": "db1", "error_class": "rate_limited"}]
        )

    def test_upstash_fanout_capped_and_no_claim_of_account_total(self):
        fixture = {"/redis/databases": [{"database_id": f"db{i}"} for i in range(21)]}
        for i in range(5):
            fixture[f"/redis/stats/db{i}"] = {"total_monthly_requests": i}
        report, calls = self.collect("upstash", fixture)
        self.assertEqual(len(calls), 6)
        self.assertEqual(report["inventory"]["returned"], 20)
        self.assertEqual(len(report["usage"]["databases"]), 5)
        self.assertTrue(report["usage"]["partial"])

    def test_malformed_list_invalid_ids_and_negative_usage_fail_explicitly(self):
        for fixture in (
            {"/projects": {}},
            {"/projects": [{"id": "../private"}]},
            {"/projects": [{"id": "db1", "name": {"value": "private"}}]},
        ):
            report, _ = self.collect("supabase", fixture)
            self.assertEqual(report["inventory"]["status"], "error")
        with self.assertRaises(adapters.CloudReadError):
            adapters._number(-1)
        with self.assertRaises(adapters.CloudReadError):
            adapters._number(float("nan"))

    def test_missing_auth_and_configuration_do_not_read_api(self):
        read = Mock()
        report = adapters.collect_provider(
            "neon",
            live=True,
            auth_resolver=lambda _: AuthResolution("not_configured"),
            json_getter=read,
        )
        self.assertEqual(report["inventory"]["status"], "not_configured")
        report = adapters.collect_provider(
            "cloudflare",
            live=True,
            auth_resolver=authenticated,
            secret_getter=lambda _: (None, None),
            json_getter=read,
        )
        self.assertEqual(
            report["inventory"]["error_class"], "required_configuration_missing"
        )
        read.assert_not_called()

    def test_inventory_surface_includes_new_adapters_offline(self):
        report = run_inventory(provider_id="supabase")
        self.assertEqual(
            [provider["id"] for provider in report["providers"]], ["supabase"]
        )
        self.assertEqual(report["providers"][0]["status"], "skipped")

    def test_transport_get_only_bounded_and_redirects_fail_closed(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"projects": []}'
        opener = Mock()
        opener.open.return_value = response
        with patch.object(adapters.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(
                adapters.get_json(
                    "neon", "/projects", {"Authorization": "Bearer fixture"}
                ),
                {"projects": []},
            )
        request = opener.open.call_args.args[0]
        self.assertEqual(request.method, "GET")
        response.read.assert_called_once_with(adapters.MAX_RESPONSE_BYTES + 1)
        redirect = urllib.error.HTTPError(
            "https://example.com",
            302,
            "PRIVATE_SENTINEL",
            {},
            BytesIO(b"PRIVATE_SENTINEL"),
        )
        opener.open.side_effect = redirect
        with patch.object(adapters.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(adapters.CloudReadError, "^redirect_blocked$"):
                adapters.get_json("neon", "/projects", {})
        with self.assertRaises(adapters.CloudReadError):
            adapters.get_json("neon", "//example.com", {})

    def test_transport_payload_limit_and_malformed_json_are_explicit_errors(self):
        for body, expected in (
            (b"x" * (adapters.MAX_RESPONSE_BYTES + 1), "response_too_large"),
            (b"not json", "invalid_payload"),
        ):
            with self.subTest(expected=expected):
                response = Mock()
                response.__enter__ = Mock(return_value=response)
                response.__exit__ = Mock(return_value=False)
                response.read.return_value = body
                opener = Mock()
                opener.open.return_value = response
                with patch.object(
                    adapters.urllib.request, "build_opener", return_value=opener
                ):
                    with self.assertRaisesRegex(
                        adapters.CloudReadError, f"^{expected}$"
                    ):
                        adapters.get_json("neon", "/projects", {})


if __name__ == "__main__":
    unittest.main()
