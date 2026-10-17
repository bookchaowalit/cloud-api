#!/usr/bin/env python3
"""Contract tests for the centralized cloud provider registry."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "adapters" / "cloud_providers.py"
SPEC = importlib.util.spec_from_file_location("cloud_providers", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {MODULE_PATH}")
cloud_providers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cloud_providers)


class CloudProviderRegistryTest(unittest.TestCase):
    def test_registry_covers_integrated_and_planned_providers(self):
        registry = cloud_providers.load_registry()
        providers = {provider["id"]: provider for provider in registry["providers"]}

        self.assertEqual(
            set(providers),
            {
                "cloudflare",
                "github",
                "vercel",
                "render",
                "railway",
                "fly-io",
                "heroku",
                "neon",
                "runpod",
                "supabase",
                "upstash",
                "infisical",
                "sentry",
                "posthog",
                "gcp",
                "azure",
                "aws",
            },
        )
        for provider in providers.values():
            self.assertEqual(
                set(provider["capabilities"]),
                {"health", "inventory", "usage", "billing"},
            )
            self.assertEqual(provider["write_policy"], "proposal_only")
        self.assertFalse(registry["read_only_by_default"] is False)
        self.assertFalse(registry["write_actions_enabled"])
        self.assertEqual(registry["write_entrypoint"], "paas:action:propose")

    def test_project_usage_distinguishes_evidence_from_live_deployments(self):
        providers = {
            provider["id"]: provider
            for provider in cloud_providers.load_registry()["providers"]
        }
        railway = providers["railway"]["project_usage"][0]
        runpod = providers["runpod"]["project_usage"][0]
        self.assertEqual(railway["status"], "adapter_only")
        self.assertEqual(runpod["status"], "control_only")
        self.assertIn("no deployed project", railway["note"])

    def test_validator_rejects_duplicate_ids_and_direct_write_policy(self):
        registry = cloud_providers.load_registry()
        duplicate = copy.deepcopy(registry)
        duplicate["providers"][1]["id"] = duplicate["providers"][0]["id"]
        self.assertTrue(
            any(
                "duplicate provider id" in error
                for error in cloud_providers.validate_registry(duplicate)
            )
        )

        unsafe_write = copy.deepcopy(registry)
        unsafe_write["providers"][0]["write_policy"] = "direct"
        self.assertTrue(
            any(
                "write_policy must be proposal_only" in error
                for error in cloud_providers.validate_registry(unsafe_write)
            )
        )

    def test_auth_names_are_registry_driven(self):
        github = next(
            provider
            for provider in cloud_providers.load_registry()["providers"]
            if provider["id"] == "github"
        )
        self.assertEqual(
            cloud_providers.auth_env_names(github),
            ["GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TOKEN"],
        )
        self.assertEqual(
            cloud_providers.secret_names(github),
            ["GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TOKEN"],
        )


if __name__ == "__main__":
    unittest.main()
