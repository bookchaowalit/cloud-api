#!/usr/bin/env python3
"""Offline contract tests for the free cloud/SaaS quota projection."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "adapters" / "free_quota.py"
SPEC = importlib.util.spec_from_file_location("free_quota", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {MODULE_PATH}")
free_quota = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(free_quota)


class FreeQuotaTest(unittest.TestCase):
    def test_catalog_is_projected_without_learning_resources(self):
        projection, errors = free_quota.build_projection(
            live=False,
            inventory={"providers": []},
            r2_usage={"status": "not_checked"},
        )

        self.assertEqual(errors, [])
        self.assertGreater(projection["summary"]["total"], 0)
        self.assertNotIn(
            "learning", {item["category"] for item in projection["services"]}
        )
        self.assertEqual(projection["summary"]["total"], len(projection["services"]))
        self.assertEqual(projection["summary"]["usage_available"], 0)
        self.assertEqual(
            projection["summary"]["reference_only"], projection["summary"]["total"]
        )
        self.assertRegex(projection["catalog_updated"], r"^\d{4}-\d{2}-\d{2}$")

    def test_r2_reports_observed_usage_and_remaining_free_quota(self):
        projection, errors = free_quota.build_projection(
            live=True,
            inventory={"providers": []},
            r2_usage={
                "status": "healthy",
                "storage_cost_estimate": {"standard": {"payload_gb": 3.5}},
            },
        )

        self.assertEqual(errors, [])
        r2 = next(
            item for item in projection["services"] if item["id"] == "cloudflare-r2"
        )
        self.assertEqual(r2["status"], "usage_available")
        self.assertEqual(r2["coverage"], "partial")
        self.assertEqual(r2["observed"]["used"], 3.5)
        self.assertEqual(r2["observed"]["remaining"], 6.5)
        self.assertEqual(r2["quota"]["limit"], 10)

    def test_failed_r2_never_becomes_zero_usage(self):
        projection, errors = free_quota.build_projection(
            live=True,
            inventory={"providers": []},
            r2_usage={"status": "error", "error_class": "http_404"},
        )

        self.assertEqual(errors, [])
        r2 = next(
            item for item in projection["services"] if item["id"] == "cloudflare-r2"
        )
        self.assertEqual(r2["status"], "unavailable")
        self.assertIsNone(r2["observed"])
        self.assertEqual(r2["status_reason"], "http_404")

    def test_github_actions_reports_minutes_without_guessing_unknown_plan(self):
        projection, errors = free_quota.build_projection(
            live=True,
            inventory={"providers": []},
            r2_usage={"status": "not_checked"},
            github_actions_usage={
                "status": "healthy",
                "actions_minutes": 75,
                "free_allowance": None,
            },
        )

        self.assertEqual(errors, [])
        actions = next(
            item for item in projection["services"] if item["id"] == "github-actions"
        )
        self.assertEqual(actions["status"], "reference_only")
        self.assertEqual(actions["coverage"], "partial")
        self.assertEqual(actions["status_reason"], "plan_allowance_unknown")
        self.assertEqual(actions["observed"]["used"], 75)
        self.assertIsNone(actions["observed"]["remaining"])
        self.assertIsNone(actions["quota"])

    def test_missing_catalog_is_an_explicit_error(self):
        with tempfile.TemporaryDirectory(prefix="solo-empire-free-quota-") as temp_dir:
            projection, errors = free_quota.build_projection(
                live=True,
                inventory={"providers": []},
                r2_usage={"status": "not_checked"},
                catalog_path=Path(temp_dir) / "missing.json",
            )

        self.assertEqual(projection["status"], "unavailable")
        self.assertEqual(projection["services"], [])
        self.assertEqual(errors[0]["source"], "free_resource_catalog")


if __name__ == "__main__":
    unittest.main()
