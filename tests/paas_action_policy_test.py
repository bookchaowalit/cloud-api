#!/usr/bin/env python3
"""Contract tests for governed PaaS actions and approval binding."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import tempfile
import unittest
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "adapters" / "paas_action.py"
SPEC = importlib.util.spec_from_file_location("paas_action", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {MODULE_PATH}")
paas_action = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(paas_action)

import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "tests" / "support"))
from sqlite_decision_store import SqliteDecisionStore, apply_legacy_decision_tables  # noqa: E402


def proposal_args(**overrides):
    values = {
        "provider": "render",
        "action": "rollback",
        "resource_type": "service",
        "resource_id": "srv-test",
        "environment": "production",
        "environment_id": "evm-test",
        "health_path": "/health",
        "target_revision": None,
        "rollback_target": "deploy-previous",
        "reason": "Verified production incident recovery",
        "approval_id": None,
        "register": False,
        "confirm_register": False,
        "json": True,
    }
    values.update(overrides)
    return Namespace(**values)


def create_decision_db(path: Path):
    """A temporary SQLite file with the legacy decision tables for the store test double."""
    conn = sqlite3.connect(path)
    apply_legacy_decision_tables(conn)
    SqliteDecisionStore(conn)  # adds the version column the double uses for optimistic concurrency
    conn.commit()
    conn.close()


def decisions_at(path: Path):
    """A drop-in for ``open_decision_store`` over ``path`` (a fresh connection per call, like the API)."""
    return lambda *_args, **_kwargs: SqliteDecisionStore(sqlite3.connect(path, timeout=10))


class PaaSActionPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = paas_action.load_policy()

    def test_policy_enables_only_reviewed_render_adapter(self):
        self.assertTrue(self.policy["execution_enabled"])
        self.assertTrue(self.policy["mutating_requests_enabled"])
        self.assertEqual(paas_action.approval_max_age_seconds(self.policy), 3600)
        for provider in self.policy["providers"]:
            if provider["id"] != "render":
                self.assertNotIn("render-v1", [spec["adapter"] for spec in provider["actions"].values()])
        providers = {provider["id"]: provider for provider in self.policy["providers"]}
        self.assertEqual(set(providers), {"vercel", "render", "railway", "fly-io", "heroku"})
        self.assertEqual(set(providers["render"]["actions"]), {"deploy", "restart", "rollback", "set-auto-deploy"})
        self.assertTrue(all(set(provider["actions"]) == {"deploy", "restart", "rollback"}
                            for provider in providers.values() if provider["id"] != "render"))
        self.assertEqual(providers["vercel"]["actions"]["restart"]["support"], "unsupported")
        self.assertEqual(providers["fly-io"]["actions"]["deploy"]["support"], "manual")

    def test_proposal_never_attempts_external_write(self):
        proposal = paas_action.build_proposal(proposal_args(), self.policy)
        self.assertEqual(proposal["status"], "blocked")
        self.assertEqual(proposal["external_calls"], 0)
        self.assertFalse(proposal["write_attempted"])
        self.assertIn("approval-id-required", proposal["blockers"])
        self.assertNotIn("write-actions-disabled", proposal["blockers"])
        self.assertNotIn("token", json.dumps(proposal).lower())

    def test_set_auto_deploy_is_bounded_and_does_not_require_health_path(self):
        proposal = paas_action.build_proposal(
            proposal_args(action="set-auto-deploy", rollback_target=None, health_path=None, auto_deploy="no"),
            self.policy,
        )
        self.assertIn("approval-id-required", proposal["blockers"])
        self.assertNotIn("health-path-required", proposal["blockers"])
        self.assertNotIn("auto-deploy-state-required", proposal["blockers"])
        self.assertEqual(proposal["request"]["auto_deploy"], "no")

    def test_set_auto_deploy_rejects_other_states(self):
        with self.assertRaisesRegex(ValueError, "auto_deploy must be yes or no"):
            paas_action.build_proposal(
                proposal_args(action="set-auto-deploy", rollback_target=None, health_path=None, auto_deploy="maybe"),
                self.policy,
            )

    def test_register_and_approval_bind_to_exact_fingerprint(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "decisions.db"
            create_decision_db(db_path)
            with patch.object(paas_action, "open_decision_store", decisions_at(db_path)):
                proposal = paas_action.build_proposal(proposal_args(), self.policy)
                registration = paas_action.register_proposal(proposal)
                self.assertTrue(registration["created"])

                pending = paas_action.check_approval(registration["decision_id"], proposal["proposal_id"])
                self.assertFalse(pending["valid"])

                conn = sqlite3.connect(db_path)
                conn.execute(
                    "UPDATE decision_records SET status='approved', approval_status='approved', action_status='queued' WHERE id=?",
                    (registration["decision_id"],),
                )
                conn.commit()
                conn.close()

                approved = paas_action.check_approval(registration["decision_id"], proposal["proposal_id"])
                self.assertTrue(approved["valid"])
                mismatched = paas_action.check_approval(registration["decision_id"], "paas-proposal:other")
                self.assertFalse(mismatched["valid"])

    def test_expired_approval_requires_fresh_review(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "decisions.db"
            create_decision_db(db_path)
            with patch.object(paas_action, "open_decision_store", decisions_at(db_path)):
                proposal = paas_action.build_proposal(proposal_args(), self.policy)
                registration = paas_action.register_proposal(proposal)
                expired_at = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
                conn = sqlite3.connect(db_path)
                conn.execute(
                    """
                    UPDATE decision_records
                    SET status='approved', approval_status='approved', action_status='queued',
                        decided_at=?, updated_at=?
                    WHERE id=?
                    """,
                    (expired_at, expired_at, registration["decision_id"]),
                )
                conn.commit()
                conn.close()

                approval = paas_action.check_approval(registration["decision_id"], proposal["proposal_id"])
                self.assertFalse(approval["valid"])
                self.assertEqual(approval["error"], "approval-expired")
                self.assertFalse(approval["checks"]["approval_fresh"])

                blocked = paas_action.build_proposal(
                    proposal_args(approval_id=registration["decision_id"]), self.policy
                )
                self.assertIn("approval-expired", blocked["blockers"])


if __name__ == "__main__":
    unittest.main()
