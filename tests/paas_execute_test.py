#!/usr/bin/env python3
"""Execution gates, replay prevention, and provider response verification."""
import json
import sys
import tempfile
import unittest
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters"))
import paas_execute as execution
import sqlite3  # noqa: E402

from paas_action_policy_test import create_decision_db, decisions_at

DB = {"path": None}  # the current test's SQLite file (the decisions store double reads the same file)


@contextmanager
def database_connection():
    conn = sqlite3.connect(DB["path"], timeout=10)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


class ExecutionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "test.db"
        create_decision_db(self.path)
        DB["path"] = self.path
        self.db_patch = patch.object(execution.actions, "open_decision_store", decisions_at(self.path))
        self.db_patch.start()
        self.exec_patch = patch.object(execution, "open_decision_store", decisions_at(self.path))
        self.exec_patch.start()
        self.request = {"provider": "render", "action": "deploy", "resource_type": "service",
                        "resource_id": "srv-test", "environment": "staging", "environment_id": "evm-test",
                        "health_path": "/health", "target_revision": "a" * 40,
                        "rollback_target": None, "reason": "Publish tested revision"}
        self.record = execution.dispatch({"operation": "register", "request": self.request})
        self.id = self.record["decision_id"]
        self.adapter = Mock()
        self.adapter.preflight.return_value = {"previous_deploy_id": "dep-old"}
        self.adapter.submit.return_value = {"id": "dep-new", "private_payload": "must-not-escape"}
        self.adapter.verify.return_value = "succeeded"

    def tearDown(self):
        self.exec_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()

    def approve(self):
        execution.approve(self.id, self.record["proposal_id"])

    def test_unapproved_never_resolves_credentials_or_calls_provider(self):
        factory = Mock()
        with self.assertRaisesRegex(execution.GateError, "approval-invalid"):
            execution.execute(self.id, factory)
        factory.assert_not_called()

    def test_review_must_match_exact_proposal(self):
        with self.assertRaisesRegex(execution.GateError, "reviewed-proposal-mismatch"):
            execution.approve(self.id, "paas-proposal:other")

    def test_dedupe_registration(self):
        again = execution.dispatch({"operation": "register", "request": self.request})
        self.assertEqual(again["decision_id"], self.id)

    def test_operation_id_allows_an_intentional_new_round(self):
        again = execution.dispatch({"operation": "register", "request": {**self.request, "operation_id": "round-2"}})
        self.assertNotEqual(again["decision_id"], self.id)
        self.assertEqual(again["request"]["operation_id"], "round-2")

    def test_full_lifecycle_and_duplicate_execution(self):
        self.approve()
        result = execution.execute(self.id, lambda: self.adapter)
        self.assertEqual(result["attempt"]["status"], "pending")
        self.assertNotIn("must-not-escape", json.dumps(result))
        result = execution.verify(self.id, lambda: self.adapter)
        self.assertEqual(result["action_status"], "executed")
        self.assertEqual(result["attempt"]["status"], "succeeded")
        with self.assertRaises(execution.GateError):
            execution.execute(self.id, lambda: self.adapter)
        self.adapter.submit.assert_called_once()

    def test_set_auto_deploy_lifecycle_verifies_without_deploy_id(self):
        request = {**self.request, "action": "set-auto-deploy", "health_path": None,
                   "target_revision": None, "rollback_target": None, "auto_deploy": "no"}
        record = execution.dispatch({"operation": "register", "request": request})
        execution.approve(record["decision_id"], record["proposal_id"])
        self.adapter.preflight.return_value = {
            "previous_auto_deploy": "yes", "requested_auto_deploy": "no"
        }
        self.adapter.submit.return_value = {"id": "srv-test", "autoDeploy": "no"}
        result = execution.execute(record["decision_id"], lambda: self.adapter)
        self.assertEqual(result["attempt"]["status"], "pending")
        result = execution.verify(record["decision_id"], lambda: self.adapter)
        self.assertEqual(result["action_status"], "executed")
        self.assertEqual(result["attempt"]["status"], "succeeded")
        self.adapter.verify.assert_called_once()

    def test_timeout_is_unknown_and_never_retried_even_if_requeued(self):
        self.approve()
        self.adapter.submit.side_effect = TimeoutError("credential-and-private-response")
        result = execution.execute(self.id, lambda: self.adapter)
        self.assertEqual(result["attempt"]["status"], "submission_unknown")
        self.assertNotIn("credential-and-private-response", json.dumps(result))
        with database_connection() as conn:
            conn.execute("UPDATE decision_records SET action_status='queued' WHERE id=?", (self.id,))
        with self.assertRaises(execution.GateError):
            execution.execute(self.id, lambda: self.adapter)
        self.adapter.submit.assert_called_once()

    def test_approval_revoked_during_preflight_blocks_write(self):
        self.approve()
        def revoke(_):
            with database_connection() as conn:
                conn.execute("UPDATE decision_records SET approval_status='rejected' WHERE id=?", (self.id,))
            return {"previous_deploy_id": "dep-old"}
        self.adapter.preflight.side_effect = revoke
        with self.assertRaisesRegex(execution.GateError, "approval-invalid"):
            execution.execute(self.id, lambda: self.adapter)
        self.adapter.submit.assert_not_called()

    def test_expired_approval_blocks_before_provider_preflight(self):
        self.approve()
        expired_at = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        with database_connection() as conn:
            conn.execute(
                "UPDATE decision_records SET decided_at=?, updated_at=? WHERE id=?",
                (expired_at, expired_at, self.id),
            )
        with self.assertRaisesRegex(execution.GateError, "approval-expired"):
            execution.execute(self.id, lambda: self.adapter)
        self.adapter.preflight.assert_not_called()
        self.adapter.submit.assert_not_called()

    def test_two_executors_can_only_submit_once(self):
        self.approve()
        barrier = Barrier(2)
        def preflight(_):
            barrier.wait(timeout=3)
            return {"previous_deploy_id": "dep-old"}
        self.adapter.preflight.side_effect = preflight
        def run():
            try:
                execution.execute(self.id, lambda: self.adapter)
                return "submitted"
            except execution.GateError:
                return "blocked"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: run(), range(2)))
        self.assertEqual(sorted(results), ["blocked", "submitted"])
        self.adapter.submit.assert_called_once()

    def test_failed_preflight_does_not_consume_approval(self):
        self.approve()
        self.adapter.preflight.side_effect = execution.GateError("environment-mismatch")
        with self.assertRaises(execution.GateError):
            execution.execute(self.id, lambda: self.adapter)
        self.assertIsNone(execution.snapshot(self.id)["attempt"])
        self.adapter.submit.assert_not_called()

    def test_no_deploy_id_cannot_claim_success(self):
        self.approve()
        self.adapter.submit.return_value = {}
        result = execution.execute(self.id, lambda: self.adapter)
        self.assertEqual(result["attempt"]["status"], "verification_required")
        execution.verify(self.id, lambda: self.adapter)
        self.adapter.verify.assert_not_called()

    def test_reconcile_resolves_ambiguous_submission_without_resubmit(self):
        self.approve()
        self.adapter.submit.return_value = {}
        self.adapter.reconcile.return_value = "succeeded"
        result = execution.execute(self.id, lambda: self.adapter)
        self.assertEqual(result["attempt"]["status"], "verification_required")
        result = execution.reconcile(self.id, lambda: self.adapter)
        self.assertEqual(result["action_status"], "executed")
        self.assertEqual(result["attempt"]["status"], "succeeded")
        self.adapter.submit.assert_called_once()
        self.adapter.reconcile.assert_called_once()

    def test_distinct_decisions_for_one_resource_are_serialized(self):
        second = execution.dispatch({"operation": "register", "request": {**self.request, "operation_id": "round-2"}})
        self.approve()
        execution.approve(second["decision_id"], second["proposal_id"])
        barrier = Barrier(2)

        def preflight(_):
            barrier.wait(timeout=3)
            return {"previous_deploy_id": "dep-old"}

        self.adapter.preflight.side_effect = preflight

        def run(decision_id):
            try:
                execution.execute(decision_id, lambda: self.adapter)
                return "submitted"
            except execution.GateError as exc:
                return str(exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, [self.id, second["decision_id"]]))
        self.assertEqual(results.count("submitted"), 1)
        self.assertEqual(results.count("resource-operation-in-progress"), 1)
        self.adapter.submit.assert_called_once()

    def test_wrapped_submission_id_is_bounded(self):
        self.approve()
        self.adapter.submit.return_value = {"deploy": {"id": "dep-new", "private": "hidden"}}
        result = execution.execute(self.id, lambda: self.adapter)
        self.assertEqual(result["attempt"]["provider_action_id"], "dep-new")
        self.assertNotIn("hidden", json.dumps(result))

    def test_provider_read_failure_keeps_pending_without_resubmit(self):
        self.approve()
        execution.execute(self.id, lambda: self.adapter)
        self.adapter.verify.side_effect = TimeoutError()
        result = execution.verify(self.id, lambda: self.adapter)
        self.assertEqual(result["attempt"]["status"], "pending")
        self.adapter.submit.assert_called_once()

    def test_disabled_policy_has_no_external_calls(self):
        self.approve()
        policy = execution.actions.load_policy()
        policy["execution_enabled"] = False
        with patch.object(execution.actions, "load_policy", return_value=policy):
            with self.assertRaisesRegex(execution.GateError, "execution-disabled"):
                execution.execute(self.id, lambda: self.adapter)
        self.adapter.preflight.assert_not_called()

    def test_validation_rejects_traversal_and_arbitrary_health_targets(self):
        for field, value in (("resource_id", "srv-test/../other"), ("health_path", "//evil.example"),
                             ("health_path", "/health?token=x"), ("target_revision", "main"),
                             ("provider", "heroku")):
            with self.subTest(field=field), self.assertRaises(execution.GateError):
                execution.validate({**self.request, field: value})

    def test_confirmation_required(self):
        with self.assertRaisesRegex(execution.GateError, "explicit-confirmation-required"):
            execution.dispatch({"operation": "execute", "decision_id": self.id})


class RenderAdapterTest(unittest.TestCase):
    def setUp(self):
        self.render = execution.Render.__new__(execution.Render)
        self.render.call = Mock()
        self.request = {"provider": "render", "action": "deploy", "resource_type": "service",
                        "resource_id": "srv-test", "environment": "staging", "environment_id": "evm-test",
                        "health_path": "/health", "target_revision": "a" * 40, "rollback_target": "dep-old"}
        self.service = {"id": "srv-test", "type": "web_service", "environmentId": "evm-test",
                        "suspended": "not_suspended", "autoDeploy": False,
                        "serviceDetails": {"url": "https://test.onrender.com"}}

    def test_exact_write_contracts(self):
        expected = {"deploy": ("/deploys", {"commitId": "a" * 40, "clearCache": "do_not_clear"}),
                    "restart": ("/restart", {}), "rollback": ("/rollback", {"deployId": "dep-old"})}
        for action, (suffix, body) in expected.items():
            self.render.submit({**self.request, "action": action})
            self.render.call.assert_called_with("/services/srv-test" + suffix, body)

    def test_environment_and_current_deploy_preflight(self):
        self.render.call.side_effect = [self.service, {"id": "evm-test", "name": "Staging"},
                                       [{"deploy": {"id": "dep-current", "status": "live"}}]]
        self.assertEqual(self.render.preflight(self.request), {"previous_deploy_id": "dep-current"})

    def test_wrapped_render_responses_are_supported(self):
        self.render.call.side_effect = [{"service": self.service}, {"environment": {"id": "evm-test", "name": "Staging"}},
                                       {"items": [{"deploy": {"id": "dep-current", "status": "live"}}]}]
        self.assertEqual(self.render.preflight(self.request), {"previous_deploy_id": "dep-current"})

    def test_other_environment_is_rejected(self):
        self.render.call.return_value = {**self.service, "environmentId": "evm-production"}
        with self.assertRaisesRegex(execution.GateError, "environment-mismatch"):
            self.render.preflight(self.request)

    def test_autodeploy_is_rejected(self):
        self.render.call.side_effect = [{**self.service, "autoDeploy": True}, {"id": "evm-test", "name": "staging"}]
        with self.assertRaisesRegex(execution.GateError, "disable-auto-deploy"):
            self.render.preflight(self.request)

    def test_set_auto_deploy_preflight_and_patch_are_bounded(self):
        request = {**self.request, "action": "set-auto-deploy", "health_path": None, "auto_deploy": "no"}
        self.render.call.side_effect = [
            {**self.service, "autoDeploy": True},
            {"id": "evm-test", "name": "Staging"},
            {"id": "srv-test", "autoDeploy": "no"},
        ]
        self.assertEqual(
            self.render.preflight(request),
            {"previous_auto_deploy": "yes", "requested_auto_deploy": "no"},
        )
        self.render.submit(request)
        self.render.call.assert_called_with(
            "/services/srv-test", {"autoDeploy": "no"}, method="PATCH"
        )

    def test_set_auto_deploy_verifies_provider_state_without_health_probe(self):
        request = {**self.request, "action": "set-auto-deploy", "health_path": None, "auto_deploy": "no"}
        self.render.call.return_value = {**self.service, "autoDeploy": False}
        self.assertEqual(self.render.verify(request, {}), "succeeded")

    def test_wrong_revision_is_not_success(self):
        self.render.call.return_value = {"id": "dep-new", "status": "live", "commit": {"id": "b" * 40}}
        with self.assertRaisesRegex(execution.GateError, "deployed-revision-mismatch"):
            self.render.verify(self.request, {"provider_action_id": "dep-new"})

    def test_failure_and_pending_are_not_health_success(self):
        for state, expected in (("build_failed", "failed"), ("build_in_progress", "pending")):
            self.render.call.return_value = {"id": "dep-new", "status": state}
            self.assertEqual(self.render.verify(self.request, {"provider_action_id": "dep-new"}), expected)

    def test_health_url_is_provider_owned_no_credentials(self):
        for url in ("http://127.0.0.1", "https://test.onrender.com.evil.com", "https://user:pass@test.onrender.com", "https://test.onrender.com/redirect"):
            with self.assertRaises(execution.GateError):
                self.render.health_url({"serviceDetails": {"url": url}}, self.request)

    def test_set_auto_deploy_same_state_is_rejected(self):
        request = {**self.request, "action": "set-auto-deploy", "health_path": None, "auto_deploy": "no"}
        self.render.call.side_effect = [self.service, {"id": "evm-test", "name": "Staging"}]
        with self.assertRaisesRegex(execution.GateError, "auto-deploy-already-set"):
            self.render.preflight(request)

    def test_success_requires_unauthenticated_health_check(self):
        self.render.call.side_effect = [{"id": "dep-new", "status": "live", "commit": {"id": "a" * 40}}, self.service]
        opener = Mock()
        response = Mock()
        response.status = 200
        opener.open.return_value.__enter__ = Mock(return_value=response)
        opener.open.return_value.__exit__ = Mock(return_value=False)
        with patch.object(execution.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(self.render.verify(self.request, {"provider_action_id": "dep-new"}), "succeeded")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://test.onrender.com/health")
        self.assertIsNone(request.get_header("Authorization"))

    def test_reconcile_deploy_uses_unique_recent_revision_evidence(self):
        rows = [{"id": "dep-new", "status": "live", "commit": {"id": "a" * 40}}]
        self.render.call.side_effect = [rows, {"id": "dep-new", "status": "live", "commit": {"id": "a" * 40}}, self.service]
        opener = Mock()
        response = Mock()
        response.status = 200
        opener.open.return_value.__enter__ = Mock(return_value=response)
        opener.open.return_value.__exit__ = Mock(return_value=False)
        with patch.object(execution.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(
                self.render.reconcile(
                    self.request,
                    {"status": "verification_required", "previous_deploy_id": "dep-old"},
                ),
                "succeeded",
            )

    def test_reconcile_restart_remains_unresolved_without_action_identity(self):
        request = {**self.request, "action": "restart"}
        self.assertEqual(self.render.reconcile(request, {"status": "submission_unknown"}), "verification_required")
        self.render.call.assert_not_called()

    def test_reconcile_does_not_confirm_the_preflight_recovery_deploy(self):
        self.render.call.return_value = [{"id": "dep-current", "status": "live", "commit": {"id": "a" * 40}}]
        self.assertEqual(
            self.render.reconcile(self.request, {"status": "verification_required", "previous_deploy_id": "dep-current"}),
            "verification_required",
        )


if __name__ == "__main__":
    unittest.main()
