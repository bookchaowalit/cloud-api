#!/usr/bin/env python3
"""Local governed PaaS commands. Read one bounded JSON command from stdin.

Render web services are the first execution adapter. Every mutation is claimed
atomically before network I/O; ambiguous submissions are never replayed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from platform_output import configure_utf8_stdio  # noqa: E402
import paas_action as actions
from auth_resolver import resolve_provider_auth  # noqa: E402
from cloud_providers import get_provider  # noqa: E402
from paas_health import _safe_error
from decision_store import DecisionStoreError, open_decision_store  # noqa: E402  (utils path set by paas_action)

ACTOR = "paas_executor"
API = "https://api.render.com/v1"
ID = re.compile(r"^(srv|evm|dep)-[A-Za-z0-9-]{1,100}$")
SHA = re.compile(r"^[a-fA-F0-9]{40}$")
HEALTH_PROBE_TIMEOUT_SECONDS = 20


class GateError(Exception):
    pass


def require(condition: Any, code: str) -> None:
    if not condition:
        raise GateError(code)


def resource(payload: Any, key: str) -> dict:
    """Accept Render's direct and wrapped response shapes without retaining payload."""
    if isinstance(payload, dict):
        nested = payload.get(key)
        if isinstance(nested, dict):
            return nested
        data = payload.get("data")
        if isinstance(data, dict) and isinstance(data.get(key), dict):
            return data[key]
        return payload
    return {}


def items(payload: Any, key: str) -> list[dict]:
    raw: Any = payload
    if isinstance(payload, dict):
        raw = next(
            (
                payload.get(name)
                for name in ("items", key, "data")
                if isinstance(payload.get(name), list)
            ),
            [],
        )
    if not isinstance(raw, list):
        return []
    return [
        item.get(key, item)
        for item in raw
        if isinstance(item, dict) and isinstance(item.get(key, item), dict)
    ]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GateError("redirect-refused")


class Render:
    def __init__(self):
        auth = resolve_provider_auth(get_provider("render"))
        if auth.status != "configured" or auth.credential is None:
            raise GateError("render-credential-unavailable")
        self.token = auth.credential

    def call(
        self, path: str, body: dict | None = None, method: str | None = None
    ) -> Any:
        verb = method or ("GET" if body is None else "POST")
        request = urllib.request.Request(
            API + path,
            data=None if body is None else json.dumps(body).encode(),
            method=verb,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        # No retries, proxies, or redirects on authenticated provider requests.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect()
        )
        with opener.open(request, timeout=15) as response:
            raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "provider-response-too-large")
        return json.loads(raw) if raw else {}

    def service(self, request: dict) -> dict:
        service = resource(self.call(f"/services/{request['resource_id']}"), "service")
        require(
            isinstance(service, dict) and service.get("id") == request["resource_id"],
            "service-mismatch",
        )
        require(service.get("type") == "web_service", "web-service-required")
        require(
            service.get("environmentId") == request["environment_id"],
            "environment-mismatch",
        )
        require(service.get("suspended") == "not_suspended", "service-not-active")
        return service

    def preflight(self, request: dict) -> dict:
        service = self.service(request)
        environment = resource(
            self.call(f"/environments/{request['environment_id']}"), "environment"
        )
        require(
            environment.get("id") == request["environment_id"], "environment-mismatch"
        )
        require(
            str(environment.get("name", "")).lower() == request["environment"],
            "environment-name-mismatch",
        )
        if request["action"] == "set-auto-deploy":
            current = self.auto_deploy_value(service)
            desired = request["auto_deploy"]
            require(current is not None, "auto-deploy-state-unknown")
            require(current != desired, "auto-deploy-already-set")
            return {"previous_auto_deploy": current, "requested_auto_deploy": desired}
        # Concurrent auto deploys can invalidate a rollback or pinned revision.
        # Render currently returns a boolean; accept the legacy string form too.
        require(
            service.get("autoDeploy") in (False, "no"),
            "disable-auto-deploy-before-execution",
        )
        deploys = items(
            self.call(f"/services/{request['resource_id']}/deploys?limit=20"), "deploy"
        )
        require(deploys, "invalid-deploy-list")
        rows = deploys
        require(
            all(
                row.get("status")
                in {
                    "live",
                    "deactivated",
                    "build_failed",
                    "update_failed",
                    "pre_deploy_failed",
                    "canceled",
                }
                for row in rows
            ),
            "deploy-already-in-progress",
        )
        live = [row for row in rows if row.get("status") == "live"]
        require(len(live) == 1, "current-deploy-required-for-recovery")
        previous = live[0].get("id")
        require(
            isinstance(previous, str)
            and ID.fullmatch(previous)
            and previous.startswith("dep-"),
            "invalid-current-deploy",
        )
        if request["action"] == "rollback":
            target = resource(
                self.call(
                    f"/services/{request['resource_id']}/deploys/{request['rollback_target']}"
                ),
                "deploy",
            )
            require(
                target.get("id") == request["rollback_target"]
                and target.get("status") in {"live", "deactivated"},
                "rollback-target-not-successful",
            )
            require(target.get("id") != previous, "rollback-target-is-current")
        # Validate verification URL before allowing the write; never send auth to it.
        self.health_url(service, request)
        return {"previous_deploy_id": previous}

    def _deploy_rows(self, service_id: str) -> list[dict]:
        rows = items(self.call(f"/services/{service_id}/deploys?limit=20"), "deploy")
        require(rows, "invalid-deploy-list")
        return rows

    @staticmethod
    def auto_deploy_value(service: dict) -> str | None:
        value = service.get("autoDeploy")
        if value is True or value == "yes":
            return "yes"
        if value is False or value == "no":
            return "no"
        return None

    @staticmethod
    def health_url(service: dict, request: dict) -> str:
        details = (
            service.get("serviceDetails")
            if isinstance(service.get("serviceDetails"), dict)
            else {}
        )
        url = details.get("url") or service.get("url") or ""
        require(
            isinstance(url, str)
            and re.fullmatch(r"https://[a-z0-9-]+\.onrender\.com/?", url),
            "render-hosted-health-url-required",
        )
        return url.rstrip("/") + request["health_path"]

    def submit(self, request: dict) -> dict:
        path = f"/services/{request['resource_id']}"
        if request["action"] == "deploy":
            return self.call(
                path + "/deploys",
                {"commitId": request["target_revision"], "clearCache": "do_not_clear"},
            )
        if request["action"] == "rollback":
            return self.call(
                path + "/rollback", {"deployId": request["rollback_target"]}
            )
        if request["action"] == "set-auto-deploy":
            return self.call(
                path, {"autoDeploy": request["auto_deploy"]}, method="PATCH"
            )
        return self.call(path + "/restart", {})

    def verify(self, request: dict, attempt: dict) -> str:
        if request["action"] == "set-auto-deploy":
            service = self.service(request)
            require(
                self.auto_deploy_value(service) == request["auto_deploy"],
                "auto-deploy-update-not-visible",
            )
            return "succeeded"
        deploy_id = attempt.get("provider_action_id")
        # Render restart returns no deploy ID. Do not infer success from an
        # unrelated deployment or an old instance's health response.
        if not deploy_id:
            return "verification_required"
        deploy = resource(
            self.call(f"/services/{request['resource_id']}/deploys/{deploy_id}"),
            "deploy",
        )
        require(deploy.get("id") == deploy_id, "deploy-mismatch")
        state = deploy.get("status")
        if state in {
            "build_failed",
            "update_failed",
            "pre_deploy_failed",
            "canceled",
            "deactivated",
        }:
            return "failed"
        if state != "live":
            return "pending"
        if request["action"] == "deploy":
            require(
                (deploy.get("commit") or {}).get("id", "").lower()
                == request["target_revision"].lower(),
                "deployed-revision-mismatch",
            )
        service = self.service(request)
        url = self.health_url(service, request)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect()
        )
        with opener.open(
            urllib.request.Request(url, method="GET"),
            timeout=HEALTH_PROBE_TIMEOUT_SECONDS,
        ) as response:
            require(200 <= response.status < 300, "health-check-failed")
        return "succeeded"

    def reconcile(self, request: dict, attempt: dict) -> str:
        """Resolve an ambiguous submission from provider read evidence only.

        A restart has no provider action identity in Render's response and
        therefore remains explicitly unresolved. Deploy and rollback may be
        resolved when exactly one bounded recent deployment proves the request.
        No reconciliation path ever submits a second provider mutation.
        """
        if attempt.get("provider_action_id") or request["action"] == "set-auto-deploy":
            return self.verify(request, attempt)
        if request["action"] == "restart":
            return "verification_required"
        # Without the preflight recovery reference, a matching old deployment
        # cannot prove that this submission caused the observed provider state.
        if not attempt.get("previous_deploy_id"):
            return "verification_required"

        rows = self._deploy_rows(request["resource_id"])
        if request["action"] == "deploy":
            target_revision = request["target_revision"].lower()
            matches = [
                row
                for row in rows
                if isinstance((row.get("commit") or {}).get("id"), str)
                and row["commit"]["id"].lower() == target_revision
                and row.get("id") != attempt.get("previous_deploy_id")
            ]
        else:
            matches = [
                row for row in rows if row.get("id") == request.get("rollback_target")
            ]
        if len(matches) != 1:
            return "verification_required"
        match = matches[0]
        if match.get("status") in {
            "build_failed",
            "update_failed",
            "pre_deploy_failed",
            "canceled",
            "deactivated",
        }:
            return "failed"
        if match.get("status") != "live":
            return "pending"
        return self.verify(request, {**attempt, "provider_action_id": match.get("id")})


def validate(request: dict) -> None:
    require(request.get("provider") == "render", "provider-adapter-unavailable")
    require(request.get("resource_type") == "service", "service-resource-required")
    for field, prefix in (("resource_id", "srv-"), ("environment_id", "evm-")):
        value = request.get(field)
        require(
            isinstance(value, str) and ID.fullmatch(value) and value.startswith(prefix),
            f"invalid-{field}",
        )
    require(
        request.get("environment") in {"staging", "production"},
        "staging-or-production-required",
    )
    require(
        request.get("action") in {"deploy", "restart", "rollback", "set-auto-deploy"},
        "invalid-action",
    )
    if request["action"] != "set-auto-deploy":
        health_path = request.get("health_path")
        require(
            isinstance(health_path, str)
            and re.fullmatch(r"/[A-Za-z0-9_/-]{0,120}", health_path)
            and "//" not in health_path,
            "invalid-health-path",
        )
    if request["action"] == "deploy":
        require(
            isinstance(request.get("target_revision"), str)
            and SHA.fullmatch(request["target_revision"]),
            "full-commit-sha-required",
        )
    if request["action"] == "rollback":
        target = request.get("rollback_target")
        require(
            isinstance(target, str)
            and ID.fullmatch(target)
            and target.startswith("dep-"),
            "invalid-rollback-target",
        )
    if request["action"] == "set-auto-deploy":
        require(
            request.get("auto_deploy") in {"yes", "no"}, "invalid-auto-deploy-state"
        )


def connection(read_only=False):
    """The decisions cell store (``read_only`` kept for callers; the API decides what is allowed)."""
    return open_decision_store("paas-operator")


def read_record(store, decision_id: int) -> tuple[dict, dict, list[dict]]:
    row = store.get(decision_id)
    require(
        row is not None
        and row["domain"] == "paas"
        and row["source_type"] == "paas_action"
        and row["privacy_class"] == "internal",
        "paas-decision-not-found",
    )
    events = store.history(
        decision_id
    )  # the whole history: the registration event is the oldest
    request = None
    attempts = []
    for event in events:
        data = (
            event["metadata"]
            if isinstance(event["metadata"], dict)
            else json.loads(event["metadata"])
        )
        if event["actor"] == "paas_action" and "request" in data:
            request = data["request"]
        if event["actor"] == ACTOR:
            attempts.append(data)
    require(isinstance(request, dict), "legacy-proposal-requires-new-registration")
    require(
        row["source_ref"] == "paas-proposal:" + actions.proposal_fingerprint(request),
        "stored-proposal-mismatch",
    )
    return (
        {**row, "approval_required": int(bool(row["approval_required"]))},
        request,
        attempts,
    )


def require_lock_schema(row: dict) -> None:
    require("execution_lock_key" in row, "execution-lock-schema-required")


def snapshot(decision_id: int) -> dict:
    row, request, attempts = read_record(connection(True), decision_id)
    return {
        "decision_id": decision_id,
        "proposal_id": row["source_ref"],
        "request": request,
        "approval_status": row["approval_status"],
        "action_status": row["action_status"],
        "attempt": attempts[-1] if attempts else None,
    }


def update(
    store,
    row: dict,
    state: str,
    metadata: dict,
    event_type="refreshed",
    extra: dict | None = None,
) -> dict:
    """One change: action state (and outcome), lock release, and the attempt event; refuses a concurrent change."""
    release_lock = state in {"executed", "failed"} or metadata.get("status") in {
        "succeeded",
        "failed",
    }
    fields: dict = {"action_status": state, **(extra or {})}
    if release_lock:
        fields["execution_lock_key"] = None
    if state == "executed":
        fields["status"] = "completed"
        fields["actual_outcome"] = (
            "Provider autoDeploy configuration and bounded state verification passed"
            if metadata.get("action") == "set-auto-deploy"
            else "Provider deployment and bounded health verification passed"
        )
        event_type = "completed"
    return store.update(
        row["id"],
        fields,
        event={"event_type": event_type, "actor": ACTOR, "metadata": metadata},
        expected_version=row["version"],
    )


def approve(decision_id: int, proposal_id: str) -> dict:
    # Approving is the owner's act (decisions.decision:approve), not the PaaS operator automation's.
    store = open_decision_store("owner-cli", channel="cli")
    now = datetime.now(UTC).isoformat(timespec="seconds")
    row, request, attempts = read_record(store, decision_id)
    require(row["source_ref"] == proposal_id, "reviewed-proposal-mismatch")
    require(
        row["status"] == "proposed"
        and row["approval_status"] == "pending"
        and not attempts,
        "decision-not-pending",
    )
    validate(request)
    try:
        store.update(
            decision_id,
            {
                "status": "approved",
                "approval_status": "approved",
                "action_status": "queued",
                "decided_at": now,
            },
            event={
                "event_type": "approved",
                "actor": "local-owner",
                "metadata": {"proposal_id": proposal_id},
            },
            expected_version=row["version"],
        )
    except DecisionStoreError as exc:
        raise GateError(
            "decision-not-pending"
            if exc.status == 409
            else "decision-store-unavailable"
        ) from exc
    return snapshot(decision_id)


def execute(decision_id: int, adapter_factory=Render) -> dict:
    current = snapshot(decision_id)
    request = current["request"]
    validate(request)
    policy = actions.load_policy()
    _, spec = actions.find_action(policy, request["provider"], request["action"])
    require(
        policy.get("execution_enabled")
        and policy.get("mutating_requests_enabled")
        and spec.get("adapter") == "render-v1",
        "execution-disabled",
    )
    approval_max_age = actions.approval_max_age_seconds(policy)
    approval = actions.check_approval(
        decision_id, current["proposal_id"], max_age_seconds=approval_max_age
    )
    require(approval.get("valid"), approval.get("error", "approval-invalid"))
    require(current["attempt"] is None, "execution-already-claimed")
    adapter = adapter_factory()
    recovery = adapter.preflight(request)
    store = connection()
    row, stored, attempts = read_record(store, decision_id)
    require_lock_schema(row)
    require(not attempts, "execution-already-claimed")
    approval = actions.assess_approval_row(
        row,
        current["proposal_id"],
        approval_id=decision_id,
        max_age_seconds=approval_max_age,
    )
    require(approval.get("valid"), approval.get("error", "approval-invalid"))
    require(stored == request, "proposal-changed")
    attempt = {
        "status": "submission_unknown",
        "action": request["action"],
        "claimed_at": datetime.now(UTC).isoformat(),
        **recovery,
    }
    lock_key = actions.execution_lock_key(request)
    require(row["execution_lock_key"] is None, "execution-already-claimed")
    try:
        # The claim, its lock key and the attempt event land in one change; expected_version refuses a
        # concurrent claim of this decision and the unique lock key refuses one on the same resource.
        update(store, row, "blocked", attempt, extra={"execution_lock_key": lock_key})
    except DecisionStoreError as exc:
        if exc.status == 409 and exc.reason == "version_conflict":
            raise GateError("execution-already-claimed") from exc
        if exc.status == 409:
            raise GateError("resource-operation-in-progress") from exc
        raise
    # A crash or transport timeout after this point leaves a durable claim.
    # Operator reconciliation is required; executing again cannot resend POST.
    try:
        response = adapter.submit(request)
        response_resource = resource(response, "deploy")
        raw_id = (
            response_resource.get("id") if isinstance(response_resource, dict) else None
        )
        deploy_id = (
            raw_id
            if isinstance(raw_id, str)
            and ID.fullmatch(raw_id)
            and raw_id.startswith("dep-")
            else None
        )
        if request["action"] == "set-auto-deploy":
            attempt.update(status="pending")
        else:
            attempt.update(
                status="pending" if deploy_id else "verification_required",
                provider_action_id=deploy_id,
            )
    except Exception as exc:
        attempt.update(status="submission_unknown", error_class=_safe_error(exc))
    store = connection()
    row, _, _ = read_record(store, decision_id)
    update(store, row, "blocked", attempt)
    return snapshot(decision_id)


def verify(decision_id: int, adapter_factory=Render) -> dict:
    current = snapshot(decision_id)
    attempt = current["attempt"]
    require(attempt is not None, "execution-not-submitted")
    if attempt["status"] in {
        "succeeded",
        "failed",
        "submission_unknown",
        "verification_required",
    }:
        return current
    validate(current["request"])
    try:
        status = adapter_factory().verify(current["request"], attempt)
        require(
            status in {"succeeded", "failed", "pending", "verification_required"},
            "invalid-verification-result",
        )
    except Exception as exc:
        # Read failures do not imply provider failure, and never cause retries.
        return {
            **current,
            "verification_error": str(exc)
            if isinstance(exc, GateError)
            else _safe_error(exc),
        }
    if status == "pending":
        age = (
            datetime.now(UTC) - datetime.fromisoformat(attempt["claimed_at"])
        ).total_seconds()
        if age > 900:
            return {
                **current,
                "verification_error": "verification-timeout-check-provider",
            }
        return current
    store = connection()
    row, _, attempts = read_record(store, decision_id)
    if attempts[-1]["status"] == "pending":
        update(
            store,
            row,
            "executed"
            if status == "succeeded"
            else "failed"
            if status == "failed"
            else "blocked",
            {**attempt, "status": status},
        )
    return snapshot(decision_id)


def reconcile(decision_id: int, adapter_factory=Render) -> dict:
    """Read provider state to resolve a claimed ambiguous submission."""
    current = snapshot(decision_id)
    attempt = current["attempt"]
    require(attempt is not None, "execution-not-submitted")
    require(
        attempt.get("status")
        in {"pending", "submission_unknown", "verification_required"},
        "reconciliation-not-needed",
    )
    validate(current["request"])
    try:
        status = adapter_factory().reconcile(current["request"], attempt)
        require(
            status in {"succeeded", "failed", "pending", "verification_required"},
            "invalid-reconciliation-result",
        )
    except Exception as exc:
        return {
            **current,
            "reconciliation_error": str(exc)
            if isinstance(exc, GateError)
            else _safe_error(exc),
        }
    if status == "pending":
        age = (
            datetime.now(UTC) - datetime.fromisoformat(attempt["claimed_at"])
        ).total_seconds()
        if age > 900:
            return {
                **current,
                "reconciliation_error": "verification-timeout-check-provider",
            }
        return current
    store = connection()
    row, _, attempts = read_record(store, decision_id)
    require_lock_schema(row)
    if attempts[-1]["status"] in {
        "pending",
        "submission_unknown",
        "verification_required",
    }:
        metadata = {**attempt, "status": status, "reconciled": True}
        update(
            store,
            row,
            "executed"
            if status == "succeeded"
            else "failed"
            if status == "failed"
            else "blocked",
            metadata,
        )
    return snapshot(decision_id)


def dispatch(command: dict) -> dict:
    operation = command.get("operation")
    if operation == "register":
        source = command.get("request")
        require(isinstance(source, dict), "request-required")
        fields = {
            key: source.get(key)
            for key in (
                "provider",
                "action",
                "resource_type",
                "resource_id",
                "environment",
                "environment_id",
                "health_path",
                "target_revision",
                "rollback_target",
                "auto_deploy",
                "operation_id",
                "reason",
            )
        }
        validate(fields)
        fields["approval_id"] = None
        proposal = actions.build_proposal(
            argparse.Namespace(**fields), actions.load_policy()
        )
        result = actions.register_proposal(proposal)
        return snapshot(result["decision_id"])
    decision_id = command.get("decision_id")
    require(type(decision_id) is int and decision_id > 0, "decision-id-required")
    if operation == "status":
        return snapshot(decision_id)
    require(command.get("confirm") is True, "explicit-confirmation-required")
    if operation == "approve":
        return approve(decision_id, command.get("proposal_id"))
    if operation == "execute":
        return execute(decision_id)
    if operation == "verify":
        return verify(decision_id)
    if operation == "reconcile":
        return reconcile(decision_id)
    raise GateError("unknown-operation")


def main() -> int:
    configure_utf8_stdio()
    try:
        raw = sys.stdin.read(16385)
        require(len(raw.encode()) <= 16384, "command-too-large")
        command = json.loads(raw)
        require(isinstance(command, dict), "invalid-command")
        result = dispatch(command)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        # Never emit provider bodies, URLs, credentials, or arbitrary exceptions.
        code = (
            str(exc)
            if isinstance(exc, GateError)
            else "invalid-command"
            if isinstance(exc, (ValueError, TypeError))
            else _safe_error(exc)
        )
        print(json.dumps({"error": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
