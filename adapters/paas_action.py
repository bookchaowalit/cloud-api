#!/usr/bin/env python3
"""Create and validate governed actions for the multi-PaaS control plane.

This module never calls a provider write endpoint. It creates bounded proposals,
optionally registers a local decision record after an explicit confirmation, and
checks that a supplied approval belongs to the exact proposal fingerprint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from platform_output import configure_utf8_stdio  # noqa: E402
from _env import PROJECT_ROOT  # noqa: E402

POLICY_PATH = PROJECT_ROOT / "registry" / "paas-action-policy.json"
from decision_store import DecisionStoreError, open_decision_store  # noqa: E402
from task_store import ClientConfigError  # noqa: E402


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
SAFE_ENV = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,63}$")
SAFE_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,79}$")
SECRET_WORD = re.compile(r"(token|secret|password|passwd|api[_-]?key|bearer|private[_-]?key)", re.IGNORECASE)
SUPPORT_STATES = {"supported", "manual", "unsupported"}
DEFAULT_APPROVAL_MAX_AGE_SECONDS = 60 * 60
MAX_APPROVAL_MAX_AGE_SECONDS = 7 * 24 * 60 * 60


def load_policy() -> dict[str, Any]:
    with POLICY_PATH.open("r", encoding="utf-8") as handle:
        policy = json.load(handle)
    if not isinstance(policy, dict) or not isinstance(policy.get("providers"), list):
        raise ValueError("Invalid PaaS action policy")
    return policy


def provider_map(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(provider["id"]): provider for provider in policy["providers"]}


def approval_max_age_seconds(policy: dict[str, Any] | None = None) -> int:
    """Return the bounded approval freshness window from the policy."""
    raw_approval = policy.get("approval", {}) if isinstance(policy, dict) else {}
    approval = raw_approval if isinstance(raw_approval, dict) else {}
    raw_value = approval.get("max_age_seconds", DEFAULT_APPROVAL_MAX_AGE_SECONDS)
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("approval max age must be an integer") from exc
    if not 60 <= value <= MAX_APPROVAL_MAX_AGE_SECONDS:
        raise ValueError("approval max age must be between 60 seconds and 7 days")
    return value


def clean_text(value: str | None, limit: int = 500) -> str | None:
    if value is None:
        return None
    return " ".join(str(value).split())[:limit] or None


def safe_text(value: str | None, limit: int = 500) -> str | None:
    """Keep operator context bounded and redact obvious credential-shaped text."""
    normalized = clean_text(value, limit)
    if not normalized:
        return None
    if SECRET_WORD.search(normalized):
        return "[REDACTED: secret-like text]"
    return normalized


def safe_identifier(value: str | None, field: str, pattern: re.Pattern[str]) -> str:
    normalized = clean_text(value, 256)
    if not normalized or not pattern.fullmatch(normalized):
        raise ValueError(f"{field} must be a bounded provider-owned identifier")
    if SECRET_WORD.search(normalized):
        raise ValueError(f"{field} looks like credential-shaped input")
    return normalized


def canonical_request(request: dict[str, Any]) -> str:
    return json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def proposal_fingerprint(request: dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_request(request).encode("utf-8")).hexdigest()
    return digest[:20]


def execution_lock_key(request: dict[str, Any]) -> str:
    """Return the stable resource scope used to serialize provider mutations.

    The operation id intentionally does not participate in this key: two
    distinct reviewed operations for one service must still be serialized.
    """
    scope = {
        "provider": request.get("provider"),
        "resource_type": request.get("resource_type"),
        "resource_id": request.get("resource_id"),
        "environment_id": request.get("environment_id") or request.get("environment"),
    }
    digest = hashlib.sha256(canonical_request(scope).encode("utf-8")).hexdigest()
    return f"paas-resource:{digest[:32]}"


def find_action(policy: dict[str, Any], provider_id: str, action: str) -> tuple[dict[str, Any], dict[str, Any]]:
    provider = provider_map(policy).get(provider_id)
    if provider is None:
        raise ValueError(f"Unknown PaaS provider: {provider_id}")
    actions = provider.get("actions") or {}
    action_spec = actions.get(action)
    if not isinstance(action_spec, dict):
        raise ValueError(f"Unknown PaaS action: {action}")
    support = action_spec.get("support")
    if support not in SUPPORT_STATES:
        raise ValueError(f"Invalid support state for {provider_id}/{action}")
    return provider, action_spec


def _parse_db_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    # SQLite CURRENT_TIMESTAMP is UTC without an offset. New writes use an
    # explicit UTC offset, but treating legacy naive values as UTC keeps the
    # expiry check deterministic and avoids local-time ambiguity.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _row_value(row: Any, key: str) -> Any:
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[key]
    except (IndexError, KeyError, TypeError):
        return None


def assess_approval_row(
    row: Any,
    proposal_id: str,
    *,
    approval_id: int | None = None,
    max_age_seconds: int = DEFAULT_APPROVAL_MAX_AGE_SECONDS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Assess status, binding, and freshness without opening another DB connection."""
    max_age_seconds = approval_max_age_seconds({"approval": {"max_age_seconds": max_age_seconds}})
    checks = {
        "domain": _row_value(row, "domain") == "paas",
        "status": _row_value(row, "status") == "approved",
        "approval_required": _row_value(row, "approval_required") == 1,
        "approval_status": _row_value(row, "approval_status") == "approved",
        "action_type": _row_value(row, "action_type") == "external_change",
        "action_status": _row_value(row, "action_status") == "queued",
        "proposal_binding": _row_value(row, "source_ref") == proposal_id,
    }
    timestamp_source = "decided_at" if _row_value(row, "decided_at") else "updated_at"
    approval_at = _parse_db_timestamp(_row_value(row, timestamp_source))
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    current_time = current_time.astimezone(timezone.utc)
    age_seconds = (current_time - approval_at).total_seconds() if approval_at else None
    checks["approval_timestamp_present"] = approval_at is not None
    checks["approval_timestamp_valid"] = approval_at is not None
    checks["approval_not_future"] = age_seconds is not None and age_seconds >= 0
    checks["approval_fresh"] = age_seconds is not None and 0 <= age_seconds <= max_age_seconds

    valid = all(checks.values())
    result: dict[str, Any] = {
        "id": approval_id if approval_id is not None else _row_value(row, "id"),
        "status": "approved" if valid else "invalid",
        "valid": valid,
        "checks": checks,
        "max_age_seconds": max_age_seconds,
    }
    if approval_at is not None:
        result["approval_timestamp"] = approval_at.isoformat()
        result["approval_expires_at"] = (approval_at + timedelta(seconds=max_age_seconds)).isoformat()
        result["approval_age_seconds"] = round(age_seconds or 0, 3)
    if all(checks[field] for field in checks if field not in {
        "approval_timestamp_present", "approval_timestamp_valid", "approval_not_future", "approval_fresh"
    }):
        if approval_at is None:
            result["error"] = "approval-timestamp-unavailable"
        elif age_seconds is not None and age_seconds < 0:
            result["error"] = "approval-timestamp-in-future"
        elif age_seconds is not None and age_seconds > max_age_seconds:
            result["error"] = "approval-expired"
    return result


def check_approval(
    approval_id: int,
    proposal_id: str,
    *,
    max_age_seconds: int = DEFAULT_APPROVAL_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    try:
        row = open_decision_store("paas-operator").get(approval_id)
    except (ClientConfigError, DecisionStoreError, OSError, RuntimeError):
        return {"id": approval_id, "status": "unavailable", "valid": False, "error": "approval-store-unavailable"}
    if row is None:
        return {"id": approval_id, "status": "not_found", "valid": False, "error": "approval-not-found"}
    row = {**row, "approval_required": int(bool(row["approval_required"]))}
    return assess_approval_row(row, proposal_id, approval_id=approval_id, max_age_seconds=max_age_seconds)


def build_proposal(args: argparse.Namespace, policy: dict[str, Any]) -> dict[str, Any]:
    provider_id = safe_identifier(args.provider, "provider", SAFE_ID)
    action = safe_identifier(args.action, "action", SAFE_ID).lower()
    resource_type = safe_identifier(args.resource_type, "resource_type", SAFE_ID).lower()
    resource_id = safe_identifier(args.resource_id, "resource_id", SAFE_ID)
    environment = safe_identifier(args.environment, "environment", SAFE_ENV).lower()
    target_revision = safe_identifier(args.target_revision, "target_revision", SAFE_ID) if args.target_revision else None
    rollback_target = safe_identifier(args.rollback_target, "rollback_target", SAFE_ID) if args.rollback_target else None
    auto_deploy = clean_text(getattr(args, "auto_deploy", None), 3)
    if auto_deploy is not None:
        auto_deploy = auto_deploy.lower()
        if auto_deploy not in {"yes", "no"}:
            raise ValueError("auto_deploy must be yes or no")
    reason = safe_text(args.reason, 500)
    raw_operation_id = clean_text(getattr(args, "operation_id", None), 80)
    operation_id = None
    if raw_operation_id:
        if not SAFE_OPERATION_ID.fullmatch(raw_operation_id) or SECRET_WORD.search(raw_operation_id):
            raise ValueError("operation_id must be a bounded non-secret identifier")
        operation_id = raw_operation_id

    provider, action_spec = find_action(policy, provider_id, action)
    allowed_resource_types = action_spec.get("resource_types", [])
    request = {
        "provider": provider_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "environment": environment,
        "target_revision": target_revision,
        "rollback_target": rollback_target,
        "auto_deploy": auto_deploy,
        "reason": reason or "[reason not supplied]",
    }
    # An optional operation id lets an owner intentionally repeat an otherwise
    # identical action while keeping retries of the same registration idempotent.
    if operation_id:
        request["operation_id"] = operation_id
    # Bind verification context to the approval, preserving older fingerprints.
    for field in ("environment_id", "health_path"):
        value = getattr(args, field, None)
        if value:
            if field == "health_path":
                if not re.fullmatch(r"/[A-Za-z0-9_/-]{0,120}", value) or "//" in value:
                    raise ValueError("health_path must be an absolute path without a query")
                request[field] = value
            else:
                request[field] = safe_identifier(value, field, SAFE_ID)
    fingerprint = proposal_fingerprint(request)
    proposal_id = f"paas-proposal:{fingerprint}"
    blockers: list[str] = []

    if resource_type not in allowed_resource_types:
        blockers.append("resource-type-not-allowed-for-action")
    if action == "deploy" and not target_revision:
        blockers.append("target-revision-required")
    if action == "rollback" and not rollback_target:
        blockers.append("rollback-target-required")
    if action == "set-auto-deploy" and not auto_deploy:
        blockers.append("auto-deploy-state-required")
    if action != "set-auto-deploy" and auto_deploy is not None:
        blockers.append("auto-deploy-only-for-set-action")
    if action_spec.get("support") == "manual":
        blockers.append("provider-adapter-manual-only")
    elif action_spec.get("support") == "unsupported":
        blockers.append("provider-action-unsupported")
    if not reason:
        blockers.append("reason-required")

    approval: dict[str, Any] = {
        "required": True,
        "id": args.approval_id,
        "status": "pending" if args.approval_id is None else "not_checked",
        "valid": False,
    }
    if args.approval_id is None:
        blockers.append("approval-id-required")
    else:
        approval = check_approval(
            args.approval_id,
            proposal_id,
            max_age_seconds=approval_max_age_seconds(policy),
        )
        if not approval.get("valid"):
            blockers.append(approval.get("error", "approval-invalid"))

    if not policy.get("execution_enabled") or not policy.get("mutating_requests_enabled"):
        blockers.append("write-actions-disabled")
    if action_spec.get("adapter") != "render-v1":
        blockers.append("provider-adapter-disabled")
    if action_spec.get("adapter") == "render-v1":
        if not request.get("environment_id"):
            blockers.append("environment-id-required")
        if action != "set-auto-deploy" and not request.get("health_path"):
            blockers.append("health-path-required")
    return {
        "schema_version": policy["schema_version"],
        "proposal_id": proposal_id,
        "fingerprint": fingerprint,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": policy["mode"],
        "execution_enabled": bool(policy["execution_enabled"]),
        "external_calls": 0,
        "write_attempted": False,
        "request": {
            **request,
            "provider": provider_id,
            "provider_name": provider.get("name", provider["id"]),
            "action": action,
            "support": action_spec["support"],
            "adapter": action_spec["adapter"],
            "resource_type": resource_type,
            "resource_id": resource_id,
            "environment": environment,
            "target_revision": target_revision,
            "rollback_target": rollback_target,
            "reason": reason,
        },
        "approval": approval,
        "blockers": list(dict.fromkeys(blockers)),
        "status": "blocked" if blockers else "ready",
    }


def register_proposal(proposal: dict[str, Any]) -> dict[str, Any]:
    """Register a local decision proposal; never call an external provider."""
    request = proposal["request"]
    if any(blocker in proposal["blockers"] for blocker in (
        "resource-type-not-allowed-for-action",
        "target-revision-required",
        "rollback-target-required",
        "auto-deploy-state-required",
        "auto-deploy-only-for-set-action",
        "reason-required",
        "environment-id-required",
        "health-path-required",
    )):
        raise ValueError("Cannot register an incomplete PaaS proposal")

    # The caller has explicitly confirmed this decision-record write (decisions cell).
    store = open_decision_store("paas-operator")
    source_ref = proposal["proposal_id"]
    dedupe_key = f"paas-action:{proposal['fingerprint']}"
    title = f"PaaS {request['action']}: {request['provider']} {request['resource_type']} {request['resource_id']}"
    target = request["rollback_target"] or request["target_revision"] or "current provider state"
    decision = (
        f"Request {request['action']} for {request['provider']} resource "
        f"{request['resource_id']} in {request['environment']} targeting {target}."
    )
    rationale = (
        f"Proposal {source_ref}; reason: {request['reason'] or '[not supplied]'}; "
        "execution requires matching approval and live preflight."
    )
    existing = store.by_dedupe(dedupe_key)
    if existing:
        return {"decision_id": int(existing["id"]), "created": False}
    fields = {
        "title": title, "domain": "paas", "decision": decision, "rationale": rationale,
        "evidence_refs": ["paas-action-policy:v1", source_ref, f"provider:{request['provider']}"],
        "confidence": 1.0,
        "expected_outcome": "Execute only after matching approval and live preflight; verify the provider result.",
        "next_action": "Review and approve/reject this proposal with decision-cli.",
        "status": "proposed", "approval_required": True, "approval_status": "pending",
        "action_type": "external_change", "action_status": "pending_approval", "privacy_class": "internal",
        "source_type": "paas_action", "source_ref": source_ref, "dedupe_key": dedupe_key,
    }
    event = {"event_type": "created", "actor": "paas_action", "metadata": {
        "proposal_id": source_ref,
        "provider": request["provider"],
        "action": request["action"],
        "resource_type": request["resource_type"],
        "environment": request["environment"],
        "request": {key: value for key, value in request.items() if key not in {"provider_name", "support", "adapter"}},
    }}
    try:
        created = store.create(fields, event=event)
    except DecisionStoreError as exc:
        if exc.status != 409:
            raise
        existing = store.by_dedupe(dedupe_key)  # a concurrent registration of the same proposal won
        if existing is None:
            raise
        return {"decision_id": int(existing["id"]), "created": False}
    return {"decision_id": int(created["id"]), "created": True}


def emit(payload: dict[str, Any], as_json: bool) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=None if as_json else 2, default=str))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    catalog = commands.add_parser("catalog", help="Show the provider action policy")
    catalog.add_argument("--json", action="store_true")

    propose = commands.add_parser("propose", help="Build a bounded PaaS action proposal")
    propose.add_argument("--provider", required=True)
    propose.add_argument("--action", required=True, choices=("deploy", "restart", "rollback", "set-auto-deploy"))
    propose.add_argument("--resource-type", required=True)
    propose.add_argument("--resource-id", required=True)
    propose.add_argument("--environment", required=True)
    propose.add_argument("--environment-id")
    propose.add_argument("--health-path")
    propose.add_argument("--target-revision")
    propose.add_argument("--operation-id", help="Optional id for an intentional new operation round")
    propose.add_argument("--rollback-target")
    propose.add_argument("--auto-deploy", choices=("yes", "no"))
    propose.add_argument("--reason", required=True)
    propose.add_argument("--approval-id", type=int)
    propose.add_argument("--register", action="store_true", help="Register a local decision record")
    propose.add_argument("--confirm-register", action="store_true", help="Confirm the local decision-record write")
    propose.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    configure_utf8_stdio()
    args = build_parser().parse_args()
    try:
        policy = load_policy()
        if args.command == "catalog":
            emit(policy, args.json)
            return 0
        if args.register and not args.confirm_register:
            raise ValueError("--register requires --confirm-register")
        proposal = build_proposal(args, policy)
        if args.register:
            proposal["registration"] = register_proposal(proposal)
        emit(proposal, args.json)
        return 0
    except (FileNotFoundError, ValueError, DecisionStoreError) as error:
        print(f"paas-action error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
