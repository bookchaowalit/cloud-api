#!/usr/bin/env python3
"""Build a sanitized, read-only cloud account and usage snapshot.

This is an aggregation boundary for the Cloud / PaaS decision board.  It
combines bounded local metadata and read-only provider sources without
exposing their raw payloads:

* the bounded PaaS resource inventory (live only when explicitly requested),
* non-secret account metadata under ``accounts/cloud``, and
* the Cloudflare R2 account-level storage metrics adapter, and
* the Vercel FOCUS billing charges adapter (both live only when explicitly
  requested), and
* the GitHub Actions current-month billing usage adapter (live only when
  explicitly requested).
* the free cloud/SaaS catalog and its bounded quota coverage projection.

``costs`` is a retired section (no finance ledger in the control plane), while ``usage`` contains
provider-specific read-only signals and catalog-backed free-quota coverage.
Vercel billing charges are kept separate
from the local ledger and only appear when the official billing endpoint
returns successfully.  The R2 projection may include a storage-only estimate
from a public rate snapshot, but it excludes provider billing reconciliation.
No provider mutation or lake/database write is performed.

Usage:
    python3 cloud_usage.py --json
    python3 cloud_usage.py --json --live
"""

from __future__ import annotations

import argparse
import json
import os
import math
import re
import sys
from collections import defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
UTILS_DIR = SCRIPT_DIR
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(UTILS_DIR))

from platform_output import configure_utf8_stdio  # noqa: E402
from _env import PROJECT_ROOT  # noqa: E402
from cloudflare_r2_usage import empty_result as empty_r2_result  # noqa: E402
from cloudflare_r2_usage import run_metrics as run_r2_metrics  # noqa: E402
from cloud_providers import get_provider, secret_names  # noqa: E402
from free_quota import build_projection as build_free_quota_projection  # noqa: E402
from github_actions_usage import empty_result as empty_github_actions_result  # noqa: E402
from github_actions_usage import run_usage as run_github_actions_usage  # noqa: E402
from paas_inventory import run_inventory  # noqa: E402
from vercel_billing import empty_result as empty_vercel_billing_result  # noqa: E402
from vercel_billing import run_billing as run_vercel_billing  # noqa: E402


SCHEMA_VERSION = "solo-empire.cloud-usage.v1"
# Account metadata lives in the bookchaowalit/accounts repository; point SOLO_ACCOUNTS_ROOT at a
# checkout (default: ``accounts/`` is absent, so the account section is empty).
ACCOUNTS_REPO = Path(os.environ.get("SOLO_ACCOUNTS_ROOT") or PROJECT_ROOT / "accounts")
ACCOUNT_ROOT = ACCOUNTS_REPO / "accounts" / "cloud"
VERCEL_SECRET_NAMES = secret_names(get_provider("vercel"))
GITHUB_SECRET_NAMES = secret_names(get_provider("github"))
SAFE_ERROR_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
SAFE_LABEL_PATTERN = re.compile(r"[^A-Za-z0-9 ._:/+()&'-]+")
SAFE_TIMESTAMP_PATTERN = re.compile(r"^[0-9T:Z+.-]{1,40}$")
SAFE_AUTH_SOURCES = {"not_checked", "secret_manager", "env", "cli_session"}
SAFE_VERCEL_ACTIONS = {
    "run_live_check",
    "configure_vercel_token",
    "install_vercel_cli",
    "run_vercel_login",
    "retry_vercel_auth",
    "cli_session_token_unavailable",
    "restore_secret_provider_session",
    "rotate_vercel_token",
    "verify_vercel_billing_scope",
    "inspect_vercel_api_status",
    "fix_vercel_team_scope",
    "fix_billing_window",
    "retry_vercel_read",
    "inspect_vercel_error",
    "none",
}
SAFE_GITHUB_ACTIONS_ACTIONS = {
    "run_live_check",
    "configure_github_token",
    "install_github_cli",
    "run_gh_auth_login",
    "retry_github_auth",
    "cli_session_token_unavailable",
    "restore_secret_provider_session",
    "rotate_github_token",
    "verify_github_billing_scope",
    "verify_github_enhanced_billing",
    "inspect_github_billing_window",
    "configure_github_billing_owner",
    "configure_github_billing_owner_type",
    "configure_github_actions_plan",
    "retry_github_read",
    "inspect_github_actions_error",
    "none",
}
SAFE_GITHUB_ACTIONS_PLANS = {
    "free",
    "pro",
    "free_for_organizations",
    "team",
    "enterprise_cloud",
}


def _safe_scalar(value: Any) -> str | int | float | bool | None:
    """Convert YAML/SQLite scalar values into safe JSON primitives."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)


def _number_or_none(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_optional_non_negative_number(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    number = _number_or_none(value)
    if number is None or not math.isfinite(number) or number < 0:
        return None
    if number.is_integer():
        return int(number)
    return round(number, 6)


def _provider_id(value: Any) -> str:
    return str(value or "unknown").strip().lower().replace("_", "-").replace(" ", "-")


def _safe_non_negative_number(value: Any, fallback: int | float = 0) -> int | float:
    """Keep provider-derived numeric projections finite and non-negative."""
    if isinstance(value, bool) or value is None or value == "":
        return fallback
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    if not math.isfinite(number) or number < 0:
        return fallback
    if number.is_integer():
        return int(number)
    return round(number, 6)


def _safe_status(value: Any, fallback: str, allowed: set[str]) -> str:
    candidate = str(value or "").strip()
    return candidate if candidate in allowed else fallback


def _safe_auth_source(value: Any) -> str | None:
    candidate = str(value or "").strip()
    return candidate if candidate in SAFE_AUTH_SOURCES else None


def _safe_error_class(value: Any, fallback: str) -> str:
    candidate = str(value or "").strip()
    if candidate == "SecretResolutionError":
        return "secret_provider_unreachable"
    if candidate == "SecretUnavailable":
        return "secret_not_found"
    return candidate if SAFE_ERROR_PATTERN.fullmatch(candidate) else fallback


def _safe_vercel_action(value: Any, fallback: str) -> str:
    candidate = str(value or "").strip()
    return candidate if candidate in SAFE_VERCEL_ACTIONS else fallback


def _safe_github_actions_action(value: Any, fallback: str) -> str:
    candidate = str(value or "").strip()
    return candidate if candidate in SAFE_GITHUB_ACTIONS_ACTIONS else fallback


def _safe_cost_number(value: Any, fallback: int | float = 0) -> int | float:
    """Keep signed provider costs finite without exposing arbitrary numbers."""
    if isinstance(value, bool) or value is None or value == "":
        return fallback
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    if not math.isfinite(number) or abs(number) > 1_000_000_000_000:
        return fallback
    if number.is_integer():
        return int(number)
    return round(number, 6)


def _safe_public_label(value: Any, fallback: str = "unknown") -> str:
    candidate = " ".join(str(value or "").split())
    candidate = SAFE_LABEL_PATTERN.sub("", candidate).strip()[:96]
    return candidate or fallback


def _safe_currency_map(value: Any) -> dict[str, int | float]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, int | float] = {}
    for raw_currency, raw_amount in value.items():
        currency = str(raw_currency or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{3,8}", currency):
            continue
        result[currency] = _safe_cost_number(raw_amount)
    return {key: result[key] for key in sorted(result)}


def _safe_timestamp(value: Any, fallback: str | None = None) -> str | None:
    candidate = str(value or "").strip()
    return candidate if SAFE_TIMESTAMP_PATTERN.fullmatch(candidate) else fallback


def _account_records(account_root: Path = ACCOUNT_ROOT) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Read only allow-listed account metadata; never return secret-shaped fields."""
    try:
        import yaml
    except ImportError:
        return [], [{"source": "accounts/cloud", "error_class": "yaml_unavailable"}]

    records: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if not account_root.is_dir():
        return records, errors

    for path in sorted(account_root.glob("**/account.y*ml")):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(payload, dict):
                raise ValueError("account_metadata_not_mapping")
            relative = path.relative_to(account_root.parent.parent)
            parts = relative.parts
            lane = parts[2] if len(parts) > 2 else "unknown"
            directory_provider = parts[3] if len(parts) > 3 else "unknown"
            resources = payload.get("resources")
            records.append(
                {
                    # The relative metadata reference is intentionally less
                    # sensitive than account_name/account_id/endpoints.
                    "metadata_ref": "/".join(relative.parts),
                    "lane": lane,
                    "provider": _provider_id(payload.get("provider") or directory_provider),
                    "plan_type": _safe_scalar(payload.get("plan_type")),
                    "status": _safe_scalar(payload.get("status")) or "unknown",
                    "budget_guard": _safe_scalar(payload.get("budget_guard")),
                    "monthly_budget_usd": _number_or_none(payload.get("monthly_budget_usd")),
                    "review_on": _safe_scalar(payload.get("review_on") or payload.get("quota_review_on")),
                    "resource_hint_count": len(resources) if isinstance(resources, dict) else 0,
                }
            )
        except Exception as exc:
            errors.append({"source": str(path.relative_to(account_root.parent.parent)), "error_class": type(exc).__name__})
    return records, errors


def _costs_section() -> dict[str, Any]:
    """Costs are no longer read from the control plane: the finance ledger left SQLite on 2026-10-11."""
    return {
        "status": "unavailable",
        "basis": "finance_ledger_retired",
        "planned_monthly_equivalent": {},
        "actual_paid_by_currency": {},
        "inventory": {"total": 0, "active": 0, "trial": 0},
        "linked_payment_count": 0,
    }


def _inventory_summary(
    live: bool,
    inventory_runner: Callable[..., dict[str, Any]] = run_inventory,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    errors: list[dict[str, str]] = []
    try:
        payload = inventory_runner(live=live)
    except Exception as exc:
        return (
            {
                "schema_version": "solo-empire.paas-inventory.v1",
                "mode": "live" if live else "offline",
                "providers": [],
                "summary": {
                    "providers": 0,
                    "healthy": 0,
                    "configured": 0,
                    "not_configured": 0,
                    "errors": 1,
                    "resources": 0,
                    "partial_providers": 0,
                    "has_more": False,
                    "total_known": False,
                },
            },
            [{"source": "paas_inventory", "error_class": _safe_error_class(type(exc).__name__, "provider_error")}],
        )

    providers: list[dict[str, Any]] = []
    for item in payload.get("providers", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        summary = item.get("summary") if isinstance(item.get("summary"), dict) else {}
        resource_count = int(summary.get("resources") or 0)
        partial = bool(item.get("partial") or summary.get("partial"))
        has_more = bool(item.get("has_more") or summary.get("has_more"))
        total_known = bool(summary.get("total_known", not partial))
        provider = {
            "id": _provider_id(item.get("id")),
            "name": _safe_scalar(item.get("name")) or _provider_id(item.get("id")),
            "status": _safe_scalar(item.get("status")) or "unknown",
            "resource_count": resource_count,
            "partial": partial,
            "has_more": has_more,
            "total_known": total_known,
            "dashboard_url": _safe_scalar(item.get("dashboard_url")),
        }
        if item.get("status") == "error":
            provider["error_class"] = _safe_error_class(item.get("error_class"), "provider_error")
        if item.get("status") == "not_configured":
            provider["credential_state"] = _safe_scalar(item.get("credential_state")) or "not_configured"
        elif item.get("status") == "configured":
            provider["credential_state"] = "configured"
        elif item.get("status") == "healthy":
            provider["credential_state"] = "verified_read_only"
        providers.append(provider)

    summary = payload.get("summary") if isinstance(payload, dict) and isinstance(payload.get("summary"), dict) else {}
    normalized = {
        "schema_version": payload.get("schema_version", "solo-empire.paas-inventory.v1") if isinstance(payload, dict) else "solo-empire.paas-inventory.v1",
        "mode": "live" if live else "offline",
        "providers": providers,
        "summary": {
            "providers": len(providers),
            "healthy": int(summary.get("healthy") or sum(item["status"] == "healthy" for item in providers)),
            "configured": int(summary.get("configured") or sum(item["status"] == "configured" for item in providers)),
            "not_configured": int(summary.get("not_configured") or sum(item["status"] == "not_configured" for item in providers)),
            "errors": int(summary.get("errors") or sum(item["status"] == "error" for item in providers)),
            "resources": int(summary.get("resources") or sum(item["resource_count"] for item in providers)),
            "partial_providers": sum(bool(item.get("partial")) for item in providers),
            "has_more": any(bool(item.get("has_more")) for item in providers),
            "total_known": bool(providers) and all(bool(item.get("total_known", True)) for item in providers),
        },
    }
    return normalized, errors


def _r2_summary(
    live: bool,
    metrics_runner: Callable[..., dict[str, Any]] = run_r2_metrics,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Keep only the allow-listed aggregate fields from the R2 adapter."""
    errors: list[dict[str, str]] = []
    try:
        payload = metrics_runner(live=live)
    except Exception as exc:
        return empty_r2_result(live=live), [{"source": "cloudflare_r2_usage", "error_class": _safe_error_class(type(exc).__name__, "provider_error")}]

    fallback = empty_r2_result(live=live)
    if not isinstance(payload, dict):
        return fallback, [{"source": "cloudflare_r2_usage", "error_class": "invalid_adapter_result"}]

    metric_fields = ("metadata_bytes", "object_count", "payload_bytes", "payload_gib")
    storage_classes: dict[str, dict[str, dict[str, int | float]]] = {}
    raw_classes = payload.get("storage_classes") if isinstance(payload.get("storage_classes"), dict) else {}
    for class_id in ("standard", "infrequent_access"):
        raw_class = raw_classes.get(class_id) if isinstance(raw_classes.get(class_id), dict) else {}
        storage_classes[class_id] = {}
        for state in ("published", "uploaded"):
            raw_group = raw_class.get(state) if isinstance(raw_class.get(state), dict) else {}
            storage_classes[class_id][state] = {
                field: _safe_non_negative_number(raw_group.get(field, 0))
                for field in metric_fields
            }

    fallback_estimate = fallback["storage_cost_estimate"]
    raw_estimate = payload.get("storage_cost_estimate") if isinstance(payload.get("storage_cost_estimate"), dict) else {}
    estimate_components: dict[str, dict[str, int | float]] = {}
    for component_id in ("standard", "infrequent_access"):
        fallback_component = fallback_estimate[component_id]
        raw_component = raw_estimate.get(component_id) if isinstance(raw_estimate.get(component_id), dict) else {}
        estimate_components[component_id] = {
            field: _safe_non_negative_number(raw_component.get(field), fallback_component[field])
            for field in (
                "payload_gb",
                "free_gb_month",
                "billable_gb_month",
                "rate_usd_per_gb_month",
                "estimated_usd",
            )
        }
    normalized_estimate = {
        "status": _safe_status(
            raw_estimate.get("status"),
            fallback_estimate["status"],
            {"estimate_only", "not_checked", "unavailable"},
        ),
        "currency": "USD",
        "estimated_usd": _safe_non_negative_number(
            raw_estimate.get("estimated_usd"), fallback_estimate["estimated_usd"]
        ),
        "basis": fallback_estimate["basis"],
        "pricing_source": fallback_estimate["pricing_source"],
        "pricing_verified_at": fallback_estimate["pricing_verified_at"],
        "includes_operations": False,
        "includes_data_retrieval": False,
        "egress_assumed_free": True,
        **estimate_components,
    }

    normalized = {
        "schema_version": fallback["schema_version"],
        "provider": "cloudflare",
        "product": "r2",
        "mode": "live" if live else "offline",
        "status": _safe_status(
            payload.get("status"),
            fallback["status"],
            {"healthy", "not_checked", "not_configured", "error", "unavailable"},
        ),
        "credential_state": _safe_status(
            payload.get("credential_state"),
            fallback["credential_state"],
            {"verified_read_only", "not_checked", "not_configured", "error", "unknown"},
        ),
        "metric_scope": "account_all_buckets",
        "metric_source": "cloudflare_r2_account_metrics",
        "metric_freshness": "provider_reported_may_lag",
        "billing_connected": False,
        "read_only": True,
        "execution_enabled": False,
        "write_attempted": False,
        "object_count": _safe_non_negative_number(payload.get("object_count")),
        "payload_bytes": _safe_non_negative_number(payload.get("payload_bytes")),
        "payload_gib": _safe_non_negative_number(payload.get("payload_gib")),
        "metadata_bytes": _safe_non_negative_number(payload.get("metadata_bytes")),
        "uploaded_object_count": _safe_non_negative_number(payload.get("uploaded_object_count")),
        "uploaded_payload_bytes": _safe_non_negative_number(payload.get("uploaded_payload_bytes")),
        "uploaded_payload_gib": _safe_non_negative_number(payload.get("uploaded_payload_gib")),
        "storage_cost_estimate": normalized_estimate,
        "storage_classes": storage_classes,
    }
    if normalized["status"] == "error":
        normalized["error_class"] = _safe_error_class(payload.get("error_class"), "provider_error")
        errors.append({"source": "cloudflare_r2_usage", "error_class": normalized["error_class"]})
    elif live and normalized["status"] == "not_configured":
        errors.append({"source": "cloudflare_r2_usage", "error_class": "credentials_not_configured"})
    return normalized, errors


def _vercel_billing_summary(
    live: bool,
    billing_runner: Callable[..., dict[str, Any]] = run_vercel_billing,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Keep only bounded, allow-listed Vercel billing aggregates."""
    errors: list[dict[str, str]] = []
    try:
        payload = billing_runner(live=live)
    except Exception as exc:
        return empty_vercel_billing_result(live=live), [{"source": "vercel_billing", "error_class": _safe_error_class(type(exc).__name__, "provider_error")}]

    fallback = empty_vercel_billing_result(live=live)
    if not isinstance(payload, dict):
        return fallback, [{"source": "vercel_billing", "error_class": "invalid_adapter_result"}]

    raw_window = payload.get("window") if isinstance(payload.get("window"), dict) else {}
    window = {
        "from": _safe_timestamp(raw_window.get("from"), fallback["window"]["from"]),
        "to": _safe_timestamp(raw_window.get("to"), fallback["window"]["to"]),
    }
    service_breakdown: list[dict[str, Any]] = []
    raw_services = payload.get("service_breakdown") if isinstance(payload.get("service_breakdown"), list) else []
    for raw_service in raw_services[:100]:
        if not isinstance(raw_service, dict):
            continue
        currency = str(raw_service.get("currency") or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{3,8}", currency):
            continue
        service_breakdown.append(
            {
                "service_name": _safe_public_label(raw_service.get("service_name")),
                "charge_category": _safe_public_label(raw_service.get("charge_category")),
                "currency": currency,
                "charge_count": _safe_non_negative_number(raw_service.get("charge_count")),
                "billed_cost": _safe_cost_number(raw_service.get("billed_cost")),
                "effective_cost": _safe_cost_number(raw_service.get("effective_cost")),
            }
        )

    status = _safe_status(
        payload.get("status"),
        fallback["status"],
        {"healthy", "not_checked", "not_configured", "error"},
    )
    normalized = {
        "schema_version": fallback["schema_version"],
        "provider": "vercel",
        "product": "billing",
        "mode": "live" if live else "offline",
        "status": status,
        "credential_state": _safe_status(
            payload.get("credential_state"),
            fallback["credential_state"],
            {"verified_read_only", "not_checked", "not_configured", "error", "unknown"},
        ),
        "metric_scope": "billing_charges_window",
        "metric_source": "vercel_billing_charges_focus",
        "focus_version": "1.3",
        "response_format": "jsonl",
        "window": window,
        "account_scope": _safe_public_label(payload.get("account_scope"), fallback["account_scope"]),
        "auth_source": _safe_auth_source(payload.get("auth_source")),
        "required_secret_names": list(VERCEL_SECRET_NAMES),
        "team_scope_configured": bool(payload.get("team_scope_configured")) if isinstance(payload.get("team_scope_configured"), bool) else False,
        "billing_access_scope": _safe_public_label(payload.get("billing_access_scope"), "pro_or_enterprise_team"),
        "next_action": _safe_vercel_action(payload.get("next_action"), fallback["next_action"]),
        "billing_connected": status == "healthy",
        "read_only": True,
        "execution_enabled": False,
        "write_attempted": False,
        "charge_count": _safe_non_negative_number(payload.get("charge_count")),
        "billed_cost_by_currency": _safe_currency_map(payload.get("billed_cost_by_currency")),
        "effective_cost_by_currency": _safe_currency_map(payload.get("effective_cost_by_currency")),
        "service_breakdown": service_breakdown,
    }
    if status == "error":
        normalized["error_class"] = _safe_error_class(payload.get("error_class"), "provider_error")
        errors.append({"source": "vercel_billing", "error_class": normalized["error_class"]})
    elif live and status == "not_configured":
        normalized["error_class"] = _safe_error_class(payload.get("error_class"), "credentials_not_configured")
        errors.append({"source": "vercel_billing", "error_class": normalized["error_class"]})
    return normalized, errors


def _github_actions_summary(
    live: bool,
    usage_runner: Callable[..., dict[str, Any]] = run_github_actions_usage,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Keep only bounded GitHub Actions current-month aggregates."""
    errors: list[dict[str, str]] = []
    try:
        payload = usage_runner(live=live)
    except Exception as exc:
        return empty_github_actions_result(live=live), [{"source": "github_actions_usage", "error_class": _safe_error_class(type(exc).__name__, "provider_error")}]

    fallback = empty_github_actions_result(live=live)
    if not isinstance(payload, dict):
        return fallback, [{"source": "github_actions_usage", "error_class": "invalid_adapter_result"}]

    raw_window = payload.get("window") if isinstance(payload.get("window"), dict) else {}
    window: dict[str, Any] = {
        "year": _safe_optional_non_negative_number(raw_window.get("year")),
        "month": _safe_optional_non_negative_number(raw_window.get("month")),
        "from": _safe_timestamp(raw_window.get("from")),
        "to": _safe_timestamp(raw_window.get("to")),
    }
    raw_allowance = payload.get("free_allowance") if isinstance(payload.get("free_allowance"), dict) else None
    allowance = None
    if raw_allowance is not None:
        allowance = {
            "minutes": _safe_optional_non_negative_number(raw_allowance.get("minutes")),
            "artifact_storage_gb": _safe_optional_non_negative_number(raw_allowance.get("artifact_storage_gb")),
            "cache_storage_gb": _safe_optional_non_negative_number(raw_allowance.get("cache_storage_gb")),
        }
    raw_owner_type = str(payload.get("owner_type") or "user").strip().lower()
    owner_type = raw_owner_type if raw_owner_type in {"user", "organization"} else "user"
    raw_plan = str(payload.get("plan") or "").strip()
    plan = raw_plan if raw_plan in SAFE_GITHUB_ACTIONS_PLANS else None
    status = _safe_status(
        payload.get("status"),
        fallback["status"],
        {"healthy", "not_checked", "not_configured", "error"},
    )
    normalized = {
        "schema_version": fallback["schema_version"],
        "provider": "github",
        "product": "actions",
        "mode": "live" if live else "offline",
        "status": status,
        "credential_state": _safe_status(
            payload.get("credential_state"),
            fallback["credential_state"],
            {"verified_read_only", "not_checked", "not_configured", "error", "unknown"},
        ),
        "metric_scope": "current_utc_month",
        "metric_source": "github_billing_usage_report",
        "billing_url": "https://docs.github.com/en/rest/billing/usage",
        "allowance_url": "https://docs.github.com/en/billing/reference/product-usage-included",
        "api_version": "2026-03-10",
        "window": window,
        "owner_type": owner_type,
        "owner_configured": bool(payload.get("owner_configured")) if isinstance(payload.get("owner_configured"), bool) else False,
        "plan": plan,
        "free_allowance": allowance,
        "required_secret_names": list(GITHUB_SECRET_NAMES),
        "required_config_names": [name for name in payload.get("required_config_names", []) if name in {"GITHUB_BILLING_OWNER", "GITHUB_BILLING_OWNER_TYPE", "GITHUB_ACTIONS_PLAN"}] if isinstance(payload.get("required_config_names"), list) else [],
        "auth_source": _safe_auth_source(payload.get("auth_source")),
        "next_action": _safe_github_actions_action(payload.get("next_action"), fallback["next_action"]),
        "read_only": True,
        "execution_enabled": False,
        "write_attempted": False,
        "usage_items_count": _safe_optional_non_negative_number(payload.get("usage_items_count")),
        "actions_rows": _safe_optional_non_negative_number(payload.get("actions_rows")),
        "actions_minutes": _safe_optional_non_negative_number(payload.get("actions_minutes")),
        "actions_artifact_storage_gb_hours": _safe_optional_non_negative_number(payload.get("actions_artifact_storage_gb_hours")),
        "actions_cache_storage_gb_hours": _safe_optional_non_negative_number(payload.get("actions_cache_storage_gb_hours")),
        "actions_other_quantity": _safe_optional_non_negative_number(payload.get("actions_other_quantity")),
    }
    if status == "error":
        normalized["error_class"] = _safe_error_class(payload.get("error_class"), "provider_error")
        errors.append({"source": "github_actions_usage", "error_class": normalized["error_class"]})
    elif live and status == "not_configured":
        normalized["error_class"] = _safe_error_class(payload.get("error_class"), "credentials_not_configured")
        errors.append({"source": "github_actions_usage", "error_class": normalized["error_class"]})
    return normalized, errors


def build_snapshot(
    *,
    live: bool = False,
    account_root: Path = ACCOUNT_ROOT,
    inventory_runner: Callable[..., dict[str, Any]] = run_inventory,
    r2_metrics_runner: Callable[..., dict[str, Any]] = run_r2_metrics,
    vercel_billing_runner: Callable[..., dict[str, Any]] = run_vercel_billing,
    github_actions_runner: Callable[..., dict[str, Any]] = run_github_actions_usage,
) -> dict[str, Any]:
    """Return the public contract used by the dashboard/API."""
    inventory, inventory_errors = _inventory_summary(live, inventory_runner)
    accounts, account_errors = _account_records(account_root)
    costs = _costs_section()
    r2_usage, r2_errors = _r2_summary(live, r2_metrics_runner)
    vercel_billing, vercel_billing_errors = _vercel_billing_summary(live, vercel_billing_runner)
    github_actions, github_actions_errors = _github_actions_summary(live, github_actions_runner)
    free_quota, free_quota_errors = build_free_quota_projection(
        live=live,
        inventory=inventory,
        r2_usage=r2_usage,
        github_actions_usage=github_actions,
    )

    account_by_provider: dict[str, int] = defaultdict(int)
    for account in accounts:
        account_by_provider[account["provider"]] += 1
    providers = []
    for provider in inventory["providers"]:
        item = dict(provider)
        item["account_record_count"] = account_by_provider.get(provider["id"], 0)
        providers.append(item)

    resource_count = int(inventory["summary"]["resources"])
    healthy_count = int(inventory["summary"]["healthy"])
    all_errors = inventory_errors + account_errors + r2_errors + vercel_billing_errors + github_actions_errors + free_quota_errors
    r2_connected = r2_usage["status"] == "healthy"
    vercel_billing_connected = vercel_billing["status"] == "healthy"
    github_actions_connected = github_actions["status"] == "healthy"
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "live" if live else "offline",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "execution_enabled": False,
        "write_attempted": False,
        "scope": {
            "usage": "bounded PaaS resource inventory plus Cloudflare R2 and GitHub Actions current-month metrics",
            "cost": "not reported: the finance subscription ledger left the control plane on 2026-10-11",
            "account_metadata": "non-secret allow-list under accounts/cloud",
            "provider_metrics": "Cloudflare R2 aggregate storage/object metrics only; provider-reported freshness may lag",
            "provider_billing": "Vercel FOCUS billing charges in the requested read-only window when live and authorized",
            "github_actions_usage": "GitHub billing usage report for the current UTC month when live and authorized",
            "free_quota": "catalog limits for free-forever/free-quota services plus observed values from supported adapters",
        },
        "accounts": accounts,
        "inventory": {**inventory, "providers": providers},
        "costs": costs,
        "usage": {
            "status": "verified_read_only_signal" if live and (healthy_count or r2_connected or vercel_billing_connected or github_actions_connected) else "inventory_not_connected",
            "resource_count": resource_count,
            "healthy_provider_count": healthy_count,
            "billing_api_connected": vercel_billing_connected,
            "provider_usage_cost_connected": r2_connected or vercel_billing_connected,
            "r2_connected": r2_connected,
            "r2_object_count": int(r2_usage["object_count"]),
            "r2_payload_gib": float(r2_usage["payload_gib"]),
            "cloudflare_r2": r2_usage,
            "vercel_billing_connected": vercel_billing_connected,
            "vercel_charge_count": int(vercel_billing["charge_count"]),
            "vercel_billed_cost_by_currency": vercel_billing["billed_cost_by_currency"],
            "vercel_billing": vercel_billing,
            "github_actions_connected": github_actions_connected,
            "github_actions_minutes": github_actions["actions_minutes"],
            "github_actions": github_actions,
            "free_quota": free_quota,
        },
        "summary": {
            "account_records": len(accounts),
            "providers": int(inventory["summary"]["providers"]),
            "healthy_providers": healthy_count,
            "resource_count": resource_count,
            "known_monthly_currencies": sorted(costs.get("planned_monthly_equivalent", {})),
            "r2_status": r2_usage["status"],
            "r2_object_count": int(r2_usage["object_count"]),
            "r2_payload_gib": float(r2_usage["payload_gib"]),
            "vercel_billing_status": vercel_billing["status"],
            "vercel_charge_count": int(vercel_billing["charge_count"]),
            "vercel_billed_cost_by_currency": vercel_billing["billed_cost_by_currency"],
            "github_actions_status": github_actions["status"],
            "github_actions_minutes": github_actions["actions_minutes"],
            "attention_count": len(all_errors) + int(inventory["summary"]["not_configured"]) + int(inventory["summary"]["errors"]),
        },
        "lineage": [
            {"source": "adapters/paas_inventory.py", "mode": "live" if live else "offline"},
            {"source": "adapters/cloudflare_r2_usage.py", "mode": "live" if live else "offline_no_credentials"},
            {"source": "adapters/vercel_billing.py", "mode": "live" if live else "offline_no_credentials"},
            {"source": "adapters/github_actions_usage.py", "mode": "live" if live else "offline_no_credentials"},
            {"source": "accounts/cloud", "mode": "nonsecret_metadata"},
        ],
        "errors": all_errors,
    }


def main(argv: list[str] | None = None) -> int:
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print the structured snapshot")
    parser.add_argument("--live", action="store_true", help="perform bounded provider read-only inventory")
    args = parser.parse_args(argv)
    print(json.dumps(build_snapshot(live=args.live), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
