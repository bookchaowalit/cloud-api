#!/usr/bin/env python3
"""Build a sanitized free-quota coverage projection.

The free-resource catalog is a reference source for plan limits.  Provider
usage is reported only when a bounded adapter returns an observed value.  A
catalog row without an adapter is deliberately marked ``reference_only`` so
the dashboard never turns an unknown usage value into zero.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "solo-empire.free-quota.v1"
CATALOG_PATH = (
    Path(__file__).resolve().parents[1] / "registry" / "free-resource-index.json"
)
FREE_ACCESS_MODELS = {"free-forever", "free-quota"}


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in (float("inf"), float("-inf")) or number < 0:  # noqa: PLR0124 - NaN check
        return None
    return int(number) if number.is_integer() else round(number, 6)


def _catalog_rows(
    catalog_path: Path = CATALOG_PATH,
) -> tuple[list[dict[str, Any]], str | None, str | None]:
    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], type(exc).__name__, None
    resources = payload.get("resources") if isinstance(payload, dict) else None
    if not isinstance(resources, list):
        return [], "invalid_catalog", None
    rows = [
        row
        for row in resources
        if isinstance(row, dict)
        and row.get("access_model") in FREE_ACCESS_MODELS
        and row.get("category") != "learning"
    ]
    updated = (
        str(payload.get("updated") or "").strip() if isinstance(payload, dict) else ""
    )
    return rows, None, updated or None


def _inventory_status(
    provider: str, inventory: dict[str, Any], *, live: bool
) -> tuple[str, str]:
    providers = inventory.get("providers") if isinstance(inventory, dict) else []
    if not isinstance(providers, list):
        return "reference_only", "no_provider_inventory"
    match = next(
        (
            item
            for item in providers
            if isinstance(item, dict) and item.get("id") == provider
        ),
        None,
    )
    if match is None:
        return "reference_only", "no_usage_adapter"
    status = str(match.get("status") or "unknown")
    if not live and match.get("credential_state") == "not_checked":
        return "reference_only", "offline_check_skipped"
    if status == "healthy":
        return "reference_only", "inventory_only"
    if status == "configured":
        return "reference_only", "usage_adapter_pending"
    if status == "not_configured":
        return "not_configured", "provider_credential_missing"
    if status == "error":
        return "unavailable", str(match.get("error_class") or "provider_error")
    return "reference_only", "provider_not_checked"


def _r2_row(r2_usage: dict[str, Any]) -> dict[str, Any]:
    status = str(r2_usage.get("status") or "unavailable")
    result: dict[str, Any] = {
        "status": "reference_only",
        "coverage": "reference",
        "status_reason": "r2_usage_adapter_not_connected",
        "observed": None,
        "quota": {
            "metric": "standard_storage",
            "limit": 10,
            "unit": "GB-month",
            "period": "monthly",
            "source": "https://developers.cloudflare.com/r2/pricing/",
        },
    }
    if status == "healthy":
        estimate = (
            r2_usage.get("storage_cost_estimate")
            if isinstance(r2_usage.get("storage_cost_estimate"), dict)
            else {}
        )
        standard = (
            estimate.get("standard")
            if isinstance(estimate.get("standard"), dict)
            else {}
        )
        used = _number(standard.get("payload_gb"))
        if used is not None:
            limit = _number(standard.get("free_gb_month")) or 10
            remaining = max(limit - float(used), 0)
            result["quota"]["limit"] = limit
            result.update(
                {
                    "status": "usage_available",
                    "coverage": "partial",
                    "status_reason": "storage_metric_only",
                    "observed": {
                        "metric": "standard_storage",
                        "used": used,
                        "remaining": int(remaining)
                        if remaining.is_integer()
                        else round(remaining, 6),
                        "unit": "GB-month",
                        "percent": round(min(float(used) / limit * 100, 100), 2),
                    },
                }
            )
        else:
            result["status_reason"] = "storage_metric_missing"
    elif status == "not_configured":
        result.update(
            {
                "status": "not_configured",
                "coverage": "none",
                "status_reason": "provider_credential_missing",
            }
        )
    elif status == "error":
        result.update(
            {
                "status": "unavailable",
                "coverage": "none",
                "status_reason": str(r2_usage.get("error_class") or "provider_error"),
            }
        )
    return result


def _github_actions_row(actions_usage: dict[str, Any]) -> dict[str, Any]:
    """Project current-month Actions minutes without guessing the plan."""
    result: dict[str, Any] = {
        "status": "reference_only",
        "coverage": "reference",
        "status_reason": "github_actions_usage_adapter_not_connected",
        "observed": None,
        "quota": None,
    }
    status = str(actions_usage.get("status") or "not_checked")
    if status == "healthy":
        used = _number(actions_usage.get("actions_minutes"))
        allowance = (
            actions_usage.get("free_allowance")
            if isinstance(actions_usage.get("free_allowance"), dict)
            else {}
        )
        limit = _number(allowance.get("minutes"))
        if used is not None:
            observed: dict[str, Any] = {
                "metric": "actions_minutes",
                "used": used,
                "remaining": None,
                "unit": "minutes",
                "percent": None,
            }
            if limit is not None and limit > 0:
                remaining = max(limit - float(used), 0)
                observed["remaining"] = (
                    int(remaining) if remaining.is_integer() else round(remaining, 6)
                )
                observed["percent"] = round(min(float(used) / limit * 100, 100), 2)
                result.update(
                    {
                        "status": "usage_available",
                        "coverage": "partial",
                        "status_reason": "current_month_actions_minutes",
                        "observed": observed,
                        "quota": {
                            "metric": "actions_minutes",
                            "limit": limit,
                            "unit": "minutes",
                            "period": "monthly",
                            "source": "https://docs.github.com/en/billing/reference/product-usage-included",
                        },
                    }
                )
            else:
                result.update(
                    {
                        "coverage": "partial",
                        "status_reason": "plan_allowance_unknown",
                        "observed": observed,
                    }
                )
        else:
            result["status_reason"] = "actions_minutes_not_reported"
    elif status == "not_configured":
        result.update(
            {
                "status": "not_configured",
                "coverage": "none",
                "status_reason": "provider_credential_missing",
            }
        )
    elif status == "error":
        error_class = str(actions_usage.get("error_class") or "provider_error")
        result.update(
            {"status": "unavailable", "coverage": "none", "status_reason": error_class}
        )
    elif status == "not_checked":
        result["status_reason"] = "offline_check_skipped"
    return result


def build_projection(
    *,
    live: bool,
    inventory: dict[str, Any],
    r2_usage: dict[str, Any],
    github_actions_usage: dict[str, Any] | None = None,
    catalog_path: Path = CATALOG_PATH,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Return catalog-backed free-quota rows and sanitized collection errors."""
    rows, catalog_error, catalog_updated = _catalog_rows(catalog_path)
    errors: list[dict[str, str]] = []
    if catalog_error:
        errors.append({"source": "free_resource_catalog", "error_class": catalog_error})

    services: list[dict[str, Any]] = []
    actions_usage = (
        github_actions_usage
        if isinstance(github_actions_usage, dict)
        else {"status": "not_checked"}
    )
    for row in rows:
        provider = str(row.get("provider") or "unknown").strip().lower()
        service_id = str(row.get("id") or "unknown").strip()
        if service_id == "cloudflare-r2":
            signal = _r2_row(r2_usage)
        elif service_id == "github-actions":
            signal = _github_actions_row(actions_usage)
        else:
            status, reason = _inventory_status(provider, inventory, live=live)
            signal = {
                "status": status,
                "coverage": "reference" if status == "reference_only" else "none",
                "status_reason": reason,
                "observed": None,
                "quota": None,
            }
        services.append(
            {
                "id": service_id,
                "name": str(row.get("name") or service_id),
                "provider": provider,
                "category": str(row.get("category") or "unknown"),
                "access_model": str(row.get("access_model") or "unknown"),
                "free_notes": str(row.get("free_notes") or ""),
                "limits": str(row.get("limits") or ""),
                "official_url": str(row.get("official_url") or ""),
                "access_url": str(row.get("access_url") or ""),
                **signal,
            }
        )

    counts = {
        "total": len(services),
        "usage_available": 0,
        "reference_only": 0,
        "unavailable": 0,
        "not_configured": 0,
        "not_connected": 0,
    }
    for service in services:
        status = service["status"]
        if status in counts:
            counts[status] += 1
    return (
        {
            "schema_version": SCHEMA_VERSION,
            "mode": "live" if live else "offline",
            "status": "available" if not catalog_error else "unavailable",
            "source": "registry/free-resource-index.json",
            "catalog_updated": catalog_updated,
            "usage_policy": "observed values only; catalog limits are reference data",
            "services": services,
            "summary": counts,
        },
        errors,
    )


def empty_projection(*, live: bool = False) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "live" if live else "offline",
        "status": "unavailable",
        "source": "registry/free-resource-index.json",
        "catalog_updated": None,
        "usage_policy": "observed values only; catalog limits are reference data",
        "services": [],
        "summary": {
            "total": 0,
            "usage_available": 0,
            "reference_only": 0,
            "unavailable": 0,
            "not_configured": 0,
            "not_connected": 0,
        },
    }
