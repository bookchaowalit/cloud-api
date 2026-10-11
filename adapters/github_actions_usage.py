#!/usr/bin/env python3
"""Read-only GitHub Actions billing-usage adapter.

GitHub exposes a billing usage report for an authenticated user or
organization.  This adapter requests only the current UTC month, keeps the
response in memory, and returns allow-listed aggregate quantities.  It never
returns the owner login, repository names, raw usage items, or the token.

Usage:
    python3 github_actions_usage.py --json
    python3 github_actions_usage.py --json --live

The user endpoint is the default.  Set ``GITHUB_BILLING_OWNER_TYPE=organization``
and ``GITHUB_BILLING_OWNER`` when the Actions minutes are billed to an
organization.  ``GITHUB_ACTIONS_PLAN`` is optional; when GitHub does not
return a plan name, it can be set to one of ``free``, ``pro``,
``free_for_organizations``, ``team`` or ``enterprise_cloud`` to calculate the
documented free allowance.
"""

from __future__ import annotations

import argparse
import calendar
import json
import math
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from platform_output import configure_utf8_stdio  # noqa: E402
from auth_resolver import AuthResolution, resolve_provider_auth  # noqa: E402
from cloud_providers import get_provider, secret_names  # noqa: E402
from _env import get_env  # noqa: E402


SCHEMA_VERSION = "solo-empire.github-actions-usage.v1"
API_BASE = "https://api.github.com"
API_VERSION = "2026-03-10"
GITHUB_PROVIDER = get_provider("github")
GITHUB_SECRET_NAMES = secret_names(GITHUB_PROVIDER)
USER_AGENT = "solo-empire-github-actions-readonly/1.0"
BILLING_URL = "https://docs.github.com/en/rest/billing/usage"
ALLOWANCE_URL = "https://docs.github.com/en/billing/reference/product-usage-included"
OWNER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
PLAN_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
SAFE_ERROR_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
MAX_RESPONSE_BYTES = 2_000_000
MAX_USAGE_ITEMS = 5_000

# GitHub's published allowance table.  The plan is intentionally optional:
# an authenticated user/org response may omit it when the token lacks plan
# visibility, so unknown limits must stay unknown in the dashboard.
FREE_ALLOWANCES: dict[str, dict[str, int | float]] = {
    "free": {"minutes": 2_000, "artifact_storage_gb": 0.5, "cache_storage_gb": 10},
    "pro": {"minutes": 3_000, "artifact_storage_gb": 1, "cache_storage_gb": 10},
    "free_for_organizations": {"minutes": 2_000, "artifact_storage_gb": 0.5, "cache_storage_gb": 10},
    "team": {"minutes": 3_000, "artifact_storage_gb": 2, "cache_storage_gb": 10},
    "enterprise_cloud": {"minutes": 50_000, "artifact_storage_gb": 50, "cache_storage_gb": 10},
}
PLAN_ALIASES = {
    "github free": "free",
    "free": "free",
    "github pro": "pro",
    "pro": "pro",
    "github free for organizations": "free_for_organizations",
    "free for organizations": "free_for_organizations",
    "free_for_organizations": "free_for_organizations",
    "github team": "team",
    "team": "team",
    "github enterprise cloud": "enterprise_cloud",
    "enterprise cloud": "enterprise_cloud",
    "enterprise_cloud": "enterprise_cloud",
}


class AdapterError(RuntimeError):
    """Expected, safe adapter failure."""


def _safe_error(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 401:
            return "github_token_unauthorized"
        if exc.code == 403:
            return "github_billing_forbidden"
        if exc.code == 404:
            return "github_billing_endpoint_unavailable"
        if exc.code == 400:
            return "github_billing_bad_request"
        return f"http_{exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return "provider_unreachable"
    if isinstance(exc, TimeoutError):
        return "provider_timeout"
    name = type(exc).__name__
    if name == "SecretResolutionError":
        return "secret_provider_unreachable"
    if name == "SecretUnavailable":
        return "secret_not_found"
    return name if SAFE_ERROR_PATTERN.fullmatch(name) else "provider_error"


def _get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
            **(headers or {}),
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise AdapterError("github_response_too_large")
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("invalid_github_json") from exc


def _number(value: Any, *, maximum: float = 1_000_000_000_000) -> float | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0 or number > maximum:
        return None
    return int(number) if number.is_integer() else round(number, 6)


def _owner(value: Any) -> str | None:
    candidate = str(value or "").strip()
    return candidate if OWNER_PATTERN.fullmatch(candidate) else None


def _normalise_plan(value: Any) -> str | None:
    candidate = " ".join(str(value or "").strip().lower().split())
    alias = PLAN_ALIASES.get(candidate, candidate.replace(" ", "_"))
    return alias if PLAN_PATTERN.fullmatch(alias) and alias in FREE_ALLOWANCES else None


def _month_window(now: datetime | None = None) -> dict[str, int | str]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    year = current.year
    month = current.month
    last_day = calendar.monthrange(year, month)[1]
    return {
        "year": year,
        "month": month,
        "from": f"{year:04d}-{month:02d}-01",
        "to": f"{year:04d}-{month:02d}-{last_day:02d}",
    }


def _base(*, live: bool, window: dict[str, int | str] | None = None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "provider": "github",
        "product": "actions",
        "mode": "live" if live else "offline",
        "status": "not_checked" if not live else "not_configured",
        "credential_state": "not_checked" if not live else "not_configured",
        "metric_scope": "current_utc_month",
        "metric_source": "github_billing_usage_report",
        "billing_url": BILLING_URL,
        "allowance_url": ALLOWANCE_URL,
        "api_version": API_VERSION,
        "window": dict(window or {}),
        "owner_type": "user",
        "owner_configured": False,
        "plan": None,
        "free_allowance": None,
        "required_secret_names": list(GITHUB_SECRET_NAMES),
        "required_config_names": [],
        "auth_source": "not_checked" if not live else None,
        "next_action": "run_live_check" if not live else "configure_github_token",
        "read_only": True,
        "execution_enabled": False,
        "write_attempted": False,
        "usage_items_count": None,
        "actions_rows": None,
        "actions_minutes": None,
        "actions_artifact_storage_gb_hours": None,
        "actions_cache_storage_gb_hours": None,
        "actions_other_quantity": None,
    }


def empty_result(*, live: bool = False) -> dict[str, Any]:
    """Return a stable sanitized result for offline or unavailable states."""
    return _base(live=live)


def _next_action(error_class: str) -> str:
    return {
        "secret_provider_unreachable": "restore_secret_provider_session",
        "secret_not_found": "configure_github_token",
        "credentials_not_configured": "configure_github_token",
        "credential_unavailable": "configure_github_token",
        "cli_not_installed": "install_github_cli",
        "cli_session_not_authenticated": "run_gh_auth_login",
        "cli_session_timeout": "retry_github_auth",
        "cli_session_token_unavailable": "configure_github_token",
        "github_token_unauthorized": "rotate_github_token",
        "github_billing_forbidden": "verify_github_billing_scope",
        "github_billing_endpoint_unavailable": "verify_github_enhanced_billing",
        "github_billing_bad_request": "inspect_github_billing_window",
        "invalid_billing_owner": "configure_github_billing_owner",
        "missing_billing_owner": "configure_github_billing_owner",
        "invalid_billing_owner_type": "configure_github_billing_owner_type",
        "invalid_actions_plan": "configure_github_actions_plan",
        "provider_timeout": "retry_github_read",
        "provider_unreachable": "retry_github_read",
    }.get(error_class, "inspect_github_actions_error")


def _error_result(
    error_class: str,
    *,
    window: dict[str, int | str],
    owner_type: str = "user",
    owner_configured: bool = False,
    plan: str | None = None,
    auth_source: str | None = None,
) -> dict[str, Any]:
    result = _base(live=True, window=window)
    result.update(
        {
            "status": "error",
            "credential_state": "error",
            "owner_type": owner_type,
            "owner_configured": owner_configured,
            "plan": plan,
            "auth_source": auth_source,
            "error_class": error_class if SAFE_ERROR_PATTERN.fullmatch(error_class) else "provider_error",
            "next_action": _next_action(error_class),
        }
    )
    return result


def _classify_row(item: dict[str, Any]) -> tuple[str, float] | None:
    product = str(item.get("product") or "").strip().lower()
    if product != "actions":
        return None
    quantity = _number(item.get("quantity"))
    if quantity is None:
        quantity = _number(item.get("grossQuantity"))
    if quantity is None:
        quantity = _number(item.get("netQuantity"))
    if quantity is None:
        return None
    sku = str(item.get("sku") or "").strip().lower()
    unit = str(item.get("unitType") or "").strip().lower().replace("_", "-")
    if "minute" in unit or "minute" in sku:
        return "minutes", float(quantity)
    if "cache" in sku:
        return "cache_storage_gb_hours", float(quantity)
    if "storage" in sku or "gb-hour" in unit or "gbhour" in unit:
        return "artifact_storage_gb_hours", float(quantity)
    return "other", float(quantity)


def _aggregate(payload: Any, *, owner_type: str, owner_configured: bool, plan: str | None, window: dict[str, int | str]) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("usageItems"), list):
        raise AdapterError("invalid_github_usage_response")
    items = payload["usageItems"]
    if len(items) > MAX_USAGE_ITEMS:
        raise AdapterError("github_usage_item_limit_exceeded")
    totals = {
        "minutes": 0.0,
        "artifact_storage_gb_hours": 0.0,
        "cache_storage_gb_hours": 0.0,
        "other": 0.0,
    }
    actions_rows = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        classified = _classify_row(item)
        if classified is None:
            continue
        metric, quantity = classified
        actions_rows += 1
        totals[metric] += quantity

    allowance = dict(FREE_ALLOWANCES[plan]) if plan else None
    result = _base(live=True, window=window)
    result.update(
        {
            "status": "healthy",
            "credential_state": "verified_read_only",
            "owner_type": owner_type,
            "owner_configured": owner_configured,
            "plan": plan,
            "free_allowance": allowance,
            "next_action": "none",
            "usage_items_count": len(items),
            "actions_rows": actions_rows,
            "actions_minutes": _number(totals["minutes"]),
            "actions_artifact_storage_gb_hours": _number(totals["artifact_storage_gb_hours"]),
            "actions_cache_storage_gb_hours": _number(totals["cache_storage_gb_hours"]),
            "actions_other_quantity": _number(totals["other"]),
        }
    )
    return result


def run_usage(
    *,
    live: bool = False,
    secret_getter: Callable[[str], str | None] | None = None,
    env_getter: Callable[[str], str | None] = get_env,
    fetcher: Callable[..., Any] = _get_json,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Read the current-month GitHub Actions billing report when live."""
    if not live:
        return empty_result(live=False)

    window = _month_window(now)
    try:
        raw_owner_type = str(env_getter("GITHUB_BILLING_OWNER_TYPE") or "user").strip().lower()
        if raw_owner_type not in {"user", "organization"}:
            return _error_result("invalid_billing_owner_type", window=window)
        configured_owner = env_getter("GITHUB_BILLING_OWNER")
        owner = _owner(configured_owner)
        if configured_owner and not owner:
            return _error_result("invalid_billing_owner", window=window, owner_type=raw_owner_type, owner_configured=False)
        raw_plan = env_getter("GITHUB_ACTIONS_PLAN")
        plan = _normalise_plan(raw_plan)
        if raw_plan and not plan:
            return _error_result("invalid_actions_plan", window=window, owner_type=raw_owner_type, owner_configured=bool(owner))
    except Exception as exc:
        error_class = _safe_error(exc)
        return _error_result(error_class, window=window)

    try:
        if secret_getter is None:
            auth = resolve_provider_auth(GITHUB_PROVIDER)
        else:
            token = next(
                (value.strip() for name in GITHUB_SECRET_NAMES if (value := secret_getter(name)) and value.strip()),
                None,
            )
            auth = AuthResolution(
                status="configured" if token else "not_configured",
                credential=token,
                auth_source="secret_manager" if token else None,
                error_class=None if token else "credentials_not_configured",
                missing=() if token else tuple(GITHUB_SECRET_NAMES),
            )
    except Exception as exc:
        return _error_result(
            _safe_error(exc),
            window=window,
            owner_type=raw_owner_type,
            owner_configured=bool(owner),
            plan=plan,
            auth_source="secret_manager",
        )

    if auth.status == "error":
        return _error_result(
            auth.error_class or "provider_error",
            window=window,
            owner_type=raw_owner_type,
            owner_configured=bool(owner),
            plan=plan,
            auth_source=auth.auth_source,
        )

    if auth.status != "configured":
        result = _base(live=True, window=window)
        result["owner_type"] = raw_owner_type
        result["owner_configured"] = bool(owner)
        result["plan"] = plan
        error_class = auth.error_class or "credentials_not_configured"
        result["auth_source"] = auth.auth_source
        result["error_class"] = error_class
        result["next_action"] = _next_action(error_class)
        result["required_config_names"] = ["GITHUB_BILLING_OWNER"] if raw_owner_type == "organization" and not owner else []
        return result

    if not auth.credential:
        return _error_result(
            "cli_session_token_unavailable",
            window=window,
            owner_type=raw_owner_type,
            owner_configured=bool(owner),
            plan=plan,
            auth_source=auth.auth_source,
        )
    token = auth.credential

    headers = {"Authorization": f"Bearer {str(token).strip()}"}
    try:
        if raw_owner_type == "user" and owner is None:
            identity = fetcher(f"{API_BASE}/user", headers)
            owner = _owner(identity.get("login")) if isinstance(identity, dict) else None
            if not owner:
                raise AdapterError("invalid_github_identity_response")
            if plan is None and isinstance(identity, dict):
                identity_plan = identity.get("plan") if isinstance(identity.get("plan"), dict) else {}
                plan = _normalise_plan(identity_plan.get("name"))
        elif raw_owner_type == "organization" and owner is None:
            return _error_result(
                "missing_billing_owner",
                window=window,
                owner_type=raw_owner_type,
                auth_source=auth.auth_source,
            )

        # Fetching plan metadata is best-effort for a configured owner.  The
        # billing endpoint remains the authoritative usage call and may still
        # succeed when plan visibility is restricted.
        if raw_owner_type == "organization" and owner and plan is None:
            try:
                metadata = fetcher(f"{API_BASE}/orgs/{urllib.parse.quote(owner, safe='')}", headers)
                if isinstance(metadata, dict):
                    metadata_plan = metadata.get("plan") if isinstance(metadata.get("plan"), dict) else {}
                    plan = _normalise_plan(metadata_plan.get("name"))
            except Exception:
                pass

        if owner is None:
            raise AdapterError("missing_billing_owner")
        prefix = "organizations" if raw_owner_type == "organization" else "users"
        params = urllib.parse.urlencode({"year": str(window["year"]), "month": str(window["month"])})
        url = f"{API_BASE}/{prefix}/{urllib.parse.quote(owner, safe='')}/settings/billing/usage?{params}"
        payload = fetcher(url, headers)
        result = _aggregate(
            payload,
            owner_type=raw_owner_type,
            owner_configured=bool(configured_owner),
            plan=plan,
            window=window,
        )
        result["auth_source"] = auth.auth_source
        return result
    except Exception as exc:
        error_class = _safe_error(exc)
        return _error_result(
            error_class,
            window=window,
            owner_type=raw_owner_type,
            owner_configured=bool(configured_owner),
            plan=plan,
            auth_source=auth.auth_source,
        )


def main(argv: list[str] | None = None) -> int:
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print the structured result")
    parser.add_argument("--live", action="store_true", help="call the GitHub read-only billing usage endpoint")
    args = parser.parse_args(argv)
    print(json.dumps(run_usage(live=args.live), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
