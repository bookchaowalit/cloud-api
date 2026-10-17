#!/usr/bin/env python3
"""Read-only Vercel billing charges adapter.

The adapter consumes Vercel's official FOCUS billing charges endpoint only in
explicit live mode.  The response is streamed as JSONL, normalized in memory,
and reduced to bounded cost aggregates.  Raw FOCUS records, account IDs,
resource IDs, tags, descriptions, and credential values never cross the
adapter boundary.

Usage:
    python3 vercel_billing.py --json
    python3 vercel_billing.py --json --live
    python3 vercel_billing.py --json --live --from 2026-09-01 --to 2026-10-01
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any
from collections.abc import Callable, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from platform_output import configure_utf8_stdio  # noqa: E402
from auth_resolver import AuthResolution, resolve_provider_auth  # noqa: E402
from cloud_providers import auth_env_names, get_provider  # noqa: E402
from _env import get_env  # noqa: E402


SCHEMA_VERSION = "solo-empire.vercel-billing.v1"
API_URL = "https://api.vercel.com/v1/billing/charges"
VERCEL_PROVIDER = get_provider("vercel")
VERCEL_SECRET_NAMES = auth_env_names(VERCEL_PROVIDER)
USER_AGENT = "solo-empire-vercel-billing-readonly/1.0"
FOCUS_VERSION = "1.3"
MAX_WINDOW_DAYS = 366
DEFAULT_WINDOW_DAYS = 30
MAX_RECORDS = 2_000
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_LABEL_LENGTH = 96
MAX_MONEY_ABS = 1_000_000_000_000.0
SAFE_ERROR_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
SAFE_SCOPE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
SAFE_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3,8}$")
SAFE_LABEL_PATTERN = re.compile(r"[^A-Za-z0-9 ._:/+()&'-]+")


class AdapterError(ValueError):
    """An expected provider-payload error with a safe public class."""

    def __init__(self, error_class: str):
        self.error_class = error_class
        super().__init__(error_class)


def _safe_error(exc: BaseException) -> str:
    if isinstance(exc, AdapterError):
        return exc.error_class
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 401:
            return "vercel_token_unauthorized"
        if exc.code == 403:
            return "vercel_billing_forbidden"
        if exc.code == 404:
            return "vercel_billing_endpoint_unavailable"
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


def _get_jsonl(url: str, headers: dict[str, str] | None = None) -> Iterable[bytes]:
    """Make one bounded GET request and yield response lines without storing it."""
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/x-ndjson, application/json",
            "User-Agent": USER_AGENT,
            **(headers or {}),
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        stream: Any = response
        if str(response.headers.get("Content-Encoding", "")).lower() == "gzip":
            stream = gzip.GzipFile(fileobj=response)
        yield from stream
        if stream is not response:
            stream.close()


def _empty_window() -> dict[str, str | None]:
    return {"from": None, "to": None}


def _format_timestamp(value: datetime) -> str:
    return (
        value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


def _parse_timestamp(value: Any) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        raise AdapterError("invalid_billing_window")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return datetime.fromisoformat(raw).replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))  # noqa: FURB162 - keep the explicit "Z" handling; lint pass is behaviour-neutral
    except ValueError as exc:
        raise AdapterError("invalid_billing_window") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _normalise_window(from_date: Any = None, to_date: Any = None) -> dict[str, str]:
    now = datetime.now(UTC)
    if from_date is None and to_date is None:
        end = now
        start = end - timedelta(days=DEFAULT_WINDOW_DAYS)
    elif from_date is None or to_date is None:
        raise AdapterError("invalid_billing_window")
    else:
        start = _parse_timestamp(from_date)
        end = _parse_timestamp(to_date)
    if end <= start or end - start > timedelta(days=MAX_WINDOW_DAYS):
        raise AdapterError("invalid_billing_window")
    return {"from": _format_timestamp(start), "to": _format_timestamp(end)}


def _safe_scope(value: Any) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    candidate = str(value).strip()
    return candidate if SAFE_SCOPE_PATTERN.fullmatch(candidate) else None


def _first(record: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in record:
            return record[name]
    return None


def _safe_currency(value: Any) -> str:
    candidate = str(value or "").strip().upper()
    if not SAFE_CURRENCY_PATTERN.fullmatch(candidate):
        raise AdapterError("invalid_focus_currency")
    return candidate


def _safe_label(value: Any, fallback: str = "unknown") -> str:
    if value is None:
        return fallback
    candidate = " ".join(str(value).split())
    candidate = SAFE_LABEL_PATTERN.sub("", candidate).strip()[:MAX_LABEL_LENGTH]
    return candidate or fallback


def _safe_money(value: Any) -> float:
    if value is None or value == "":
        return 0.0
    if isinstance(value, bool):
        raise AdapterError("invalid_focus_cost")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise AdapterError("invalid_focus_cost") from exc
    if not math.isfinite(number) or abs(number) > MAX_MONEY_ABS:
        raise AdapterError("invalid_focus_cost")
    return round(number, 6)


def _record(record: Any) -> tuple[str, str, str, float, float]:
    if not isinstance(record, dict):
        raise AdapterError("invalid_focus_record")
    currency = _safe_currency(
        _first(record, "BillingCurrency", "billingCurrency", "Currency", "currency")
    )
    service = _safe_label(
        _first(record, "ServiceName", "serviceName", "ServiceCategory")
    )
    category = _safe_label(_first(record, "ChargeCategory", "chargeCategory"))
    billed = _safe_money(_first(record, "BilledCost", "billedCost", "billed_cost"))
    effective = _safe_money(
        _first(record, "EffectiveCost", "effectiveCost", "effective_cost")
    )
    return service, category, currency, billed, effective


def _aggregate(lines: Iterable[Any]) -> dict[str, Any]:
    charge_count = 0
    total_bytes = 0
    billed: dict[str, float] = {}
    effective: dict[str, float] = {}
    services: dict[tuple[str, str, str], dict[str, float | int | str]] = {}

    for raw_line in lines:
        if isinstance(raw_line, bytes):
            total_bytes += len(raw_line)
            line = raw_line.decode("utf-8")
        else:
            line = str(raw_line)
            total_bytes += len(line.encode("utf-8"))
        if total_bytes > MAX_RESPONSE_BYTES:
            raise AdapterError("focus_response_too_large")
        if not line.strip():
            continue
        charge_count += 1
        if charge_count > MAX_RECORDS:
            raise AdapterError("focus_record_limit_exceeded")
        try:
            parsed = json.loads(line)
        except (TypeError, ValueError) as exc:
            raise AdapterError("invalid_focus_jsonl") from exc
        service, category, currency, billed_cost, effective_cost = _record(parsed)
        billed[currency] = billed.get(currency, 0.0) + billed_cost
        effective[currency] = effective.get(currency, 0.0) + effective_cost
        key = (service, category, currency)
        row = services.setdefault(
            key,
            {
                "service_name": service,
                "charge_category": category,
                "currency": currency,
                "charge_count": 0,
                "billed_cost": 0.0,
                "effective_cost": 0.0,
            },
        )
        row["charge_count"] = int(row["charge_count"]) + 1
        row["billed_cost"] = float(row["billed_cost"]) + billed_cost
        row["effective_cost"] = float(row["effective_cost"]) + effective_cost

    def rounded(values: dict[str, float]) -> dict[str, float]:
        return {key: round(value, 4) for key, value in sorted(values.items())}

    service_breakdown = []
    for row in sorted(
        services.values(),
        key=lambda item: (
            str(item["service_name"]),
            str(item["charge_category"]),
            str(item["currency"]),
        ),
    )[:100]:
        service_breakdown.append(
            {
                "service_name": row["service_name"],
                "charge_category": row["charge_category"],
                "currency": row["currency"],
                "charge_count": int(row["charge_count"]),
                "billed_cost": round(float(row["billed_cost"]), 4),
                "effective_cost": round(float(row["effective_cost"]), 4),
            }
        )
    return {
        "charge_count": charge_count,
        "billed_cost_by_currency": rounded(billed),
        "effective_cost_by_currency": rounded(effective),
        "service_breakdown": service_breakdown,
    }


def _base(*, live: bool, window: dict[str, str | None] | None = None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "provider": "vercel",
        "product": "billing",
        "mode": "live" if live else "offline",
        "status": "not_checked" if not live else "not_configured",
        "credential_state": "not_checked" if not live else "not_configured",
        "metric_scope": "billing_charges_window",
        "metric_source": "vercel_billing_charges_focus",
        "focus_version": FOCUS_VERSION,
        "response_format": "jsonl",
        "window": dict(window or _empty_window()),
        "account_scope": "team_or_personal_token_scope",
        "required_secret_names": list(VERCEL_SECRET_NAMES),
        "auth_source": "not_checked" if not live else None,
        "team_scope_configured": False,
        "billing_access_scope": "pro_or_enterprise_team",
        "next_action": "run_live_check" if not live else "configure_vercel_token",
        "billing_connected": False,
        "read_only": True,
        "execution_enabled": False,
        "write_attempted": False,
        "charge_count": 0,
        "billed_cost_by_currency": {},
        "effective_cost_by_currency": {},
        "service_breakdown": [],
    }


def empty_result(
    *, live: bool = False, window: dict[str, str | None] | None = None
) -> dict[str, Any]:
    """Return a stable sanitized result for offline or unavailable states."""
    return _base(live=live, window=window)


def _next_action_for_error(error_class: str) -> str:
    return {
        "secret_provider_unreachable": "restore_secret_provider_session",
        "secret_not_found": "configure_vercel_token",
        "credentials_not_configured": "configure_vercel_token",
        "credential_unavailable": "configure_vercel_token",
        "cli_not_installed": "install_vercel_cli",
        "cli_session_not_authenticated": "run_vercel_login",
        "cli_session_timeout": "retry_vercel_auth",
        "cli_session_token_unavailable": "configure_vercel_token",
        "vercel_token_unauthorized": "rotate_vercel_token",
        "vercel_billing_forbidden": "verify_vercel_billing_scope",
        "vercel_billing_endpoint_unavailable": "inspect_vercel_api_status",
        "invalid_team_scope": "fix_vercel_team_scope",
        "invalid_billing_window": "fix_billing_window",
        "provider_timeout": "retry_vercel_read",
        "provider_unreachable": "retry_vercel_read",
    }.get(error_class, "inspect_vercel_error")


def _live_error(
    error_class: str,
    *,
    window: dict[str, str | None] | None = None,
    team_scope_configured: bool = False,
    auth_source: str | None = None,
) -> dict[str, Any]:
    result = _base(live=True, window=window)
    result["status"] = "error"
    result["credential_state"] = "error"
    result["error_class"] = (
        error_class if SAFE_ERROR_PATTERN.fullmatch(error_class) else "provider_error"
    )
    result["auth_source"] = auth_source
    result["team_scope_configured"] = team_scope_configured
    result["next_action"] = _next_action_for_error(result["error_class"])
    return result


def _not_configured_result(
    *,
    window: dict[str, str | None] | None = None,
    error_class: str = "credentials_not_configured",
    auth_source: str | None = None,
) -> dict[str, Any]:
    result = _base(live=True, window=window)
    result["error_class"] = (
        error_class if SAFE_ERROR_PATTERN.fullmatch(error_class) else "provider_error"
    )
    result["auth_source"] = auth_source
    result["next_action"] = _next_action_for_error(result["error_class"])
    return result


def _healthy_result(
    aggregate: dict[str, Any],
    *,
    window: dict[str, str],
    account_scope: str,
    team_scope_configured: bool,
    auth_source: str | None,
) -> dict[str, Any]:
    return {
        **_base(live=True, window=window),
        "status": "healthy",
        "credential_state": "verified_read_only",
        "account_scope": account_scope,
        "auth_source": auth_source,
        "team_scope_configured": team_scope_configured,
        "next_action": "none",
        "billing_connected": True,
        **aggregate,
    }


def run_billing(
    *,
    live: bool = False,
    from_date: Any = None,
    to_date: Any = None,
    secret_getter: Callable[[str], str | None] | None = None,
    env_getter: Callable[[str], str | None] = get_env,
    fetcher: Callable[..., Iterable[Any]] = _get_jsonl,
) -> dict[str, Any]:
    """Read Vercel FOCUS billing charges only when explicitly live."""
    if not live:
        return empty_result(live=False)

    try:
        window = _normalise_window(from_date, to_date)
    except Exception as exc:
        return _live_error(_safe_error(exc))

    try:
        raw_team_id = env_getter("VERCEL_TEAM_ID")
        raw_team_slug = env_getter("VERCEL_TEAM_SLUG")
        team_id = _safe_scope(raw_team_id)
        team_slug = _safe_scope(raw_team_slug)
    except Exception as exc:
        return _live_error(_safe_error(exc), window=window)

    if raw_team_id and not team_id:
        return _live_error("invalid_team_scope", window=window)
    if raw_team_slug and not team_slug:
        return _live_error("invalid_team_scope", window=window)

    try:
        if secret_getter is None:
            auth = resolve_provider_auth(VERCEL_PROVIDER)
        else:
            token = next(
                (
                    value.strip()
                    for name in VERCEL_SECRET_NAMES
                    if (value := secret_getter(name)) and value.strip()
                ),
                None,
            )
            auth = AuthResolution(
                status="configured" if token else "not_configured",
                credential=token,
                auth_source="secret_manager" if token else None,
                error_class=None if token else "credentials_not_configured",
                missing=() if token else tuple(VERCEL_SECRET_NAMES),
            )
    except Exception as exc:
        return _live_error(
            _safe_error(exc), window=window, auth_source="secret_manager"
        )

    if auth.status == "error":
        return _live_error(
            auth.error_class or "provider_error",
            window=window,
            team_scope_configured=bool(team_id or team_slug),
            auth_source=auth.auth_source,
        )
    if auth.status != "configured":
        return _not_configured_result(
            window=window,
            error_class=auth.error_class or "credentials_not_configured",
            auth_source=auth.auth_source,
        )
    if not auth.credential:
        return _live_error(
            "cli_session_token_unavailable",
            window=window,
            team_scope_configured=bool(team_id or team_slug),
            auth_source=auth.auth_source,
        )
    token = auth.credential

    params: dict[str, str] = {"from": window["from"], "to": window["to"]}
    if team_id:
        params["teamId"] = team_id
    if team_slug:
        params["slug"] = team_slug
    url = f"{API_URL}?{urllib.parse.urlencode(params)}"
    account_scope = (
        "configured_team" if team_id or team_slug else "personal_or_token_scope"
    )
    try:
        aggregate = _aggregate(
            fetcher(url, {"Authorization": f"Bearer {str(token).strip()}"})
        )
    except Exception as exc:
        return _live_error(
            _safe_error(exc),
            window=window,
            team_scope_configured=bool(team_id or team_slug),
            auth_source=auth.auth_source,
        )
    return _healthy_result(
        aggregate,
        window=window,
        account_scope=account_scope,
        team_scope_configured=bool(team_id or team_slug),
        auth_source=auth.auth_source,
    )


def main(argv: list[str] | None = None) -> int:
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="print the structured result"
    )
    parser.add_argument(
        "--live", action="store_true", help="call the Vercel read-only billing endpoint"
    )
    parser.add_argument("--from", dest="from_date", help="UTC date or ISO timestamp")
    parser.add_argument("--to", dest="to_date", help="UTC date or ISO timestamp")
    args = parser.parse_args(argv)
    print(
        json.dumps(
            run_billing(live=args.live, from_date=args.from_date, to_date=args.to_date),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
