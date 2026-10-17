#!/usr/bin/env python3
"""Read-only Cloudflare R2 account metrics adapter.

The adapter deliberately exposes aggregate usage signals only.  It uses the
official account-level metrics endpoint and never returns the account ID,
credential values, bucket names, or the raw provider response.

Usage:
    python3 cloudflare_r2_usage.py --json
    python3 cloudflare_r2_usage.py --json --live
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from platform_output import configure_utf8_stdio  # noqa: E402
from _env import get_secret  # noqa: E402


SCHEMA_VERSION = "solo-empire.cloudflare-r2-usage.v1"
API_BASE = "https://api.cloudflare.com/client/v4/accounts"
USER_AGENT = "solo-empire-cloudflare-r2-readonly/1.0"
ACCOUNT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
BYTES_PER_GIB = 1024**3
BILLING_BYTES_PER_GB = 1_000_000_000
PRICING_URL = "https://developers.cloudflare.com/r2/pricing/"
PRICING_VERIFIED_AT = "2026-09-05"
STANDARD_STORAGE_RATE_USD_PER_GB_MONTH = 0.015
INFREQUENT_ACCESS_STORAGE_RATE_USD_PER_GB_MONTH = 0.01
STANDARD_FREE_STORAGE_GB_MONTH = 10.0


def _safe_error(exc: BaseException) -> str:
    """Classify an exception without returning URLs or provider messages."""
    if isinstance(exc, urllib.error.HTTPError):
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
    return "provider_error"


def _get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    """Make one bounded GET request; response parsing stays in memory only."""
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            **(headers or {}),
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool) or value is None or value == "":
        return 0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if not math.isfinite(number) or number < 0:
        return 0
    return int(number)


def _empty_metric_group() -> dict[str, int | float]:
    return {
        "metadata_bytes": 0,
        "object_count": 0,
        "payload_bytes": 0,
        "payload_gib": 0.0,
    }


def _metric_group(payload: Any) -> dict[str, int | float]:
    payload = payload if isinstance(payload, dict) else {}
    metadata_bytes = _non_negative_int(payload.get("metadataSize"))
    object_count = _non_negative_int(payload.get("objects"))
    payload_bytes = _non_negative_int(payload.get("payloadSize"))
    return {
        "metadata_bytes": metadata_bytes,
        "object_count": object_count,
        "payload_bytes": payload_bytes,
        "payload_gib": round(payload_bytes / BYTES_PER_GIB, 6),
    }


def _class_metrics(payload: Any) -> dict[str, dict[str, int | float]]:
    payload = payload if isinstance(payload, dict) else {}
    return {
        "published": _metric_group(payload.get("published")),
        "uploaded": _metric_group(payload.get("uploaded")),
    }


def _sum_groups(groups: list[dict[str, int | float]]) -> dict[str, int | float]:
    metadata_bytes = sum(int(group["metadata_bytes"]) for group in groups)
    object_count = sum(int(group["object_count"]) for group in groups)
    payload_bytes = sum(int(group["payload_bytes"]) for group in groups)
    return {
        "metadata_bytes": metadata_bytes,
        "object_count": object_count,
        "payload_bytes": payload_bytes,
        "payload_gib": round(payload_bytes / BYTES_PER_GIB, 6),
    }


def _storage_cost_estimate(
    storage_classes: dict[str, dict[str, dict[str, int | float]]],
) -> dict[str, Any]:
    """Estimate storage-only cost from the current published payload snapshot.

    The R2 metrics endpoint does not expose operation or retrieval counts, and
    its storage metric is not a 30-day daily average.  Keep those omissions
    explicit so this result cannot be mistaken for a provider invoice.
    """
    standard_bytes = int(storage_classes["standard"]["published"]["payload_bytes"])
    infrequent_access_bytes = int(
        storage_classes["infrequent_access"]["published"]["payload_bytes"]
    )
    standard_gb = standard_bytes / BILLING_BYTES_PER_GB
    infrequent_access_gb = infrequent_access_bytes / BILLING_BYTES_PER_GB
    standard_billable_gb = max(standard_gb - STANDARD_FREE_STORAGE_GB_MONTH, 0.0)
    standard_estimate = standard_billable_gb * STANDARD_STORAGE_RATE_USD_PER_GB_MONTH
    infrequent_access_estimate = (
        infrequent_access_gb * INFREQUENT_ACCESS_STORAGE_RATE_USD_PER_GB_MONTH
    )

    def component(
        payload_gb: float,
        free_gb_month: float,
        billable_gb_month: float,
        rate: float,
        estimate: float,
    ) -> dict[str, float]:
        return {
            "payload_gb": round(payload_gb, 6),
            "free_gb_month": round(free_gb_month, 6),
            "billable_gb_month": round(billable_gb_month, 6),
            "rate_usd_per_gb_month": rate,
            "estimated_usd": round(estimate, 4),
        }

    return {
        "status": "estimate_only",
        "currency": "USD",
        "estimated_usd": round(standard_estimate + infrequent_access_estimate, 4),
        "basis": "current_published_payload_as_constant_gb_month",
        "pricing_source": PRICING_URL,
        "pricing_verified_at": PRICING_VERIFIED_AT,
        "includes_operations": False,
        "includes_data_retrieval": False,
        "egress_assumed_free": True,
        "standard": component(
            standard_gb,
            STANDARD_FREE_STORAGE_GB_MONTH,
            standard_billable_gb,
            STANDARD_STORAGE_RATE_USD_PER_GB_MONTH,
            standard_estimate,
        ),
        "infrequent_access": component(
            infrequent_access_gb,
            0.0,
            infrequent_access_gb,
            INFREQUENT_ACCESS_STORAGE_RATE_USD_PER_GB_MONTH,
            infrequent_access_estimate,
        ),
    }


def _empty_storage_cost_estimate(*, live: bool) -> dict[str, Any]:
    return {
        "status": "not_checked" if not live else "unavailable",
        "currency": "USD",
        "estimated_usd": 0.0,
        "basis": "current_published_payload_as_constant_gb_month",
        "pricing_source": PRICING_URL,
        "pricing_verified_at": PRICING_VERIFIED_AT,
        "includes_operations": False,
        "includes_data_retrieval": False,
        "egress_assumed_free": True,
        "standard": {
            "payload_gb": 0.0,
            "free_gb_month": STANDARD_FREE_STORAGE_GB_MONTH,
            "billable_gb_month": 0.0,
            "rate_usd_per_gb_month": STANDARD_STORAGE_RATE_USD_PER_GB_MONTH,
            "estimated_usd": 0.0,
        },
        "infrequent_access": {
            "payload_gb": 0.0,
            "free_gb_month": 0.0,
            "billable_gb_month": 0.0,
            "rate_usd_per_gb_month": INFREQUENT_ACCESS_STORAGE_RATE_USD_PER_GB_MONTH,
            "estimated_usd": 0.0,
        },
    }


def empty_result(*, live: bool = False) -> dict[str, Any]:
    """Return a stable sanitized result for offline or unavailable states."""
    empty = _empty_metric_group()
    return {
        "schema_version": SCHEMA_VERSION,
        "provider": "cloudflare",
        "product": "r2",
        "mode": "live" if live else "offline",
        "status": "not_checked" if not live else "not_configured",
        "credential_state": "not_checked" if not live else "not_configured",
        "metric_scope": "account_all_buckets",
        "metric_source": "cloudflare_r2_account_metrics",
        "metric_freshness": "provider_reported_may_lag",
        "billing_connected": False,
        "read_only": True,
        "execution_enabled": False,
        "write_attempted": False,
        "object_count": 0,
        "payload_bytes": 0,
        "payload_gib": 0.0,
        "metadata_bytes": 0,
        "uploaded_object_count": 0,
        "uploaded_payload_bytes": 0,
        "uploaded_payload_gib": 0.0,
        "storage_cost_estimate": _empty_storage_cost_estimate(live=live),
        "storage_classes": {
            "standard": {"published": dict(empty), "uploaded": dict(empty)},
            "infrequent_access": {"published": dict(empty), "uploaded": dict(empty)},
        },
    }


def _live_error(error_class: str) -> dict[str, Any]:
    result = empty_result(live=True)
    result["status"] = "error"
    result["credential_state"] = "error"
    result["error_class"] = error_class
    return result


def _not_configured_result() -> dict[str, Any]:
    result = empty_result(live=True)
    result["status"] = "not_configured"
    result["credential_state"] = "not_configured"
    result["error_class"] = "credentials_not_configured"
    return result


def _normalise_account_id(value: Any) -> str | None:
    if value is None:
        return None
    account_id = str(value).strip()
    if not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        return None
    return account_id


def _healthy_result(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        return _live_error("cloudflare_api_error")

    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    storage_classes = {
        "standard": _class_metrics(result.get("standard")),
        "infrequent_access": _class_metrics(result.get("infrequentAccess")),
    }
    published = [
        storage_classes["standard"]["published"],
        storage_classes["infrequent_access"]["published"],
    ]
    uploaded = [
        storage_classes["standard"]["uploaded"],
        storage_classes["infrequent_access"]["uploaded"],
    ]
    aggregate = _sum_groups(published)
    uploaded_aggregate = _sum_groups(uploaded)
    return {
        **empty_result(live=True),
        "status": "healthy",
        "credential_state": "verified_read_only",
        "object_count": aggregate["object_count"],
        "payload_bytes": aggregate["payload_bytes"],
        "payload_gib": aggregate["payload_gib"],
        "metadata_bytes": aggregate["metadata_bytes"],
        "uploaded_object_count": uploaded_aggregate["object_count"],
        "uploaded_payload_bytes": uploaded_aggregate["payload_bytes"],
        "uploaded_payload_gib": uploaded_aggregate["payload_gib"],
        "storage_cost_estimate": _storage_cost_estimate(storage_classes),
        "storage_classes": storage_classes,
    }


def run_metrics(
    *,
    live: bool = False,
    secret_getter: Callable[[str], str | None] = get_secret,
    fetcher: Callable[..., Any] = _get_json,
) -> dict[str, Any]:
    """Read Cloudflare R2 account metrics only when explicitly live."""
    if not live:
        return empty_result(live=False)

    try:
        token = secret_getter("CLOUDFLARE_API_TOKEN")
        account_id = _normalise_account_id(secret_getter("CLOUDFLARE_ACCOUNT_ID"))
    except Exception as exc:
        return _live_error(_safe_error(exc))

    if not token or not account_id:
        return _not_configured_result()

    url = f"{API_BASE}/{urllib.parse.quote(account_id, safe='')}/r2/metrics"
    try:
        payload = fetcher(url, {"Authorization": f"Bearer {token}"})
    except Exception as exc:
        return _live_error(_safe_error(exc))
    return _healthy_result(payload)


def main(argv: list[str] | None = None) -> int:
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="print the structured result"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="call the read-only Cloudflare R2 metrics API",
    )
    args = parser.parse_args(argv)
    print(json.dumps(run_metrics(live=args.live), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
