"""Bounded management-API reads with metadata-only projections."""

from __future__ import annotations

import base64
import json
import math
import re
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlsplit

from auth_resolver import AuthResolution, SecretGetter, resolve_provider_auth
from cloud_providers import get_provider
from secret_resolver import SecretResolutionError, SecretUnavailable, get_secret_with_source


READ_PROVIDERS = frozenset({"neon", "cloudflare", "runpod", "supabase", "upstash"})
BASE_URLS = {
    "neon": "https://console.neon.tech/api/v2",
    "cloudflare": "https://api.cloudflare.com/client/v4",
    "runpod": "https://rest.runpod.io/v1",
    "supabase": "https://api.supabase.com/v1",
    "upstash": "https://api.upstash.com/v2",
}
MAX_ITEMS = 20
MAX_DETAIL_READS = 5
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
JsonGetter = Callable[[str, str, dict[str, str]], Any]


class CloudReadError(Exception):
    """Safe, classified read failure; never carries a provider response."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_json(provider_id: str, path: str, headers: dict[str, str]) -> Any:
    if provider_id not in BASE_URLS or not path.startswith("/") or path.startswith("//"):
        raise CloudReadError("invalid_endpoint")
    url = BASE_URLS[provider_id] + path
    parts = urlsplit(url)
    base = urlsplit(BASE_URLS[provider_id])
    if parts.netloc != base.netloc or parts.fragment or any(char in path for char in "\r\n\\"):
        raise CloudReadError("invalid_endpoint")
    request = urllib.request.Request(url, headers={**headers, "Accept": "application/json"}, method="GET")
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=15) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise CloudReadError("response_too_large")
        return json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        raise CloudReadError(
            "authentication_failed" if code in {401, 403}
            else "rate_limited" if code == 429
            else "redirect_blocked" if 300 <= code < 400
            else "http_error"
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise CloudReadError("provider_unreachable") from None
    except (ValueError, UnicodeError):
        raise CloudReadError("invalid_payload") from None


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise CloudReadError("invalid_resource_identifier")
    return value


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 200 or any(ord(c) < 32 for c in value):
        raise CloudReadError("invalid_payload")
    return value


def _number(value: Any) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise CloudReadError("invalid_payload")
    return value


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CloudReadError("invalid_payload")
    return value


def _items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise CloudReadError("invalid_payload")
    return value


def _inventory(items: list[dict[str, Any]], partial: bool, **extra: Any) -> dict[str, Any]:
    return {
        "status": "healthy", "items": items, "returned": len(items),
        "partial": partial, "has_more": partial, "total_known": not partial, **extra,
    }


def _failure(error_class: str) -> dict[str, Any]:
    return {"status": "error", "error_class": error_class}


def _config_secret(name: str, getter: SecretGetter, *, required: bool = True) -> str | None:
    try:
        value, _ = getter(name)
    except SecretUnavailable:
        value = None
    except SecretResolutionError:
        raise CloudReadError("secret_provider_unreachable") from None
    if value:
        return value.strip()
    if required:
        raise CloudReadError("required_configuration_missing")
    return None


def _neon(read: Callable[[str], Any]) -> dict[str, Any]:
    payload = _object(read("/projects?limit=20"))
    projects = _items(payload.get("projects"))
    partial = len(projects) > MAX_ITEMS or bool(_object(payload.get("pagination", {})).get("cursor"))
    items = []
    usage_projects = []
    detail_errors = []
    for index, project in enumerate(projects[:MAX_ITEMS]):
        project_id = _identifier(project.get("id"))
        item = {"id": project_id, "type": "project", "name": _text(project.get("name")), "region": _text(project.get("region_id"))}
        if index < MAX_DETAIL_READS:
            try:
                branches = _object(read(f"/projects/{project_id}/branches?limit=20"))
                branch_items = _items(branches.get("branches"))
                item["branches"] = [
                    {"id": _identifier(b.get("id")), "name": _text(b.get("name"))}
                    for b in branch_items[:MAX_ITEMS]
                ]
                item["branches_partial"] = len(branch_items) >= MAX_ITEMS or bool(
                    _object(branches.get("pagination", {})).get("cursor")
                )
            except CloudReadError as exc:
                item["branches_status"] = "error"
                item["branches_error_class"] = str(exc)
            try:
                detail = _object(_object(read(f"/projects/{project_id}")).get("project"))
                seconds = _number(detail.get("compute_time_seconds"))
                usage_projects.append({
                    "id": project_id,
                    "compute_hours": seconds / 3600 if seconds is not None else None,
                    "current_storage_bytes": _number(detail.get("synthetic_storage_size")),
                    "storage_byte_hours": _number(detail.get("data_storage_bytes_hour")),
                    "data_transfer_bytes": _number(detail.get("data_transfer_bytes")),
                    "period_start": _text(detail.get("consumption_period_start")),
                    "period_end": _text(detail.get("consumption_period_end")),
                })
            except CloudReadError as exc:
                detail_errors.append({"id": project_id, "error_class": str(exc)})
        else:
            item["branches_status"] = "not_checked"
        items.append(item)
    return {
        "inventory": _inventory(items, partial),
        "usage": {
            "status": "healthy" if not detail_errors else "partial" if usage_projects else "error",
            "projects": usage_projects, "errors": detail_errors,
            "partial": partial or len(projects) > MAX_DETAIL_READS or bool(detail_errors),
            "scope": "up to five projects; billing-period compute hours and storage; not billed spend",
        },
    }


def _cloudflare(read: Callable[[str], Any], account_id: str) -> dict[str, Any]:
    account_id = _identifier(account_id)

    def envelope(path: str) -> tuple[Any, dict[str, Any]]:
        payload = _object(read(path))
        if payload.get("success") is not True:
            raise CloudReadError("provider_api_error")
        return payload.get("result"), _object(payload.get("result_info", {}))

    resources = []
    errors = []
    partial = False
    for kind, path in (
        ("worker", f"/accounts/{account_id}/workers/scripts"),
        ("pages_project", f"/accounts/{account_id}/pages/projects?page=1&per_page=20"),
    ):
        try:
            result, info = envelope(path)
            items = _items(result)
            total = _number(info.get("total_count"))
            pages = _number(info.get("total_pages"))
            partial |= len(items) >= MAX_ITEMS or (total is not None and total > len(items)) or (pages is not None and pages > 1)
            for item in items[:MAX_ITEMS]:
                projected = {
                    "id": _identifier(item.get("id") or item.get("name")),
                    "type": kind, "name": _text(item.get("name")),
                }
                if kind == "pages_project":
                    deployment = item.get("canonical_deployment")
                    projected["production_deployment"] = None if deployment is None else {
                        "id": _identifier(_object(deployment).get("id")),
                        "created_at": _text(deployment.get("created_on")),
                        "stage_status": _text(_object(deployment.get("latest_stage", {})).get("status")),
                    }
                resources.append(projected)
        except CloudReadError as exc:
            errors.append({"resource_type": kind, "error_class": str(exc)})
    if errors:
        return {
            "inventory": {
                **_inventory(resources, True), "status": "partial" if resources else "error",
                "errors": errors,
            },
            "health": {"status": "partial" if resources else "error", "errors": errors},
        }
    return {"inventory": _inventory(resources, partial)}


def _runpod(read: Callable[[str], Any]) -> dict[str, Any]:
    pods = _items(read("/pods"))
    endpoints = _items(read("/endpoints"))
    resources = [
        {
            "id": _identifier(pod.get("id")), "type": "pod",
            "name": _text(pod.get("name")), "desired_status": _text(pod.get("desiredStatus")),
            "credits_per_hour": _number(pod.get("adjustedCostPerHr", pod.get("costPerHr"))),
        }
        for pod in pods[:MAX_ITEMS]
    ] + [
        {"id": _identifier(endpoint.get("id")), "type": "endpoint", "name": _text(endpoint.get("name"))}
        for endpoint in endpoints[:MAX_ITEMS]
    ]
    partial = len(pods) > MAX_ITEMS or len(endpoints) > MAX_ITEMS
    return {
        "inventory": _inventory(resources, partial),
        "usage": {
            "status": "healthy", "pods": [
                {key: pod[key] for key in ("id", "desired_status", "credits_per_hour")}
                for pod in resources if pod["type"] == "pod"
            ], "partial": partial,
            "scope": "desired pod states and credit rates only; not actual runtime, accumulated spend or USD billing",
        },
    }


def _supabase(read: Callable[[str], Any]) -> dict[str, Any]:
    projects = _items(read("/projects"))
    return {"inventory": _inventory([
        {
            "id": _identifier(project.get("ref") or project.get("id")),
            "type": "project", "name": _text(project.get("name")),
            "region": _text(project.get("region")), "database_status": _text(project.get("status")),
        }
        for project in projects[:MAX_ITEMS]
    ], len(projects) > MAX_ITEMS)}


def _upstash(read: Callable[[str], Any]) -> dict[str, Any]:
    databases = _items(read("/redis/databases"))
    resources = []
    stats = []
    errors = []
    for index, database in enumerate(databases[:MAX_ITEMS]):
        database_id = _identifier(database.get("database_id"))
        resources.append({
            "id": database_id, "type": "redis_database",
            "name": _text(database.get("database_name")), "region": _text(database.get("region")),
            "state": _text(database.get("state")),
        })
        if index < MAX_DETAIL_READS:
            try:
                payload = _object(read(f"/redis/stats/{database_id}"))
                stats.append({
                    "id": database_id,
                    "monthly_requests": _number(payload.get("total_monthly_requests")),
                    "monthly_bandwidth_bytes": _number(payload.get("total_monthly_bandwidth")),
                    "current_storage_bytes": _number(payload.get("current_storage")),
                })
            except CloudReadError as exc:
                errors.append({"id": database_id, "error_class": str(exc)})
    return {
        "inventory": _inventory(resources, len(databases) > MAX_ITEMS),
        "usage": {
            "status": "healthy" if not errors else "partial" if stats else "error",
            "databases": stats, "errors": errors,
            "partial": len(databases) > MAX_DETAIL_READS or bool(errors),
            "scope": "up to five Redis databases; current-month API counters; no currency assumptions",
        },
    }


def collect_provider(
    provider_id: str, *, live: bool = False,
    auth_resolver: Callable[[dict[str, Any]], AuthResolution] | None = None,
    secret_getter: SecretGetter | None = None,
    json_getter: JsonGetter | None = None,
) -> dict[str, Any]:
    if provider_id not in READ_PROVIDERS:
        raise KeyError(f"Unknown read adapter: {provider_id}")
    provider = get_provider(provider_id)
    supported = ["health", "inventory"]
    if provider_id in {"neon", "runpod", "upstash"}:
        supported.append("usage")
    if not live:
        return {key: {"status": "skipped", "reason": "offline_mode", "credential_state": "not_checked"} for key in supported}
    getter = secret_getter or get_secret_with_source
    auth = auth_resolver(provider) if auth_resolver else resolve_provider_auth(provider, secret_getter=getter)
    if auth.status != "configured" or not auth.credential:
        failure = {
            "status": "error" if auth.status == "error" else "not_configured",
            "error_class": auth.error_class or "api_credential_unavailable",
            "auth_source": auth.auth_source,
        }
        return {key: dict(failure) for key in supported}
    try:
        if "\r" in auth.credential or "\n" in auth.credential:
            raise CloudReadError("invalid_credential")
        headers = {"Authorization": f"Bearer {auth.credential}"}
        account_id = None
        org_id = None
        if provider_id == "cloudflare":
            account_id = _config_secret("CLOUDFLARE_ACCOUNT_ID", getter)
        elif provider_id == "neon":
            org_id = _config_secret("NEON_ORG_ID", getter, required=False)
        elif provider_id == "upstash":
            email = _config_secret("UPSTASH_EMAIL", getter)
            if email is None or any(char in email for char in ":\r\n") or "@" not in email:
                raise CloudReadError("invalid_credential")
            encoded = base64.b64encode(f"{email}:{auth.credential}".encode("utf-8")).decode("ascii")
            headers = {"Authorization": f"Basic {encoded}"}
        get = json_getter or get_json

        def read(path: str) -> Any:
            if provider_id == "neon" and path.startswith("/projects?") and org_id:
                path += f"&org_id={_identifier(org_id)}"
            return get(provider_id, path, headers)

        if provider_id == "neon":
            report = _neon(read)
        elif provider_id == "cloudflare":
            if account_id is None:
                raise CloudReadError("required_configuration_missing")
            report = _cloudflare(read, account_id)
        elif provider_id == "runpod":
            report = _runpod(read)
        elif provider_id == "supabase":
            report = _supabase(read)
        else:
            report = _upstash(read)
        report.setdefault("health", {"status": "healthy", "scope": "management API accessibility; not resource uptime"})
    except CloudReadError as exc:
        report = {key: _failure(str(exc)) for key in supported}
    return {key: {**value, "auth_source": auth.auth_source} for key, value in report.items()}
