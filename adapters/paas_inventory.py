#!/usr/bin/env python3
"""Bounded read-only resource inventory for the supported PaaS providers.

Only list/read APIs are used. The Railway request is an authenticated
GraphQL query and is deliberately rejected if the response contains errors or
if a mutation query is ever introduced.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from platform_output import configure_utf8_stdio  # noqa: E402
from auth_resolver import AuthResolution, resolve_provider_auth  # noqa: E402
from cloud_providers import get_provider as _get_provider  # noqa: E402
from paas_health import (
    _get_json,
    _load_registry,
    _post_json,
    _safe_error,
    get_env,
)


SCHEMA_VERSION = "solo-empire.paas-inventory.v1"
MAX_ITEMS = 20


def _base(provider: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": provider["id"],
        "name": provider["name"],
        "dashboard_url": provider["dashboard_url"],
        "status": "unknown",
        "resources": [],
        "summary": {
            "resources": 0,
            "returned": 0,
            "partial": False,
            "has_more": False,
            "total_known": False,
        },
    }


def _missing(result: dict[str, Any], names: list[str]) -> dict[str, Any]:
    result["status"] = "not_configured"
    result["error_class"] = "missing_credential"
    result["missing"] = names
    return result


def _offline(result: dict[str, Any]) -> dict[str, Any]:
    """Keep offline inventory deterministic and independent of secret stores."""
    result["status"] = "not_configured"
    result["auth_source"] = "not_checked"
    result["credential_state"] = "not_checked"
    result["error_class"] = "offline_credential_check_skipped"
    result["detail"] = "Offline mode; credentials and provider APIs were not read"
    return result


def _response_error(result: dict[str, Any], exc: BaseException) -> dict[str, Any]:
    result["status"] = "error"
    result["error_class"] = _safe_error(exc)
    return result


def _apply_auth(result: dict[str, Any], auth: AuthResolution) -> bool:
    result["auth_source"] = auth.auth_source
    if auth.status == "error":
        result["status"] = "error"
        result["error_class"] = auth.error_class or "auth_resolution_error"
        return False
    if auth.status != "configured":
        result["status"] = "not_configured"
        result["error_class"] = auth.error_class or "missing_credential"
        if auth.missing:
            result["missing"] = list(auth.missing)
        return False
    return True


def _configured(result: dict[str, Any]) -> dict[str, Any]:
    result["status"] = "configured"
    result["detail"] = "CLI session available; API inventory skipped"
    return result


def _pagination_has_more(
    payload: Any,
    source_count: int,
    *,
    request_limited: bool = False,
) -> bool:
    """Detect provider pagination without exposing provider response payloads."""
    containers: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        containers.append(payload)
        for key in ("pagination", "meta", "page"):
            value = payload.get(key)
            if isinstance(value, dict):
                containers.append(value)
    for container in containers:
        for key in ("has_more", "hasMore", "has_next", "hasNext"):
            if container.get(key) is True:
                return True
        for key in ("next", "next_page", "nextPage", "next_cursor", "nextCursor"):
            value = container.get(key)
            if value not in (None, "", False, 0, [], {}):
                return True
        total = container.get("total")
        if isinstance(total, int) and total > source_count:
            return True
    # Vercel and Render requests are explicitly capped at MAX_ITEMS. If the
    # provider fills that page but omits pagination metadata, report the
    # result conservatively as partial instead of claiming a complete total.
    return request_limited and source_count >= MAX_ITEMS


def _finish(
    result: dict[str, Any],
    resources: list[dict[str, Any]],
    *,
    source_count: int | None = None,
    has_more: bool | None = None,
) -> dict[str, Any]:
    result["status"] = "healthy"
    returned = min(len(resources), MAX_ITEMS)
    observed = (
        len(resources) if source_count is None else max(len(resources), source_count, 0)
    )
    more = observed > returned if has_more is None else bool(has_more)
    partial = more or observed > returned
    result["resources"] = resources[:MAX_ITEMS]
    result["partial"] = partial
    result["has_more"] = more
    result["summary"] = {
        "resources": returned,
        "returned": returned,
        "partial": partial,
        "has_more": more,
        "total_known": not partial,
    }
    return result


def _vercel(provider: dict[str, Any], live: bool) -> dict[str, Any]:
    result = _base(provider)
    if not live:
        return _offline(result)
    auth = resolve_provider_auth(provider)
    if not _apply_auth(result, auth):
        return result
    if not auth.credential:
        return _configured(result)
    token = auth.credential
    try:
        _get_json(
            "https://api.vercel.com/v2/user", {"Authorization": f"Bearer {token}"}
        )
    except Exception as exc:
        return _vercel_error(result, _safe_error(exc), auth_endpoint=True)
    try:
        query = urllib.parse.urlencode({"limit": str(MAX_ITEMS)})
        team_id = (
            get_env("VERCEL_TEAM_ID")
            if "VERCEL_TEAM_ID" in provider.get("optional_env", [])
            else None
        )
        if team_id:
            query += "&" + urllib.parse.urlencode({"teamId": team_id})
        payload = _get_json(
            f"https://api.vercel.com/v9/projects?{query}",
            {"Authorization": f"Bearer {token}"},
        )
        projects = (
            payload.get("projects")
            if isinstance(payload, dict) and isinstance(payload.get("projects"), list)
            else []
        )
        resources = [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "framework": item.get("framework"),
                "updated_at": item.get("updatedAt"),
            }
            for item in projects
            if isinstance(item, dict)
        ]
        return _finish(
            result,
            resources,
            source_count=len(projects),
            has_more=_pagination_has_more(payload, len(projects), request_limited=True),
        )
    except Exception as exc:
        return _vercel_error(result, _safe_error(exc), auth_endpoint=False)


def _render(provider: dict[str, Any], live: bool) -> dict[str, Any]:
    result = _base(provider)
    if not live:
        return _offline(result)
    auth = resolve_provider_auth(provider)
    if not _apply_auth(result, auth):
        return result
    if not auth.credential:
        return _configured(result)
    token = auth.credential
    try:
        payload = _get_json(
            f"https://api.render.com/v1/services?limit={MAX_ITEMS}",
            {"Authorization": f"Bearer {token}"},
        )
        items = payload.get("items") if isinstance(payload, dict) else []
        resources = []
        for item in items if isinstance(items, list) else []:
            service = item.get("service", item) if isinstance(item, dict) else {}
            if not isinstance(service, dict):
                continue
            resources.append(
                {
                    "id": service.get("id"),
                    "name": service.get("name"),
                    "type": service.get("type"),
                    "region": service.get("region"),
                    "environment_id": service.get("environmentId"),
                    "auto_deploy": service.get("autoDeploy"),
                }
            )
        source_count = len(items) if isinstance(items, list) else 0
        return _finish(
            result,
            resources,
            source_count=source_count,
            has_more=_pagination_has_more(payload, source_count, request_limited=True),
        )
    except Exception as exc:
        return _response_error(result, exc)


def _vercel_error(
    result: dict[str, Any], error_class: str, *, auth_endpoint: bool
) -> dict[str, Any]:
    result["status"] = "error"
    if error_class == "http_403":
        result["error_class"] = (
            "vercel_token_forbidden"
            if auth_endpoint
            else "vercel_project_access_forbidden"
        )
        result["detail"] = (
            "Vercel denied the token at the user endpoint; verify the token is a Vercel REST API token and is not expired."
            if auth_endpoint
            else "Vercel authenticated the request but denied project inventory; verify team membership or VERCEL_TEAM_ID."
        )
    else:
        result["error_class"] = error_class
    return result


def _railway(provider: dict[str, Any], live: bool) -> dict[str, Any]:
    result = _base(provider)
    if not live:
        return _offline(result)
    auth = resolve_provider_auth(provider)
    if not _apply_auth(result, auth):
        return result
    if not auth.credential:
        return _configured(result)
    token = auth.credential
    workspace_id = (
        get_env("RAILWAY_WORKSPACE_ID")
        if "RAILWAY_WORKSPACE_ID" in provider.get("optional_env", [])
        else None
    )
    if workspace_id:
        query = "query($workspaceId: String!) { workspace(workspaceId: $workspaceId) { projects { edges { node { id name } } } } }"
        variables = {"workspaceId": workspace_id}
        root_key = "workspace"
    else:
        query = "query { projects { edges { node { id name } } } }"
        variables = {}
        root_key = "projects"
    if "mutation" in query.lower():
        result["status"] = "error"
        result["error_class"] = "mutation_query_rejected"
        return result
    try:
        payload = _post_json(
            "https://backboard.railway.com/graphql/v2",
            {"query": query, "variables": variables},
            {"Authorization": f"Bearer {token}"},
        )
        if not isinstance(payload, dict) or payload.get("errors"):
            result["status"] = "error"
            result["error_class"] = "railway_graphql_error"
            return result
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        root = data.get(root_key) if isinstance(data.get(root_key), dict) else {}
        if root_key == "workspace":
            projects_root = (
                root.get("projects") if isinstance(root.get("projects"), dict) else {}
            )
            edges = (
                projects_root.get("edges")
                if isinstance(projects_root.get("edges"), list)
                else []
            )
        else:
            edges = root.get("edges") if isinstance(root.get("edges"), list) else []
        resources = [
            {
                "id": edge.get("node", {}).get("id"),
                "name": edge.get("node", {}).get("name"),
            }
            for edge in edges
            if isinstance(edge, dict) and isinstance(edge.get("node"), dict)
        ]
        source_count = len(edges) if isinstance(edges, list) else 0
        return _finish(
            result,
            resources,
            source_count=source_count,
            has_more=_pagination_has_more(payload, source_count),
        )
    except Exception as exc:
        return _response_error(result, exc)


def _fly(provider: dict[str, Any], live: bool) -> dict[str, Any]:
    result = _base(provider)
    if not live:
        return _offline(result)
    auth = resolve_provider_auth(provider)
    if not _apply_auth(result, auth):
        return result
    if not auth.credential:
        return _configured(result)
    token = auth.credential
    org_slug = (
        get_env("FLY_ORG_SLUG")
        if "FLY_ORG_SLUG" in provider.get("optional_env", [])
        else None
    )
    if not org_slug:
        return _missing(
            result,
            ["FLY_ORG_SLUG"]
            if "FLY_ORG_SLUG" in provider.get("optional_env", [])
            else [],
        )
    try:
        query = urllib.parse.urlencode({"org_slug": org_slug})
        payload = _get_json(
            f"https://api.machines.dev/v1/apps?{query}",
            {"Authorization": f"Bearer {token}"},
        )
        apps = (
            payload.get("apps")
            if isinstance(payload, dict) and isinstance(payload.get("apps"), list)
            else []
        )
        resources = [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "machine_count": item.get("machine_count"),
                "volume_count": item.get("volume_count"),
                "network": item.get("network"),
            }
            for item in apps
            if isinstance(item, dict)
        ]
        source_count = len(apps) if isinstance(apps, list) else 0
        return _finish(
            result,
            resources,
            source_count=source_count,
            has_more=_pagination_has_more(payload, source_count),
        )
    except Exception as exc:
        return _response_error(result, exc)


def _heroku(provider: dict[str, Any], live: bool) -> dict[str, Any]:
    result = _base(provider)
    if not live:
        return _offline(result)
    auth = resolve_provider_auth(provider)
    if not _apply_auth(result, auth):
        return result
    if not auth.credential:
        return _configured(result)
    token = auth.credential
    try:
        payload = _get_json(
            "https://api.heroku.com/apps",
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.heroku+json; version=3",
            },
        )
        resources = []
        for item in payload if isinstance(payload, list) else []:
            if not isinstance(item, dict):
                continue
            region = item.get("region") if isinstance(item.get("region"), dict) else {}
            stack = item.get("stack") if isinstance(item.get("stack"), dict) else {}
            resources.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "region": region.get("name"),
                    "stack": stack.get("name"),
                    "maintenance": item.get("maintenance"),
                    "locked": item.get("locked"),
                }
            )
        source_count = len(payload) if isinstance(payload, list) else 0
        return _finish(
            result,
            resources,
            source_count=source_count,
            has_more=_pagination_has_more(payload, source_count),
        )
    except Exception as exc:
        return _response_error(result, exc)


INVENTORIES: dict[str, Callable[[dict[str, Any], bool], dict[str, Any]]] = {
    "vercel": _vercel,
    "render": _render,
    "railway": _railway,
    "fly-io": _fly,
    "heroku": _heroku,
}


def run_inventory(live: bool = False, provider_id: str | None = None) -> dict[str, Any]:
    from cloud_read_adapters import READ_PROVIDERS, collect_provider

    registry = _load_registry()
    available = set(INVENTORIES) | READ_PROVIDERS
    if provider_id and provider_id not in available:
        raise ValueError(f"Inventory adapter is not implemented: {provider_id}")
    providers = [
        provider
        for provider in registry["providers"]
        if provider.get("paas") is True
        and provider["id"] in INVENTORIES
        and (not provider_id or provider["id"] == provider_id)
    ]
    with ThreadPoolExecutor(max_workers=min(5, max(1, len(providers)))) as executor:
        results = list(
            executor.map(
                lambda provider: INVENTORIES[provider["id"]](provider, live), providers
            )
        )
    if provider_id in READ_PROVIDERS:
        for provider in registry["providers"]:
            current_id = provider["id"]
            if current_id in READ_PROVIDERS and (
                provider_id is None or current_id == provider_id
            ):
                inventory = collect_provider(current_id, live=live)["inventory"]
                results.append(
                    {
                        **inventory,
                        "id": current_id,
                        "name": provider["name"],
                        "resources": inventory.get("items", []),
                        "summary": {
                            "resources": inventory.get("returned", 0),
                            "total_known": inventory.get("total_known", False),
                        },
                    }
                )
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "live" if live else "offline",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "execution_enabled": False,
        "write_attempted": False,
        "providers": results,
        "summary": {
            "providers": len(results),
            "healthy": sum(item["status"] == "healthy" for item in results),
            "configured": sum(item["status"] == "configured" for item in results),
            "not_configured": sum(
                item["status"] == "not_configured" for item in results
            ),
            "errors": sum(item["status"] == "error" for item in results),
            "resources": sum(
                item.get("summary", {}).get("resources", 0) for item in results
            ),
            "partial_providers": sum(
                bool(item.get("partial") or item.get("summary", {}).get("partial"))
                for item in results
            ),
            "has_more": any(
                bool(item.get("has_more") or item.get("summary", {}).get("has_more"))
                for item in results
            ),
            "total_known": all(
                bool(
                    item.get("summary", {}).get("total_known", not item.get("partial"))
                )
                for item in results
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    configure_utf8_stdio()
    args = set(sys.argv[1:] if argv is None else argv)
    provider_id = next(
        (arg.split("=", 1)[1] for arg in args if arg.startswith("--provider=")), None
    )
    if "--provider" in args:
        index = list(sys.argv[1:] if argv is None else argv).index("--provider")
        values = list(sys.argv[1:] if argv is None else argv)
        provider_id = values[index + 1] if index + 1 < len(values) else None
    if provider_id:
        from cloud_read_adapters import READ_PROVIDERS

        try:
            _get_provider(provider_id)
        except KeyError:
            raise SystemExit(f"Unknown provider: {provider_id}") from None
        if provider_id not in set(INVENTORIES) | READ_PROVIDERS:
            raise SystemExit(f"Inventory adapter is not implemented: {provider_id}")
    print(
        json.dumps(
            run_inventory(live="--live" in args, provider_id=provider_id),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
