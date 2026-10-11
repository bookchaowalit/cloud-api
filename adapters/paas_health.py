#!/usr/bin/env python3
"""Read-only health checks for the central multi-PaaS catalog.

The module deliberately returns bounded metadata only. It never returns
provider payloads, account identifiers, or credential values and it never
calls a mutating endpoint.

Usage:
    python3 paas_health.py --json --offline
    python3 paas_health.py --json --live
    python3 paas_health.py --catalog --json
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from platform_output import configure_utf8_stdio  # noqa: E402
from cloud_providers import get_provider as _get_provider, load_registry as _load_registry  # noqa: E402
from auth_resolver import AuthResolution, resolve_provider_auth  # noqa: E402
from _env import get_env  # noqa: E402


def get_provider(provider_id: str) -> dict[str, Any]:
    return _get_provider(provider_id)


def _safe_error(exc: BaseException) -> str:
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
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "solo-empire-paas-readonly/1.0",
            **(headers or {}),
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_json(url: str, body: dict[str, Any], headers: dict[str, str] | None = None) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "solo-empire-paas-readonly/1.0",
            **(headers or {}),
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _base_result(provider: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": provider["id"],
        "name": provider["name"],
        "icon": provider.get("icon", ""),
        "category": provider["category"],
        "dashboard_url": provider["dashboard_url"],
        "api_docs": provider["api_docs"],
        "read_capabilities": provider.get("read_capabilities", []),
        "write_capabilities": provider.get("write_capabilities", []),
        "status": "unknown",
    }


def _not_configured(result: dict[str, Any], missing: list[str]) -> dict[str, Any]:
    result["status"] = "not_configured"
    result["error"] = f"Missing {' or '.join(missing)}"
    return result


def _healthy(result: dict[str, Any], detail: str) -> dict[str, Any]:
    result["status"] = "healthy"
    result["detail"] = detail
    return result


def _configured(result: dict[str, Any]) -> dict[str, Any]:
    result["status"] = "configured"
    result["detail"] = "Credential available; live API check skipped"
    return result


def _offline(result: dict[str, Any]) -> dict[str, Any]:
    """Keep offline health checks independent of credential providers."""
    result["status"] = "not_configured"
    result["auth_source"] = "not_checked"
    result["credential_state"] = "not_checked"
    result["error_class"] = "offline_credential_check_skipped"
    result["detail"] = "Offline mode; credentials and provider APIs were not read"
    return result


def _check_vercel(
    provider: dict[str, Any],
    result: dict[str, Any],
    live: bool,
    auth: AuthResolution | None,
) -> dict[str, Any]:
    if not live:
        return _offline(result)
    if auth is None or not auth.credential:
        return _configured(result)
    token = auth.credential
    try:
        query = urllib.parse.urlencode({"limit": "1"})
        team_id = get_env("VERCEL_TEAM_ID") if "VERCEL_TEAM_ID" in provider.get("optional_env", []) else None
        if team_id:
            query += "&" + urllib.parse.urlencode({"teamId": team_id})
        payload = _get_json(
            f"https://api.vercel.com/v9/projects?{query}",
            {"Authorization": f"Bearer {token}"},
        )
        projects = payload.get("projects") if isinstance(payload, dict) else None
        detail = "Vercel API reachable"
        if isinstance(projects, list):
            detail += f"; sample_projects={len(projects)}"
        return _healthy(result, detail)
    except Exception as exc:
        result["status"] = "error"
        error_class = _safe_error(exc)
        result["error_class"] = "vercel_access_forbidden" if error_class == "http_403" else error_class
        if error_class == "http_403":
            result["detail"] = "Vercel denied the token; verify REST API token validity and team access"
        return result


def _check_render(
    provider: dict[str, Any],
    result: dict[str, Any],
    live: bool,
    auth: AuthResolution | None,
) -> dict[str, Any]:
    if not live:
        return _offline(result)
    if auth is None or not auth.credential:
        return _configured(result)
    token = auth.credential
    try:
        payload = _get_json(
            "https://api.render.com/v1/services?limit=1",
            {"Authorization": f"Bearer {token}"},
        )
        items = payload.get("items") if isinstance(payload, dict) else None
        detail = "Render API reachable"
        if isinstance(items, list):
            detail += f"; sample_services={len(items)}"
        return _healthy(result, detail)
    except Exception as exc:
        result["status"] = "error"
        result["error_class"] = _safe_error(exc)
        return result


def _check_railway(
    provider: dict[str, Any],
    result: dict[str, Any],
    live: bool,
    auth: AuthResolution | None,
) -> dict[str, Any]:
    if not live:
        return _offline(result)
    if auth is None or not auth.credential:
        return _configured(result)
    token = auth.credential
    try:
        payload = _post_json(
            "https://backboard.railway.com/graphql/v2",
            {"query": "query { me { id name } }"},
            {"Authorization": f"Bearer {token}"},
        )
        if not isinstance(payload, dict) or payload.get("errors") or not isinstance(payload.get("data", {}).get("me"), dict):
            result["status"] = "error"
            result["error_class"] = "railway_graphql_error"
            return result
        return _healthy(result, "Railway GraphQL API reachable")
    except Exception as exc:
        result["status"] = "error"
        result["error_class"] = _safe_error(exc)
        return result


def _check_fly_io(
    provider: dict[str, Any],
    result: dict[str, Any],
    live: bool,
    auth: AuthResolution | None,
) -> dict[str, Any]:
    if not live:
        return _offline(result)
    if auth is None or not auth.credential:
        return _configured(result)
    token = auth.credential
    org_slug = get_env("FLY_ORG_SLUG") if "FLY_ORG_SLUG" in provider.get("optional_env", []) else None
    if not org_slug:
        return _not_configured(result, ["FLY_ORG_SLUG"] if "FLY_ORG_SLUG" in provider.get("optional_env", []) else [])
    try:
        query = urllib.parse.urlencode({"org_slug": org_slug})
        payload = _get_json(
            f"https://api.machines.dev/v1/apps?{query}",
            {"Authorization": f"Bearer {token}"},
        )
        total = payload.get("total_apps") if isinstance(payload, dict) else None
        detail = "Fly.io Machines API reachable"
        if isinstance(total, int):
            detail += f"; apps={total}"
        return _healthy(result, detail)
    except Exception as exc:
        result["status"] = "error"
        result["error_class"] = _safe_error(exc)
        return result


def _check_heroku(
    provider: dict[str, Any],
    result: dict[str, Any],
    live: bool,
    auth: AuthResolution | None,
) -> dict[str, Any]:
    if not live:
        return _offline(result)
    if auth is None or not auth.credential:
        return _configured(result)
    token = auth.credential
    try:
        _get_json(
            "https://api.heroku.com/account",
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.heroku+json; version=3",
            },
        )
        return _healthy(result, "Heroku Platform API reachable")
    except Exception as exc:
        result["status"] = "error"
        result["error_class"] = _safe_error(exc)
        return result


CHECKERS: dict[
    str,
    Callable[[dict[str, Any], dict[str, Any], bool, AuthResolution | None], dict[str, Any]],
] = {
    "vercel": _check_vercel,
    "render": _check_render,
    "railway": _check_railway,
    "fly-io": _check_fly_io,
    "heroku": _check_heroku,
}


def check_provider(provider: dict[str, Any], live: bool = False) -> dict[str, Any]:
    result = _base_result(provider)
    checker = CHECKERS.get(provider.get("health_check"))
    if checker is None:
        result["status"] = "unknown"
        result["error_class"] = "unsupported_health_check"
        return result
    if not live:
        return checker(provider, result, False, None)

    auth = resolve_provider_auth(provider)
    result["auth_source"] = auth.auth_source
    if auth.status == "error":
        result["status"] = "error"
        result["error_class"] = auth.error_class or "auth_resolution_error"
        return result
    if auth.status != "configured":
        _not_configured(result, list(auth.missing))
        result["error_class"] = auth.error_class or "credential_unavailable"
        return result
    return checker(provider, result, True, auth)


def check_paas_provider(provider_id: str, live: bool = False) -> dict[str, Any]:
    """Run one bounded provider check for integration_health.py and the API."""
    return check_provider(get_provider(provider_id), live=live)


def run_health_check(live: bool = False) -> dict[str, Any]:
    registry = _load_registry()
    provider_specs = [provider for provider in registry["providers"] if provider.get("paas") is True]
    # Credential lookups may consult a remote secret manager. Keep the
    # dashboard responsive by checking independent providers concurrently.
    with ThreadPoolExecutor(max_workers=min(5, max(1, len(provider_specs)))) as executor:
        providers = list(executor.map(lambda provider: check_provider(provider, live=live), provider_specs))
    return {
        "version": registry["version"],
        "mode": "live" if live else "offline",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "write_actions_enabled": bool(registry.get("write_actions_enabled", False)),
        "write_actions_reason": registry.get("write_actions_reason"),
        "providers": providers,
        "summary": {
            "total": len(providers),
            "healthy": sum(item["status"] == "healthy" for item in providers),
            "configured": sum(item["status"] == "configured" for item in providers),
            "not_configured": sum(item["status"] == "not_configured" for item in providers),
            "errors": sum(item["status"] == "error" for item in providers),
        },
    }


def main() -> int:
    configure_utf8_stdio()
    args = set(sys.argv[1:])
    registry = _load_registry()
    if "--catalog" in args:
        payload = {
            "version": registry["version"],
            "purpose": registry["purpose"],
            "deployment_enabled": registry["deployment_enabled"],
            "write_actions_enabled": registry["write_actions_enabled"],
            "write_actions_reason": registry["write_actions_reason"],
            "providers": registry["providers"],
        }
    else:
        payload = run_health_check(live="--live" in args)
    if "--json" in args:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
