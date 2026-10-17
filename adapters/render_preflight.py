#!/usr/bin/env python3
"""Read-only Render discovery and rollback preflight.

This module deliberately never calls Render's rollback, deploy, or update
endpoints. It discovers bounded service/deploy metadata and evaluates whether
an explicitly named staging or production service is safe to propose for a
future rollback.

Usage:
    python3 render_preflight.py discover --json
    python3 render_preflight.py discover --live --environment-id env-example --json
    python3 render_preflight.py preflight --live --service-id srv-example \
        --environment-id evm-example --environment production \
        --target-deploy-id dep-previous \
        --health-url https://service.onrender.com/healthz --json
    python3 render_preflight.py action-preflight --live --source cli \
        --action deploy --service-id srv-example --environment-id evm-example \
        --environment production --target-revision <40-char-sha> --json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from platform_output import configure_utf8_stdio  # noqa: E402
from auth_resolver import AuthResolution, resolve_provider_auth  # noqa: E402
from cloud_providers import get_provider  # noqa: E402
from paas_health import _get_json, _safe_error  # noqa: E402


SCHEMA_VERSION = "solo-empire.render-preflight.v1"
BASE_URL = "https://api.render.com/v1"
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
SAFE_HEALTH_PATH = re.compile(r"^/[A-Za-z0-9_/-]{0,120}$")
FULL_SHA = re.compile(r"^[a-fA-F0-9]{40}$")
SUCCESSFUL_DEPLOY_STATUSES = {"live", "deactivated", "succeeded", "success"}
NON_RUNNING_DEPLOY_STATUSES = {
    "live",
    "deactivated",
    "build_failed",
    "update_failed",
    "pre_deploy_failed",
    "canceled",
}
SOURCES = {"api", "cli"}
HEALTH_PROBE_TIMEOUT_SECONDS = 20
RENDER_PROVIDER = get_provider("render")


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _api_url(path: str, params: dict[str, str] | None = None) -> str:
    url = f"{BASE_URL}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    return url


def _safe_identifier(value: str | None, field: str) -> str:
    normalized = " ".join(str(value or "").split())[:256]
    if not normalized or not SAFE_ID.fullmatch(normalized):
        raise ValueError(f"{field} must be a bounded Render identifier")
    return normalized


def _run_cli(arguments: list[str]) -> Any:
    """Run a Render CLI read command without exposing stderr or raw payloads."""
    try:
        completed = subprocess.run(
            ["render", *arguments, "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("render_cli_not_installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("render_cli_timeout") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("render_cli_command_failed") from exc
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("render_cli_invalid_json") from exc


def _extract_items(payload: Any, resource_key: str) -> list[dict[str, Any]]:
    """Accept Render's cursor-wrapped list shape and safe direct-list fixtures."""
    raw_items: list[Any] = []
    if isinstance(payload, list):
        raw_items = payload
    elif isinstance(payload, dict):
        for key in ("items", resource_key, "data"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                raw_items = candidate
                break

    items: list[dict[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        nested = item.get(resource_key)
        items.append(nested if isinstance(nested, dict) else item)
    return items


def _extract_resource(payload: Any, resource_key: str) -> dict[str, Any]:
    if isinstance(payload, dict):
        nested = payload.get(resource_key)
        if isinstance(nested, dict):
            return nested
        data = payload.get("data")
        if isinstance(data, dict):
            nested = data.get(resource_key)
            if isinstance(nested, dict):
                return nested
        return payload
    return {}


def _render_health_host(service: dict[str, Any]) -> str | None:
    """Return only a provider-owned Render host suitable for health probes."""
    details = (
        service.get("serviceDetails")
        if isinstance(service.get("serviceDetails"), dict)
        else {}
    )
    raw_url = details.get("url") or service.get("url") or ""
    if not isinstance(raw_url, str):
        return None
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        hostname = (parsed.hostname or "").lower()
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.port
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]*\.onrender\.com", hostname)
        ):
            return None
        return hostname
    except (TypeError, ValueError):
        return None


def _clean_health_path(value: Any) -> str | None:
    """Return only a bounded path suitable for a provider-owned health probe."""
    if not isinstance(value, str):
        return None
    path = value.strip()
    if not SAFE_HEALTH_PATH.fullmatch(path) or "//" in path:
        return None
    return path


def _auto_deploy_value(value: Any) -> str | None:
    if value is True or value == "yes":
        return "yes"
    if value is False or value == "no":
        return "no"
    return None


def _clean_service(
    service: dict[str, Any], environment_name: str | None = None
) -> dict[str, Any]:
    return {
        "id": service.get("id"),
        "name": service.get("name"),
        "type": service.get("type"),
        "environment_id": service.get("environmentId"),
        "auto_deploy": service.get("autoDeploy"),
        "branch": service.get("branch"),
        "suspended": service.get("suspended"),
        "environment_name": environment_name,
        "health_host": _render_health_host(service),
        "health_path": _clean_health_path(service.get("healthCheckPath")),
    }


def _cli_service_entries(payload: Any) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    entries: list[tuple[dict[str, Any], dict[str, Any]]] = []
    if not isinstance(payload, list):
        return entries
    for item in payload:
        if not isinstance(item, dict) or not isinstance(item.get("service"), dict):
            continue
        environment = item.get("environment")
        entries.append(
            (item["service"], environment if isinstance(environment, dict) else {})
        )
    return entries


def _cli_service_match(
    payload: Any, service_id: str
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    for service, environment in _cli_service_entries(payload):
        if service.get("id") == service_id:
            return service, environment
    return None


def _clean_environment(environment: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": environment.get("id"),
        "name": environment.get("name"),
        "project_id": environment.get("projectId"),
    }


def _clean_deploy(
    deploy: dict[str, Any], service_id: str | None = None
) -> dict[str, Any]:
    commit = deploy.get("commit")
    commit_id = commit.get("id") if isinstance(commit, dict) else deploy.get("commitId")
    return {
        "id": deploy.get("id"),
        # The list endpoint may omit serviceId because the request is already
        # scoped to `/services/{service_id}/deploys`.
        "service_id": deploy.get("serviceId") or service_id,
        "status": deploy.get("status"),
        "commit_id": commit_id,
        "created_at": deploy.get("createdAt"),
        "finished_at": deploy.get("finishedAt"),
        "trigger": deploy.get("trigger"),
    }


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Keep each health probe on its explicitly selected URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _probe_url(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "solo-empire-render-preflight/1.0",
        },
        method="GET",
    )
    try:
        opener = urllib.request.build_opener(_NoRedirects())
        with opener.open(request, timeout=HEALTH_PROBE_TIMEOUT_SECONDS) as response:
            status = int(response.status)
        return {
            "status": "passed" if 200 <= status < 300 else "blocked",
            "http_status": status,
        }
    except Exception as exc:
        status = getattr(exc, "code", None)
        result: dict[str, Any] = {"status": "blocked", "error_class": _safe_error(exc)}
        if isinstance(status, int):
            result["http_status"] = status
        return result


def _health_host(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("health_url must be an http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("health_url must not contain credentials")
    return parsed.hostname or parsed.netloc


def _base_payload(mode: str, action: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "provider": "render",
        "mode": mode,
        "read_only": True,
        "action": action,
        "execution_allowed": False,
        "write_actions_enabled": False,
        "external_calls": 0,
        "write_attempted": False,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _auth_context(
    *,
    live: bool,
    source: str,
    auth: AuthResolution | None = None,
) -> tuple[AuthResolution | None, str | None, dict[str, Any], str]:
    if not live:
        return None, None, {"status": "not_checked", "missing": []}, "not_checked"
    if source == "cli":
        return None, None, {"status": "cli_session", "missing": []}, "cli_session"

    resolved = auth or resolve_provider_auth(RENDER_PROVIDER)
    credential = resolved.credential if resolved.status == "configured" else None
    credentials: dict[str, Any] = {
        "status": resolved.status,
        "missing": list(resolved.missing),
    }
    if resolved.error_class:
        credentials["error_class"] = resolved.error_class
    return resolved, credential, credentials, resolved.auth_source or "not_checked"


def discover(
    *,
    live: bool = False,
    service_id: str | None = None,
    environment_id: str | None = None,
    limit: int = 20,
    source: str = "api",
    _auth: AuthResolution | None = None,
) -> dict[str, Any]:
    """Discover Render services and, when selected, recent deploy metadata."""
    payload = _base_payload("live" if live else "offline", "discover")
    payload.update(
        {"services": [], "deploys": [], "summary": {"services": 0, "deploys": 0}}
    )

    if limit < 1 or limit > 100:
        raise ValueError("limit must be between 1 and 100")
    if source not in SOURCES:
        raise ValueError("source must be api or cli")
    selected_service = (
        _safe_identifier(service_id, "service_id") if service_id else None
    )
    selected_environment = (
        _safe_identifier(environment_id, "environment_id") if environment_id else None
    )
    payload["request"] = {
        "service_id": selected_service,
        "environment_id": selected_environment,
        "limit": limit,
        "source": source,
    }

    auth, token, credentials, auth_source = _auth_context(
        live=live,
        source=source,
        auth=_auth,
    )
    payload["auth_source"] = auth_source
    payload["credentials"] = credentials
    if not live:
        payload["status"] = "not_checked"
        payload["blockers"] = ["live-check-not-requested"]
        return payload
    if source == "api" and not token:
        auth_error = credentials["status"] == "error"
        payload["status"] = "error" if auth_error else "not_configured"
        payload["blockers"] = [
            "render-auth-resolution-failed"
            if auth_error
            else "render-credential-not-configured"
        ]
        return payload

    try:
        if source == "cli":
            response = _run_cli(["services"])
            payload["external_calls"] += 1
            entries = _cli_service_entries(response)
            services = [
                _clean_service(service, environment.get("name"))
                for service, environment in entries
                if not selected_environment
                or service.get("environmentId") == selected_environment
            ]
        else:
            params = {"limit": str(limit), "includePreviews": "false"}
            if selected_environment:
                params["environmentId"] = selected_environment
            response = _get_json(_api_url("/services", params), _headers(token))
            payload["external_calls"] += 1
            services = [
                _clean_service(item) for item in _extract_items(response, "service")
            ]
        if selected_service:
            services = [item for item in services if item.get("id") == selected_service]
        if (
            source == "api"
            and selected_service
            and services
            and (
                not services[0].get("health_host") or not services[0].get("health_path")
            )
        ):
            # Render's list response can omit serviceDetails or the configured
            # health path; fetch only the selected resource so the dashboard
            # can derive bounded provider-owned values without exposing raw
            # response fields.
            try:
                detail_response = _get_json(
                    _api_url(
                        f"/services/{urllib.parse.quote(selected_service, safe='')}"
                    ),
                    _headers(token),
                )
                payload["external_calls"] += 1
                detail = _extract_resource(detail_response, "service")
                services[0]["health_host"] = _render_health_host(detail)
                services[0]["health_path"] = _clean_health_path(
                    detail.get("healthCheckPath")
                )
            except Exception:
                services[0]["health_host"] = None
                services[0]["health_path"] = None
        payload["services"] = services
    except Exception as exc:
        if payload["external_calls"] == 0:
            payload["external_calls"] += 1
        payload["status"] = "error"
        payload["error_class"] = (
            str(exc) if str(exc).startswith("render_cli_") else _safe_error(exc)
        )
        payload["blockers"] = ["render-services-discovery-failed"]
        return payload

    if selected_service and not payload["services"]:
        payload["status"] = "blocked"
        payload["blockers"] = ["service-not-found-in-scope"]
    else:
        payload["status"] = "ready"
        payload["blockers"] = []

    if selected_service and payload["services"]:
        try:
            if source == "cli":
                deploy_response = _run_cli(["deploys", "list", selected_service])
            else:
                deploy_response = _get_json(
                    _api_url(
                        f"/services/{urllib.parse.quote(selected_service, safe='')}/deploys",
                        {"limit": "20"},
                    ),
                    _headers(token),
                )
            payload["external_calls"] += 1
            payload["deploys"] = [
                _clean_deploy(item, selected_service)
                for item in _extract_items(deploy_response, "deploy")
            ]
        except Exception as exc:
            payload["external_calls"] += 1
            payload["status"] = "error"
            payload["error_class"] = (
                str(exc) if str(exc).startswith("render_cli_") else _safe_error(exc)
            )
            payload["blockers"] = ["render-deploy-discovery-failed"]

    payload["summary"] = {
        "services": len(payload["services"]),
        "deploys": len(payload["deploys"]),
    }
    return payload


def _finish_preflight(payload: dict[str, Any], blockers: list[str]) -> dict[str, Any]:
    payload["blockers"] = list(dict.fromkeys(blockers))
    payload["preflight_passed"] = not payload["blockers"]
    payload["status"] = "preflight_passed" if payload["preflight_passed"] else "blocked"
    return payload


def _preflight_cli(
    payload: dict[str, Any],
    blockers: list[str],
    service: str,
    environment_ref: str,
    deploy: str,
    health_url: str,
    health_host: str,
    expected_environment: str,
) -> dict[str, Any]:
    """Evaluate a target using the already-authenticated Render CLI session."""
    try:
        services_response = _run_cli(["services"])
        payload["external_calls"] += 1
        match = _cli_service_match(services_response, service)
        if match is None:
            payload["checks"]["service"] = {
                "status": "blocked",
                "error_class": "service_not_found",
            }
            blockers.append("render-service-not-found")
            return _finish_preflight(payload, blockers)
        service_data, environment_data = match
        cleaned_service = _clean_service(service_data, environment_data.get("name"))
        service_check = {"status": "passed", "service": cleaned_service}
        if service_data.get("id") != service:
            blockers.append("service-id-mismatch")
        actual_environment_id = service_data.get(
            "environmentId"
        ) or environment_data.get("id")
        if actual_environment_id != environment_ref:
            blockers.append("service-environment-mismatch")
        service_type = str(service_data.get("type") or "").lower()
        if service_type == "cron_job":
            blockers.append("cron-job-not-supported")
        auto_deploy = str(service_data.get("autoDeploy") or "").lower()
        service_check["auto_deploy"] = service_data.get("autoDeploy")
        if auto_deploy not in {"no", "false", "0"}:
            blockers.append("auto-deploy-enabled")
        payload["checks"]["service"] = service_check

        environment_check = {
            "status": "passed",
            "environment": _clean_environment(environment_data),
        }
        if environment_data.get("id") != environment_ref:
            blockers.append("environment-id-mismatch")
        if str(environment_data.get("name") or "").lower() != expected_environment:
            blockers.append("environment-name-mismatch")
        payload["checks"]["environment"] = environment_check
    except Exception as exc:
        payload["external_calls"] += 1
        payload["checks"]["service"] = {"status": "blocked", "error_class": str(exc)}
        blockers.append("render-cli-services-read-failed")
        return _finish_preflight(payload, blockers)

    try:
        deploy_response = _run_cli(["deploys", "list", service])
        payload["external_calls"] += 1
        deploy_items = _extract_items(deploy_response, "deploy")
        deploy_data = next(
            (item for item in deploy_items if item.get("id") == deploy), None
        )
        if deploy_data is None:
            payload["checks"]["target_deploy"] = {
                "status": "blocked",
                "error_class": "deploy_not_found",
            }
            blockers.append("target-deploy-not-found")
        else:
            deploy_check = {"status": "passed", "deploy": _clean_deploy(deploy_data)}
            if deploy_data.get("serviceId") not in {None, service}:
                blockers.append("deploy-service-mismatch")
            deploy_status = str(deploy_data.get("status") or "").lower()
            if deploy_status not in SUCCESSFUL_DEPLOY_STATUSES:
                blockers.append("target-deploy-not-successful")
            payload["checks"]["target_deploy"] = deploy_check
    except Exception as exc:
        payload["external_calls"] += 1
        payload["checks"]["target_deploy"] = {
            "status": "blocked",
            "error_class": str(exc),
        }
        blockers.append("render-cli-deploys-read-failed")

    health_check = _probe_url(health_url)
    payload["external_calls"] += 1
    payload["checks"]["health_endpoint"] = {"host": health_host, **health_check}
    if health_check.get("status") != "passed":
        blockers.append("health-endpoint-not-healthy")
    return _finish_preflight(payload, blockers)


def preflight(
    *,
    live: bool,
    service_id: str,
    environment_id: str,
    target_deploy_id: str,
    health_url: str,
    environment: str = "staging",
    source: str = "api",
    _auth: AuthResolution | None = None,
) -> dict[str, Any]:
    """Evaluate a Render rollback target without making a provider mutation."""
    payload = _base_payload("live" if live else "offline", "rollback")
    if source not in SOURCES:
        raise ValueError("source must be api or cli")
    blockers: list[str] = []
    service = _safe_identifier(service_id, "service_id")
    environment_ref = _safe_identifier(environment_id, "environment_id")
    deploy = _safe_identifier(target_deploy_id, "target_deploy_id")
    health_host = _health_host(health_url)
    payload["target_environment"] = environment
    payload["request"] = {
        "service_id": service,
        "environment_id": environment_ref,
        "target_deploy_id": deploy,
        "health_host": health_host,
        "health_check_requested": True,
        "source": source,
    }
    payload["checks"] = {}

    if environment.lower() not in {"staging", "production"}:
        blockers.append("invalid-environment")
    if not live:
        blockers.append("live-check-required")

    auth, token, credentials, auth_source = _auth_context(
        live=live,
        source=source,
        auth=_auth,
    )
    payload["auth_source"] = auth_source
    payload["credentials"] = credentials
    if source == "api" and live and not token:
        blockers.append(
            "render-auth-resolution-failed"
            if credentials["status"] == "error"
            else "render-credential-not-configured"
        )

    if blockers:
        payload["blockers"] = list(dict.fromkeys(blockers))
        payload["preflight_passed"] = False
        payload["status"] = (
            "error"
            if source == "api" and credentials["status"] == "error"
            else "not_configured"
            if source == "api" and live and not token
            else "blocked"
        )
        return payload

    if source == "cli":
        return _preflight_cli(
            payload,
            blockers,
            service,
            environment_ref,
            deploy,
            health_url,
            health_host,
            environment.lower(),
        )

    headers = _headers(token)

    try:
        raw_service = _get_json(
            _api_url(f"/services/{urllib.parse.quote(service, safe='')}"),
            headers,
        )
        payload["external_calls"] += 1
        service_data = _extract_resource(raw_service, "service")
        cleaned_service = _clean_service(service_data)
        service_check = {"status": "passed", "service": cleaned_service}
        if service_data.get("id") != service:
            blockers.append("service-id-mismatch")
        if service_data.get("environmentId") != environment_ref:
            blockers.append("service-environment-mismatch")
        service_type = str(service_data.get("type") or "").lower()
        if service_type == "cron_job":
            blockers.append("cron-job-not-supported")
        auto_deploy = str(service_data.get("autoDeploy") or "").lower()
        service_check["auto_deploy"] = service_data.get("autoDeploy")
        if auto_deploy not in {"no", "false", "0"}:
            blockers.append("auto-deploy-enabled")
        payload["checks"]["service"] = service_check
    except Exception as exc:
        payload["external_calls"] += 1
        payload["checks"]["service"] = {
            "status": "blocked",
            "error_class": _safe_error(exc),
        }
        blockers.append("render-service-read-failed")

    try:
        raw_environment = _get_json(
            _api_url(f"/environments/{urllib.parse.quote(environment_ref, safe='')}"),
            headers,
        )
        payload["external_calls"] += 1
        environment_data = _extract_resource(raw_environment, "environment")
        clean_environment = _clean_environment(environment_data)
        environment_check = {"status": "passed", "environment": clean_environment}
        if environment_data.get("id") != environment_ref:
            blockers.append("environment-id-mismatch")
        if str(environment_data.get("name") or "").lower() != environment.lower():
            blockers.append("environment-name-mismatch")
        payload["checks"]["environment"] = environment_check
    except Exception as exc:
        payload["external_calls"] += 1
        payload["checks"]["environment"] = {
            "status": "blocked",
            "error_class": _safe_error(exc),
        }
        blockers.append("render-environment-read-failed")

    try:
        raw_deploy = _get_json(
            _api_url(
                f"/services/{urllib.parse.quote(service, safe='')}/deploys/{urllib.parse.quote(deploy, safe='')}"
            ),
            headers,
        )
        payload["external_calls"] += 1
        deploy_data = _extract_resource(raw_deploy, "deploy")
        cleaned_deploy = _clean_deploy(deploy_data)
        deploy_check = {"status": "passed", "deploy": cleaned_deploy}
        if deploy_data.get("id") != deploy:
            blockers.append("deploy-id-mismatch")
        if deploy_data.get("serviceId") not in {None, service}:
            blockers.append("deploy-service-mismatch")
        deploy_status = str(deploy_data.get("status") or "").lower()
        if deploy_status not in SUCCESSFUL_DEPLOY_STATUSES:
            blockers.append("target-deploy-not-successful")
        payload["checks"]["target_deploy"] = deploy_check
    except Exception as exc:
        payload["external_calls"] += 1
        payload["checks"]["target_deploy"] = {
            "status": "blocked",
            "error_class": _safe_error(exc),
        }
        blockers.append("render-deploy-read-failed")

    health_check = _probe_url(health_url)
    payload["external_calls"] += 1
    payload["checks"]["health_endpoint"] = {"host": health_host, **health_check}
    if health_check.get("status") != "passed":
        blockers.append("health-endpoint-not-healthy")

    return _finish_preflight(payload, blockers)


def action_preflight(
    *,
    live: bool,
    action: str,
    service_id: str,
    environment_id: str,
    environment: str = "staging",
    target_deploy_id: str | None = None,
    target_revision: str | None = None,
    auto_deploy: str | None = None,
    health_path: str | None = "/healthz",
    source: str = "api",
) -> dict[str, Any]:
    """Check a Render action's live recovery and health prerequisites.

    This is read-only. Rollback delegates to the stricter existing preflight;
    deploy, restart, and set-auto-deploy use the same bounded discovery data
    without submitting a provider mutation.
    """
    allowed_actions = {"deploy", "restart", "rollback", "set-auto-deploy"}
    if action == "rollback":
        if not target_deploy_id:
            raise ValueError("target_deploy_id is required for rollback")
        path = _clean_health_path(health_path or "/healthz")
        if path is None:
            raise ValueError("invalid health_path")
        if not live:
            return preflight(
                live=False,
                source=source,
                service_id=service_id,
                environment_id=environment_id,
                target_deploy_id=target_deploy_id,
                health_url=f"https://service.onrender.com{path}",
                environment=environment,
            )
        auth, _, _, _ = _auth_context(live=True, source=source)
        # Derive the real provider-owned host before probing. This branch
        # intentionally does not trust an operator-supplied host.
        discovery = discover(
            live=True,
            service_id=service_id,
            environment_id=environment_id,
            source=source,
            _auth=auth,
        )
        service = (discovery.get("services") or [{}])[0]
        health_host = service.get("health_host")
        if not health_host:
            blocked = _base_payload("live", action)
            blocked.update(
                {
                    "target_environment": environment,
                    "auth_source": discovery.get("auth_source", "not_checked"),
                    "request": {
                        "service_id": service_id,
                        "environment_id": environment_id,
                        "target_deploy_id": target_deploy_id,
                        "health_path": path,
                        "source": source,
                    },
                    "credentials": discovery.get("credentials", {}),
                    "checks": {
                        "service": {
                            "status": "blocked",
                            "error_class": "render-health-host-unavailable",
                        }
                    },
                    "external_calls": int(discovery.get("external_calls") or 0),
                }
            )
            return _finish_preflight(blocked, ["render-health-host-unavailable"])
        result = preflight(
            live=True,
            source=source,
            service_id=service_id,
            environment_id=environment_id,
            target_deploy_id=target_deploy_id,
            health_url=f"https://{health_host}{path}",
            environment=environment,
            _auth=auth,
        )
        result["external_calls"] = int(result.get("external_calls") or 0) + int(
            discovery.get("external_calls") or 0
        )
        return result

    payload = _base_payload("live" if live else "offline", action)
    blockers: list[str] = []
    if source not in SOURCES:
        raise ValueError("source must be api or cli")
    service = _safe_identifier(service_id, "service_id")
    environment_ref = _safe_identifier(environment_id, "environment_id")
    checked_path = (
        _clean_health_path(health_path or "/healthz")
        if action != "set-auto-deploy"
        else None
    )
    payload["target_environment"] = environment
    payload["request"] = {
        "service_id": service,
        "environment_id": environment_ref,
        "environment": environment,
        "target_revision": target_revision if action == "deploy" else None,
        "auto_deploy": auto_deploy if action == "set-auto-deploy" else None,
        "health_path": checked_path,
        "source": source,
    }
    payload["checks"] = {}

    if action not in allowed_actions:
        blockers.append("invalid-action")
    if environment.lower() not in {"staging", "production"}:
        blockers.append("invalid-environment")
    if not live:
        blockers.append("live-check-required")
    if action == "deploy" and not isinstance(target_revision, str):
        blockers.append("full-commit-sha-required")
    elif action == "deploy" and not FULL_SHA.fullmatch(target_revision):
        blockers.append("full-commit-sha-required")
    if action == "set-auto-deploy" and auto_deploy not in {"yes", "no"}:
        blockers.append("invalid-auto-deploy-state")
    if action != "set-auto-deploy" and checked_path is None:
        blockers.append("invalid-health-path")

    auth, token, credentials, auth_source = _auth_context(live=live, source=source)
    payload["auth_source"] = auth_source
    payload["credentials"] = credentials
    if source == "api" and live and not token:
        blockers.append(
            "render-auth-resolution-failed"
            if credentials["status"] == "error"
            else "render-credential-not-configured"
        )
    if blockers:
        return _finish_preflight(payload, blockers)

    discovery = discover(
        live=True,
        service_id=service,
        environment_id=environment_ref,
        source=source,
        _auth=auth,
    )
    payload["external_calls"] += int(discovery.get("external_calls") or 0)
    payload["credentials"] = discovery.get("credentials", payload["credentials"])
    services = discovery.get("services") or []
    if discovery.get("status") not in {"ready"} or not services:
        blockers.extend(
            discovery.get("blockers") or ["render-services-discovery-failed"]
        )
        return _finish_preflight(payload, blockers)

    service_data = services[0]
    service_check = {"status": "passed", "service": service_data}
    if service_data.get("id") != service:
        blockers.append("service-id-mismatch")
    if service_data.get("environment_id") != environment_ref:
        blockers.append("service-environment-mismatch")
    if str(service_data.get("type") or "").lower() != "web_service":
        blockers.append("web-service-required")
    if str(service_data.get("environment_name") or "").lower() != environment.lower():
        blockers.append("environment-name-mismatch")
    current_auto_deploy = _auto_deploy_value(service_data.get("auto_deploy"))
    service_check["auto_deploy"] = current_auto_deploy
    payload["checks"]["service"] = service_check

    if action == "set-auto-deploy":
        if current_auto_deploy is None:
            blockers.append("auto-deploy-state-unknown")
        elif current_auto_deploy == auto_deploy:
            blockers.append("auto-deploy-already-set")
        return _finish_preflight(payload, blockers)

    if current_auto_deploy != "no":
        blockers.append("auto-deploy-enabled")
    deploys = discovery.get("deploys") or []
    if not deploys:
        blockers.append("invalid-deploy-list")
    elif any(row.get("status") not in NON_RUNNING_DEPLOY_STATUSES for row in deploys):
        blockers.append("deploy-already-in-progress")
    live_deploys = [row for row in deploys if row.get("status") == "live"]
    if len(live_deploys) != 1:
        blockers.append("current-deploy-required-for-recovery")
    current_deploy = live_deploys[0] if len(live_deploys) == 1 else {}
    payload["checks"]["current_deploy"] = {
        "status": "passed" if len(live_deploys) == 1 else "blocked",
        "deploy": current_deploy,
    }
    health_host = service_data.get("health_host")
    if not health_host:
        blockers.append("render-health-host-unavailable")
    else:
        health_url = f"https://{health_host}{checked_path}"
        health_check = _probe_url(health_url)
        payload["external_calls"] += 1
        payload["checks"]["health_endpoint"] = {
            "host": health_host,
            "path": checked_path,
            **health_check,
        }
        if health_check.get("status") != "passed":
            blockers.append("health-endpoint-not-healthy")
    return _finish_preflight(payload, blockers)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only Render discovery and rollback preflight"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser(
        "discover", help="Discover services and recent deploy metadata"
    )
    discover_parser.add_argument(
        "--live", action="store_true", help="Call Render read-only endpoints or CLI"
    )
    discover_parser.add_argument(
        "--source",
        choices=sorted(SOURCES),
        default="api",
        help="Authentication/read source",
    )
    discover_parser.add_argument("--service-id")
    discover_parser.add_argument("--environment-id")
    discover_parser.add_argument("--limit", type=int, default=20)
    discover_parser.add_argument("--json", action="store_true")

    preflight_parser = subparsers.add_parser(
        "preflight", help="Check a staging or production rollback target"
    )
    preflight_parser.add_argument(
        "--live",
        action="store_true",
        help="Call Render read-only endpoints or CLI and health URL",
    )
    preflight_parser.add_argument(
        "--source",
        choices=sorted(SOURCES),
        default="api",
        help="Authentication/read source",
    )
    preflight_parser.add_argument("--service-id", required=True)
    preflight_parser.add_argument("--environment-id", required=True)
    preflight_parser.add_argument("--target-deploy-id", required=True)
    preflight_parser.add_argument("--health-url", required=True)
    preflight_parser.add_argument(
        "--environment", default="staging", choices=["staging", "production"]
    )
    preflight_parser.add_argument("--json", action="store_true")

    action_parser = subparsers.add_parser(
        "action-preflight",
        help="Check a deploy, restart, rollback, or configuration action",
    )
    action_parser.add_argument(
        "--live",
        action="store_true",
        help="Call Render read-only endpoints or CLI and health URL",
    )
    action_parser.add_argument(
        "--source",
        choices=sorted(SOURCES),
        default="api",
        help="Authentication/read source",
    )
    action_parser.add_argument(
        "--action",
        choices=["deploy", "restart", "rollback", "set-auto-deploy"],
        required=True,
    )
    action_parser.add_argument("--service-id", required=True)
    action_parser.add_argument("--environment-id", required=True)
    action_parser.add_argument(
        "--environment", default="staging", choices=["staging", "production"]
    )
    action_parser.add_argument("--target-deploy-id")
    action_parser.add_argument("--target-revision")
    action_parser.add_argument("--auto-deploy", choices=["yes", "no"])
    action_parser.add_argument("--health-path", default="/healthz")
    action_parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_utf8_stdio()
    args = _parser().parse_args(argv)
    try:
        if args.command == "discover":
            result = discover(
                live=args.live,
                service_id=args.service_id,
                environment_id=args.environment_id,
                limit=args.limit,
                source=args.source,
            )
        else:
            if args.command == "preflight":
                result = preflight(
                    live=args.live,
                    service_id=args.service_id,
                    environment_id=args.environment_id,
                    target_deploy_id=args.target_deploy_id,
                    health_url=args.health_url,
                    environment=args.environment,
                    source=args.source,
                )
            else:
                result = action_preflight(
                    live=args.live,
                    action=args.action,
                    service_id=args.service_id,
                    environment_id=args.environment_id,
                    environment=args.environment,
                    target_deploy_id=args.target_deploy_id,
                    target_revision=args.target_revision,
                    auto_deploy=args.auto_deploy,
                    health_path=args.health_path,
                    source=args.source,
                )
    except ValueError as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "provider": "render",
            "read_only": True,
            "execution_allowed": False,
            "write_attempted": False,
            "status": "invalid_request",
            "error_class": "invalid_request",
            "error": str(exc),
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
