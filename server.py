#!/usr/bin/env python3
"""Independent Cloud / PaaS API for the Solo Empire extraction pilot.

The service exposes the existing sanitized, read-only cloud projections behind
its own process boundary.  PaaS mutations are still governed by
``paas_execute.dispatch`` and require the same local-owner boundary as the
legacy dashboard.  Provider credentials are resolved by the existing
platform adapters and never enter an HTTP response.

Run from the repository root::

    python3 server.py

The default bind is ``127.0.0.1:3440``.  A non-loopback bind requires
``CLOUD_API_TOKEN`` and should also be placed behind TLS and an authenticated
reverse proxy.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, UTC
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from collections.abc import Mapping
from urllib.parse import parse_qs, urlsplit


# The sanitized provider adapters (cloud_usage, paas_*, render_preflight and helpers) are
# vendored in ./adapters together with the registries they read in ./registry.
REPOSITORY_ROOT = Path(__file__).resolve().parent
ADAPTERS_ROOT = REPOSITORY_ROOT / "adapters"
if str(ADAPTERS_ROOT) not in sys.path:
    sys.path.insert(0, str(ADAPTERS_ROOT))

import cloud_usage  # noqa: E402
import paas_action  # noqa: E402
import paas_execute  # noqa: E402
import paas_inventory  # noqa: E402
import render_preflight  # noqa: E402


SERVICE_NAME = "solo-empire-cloud-api"
SCHEMA_VERSION = "solo-empire.cloud-api.v1"
MAX_BODY_BYTES = 16 * 1024
MAX_TARGET_CHARS = 4096
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
LOOPBACK_PEERS = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}
FORWARDED_HEADERS = {
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
}
COMMAND_OPERATIONS = {"register", "status", "approve", "execute", "verify", "reconcile"}
SAFE_ERROR_CODE = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")


class ApiError(Exception):
    """Expected client/service error with a safe public code."""

    def __init__(self, status: int, message: str, *, code: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code


@dataclass(frozen=True)
class Response:
    status: int
    payload: dict[str, Any]


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _error_payload(code: str, message: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": utc_now(),
        "error": {"code": code, "message": message},
    }


def _contract_payload(payload: Mapping[str, Any], route: str) -> dict[str, Any]:
    """Attach the service contract without changing adapter-owned fields."""
    result = dict(payload)
    result.setdefault("contract", SCHEMA_VERSION)
    result.setdefault("route", route)
    return result


def _safe_error_code(value: Any, fallback: str) -> str:
    candidate = str(value or "").strip()
    return candidate if SAFE_ERROR_CODE.fullmatch(candidate) else fallback


def _is_loopback_host(value: str) -> bool:
    normalized = value.strip().lower().strip("[]")
    return normalized in LOCAL_HOSTS


def _host_name(value: str) -> str | None:
    try:
        return urlsplit(f"http://{value}").hostname
    except ValueError:
        return None


def _json_body(body: bytes | None) -> dict[str, Any]:
    raw = body or b""
    if len(raw) > MAX_BODY_BYTES:
        raise ApiError(413, "request body is too large", code="command_too_large")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError(
            400, "request body must be valid JSON", code="invalid_command"
        ) from exc
    if not isinstance(parsed, dict):
        raise ApiError(
            400, "request body must be a JSON object", code="invalid_command"
        )
    return parsed


def _query_bool(
    query: Mapping[str, list[str]], name: str, default: bool = False
) -> bool:
    raw = (query.get(name) or [None])[0]
    if raw is None or raw == "":
        return default
    if raw.lower() in {"true", "1", "yes"}:
        return True
    if raw.lower() in {"false", "0", "no"}:
        return False
    raise ApiError(400, f"{name} must be true or false", code=f"invalid_{name}")


def _query_int(
    query: Mapping[str, list[str]], name: str, default: int, minimum: int, maximum: int
) -> int:
    raw = (query.get(name) or [None])[0]
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ApiError(
            400, f"{name} must be an integer", code=f"invalid_{name}"
        ) from exc
    if value < minimum or value > maximum:
        raise ApiError(
            400,
            f"{name} must be between {minimum} and {maximum}",
            code=f"invalid_{name}",
        )
    return value


class CloudApi:
    """Transport-independent Cloud/PaaS API used by the HTTP adapter and tests."""

    def __init__(
        self,
        *,
        token: str | None = None,
        environment: str | None = None,
        allowed_origins: tuple[str, ...] | None = None,
    ) -> None:
        self.token = (
            token
            if token is not None
            else os.environ.get("CLOUD_API_TOKEN", "").strip()
        )
        self.environment = (
            (environment or os.environ.get("CLOUD_API_ENV", "development"))
            .strip()
            .lower()
        )
        configured_origins = os.environ.get(
            "CLOUD_API_CORS_ORIGINS",
            "http://localhost:3400,http://127.0.0.1:3400",
        )
        self.allowed_origins = allowed_origins or tuple(
            value.strip() for value in configured_origins.split(",") if value.strip()
        )

    def _authorized(self, headers: Mapping[str, str]) -> bool:
        if not self.token:
            return self.environment != "production"
        authorization = str(headers.get("authorization", ""))
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            return False
        return secrets.compare_digest(authorization[len(prefix) :], self.token)

    def _require_read_auth(self, headers: Mapping[str, str]) -> None:
        if not self._authorized(headers):
            raise ApiError(
                401,
                "Cloud API authentication is required",
                code="cloud_api_auth_required",
            )

    def _owner_gate(
        self, headers: Mapping[str, str], remote_address: str | None
    ) -> None:
        if remote_address not in LOOPBACK_PEERS:
            raise ApiError(
                403,
                "local owner request is required",
                code="local_owner_request_required",
            )
        if any(key.lower() in FORWARDED_HEADERS for key in headers):
            raise ApiError(
                403,
                "forwarded command requests are not accepted",
                code="forwarded_request_rejected",
            )
        if headers.get("x-solo-paas-command") != "1":
            raise ApiError(
                403,
                "PaaS command marker is required",
                code="local_owner_request_required",
            )
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ApiError(
                415,
                "PaaS commands require application/json",
                code="json_content_type_required",
            )
        host = _host_name(headers.get("host", ""))
        origin_value = headers.get("origin", "")
        try:
            origin = urlsplit(origin_value)
            origin_hostname = origin.hostname or ""
            origin_username = origin.username
            origin_password = origin.password
        except ValueError as exc:
            raise ApiError(
                403,
                "a local browser origin is required",
                code="local_owner_request_required",
            ) from exc
        if (
            not host
            or not _is_loopback_host(host)
            or not _is_loopback_host(origin_hostname)
        ):
            raise ApiError(
                403,
                "local owner request is required",
                code="local_owner_request_required",
            )
        origin_base = f"{origin.scheme}://{origin.netloc}"
        if (
            origin.scheme != "http"
            or origin_username
            or origin_password
            or origin_base not in self.allowed_origins
        ):
            raise ApiError(
                403,
                "origin is not an allowed local owner origin",
                code="local_owner_request_required",
            )
        if not self._authorized(headers):
            raise ApiError(
                401,
                "Cloud API authentication is required",
                code="cloud_api_auth_required",
            )

    @staticmethod
    def _unavailable(code: str) -> Response:
        return Response(
            503, _error_payload(code, "Cloud API dependency is unavailable")
        )

    def _cloud_usage(self, live: bool) -> Response:
        try:
            return Response(
                200,
                _contract_payload(cloud_usage.build_snapshot(live=live), "cloud_usage"),
            )
        except Exception:
            return self._unavailable("cloud_usage_unavailable")

    def _inventory(self, live: bool, provider_id: str | None = None) -> Response:
        try:
            return Response(
                200,
                _contract_payload(
                    paas_inventory.run_inventory(live=live, provider_id=provider_id),
                    "paas_inventory",
                ),
            )
        except Exception:
            return self._unavailable("paas_inventory_unavailable")

    def _actions(self) -> Response:
        try:
            policy = paas_action.load_policy()
            if not isinstance(policy, dict):
                raise ValueError("policy is not an object")
            return Response(200, _contract_payload(policy, "paas_actions"))
        except Exception:
            return self._unavailable("paas_action_policy_unavailable")

    def _render_discovery(self, query: Mapping[str, list[str]]) -> Response:
        try:
            result = render_preflight.discover(
                live=_query_bool(query, "live"),
                source=(query.get("source") or ["api"])[0],
                service_id=(query.get("service_id") or [None])[0],
                environment_id=(query.get("environment_id") or [None])[0],
                limit=_query_int(query, "limit", 20, 1, 100),
            )
            return Response(200, _contract_payload(result, "render_discovery"))
        except ApiError:
            raise
        except (ValueError, TypeError):
            raise ApiError(
                400, "invalid Render discovery request", code="invalid_render_request"
            )
        except Exception:
            return self._unavailable("render_discovery_unavailable")

    def _render_preflight(self, query: Mapping[str, list[str]]) -> Response:
        live = _query_bool(query, "live")
        source = (query.get("source") or ["api"])[0]
        action = (query.get("action") or ["rollback"])[0]
        service_id = (query.get("service_id") or [None])[0]
        environment_id = (query.get("environment_id") or [None])[0]
        environment = (query.get("environment") or ["staging"])[0]
        target_deploy_id = (query.get("target_deploy_id") or [None])[0]
        target_revision = (query.get("target_revision") or [None])[0]
        auto_deploy = (query.get("auto_deploy") or [None])[0]
        health_path = (query.get("health_path") or ["/healthz"])[0]
        if not service_id or not environment_id:
            raise ApiError(
                400,
                "service_id and environment_id are required",
                code="invalid_render_request",
            )
        try:
            result = render_preflight.action_preflight(
                live=live,
                source=source,
                action=action,
                service_id=service_id,
                environment_id=environment_id,
                environment=environment,
                target_deploy_id=target_deploy_id,
                target_revision=target_revision,
                auto_deploy=auto_deploy,
                health_path=health_path,
            )
            return Response(200, _contract_payload(result, "render_preflight"))
        except (ValueError, TypeError):
            raise ApiError(
                400, "invalid Render preflight request", code="invalid_render_request"
            )
        except Exception:
            return self._unavailable("render_preflight_unavailable")

    def _command(
        self, headers: Mapping[str, str], remote_address: str | None, body: bytes | None
    ) -> Response:
        self._owner_gate(headers, remote_address)
        command = _json_body(body)
        operation = command.get("operation")
        if operation not in COMMAND_OPERATIONS:
            raise ApiError(
                400, "unknown PaaS command operation", code="unknown_operation"
            )
        try:
            return Response(
                200, _contract_payload(paas_execute.dispatch(command), "paas_command")
            )
        except paas_execute.GateError as exc:
            code = _safe_error_code(str(exc), "command_blocked")
            return Response(
                409, _error_payload(code, "PaaS command was blocked by its safety gate")
            )
        except (ValueError, TypeError):
            return Response(
                400, _error_payload("invalid_command", "PaaS command is invalid")
            )
        except Exception:
            # A provider timeout or an ambiguous submission must remain a
            # generic result; never return its body, URL, or traceback.
            return Response(
                503,
                _error_payload(
                    "command_result_unknown",
                    "PaaS command result is unknown; inspect the decision record",
                ),
            )

    def handle(
        self,
        method: str,
        target: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        remote_address: str | None = None,
    ) -> Response:
        request_headers = {
            str(key).lower(): str(value) for key, value in (headers or {}).items()
        }
        if len(target) > MAX_TARGET_CHARS:
            return Response(
                414, _error_payload("target_too_large", "request target is too large")
            )
        try:
            parsed = urlsplit(target)
        except ValueError:
            return Response(
                400, _error_payload("invalid_target", "request target is invalid")
            )
        query = parse_qs(parsed.query)
        path = parsed.path.rstrip("/") or "/"
        try:
            if method == "OPTIONS":
                return Response(204, {})
            if method == "GET" and path == "/health":
                return Response(
                    200,
                    {
                        "status": "ok",
                        "service": SERVICE_NAME,
                        "schema_version": SCHEMA_VERSION,
                        "environment": self.environment,
                        "timestamp": utc_now(),
                    },
                )
            if method == "POST" and path == "/api/v1/paas/commands":
                return self._command(request_headers, remote_address, body)
            if method != "GET":
                raise ApiError(405, "method not allowed", code="method_not_allowed")
            self._require_read_auth(request_headers)
            if path == "/api/v1/cloud/usage":
                return self._cloud_usage(_query_bool(query, "live"))
            if path == "/api/v1/paas/inventory":
                return self._inventory(
                    _query_bool(query, "live"), (query.get("provider_id") or [None])[0]
                )
            if path == "/api/v1/paas/actions":
                return self._actions()
            if path == "/api/v1/paas/render/discovery":
                return self._render_discovery(query)
            if path in {
                "/api/v1/paas/render/preflight",
                "/api/v1/paas/render/action-preflight",
            }:
                return self._render_preflight(query)
            raise ApiError(404, "route not found", code="route_not_found")
        except ApiError as exc:
            return Response(exc.status, _error_payload(exc.code, exc.message))
        except Exception:
            return Response(
                500, _error_payload("internal_error", "unexpected service error")
            )


class RequestHandler(BaseHTTPRequestHandler):
    """HTTP adapter; all business behavior lives in ``CloudApi``."""

    server_version = "CloudApi/1.0"

    @property
    def api(self) -> CloudApi:
        return self.server.cloud_api  # type: ignore[attr-defined]

    def _response_headers(self) -> dict[str, str]:
        origin = self.headers.get("Origin", "")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            "Vary": "Origin",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Solo-PaaS-Command",
        }
        if origin and origin in self.api.allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin
        return headers

    def _send(self, response: Response) -> None:
        payload = (
            json.dumps(response.payload, ensure_ascii=False).encode("utf-8")
            if response.payload
            else b""
        )
        self.send_response(response.status)
        for key, value in self._response_headers().items():
            self.send_header(key, value)
        if response.status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _dispatch(self, method: str) -> None:
        transfer_encoding = self.headers.get("Transfer-Encoding", "").strip().lower()
        if transfer_encoding not in {"", "identity"}:
            self._send(
                Response(
                    411,
                    _error_payload(
                        "content_length_required", "Content-Length is required"
                    ),
                )
            )
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self._send(
                Response(
                    400,
                    _error_payload(
                        "invalid_content_length", "Content-Length must be an integer"
                    ),
                )
            )
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._send(
                Response(
                    413,
                    _error_payload("command_too_large", "request body is too large"),
                )
            )
            return
        body = self.rfile.read(length) if length else None
        response = self.api.handle(
            method,
            self.path,
            headers=self.headers,
            body=body,
            remote_address=self.client_address[0],
        )
        self._send(response)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch("OPTIONS")

    def log_message(self, format: str, *args: Any) -> None:
        # Do not print request bodies or authorization material.
        print(f"{self.command} {self.path.split('?', 1)[0]} - {format % args}")


def _is_loopback_bind(host: str) -> bool:
    return _is_loopback_host(host)


def serve(host: str, port: int, api: CloudApi) -> None:
    if (
        not _is_loopback_bind(host) or api.environment == "production"
    ) and not api.token:
        raise ValueError(
            "CLOUD_API_TOKEN is required for a non-loopback or production Cloud API"
        )
    httpd = ThreadingHTTPServer((host, port), RequestHandler)
    httpd.cloud_api = api  # type: ignore[attr-defined]
    print(f"{SERVICE_NAME} listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        httpd.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("CLOUD_API_HOST", "127.0.0.1"))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("CLOUD_API_PORT", "3440"))
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        serve(args.host, args.port, CloudApi())
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
