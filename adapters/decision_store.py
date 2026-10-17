#!/usr/bin/env python3
"""Decisions live in the decisions cell (decisions); this is its client.

Every reader and writer of decision records, events and reviews goes through
``open_decision_store`` instead of the retired SQLite tables. The API URL comes
from ``EMPIRE_DECISIONS_API`` (environment, or the owner-only client switch
``~/.config/empire-platform/client.env``); the token is the caller's automation
token, as for tasks. https only (http only on loopback); redirects are never
followed, so a token is never forwarded to another host.

Records keep their integer ``id``; ``evidence_refs`` is a list and
``metadata`` a dict (not JSON strings); timestamps are ISO 8601.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

from task_store import (
    ClientConfigError,
    _NoRedirect,
    automation_token,
    client_config_path,
    read_client_file,
    validate_api_url,
)

API_KEY = "EMPIRE_DECISIONS_API"


class DecisionStoreError(RuntimeError):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(f"decisions API {status}: {reason}")
        self.status = status
        self.reason = reason


def decisions_api_url(environ: Any = None) -> str:
    import os

    environ = os.environ if environ is None else environ
    value = (environ.get(API_KEY) or "").strip()
    if not value:
        value = read_client_file(client_config_path(environ)).get(API_KEY, "")
    if not value:
        raise ClientConfigError(
            f"the decisions API is not configured: set {API_KEY} (env or client.env)"
        )
    try:
        return validate_api_url(value)
    except ClientConfigError:
        raise ClientConfigError(
            f"{API_KEY} must be https (http only for 127.0.0.1, ::1 or localhost)"
        ) from None


class ApiDecisionStore:
    """Stdlib HTTP client for the decisions API."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        channel: str = "workflow",
        correlation_id: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.channel = channel
        self.correlation_id = correlation_id or uuid.uuid4().hex
        self.timeout = timeout  # the cell may be waking from sleep
        self._opener = urllib.request.build_opener(_NoRedirect)

    def __repr__(self) -> str:
        return f"ApiDecisionStore({self.base_url!r}, channel={self.channel!r})"

    def _call(
        self,
        method: str,
        path: str,
        body: Any = None,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> Any:
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        query = f"?{urllib.parse.urlencode(clean, doseq=True)}" if clean else ""
        request = urllib.request.Request(
            f"{self.base_url}{path}{query}",
            method=method,
            data=json.dumps(body, default=str).encode() if body is not None else None,
            headers={
                "Authorization": f"Bearer {self.token}",
                "X-Empire-Channel": self.channel,
                "X-Correlation-Id": self.correlation_id,
                "Content-Type": "application/json",
                **(headers or {}),
            },
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            try:
                detail = json.loads(error.read()).get("detail")
            except (ValueError, AttributeError):
                detail = None
            reason = (
                (detail.get("reason") or detail.get("error"))
                if isinstance(detail, dict)
                else "error"
            )
            raise DecisionStoreError(error.code, str(reason)) from None
        except (
            urllib.error.URLError,
            OSError,
        ) as error:  # timeout, DNS, refused: one error type for callers
            raise DecisionStoreError(
                503, f"unavailable:{type(error).__name__}"
            ) from None

    # --- records ---------------------------------------------------------------------------

    def list(
        self,
        *,
        status: list[str] | str | None = None,
        limit: int = 100,
        offset: int = 0,
        **filters: Any,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit, "offset": offset, **filters}
        if status:
            params["status"] = [status] if isinstance(status, str) else list(status)
        return self._call("GET", "/v1/decisions", params=params)["items"]

    def all(self, **filters: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        while True:
            page = self.list(limit=500, offset=len(out), **filters)
            out.extend(page)
            if len(page) < 500:
                return out

    def stats(self, group_by: str = "status") -> dict[str, int]:
        return self._call("GET", "/v1/decisions/stats", params={"group_by": group_by})[
            "groups"
        ]

    def get(self, decision_id: int) -> dict[str, Any] | None:
        try:
            return self._call("GET", f"/v1/decisions/{int(decision_id)}")
        except DecisionStoreError as exc:
            if exc.status == 404:
                return None
            raise

    def by_dedupe(self, key: str) -> dict[str, Any] | None:
        try:
            return self._call(
                "GET", f"/v1/decisions/dedupe/{urllib.parse.quote(key, safe='')}"
            )
        except DecisionStoreError as exc:
            if exc.status == 404:
                return None
            raise

    def create(
        self,
        fields: dict[str, Any],
        *,
        event: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        body = {**fields, **({"event": event} if event else {})}
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self._call("POST", "/v1/decisions", body, headers=headers)

    def upsert(
        self,
        dedupe_key: str,
        fields: dict[str, Any],
        *,
        event: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """(outcome, record): outcome is created, refreshed, or unchanged."""
        body = {**fields, **({"event": event} if event else {})}
        result = self._call(
            "PUT",
            f"/v1/decisions/dedupe/{urllib.parse.quote(dedupe_key, safe='')}",
            body,
        )
        return result["outcome"], result["decision"]

    def update(
        self,
        decision_id: int,
        fields: dict[str, Any],
        *,
        event: dict[str, Any] | None = None,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        body = dict(fields)
        if event:
            body["event"] = event
        if expected_version is not None:
            body["expected_version"] = expected_version
        return self._call("PATCH", f"/v1/decisions/{int(decision_id)}", body)

    def delete(self, decision_id: int) -> None:
        self._call("DELETE", f"/v1/decisions/{int(decision_id)}")

    # --- history -----------------------------------------------------------------------------

    def add_event(
        self,
        decision_id: int,
        event_type: str,
        *,
        actor: str = "system",
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._call(
            "POST",
            f"/v1/decisions/{int(decision_id)}/events",
            {
                "event_type": event_type,
                "actor": actor,
                "reason": reason,
                "metadata": metadata or {},
            },
        )

    def events(self, decision_id: int, limit: int = 100) -> list[dict[str, Any]]:
        return self._call(
            "GET", f"/v1/decisions/{int(decision_id)}/events", params={"limit": limit}
        )["items"]

    def history(self, decision_id: int) -> list[dict[str, Any]]:
        """Every event of one decision, oldest first (paged, never truncated)."""
        out: list[dict[str, Any]] = []
        while True:
            page = self._call(
                "GET",
                f"/v1/decisions/{int(decision_id)}/events",
                params={
                    "order": "asc",
                    "after_id": out[-1]["id"] if out else 0,
                    "limit": 500,
                },
            )["items"]
            out.extend(page)
            if len(page) < 500:
                return out

    def recent_events(
        self,
        *,
        event_type: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self._call(
            "GET",
            "/v1/decision-events",
            params={"event_type": event_type, "since": since, "limit": limit},
        )["items"]

    # --- reviews -----------------------------------------------------------------------------

    def reviews(
        self,
        *,
        status: str | None = None,
        decision_id: int | None = None,
        due_on_or_before: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self._call(
            "GET",
            "/v1/decision-reviews",
            params={
                "status": status,
                "decision_id": decision_id,
                "due_on_or_before": due_on_or_before,
                "limit": limit,
            },
        )["items"]

    def review(self, review_id: int) -> dict[str, Any] | None:
        try:
            return self._call("GET", f"/v1/decision-reviews/{int(review_id)}")
        except DecisionStoreError as exc:
            if exc.status == 404:
                return None
            raise

    def put_review(
        self, decision_id: int, due_date: str, fields: dict[str, Any] | None = None
    ) -> tuple[str, dict[str, Any]]:
        result = self._call(
            "PUT", f"/v1/decisions/{int(decision_id)}/reviews/{due_date}", fields or {}
        )
        return result["outcome"], result["review"]

    def update_review(
        self,
        review_id: int,
        fields: dict[str, Any],
        *,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        body = dict(fields)
        if expected_version is not None:
            body["expected_version"] = expected_version
        return self._call("PATCH", f"/v1/decision-reviews/{int(review_id)}", body)


def open_decision_store(
    automation: str, *, channel: str = "workflow"
) -> ApiDecisionStore:
    """The decisions API store for ``automation`` (an ID from the automations registry)."""
    url = decisions_api_url()
    try:
        token = automation_token(automation)
    except (
        RuntimeError
    ) as exc:  # a missing token is a configuration problem, like a missing URL
        raise ClientConfigError(str(exc)) from None
    return ApiDecisionStore(url, token, channel=channel)
