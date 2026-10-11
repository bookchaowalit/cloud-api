#!/usr/bin/env python3
"""One task-writing interface over the empire-platform Tasks API.

The SQLite task backend was retired on 2026-10-09; its implementation lives on
only as a test double in a test double.

Writers call this module instead of writing ``tasks`` directly, so the
business logic exists once and the backend is a configuration switch:

    SOLO_EMPIRE_TASKS_BACKEND=api      # required; "sqlite" is a retirement error
    EMPIRE_TASKS_API=http://127.0.0.1:3601
    EMPIRE_AUTOMATION_TOKEN_<NAME>=... # or .runtime/automation-tokens/<name>.jwt

The two switch values may also come from one owner-only client file
(``~/.config/empire-platform/client.env``, or ``$EMPIRE_CLIENT_CONFIG``) so
every process, however started, agrees. A non-empty process env var wins, then
the file; there is no default. A file that is group/world accessible is refused.

Reads go through the same store (``list`` with filters, ``stats``, ``links``,
``assignments``, ``role_suggestions``, ``task_types``) so no code outside this
module touches the task tables.

Tasks are identified by their number, which is the SQLite ``tasks.id`` and the
Tasks API ``number`` (imported tasks keep their IDs; new ones continue the
sequence), so SQLite tables that still reference tasks by integer keep
working. Every API call carries the automation's own token and one
correlation ID per run.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

try:
    from recurring_step import next_due_dates
except ImportError:  # imported as a package module
    from .recurring_step import next_due_dates  # type: ignore[no-redef]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOKEN_DIR = PROJECT_ROOT / ".runtime" / "automation-tokens"
# Columns a writer may set through the store. Anything else is SQLite-only
# bookkeeping (sync_status, md_hash, last_synced_at) passed as ``legacy``.
FIELDS = {
    "title", "description", "status", "priority", "project", "tags", "category", "due_date", "notes",
    "estimated_minutes", "actual_minutes", "started_at", "reminder_at", "reminder_channels",
    "recurrence_rule", "external_url", "calendar_event_id", "progress_percent",
    "parent_task_id",  # a task number on both backends
}


CLIENT_CONFIG_ENV = "EMPIRE_CLIENT_CONFIG"
# EMPIRE_DECISIONS_API and EMPIRE_HABITS_API are read by decision_store.py and habits_store.py from the same file.
CLIENT_CONFIG_KEYS = ("SOLO_EMPIRE_TASKS_BACKEND", "EMPIRE_TASKS_API", "EMPIRE_DECISIONS_API", "EMPIRE_HABITS_API",
                      "EMPIRE_NOTIFICATIONS_API", "EMPIRE_GOALS_API", "EMPIRE_PROJECTS_API", "EMPIRE_ROLES_SKILLS_API",
                      "EMPIRE_OPERATING_API", "EMPIRE_INTAKE_API", "EMPIRE_AUTOMATION_API",
                      "EMPIRE_CRM_LEDGER_API")
RETIRED_BACKEND_MESSAGE = "the SQLite task backend was retired on 2026-10-09; tasks live in the Tasks API"


LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")


class ClientConfigError(ValueError):
    """The client config file is unsafe or inconsistent."""


def validate_api_url(url: str) -> str:
    """``url`` when it is https, or http to a loopback host; otherwise ClientConfigError (never echoes userinfo)."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError:
        raise ClientConfigError("EMPIRE_TASKS_API is not a valid URL") from None
    if parts.scheme.lower() == "https" and host:
        return url
    if parts.scheme.lower() == "http" and host in LOOPBACK_HOSTS:
        return url
    raise ClientConfigError("EMPIRE_TASKS_API must be https (http only for 127.0.0.1, ::1 or localhost)")


def client_config_path(environ: Any = None) -> Path:
    environ = os.environ if environ is None else environ
    override = (environ.get(CLIENT_CONFIG_ENV) or "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "empire-platform" / "client.env"


def read_client_file(path: Path) -> dict[str, str]:
    """The two switch keys from ``path`` ({} when absent); refuses unsafe permissions."""
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return {}
    if mode & 0o077:
        raise ClientConfigError(
            f"refusing client config {path}: mode {mode & 0o777:03o} is group/world accessible; run chmod 600")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key in CLIENT_CONFIG_KEYS:
            values[key] = value
    return values


def client_settings(environ: Any = None) -> dict[str, str]:
    """Effective ``backend``, ``api_url`` and ``source`` (env, file or default); never a token."""
    environ = os.environ if environ is None else environ
    path = client_config_path(environ)
    file_values = read_client_file(path)

    def pick(key: str) -> tuple[str, str]:
        if (environ.get(key) or "").strip():
            return environ[key].strip(), "env"
        if file_values.get(key):
            return file_values[key], "file"
        return "", "default"

    backend, backend_source = pick("SOLO_EMPIRE_TASKS_BACKEND")
    api_url, url_source = pick("EMPIRE_TASKS_API")
    if backend == "sqlite":
        raise ClientConfigError(RETIRED_BACKEND_MESSAGE)
    if backend not in ("", "api"):
        raise ClientConfigError(f"unknown SOLO_EMPIRE_TASKS_BACKEND {backend!r}; the only backend is api")
    if backend != "api" or not api_url:
        raise ClientConfigError(
            "the Tasks API is not configured: set SOLO_EMPIRE_TASKS_BACKEND=api and EMPIRE_TASKS_API "
            f"(env, or {path}; see tasks_backend.py use-api --url ...)")
    validate_api_url(api_url)
    return {"backend": "api", "api_url": api_url, "backend_source": backend_source,
            "api_url_source": url_source, "path": str(path)}


class TaskStoreError(RuntimeError):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(f"{status}: {reason}")
        self.status = status
        self.reason = reason


def tags_list(value: Any) -> list[str]:
    """Tags as a list whatever the stored form (JSON array or comma-separated text)."""
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(tag).strip() for tag in value if str(tag).strip()]
    text = str(value).strip()
    if text.startswith("["):
        try:
            return [str(tag).strip() for tag in json.loads(text) if str(tag).strip()]
        except json.JSONDecodeError:
            pass
    return [tag.strip() for tag in text.split(",") if tag.strip()]


def _date(value: Any) -> str | None:
    return str(value)[:10] if value not in (None, "") else None


def _check_fields(fields: dict[str, Any]) -> None:
    unknown = set(fields) - FIELDS
    if unknown:
        raise ValueError(f"unknown task fields: {sorted(unknown)}")


# Filters accepted by list() and stats(); dates are local calendar dates.
FILTERS = {
    "status", "external_source", "no_external_source", "project", "category", "priority_max", "due_from",
    "due_before", "completed_between", "created_between", "reminder_due_before", "missing_calendar_event",
    "numbers", "parent", "q", "include_archived",
}
# Link targets: SQLite table, its target column, and the URN prefix of the target cell.
LINK_TABLES = {
    "goal": ("task_goal_links", "goal_id", "empire:goals:goal:legacy-"),
    "project": ("task_project_links", "project_id", "empire:projects:project:legacy-"),
    "context": ("task_context_links", "context_id", "empire:projects:context:legacy-"),
    "skill": ("task_skill_links", "skill_id", "empire:roles-skills:skill:legacy-"),
}
LINK_ATTRIBUTES = {
    "goal": {"link_type", "source"},
    "project": {"relation_type", "weight", "source"},
    "context": {"relation_type", "weight", "source"},
    "skill": {"link_type", "match_reason", "source_registry"},
}
# SQLite says 'user' where the platform says 'identity'.
ASSIGNEE_TO_API = {"user": "identity", "role": "role", "team": "team"}
ASSIGNEE_FROM_API = {v: k for k, v in ASSIGNEE_TO_API.items()}


def _check_filters(filters: dict[str, Any]) -> None:
    unknown = set(filters) - FILTERS
    if unknown:
        raise ValueError(f"unknown task filters: {sorted(unknown)}")


def link_relation(target_type: str, attributes: dict[str, Any]) -> str:
    """The Empire Graph relation for a legacy link row (same rule as the importer)."""
    if target_type == "goal":
        return "supports-goal"
    if target_type == "project" and attributes.get("relation_type", "delivery") == "delivery":
        return "belongs-to"
    return "related-to"


def _link_order(link: dict[str, Any]) -> tuple:
    target = link["target_id"]
    return link["task"], link["target_type"], (0, target, "") if isinstance(target, int) else (1, 0, str(target))


class TaskStore(Protocol):
    def get(self, number: int) -> dict[str, Any] | None: ...
    def find_external(self, source: str, external_id: str) -> dict[str, Any] | None: ...
    def list(self, **filters: Any) -> list[dict[str, Any]]: ...
    def stats(self, *, group_by: str | None = None, **filters: Any) -> dict[str, Any]: ...
    def links(self, *, task: int | None = None, target_type: str | None = None,
              target_id: int | None = None) -> list[dict[str, Any]]: ...
    def link(self, task: int, target_type: str, target_id: int, attributes: dict[str, Any] | None = None,
             *, update: bool = False) -> str: ...
    def unlink(self, task: int, target_type: str, target_id: int, *, source_registry: str | None = None) -> bool: ...
    def assignments(self, *, task: int | None = None, assignee_type: str | None = None,
                    assignee_id: str | None = None, assignment_type: str | None = None) -> list[dict[str, Any]]: ...
    def assign(self, task: int, assignee_type: str, assignee_id: str, assignee_name: str | None = None,
               assignment_type: str = "assigned") -> str: ...
    def role_suggestions(self, *, task: int | None = None, role_id: str | None = None,
                         source_registry: str | None = None, review_status: str | None = None,
                         confidence: str | None = None) -> list[dict[str, Any]]: ...
    def suggest_role(self, task: int, role_id: str, source_registry: str, confidence: str, match_reason: str,
                     review_status: str | None = None) -> str: ...
    def review_role(self, task: int, role_id: str, source_registry: str, review_status: str,
                    expected_status: str | None = None) -> bool: ...
    def withdraw_role(self, task: int, role_id: str, source_registry: str,
                      only_status: str | None = None) -> bool: ...
    def dependencies(self, *, task: int | None = None) -> list[dict[str, Any]]: ...
    def add_dependency(self, task: int, depends_on: int, dependency_type: str = "finish_to_start") -> str: ...
    def task_types(self, *, include_inactive: bool = False) -> list[dict[str, Any]]: ...
    def create(self, fields: dict[str, Any], *, legacy: dict[str, Any] | None = None) -> int: ...
    def upsert_external(self, source: str, external_id: str, fields: dict[str, Any],
                        *, legacy: dict[str, Any] | None = None) -> tuple[str, int]: ...
    def update(self, number: int, fields: dict[str, Any], *, legacy: dict[str, Any] | None = None) -> None: ...
    def complete(self, number: int, *, legacy: dict[str, Any] | None = None) -> None: ...
    def archive(self, number: int, reason: str) -> None: ...
    def unarchive(self, number: int) -> None: ...
    def record_reminder_delivered(self, number: int, reminder_at: str, channel: str) -> bool: ...
    def generate_occurrences(self, number: int, until: str) -> list[int]: ...


def _record(row: dict[str, Any]) -> dict[str, Any]:
    """Backend-neutral view of a task."""
    return {
        "id": row["number"], "title": row["title"], "description": row.get("description"),
        "status": row["status"], "priority": row["priority"], "project": row.get("project"),
        "tags": tags_list(row.get("tags")), "category": row.get("category"), "due_date": _date(row.get("due_date")),
        "completed_at": row.get("completed_at"), "notes": row.get("notes"),
        "external_source": row.get("external_source"), "external_id": row.get("external_id"),
        "external_url": row.get("external_url"), "estimated_minutes": row.get("estimated_minutes"),
        "reminder_at": row.get("reminder_at"), "reminder_sent": bool(row.get("reminder_sent")),
        "reminder_channels": row.get("reminder_channels"), "calendar_event_id": row.get("calendar_event_id"),
        "recurrence_rule": row.get("recurrence_rule"), "archived_at": row.get("archived_at"),
        "is_recurring_instance": bool(row.get("is_recurring_instance")),
        "recurrence_occurrence": row.get("recurrence_occurrence"),
        "progress_percent": row.get("progress_percent") or 0, "parent_task_id": row.get("parent_number"),
        "parent_recurring_id": row.get("parent_recurring_number"), "started_at": row.get("started_at"),
        "actual_minutes": row.get("actual_minutes") or 0, "archive_reason": row.get("archive_reason"),
        "created_at": row.get("created_at"), "updated_at": row.get("updated_at"),
    }


def _local_day_start(day: str) -> str:
    """Local midnight of a calendar date as an aware ISO timestamp."""
    return datetime.combine(date.fromisoformat(day), datetime.min.time()).astimezone().isoformat()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the Bearer token must not be forwarded to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ApiTaskStore:
    """The Tasks API backend (stdlib HTTP; no extra dependencies)."""

    def __init__(self, base_url: str, token: str, *, channel: str = "workflow",
                 correlation_id: str | None = None, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.channel = channel
        self.correlation_id = correlation_id or uuid.uuid4().hex
        self.timeout = timeout
        self._ids: dict[int, str] = {}
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _call(self, method: str, path: str, body: Any = None, params: dict | None = None,
              headers: dict | None = None) -> Any:
        query = f"?{urllib.parse.urlencode(params, doseq=True)}" if params else ""
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}{query}", data=data, method=method,
            headers={"Authorization": f"Bearer {self.token}", "X-Empire-Channel": self.channel,
                     "X-Correlation-Id": self.correlation_id, "Content-Type": "application/json", **(headers or {})})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            try:
                detail = json.loads(error.read()).get("detail")
            except (ValueError, AttributeError):
                detail = None
            reason = (detail.get("reason") or detail.get("error")) if isinstance(detail, dict) else "error"
            raise TaskStoreError(error.code, reason) from None

    def _record(self, task: dict[str, Any]) -> dict[str, Any]:
        self._ids[task["number"]] = task["id"]
        return _record(task)

    def _id(self, number: int) -> str:
        if number not in self._ids:
            self._record(self._call("GET", f"/v1/tasks/number/{number}"))
        return self._ids[number]

    def _body(self, fields: dict[str, Any]) -> dict[str, Any]:
        _check_fields(fields)
        body = dict(fields)
        if body.get("parent_task_id") is not None:
            body["parent_task_id"] = self._id(int(body["parent_task_id"]))
        if "tags" in body:
            body["tags"] = tags_list(body["tags"])
        if body.get("due_date") is not None:
            body["due_date"] = _date(body["due_date"])
        return body

    def get(self, number):
        try:
            return self._record(self._call("GET", f"/v1/tasks/number/{number}"))
        except TaskStoreError as error:
            if error.status == 404:
                return None
            raise

    def find_external(self, source, external_id):
        try:
            return self._record(self._call("GET", f"/v1/tasks/external/{source}/{urllib.parse.quote(str(external_id), safe='')}"))
        except TaskStoreError as error:
            if error.status == 404:
                return None
            raise

    @staticmethod
    def _params(filters: dict[str, Any]) -> dict[str, Any]:
        _check_filters(filters)
        params: dict[str, Any] = {}
        for key, value in filters.items():
            if value is None or value is False or value == []:
                continue
            if key == "completed_between":
                params["completed_from"] = _local_day_start(value[0])
                params["completed_before"] = _local_day_start((date.fromisoformat(value[1]) + timedelta(days=1)).isoformat())
            elif key == "created_between":
                params["created_from"] = _local_day_start(value[0])
                params["created_before"] = _local_day_start((date.fromisoformat(value[1]) + timedelta(days=1)).isoformat())
            elif value is True:
                params[key] = "true"
            else:
                params[key] = value
        if filters.get("numbers") == []:
            params["numbers"] = [-1]  # nothing matches, as in SQLite
        return params

    def _pages(self, path: str, params: dict[str, Any], *, cursor: bool = False, limit: int = 200) -> list[dict]:
        items, after, offset = [], None, 0
        while True:
            page_params = {**params, "limit": limit, **({"after": after} if cursor and after else {}),
                           **({"offset": offset} if not cursor else {})}
            page = self._call("GET", path, params=page_params)["items"]
            items.extend(page)
            if len(page) < limit:
                return items
            after, offset = page[-1].get("number"), offset + limit

    def list(self, **filters):
        numbers = filters.get("numbers")
        if numbers and len(numbers) > 500:  # the API takes at most 500 numbers per request
            chunks = [self.list(**{**filters, "numbers": numbers[i:i + 500]}) for i in range(0, len(numbers), 500)]
            return sorted((task for chunk in chunks for task in chunk), key=lambda task: task["id"])
        return [self._record(task) for task in self._pages("/v1/tasks", self._params(filters), cursor=True)]

    def stats(self, *, group_by=None, **filters):
        params = self._params(filters)
        if group_by:
            params["group_by"] = group_by
        result = self._call("GET", "/v1/tasks/stats", params=params)
        return {"total": result["total"], "groups": {g["key"]: g["count"] for g in result["groups"]}}

    @staticmethod
    def _target_id(kind: str, ref: str) -> int | str:
        prefix = LINK_TABLES[kind][2]
        tail = ref[len(prefix):] if ref.startswith(prefix) else ref
        return int(tail) if tail.isdigit() else ref

    def links(self, *, task=None, target_type=None, target_id=None):
        params: dict[str, Any] = {}
        if task is not None:
            params["task"] = task
        if target_type:
            params["target_type"] = target_type
        if target_id is not None:
            if not target_type:
                raise ValueError("target_id needs target_type")
            params["target_ref"] = f"{LINK_TABLES[target_type][2]}{target_id}"
        records = []
        for item in self._pages("/v1/task-links", params, limit=500):
            if item["target_type"] not in LINK_TABLES:
                continue
            kind = item["target_type"]
            records.append({"task": item["task_number"], "target_type": kind,
                            "target_id": self._target_id(kind, item["target_ref"]), "relation": item["relation"],
                            "attributes": {k: v for k, v in item["attributes"].items() if k in LINK_ATTRIBUTES[kind]}})
        return sorted(records, key=_link_order)

    def link(self, task, target_type, target_id, attributes=None, *, update=False) -> str:
        attributes = dict(attributes or {})
        unknown = set(attributes) - LINK_ATTRIBUTES[target_type]
        if unknown:
            raise ValueError(f"unknown {target_type} link attributes: {sorted(unknown)}")
        existing = self.links(task=task, target_type=target_type, target_id=target_id)
        if existing and (not update or not attributes or
                         all(existing[0]["attributes"].get(k) == v for k, v in attributes.items())):
            return "unchanged"
        merged = {**(existing[0]["attributes"] if existing else {}), **attributes}
        self._call("POST", f"/v1/tasks/{self._id(task)}/links",
                   {"relation": link_relation(target_type, merged), "target_type": target_type,
                    "target_ref": f"{LINK_TABLES[target_type][2]}{target_id}", "attributes": merged})
        return "updated" if existing else "created"

    def unlink(self, task, target_type, target_id, *, source_registry=None) -> bool:
        existing = [link for link in self.links(task=task, target_type=target_type, target_id=target_id)
                    if not source_registry or link["attributes"].get("source_registry") in (None, source_registry)]
        if not existing:
            return False
        result = self._call("DELETE", f"/v1/tasks/{self._id(task)}/links",
                            params={"relation": existing[0]["relation"],
                                    "target_ref": f"{LINK_TABLES[target_type][2]}{target_id}"})
        return result["outcome"] == "removed"

    def assignments(self, *, task=None, assignee_type=None, assignee_id=None, assignment_type=None):
        params = {k: v for k, v in {"task": task, "assignee_type": ASSIGNEE_TO_API.get(assignee_type) if assignee_type else None,
                                    "assignee_ref": assignee_id, "assignment_type": assignment_type}.items()
                  if v is not None}
        return [{"task": a["task_number"], "assignee_type": ASSIGNEE_FROM_API[a["assignee_type"]],
                 "assignee_id": a["assignee_ref"], "assignee_name": a["assignee_name"],
                 "assignment_type": a["assignment_type"]}
                for a in self._pages("/v1/task-assignments", params, limit=500)]

    def assign(self, task, assignee_type, assignee_id, assignee_name=None, assignment_type="assigned") -> str:
        result = self._call("PUT", f"/v1/tasks/{self._id(task)}/assignments",
                            {"assignee_type": ASSIGNEE_TO_API[assignee_type], "assignee_ref": assignee_id,
                             "assignee_name": assignee_name, "assignment_type": assignment_type})
        return result["outcome"]

    def role_suggestions(self, *, task=None, role_id=None, source_registry=None, review_status=None, confidence=None):
        params = {k: v for k, v in {"task": task, "role_id": role_id, "source_registry": source_registry,
                                    "review_status": review_status, "confidence": confidence}.items() if v is not None}
        return [{"task": s["task_number"], "role_id": s["role_id"], "confidence": s["confidence"],
                 "match_reason": s["match_reason"], "review_status": s["review_status"],
                 "source_registry": s["source_registry"], "updated_at": s["updated_at"]}
                for s in self._pages("/v1/task-role-suggestions", params, limit=500)]

    def suggest_role(self, task, role_id, source_registry, confidence, match_reason, review_status=None) -> str:
        body = {"role_id": role_id, "source_registry": source_registry, "confidence": confidence,
                "match_reason": match_reason}
        if review_status:
            body["review_status"] = review_status
        return self._call("PUT", f"/v1/tasks/{self._id(task)}/role-suggestions", body)["outcome"]

    def review_role(self, task, role_id, source_registry, review_status, expected_status=None) -> bool:
        body = {"role_id": role_id, "source_registry": source_registry, "review_status": review_status}
        if expected_status:
            body["expected_status"] = expected_status
        return self._call("PATCH", f"/v1/tasks/{self._id(task)}/role-suggestions", body)["outcome"] == "updated"

    def withdraw_role(self, task, role_id, source_registry, only_status=None) -> bool:
        params = {"role_id": role_id, "source_registry": source_registry}
        if only_status:
            params["only_status"] = only_status
        return self._call("DELETE", f"/v1/tasks/{self._id(task)}/role-suggestions", params=params)["outcome"] == "removed"

    def dependencies(self, *, task=None):
        params = {"task": task} if task is not None else {}
        return [{"task": d["task_number"], "depends_on": d["depends_on_number"], "dependency_type": d["dependency_type"]}
                for d in self._pages("/v1/task-dependencies", params, limit=500)]

    def add_dependency(self, task, depends_on, dependency_type="finish_to_start") -> str:
        """Idempotent: 'created' or 'unchanged'."""
        return self._call("PUT", f"/v1/tasks/{self._id(task)}/dependencies",
                          {"depends_on": depends_on, "dependency_type": dependency_type})["outcome"]

    def task_types(self, *, include_inactive=False):
        items = self._call("GET", "/v1/task-types", params={"include_inactive": str(include_inactive).lower()})["items"]
        return [{"id": t["number"], **{k: t[k] for k in ("name", "description", "icon", "color", "default_status",
                                                         "allowed_statuses", "is_active", "sort_order")}}
                for t in items]

    def create(self, fields, *, legacy=None) -> int:
        body = self._body(fields)
        status = body.pop("status", None)
        task = self._call("POST", "/v1/tasks", body)
        number = self._record(task)["id"]
        if status and status != "todo":
            self.update(number, {"status": status})
        return number

    def upsert_external(self, source, external_id, fields, *, legacy=None):
        result = self._call("PUT", f"/v1/tasks/external/{source}/{urllib.parse.quote(str(external_id), safe='')}",
                            self._body(fields))
        return result["outcome"], self._record(result["task"])["id"]

    def update(self, number, fields, *, legacy=None) -> None:
        body = self._body(fields)
        if body.get("status") == "done":
            body.pop("status")
            if body:
                self._call("PATCH", f"/v1/tasks/{self._id(number)}", body)
            self.complete(number)
            return
        if body:
            self._call("PATCH", f"/v1/tasks/{self._id(number)}", body)

    def complete(self, number, *, legacy=None) -> None:
        self._call("POST", f"/v1/tasks/{self._id(number)}/complete")

    def archive(self, number, reason) -> None:
        self._call("POST", f"/v1/tasks/{self._id(number)}/archive", {"reason": reason})

    def unarchive(self, number) -> None:
        self._call("POST", f"/v1/tasks/{self._id(number)}/unarchive")

    def record_reminder_delivered(self, number, reminder_at, channel) -> bool:
        at = reminder_at if "T" in reminder_at or "+" in reminder_at else f"{reminder_at.replace(' ', 'T')}+00:00"
        result = self._call("POST", f"/v1/tasks/{self._id(number)}/reminders/delivered",
                            {"reminder_at": at, "channel": channel})
        return result["outcome"] == "recorded"

    def generate_occurrences(self, number, until) -> list[int]:
        result = self._call("POST", f"/v1/tasks/{self._id(number)}/occurrences/generate", {"until": until})
        return [self._record(task)["id"] for task in result["created"]]


def token_dirs() -> list[Path]:
    """Where token files are looked up, in order."""
    return [TOKEN_DIR, Path.home() / ".config" / "empire-platform" / "tokens"]


def automation_token(name: str) -> str:
    key = "EMPIRE_AUTOMATION_TOKEN_" + name.upper().replace("-", "_")
    if os.environ.get(key):
        return os.environ[key]
    for directory in token_dirs():
        path = directory / f"{name}.jwt"
        if path.is_file():
            if path.stat().st_mode & 0o077:
                raise RuntimeError(f"token file {path} must be readable by its owner only (chmod 600)")
            return path.read_text(encoding="utf-8").strip()
    raise RuntimeError(f"no token for automation {name!r}: set {key} or create {token_dirs()[0] / (name + '.jwt')}")


def open_task_store(conn: Any, automation: str, *, channel: str = "workflow") -> TaskStore:
    """The Tasks API store for ``automation`` (an ID from the automations registry).

    ``conn`` is accepted for caller compatibility (callers keep their SQLite
    connection for non-task tables) and is ignored: tasks live in the API.
    """
    settings = client_settings()
    return ApiTaskStore(settings["api_url"], automation_token(automation), channel=channel)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


__all__ = ["ApiTaskStore", "ClientConfigError", "client_settings", "TaskStore", "TaskStoreError", "automation_token", "open_task_store", "validate_api_url", "tags_list", "utc_now"]
