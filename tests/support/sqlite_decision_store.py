#!/usr/bin/env python3
"""Test double: the retired SQLite decision tables behind the ``ApiDecisionStore`` interface.

Decisions live in the decisions cell (solo-decisions) since 2026-10-10;
production code uses ``open_decision_store`` only and must not import this
module. Behaviour tests patch ``open_decision_store`` to return this double
over a temporary SQLite database with ``legacy_decision_tables.sql`` applied.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Safety: a test that imports this double must never reach the live decisions API.
os.environ.pop("EMPIRE_DECISIONS_API", None)
os.environ["EMPIRE_CLIENT_CONFIG"] = "/nonexistent/solo-empire-test/client.env"

LEGACY_DDL = Path(__file__).resolve().parent / "legacy_decision_tables.sql"
FIELDS = ("title", "domain", "decision", "rationale", "evidence_refs", "confidence", "expected_outcome",
          "actual_outcome", "next_action", "status", "approval_required", "approval_status", "action_type",
          "action_status", "privacy_class", "source_type", "source_ref", "review_date", "decided_at",
          "dedupe_key", "execution_lock_key")
DEFAULTS = {"domain": "general", "status": "proposed", "approval_required": True, "approval_status": "pending",
            "action_type": "none", "action_status": "none", "privacy_class": "private", "evidence_refs": []}
REVIEW_FIELDS = ("task_id", "status", "reviewer", "outcome", "notes", "reviewed_at")


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters"))
from decision_store import DecisionStoreError  # noqa: E402  (the same error the production client raises)


def apply_legacy_decision_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(LEGACY_DDL.read_text(encoding="utf-8"))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


class SqliteDecisionStore:
    """Same methods and shapes as ``ApiDecisionStore`` (ids are integers, refs a list)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        # schema.sql no longer has the decision tables (migration 081); the double brings its own.
        apply_legacy_decision_tables(self.conn)
        # The API's optimistic concurrency lives in the row, so every store over the file agrees.
        for table in ("decision_records", "decision_reviews"):
            columns = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            if "version" not in columns:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
        self.conn.commit()

    def _record(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        data = dict(row)
        data["evidence_refs"] = json.loads(data.get("evidence_refs") or "[]")
        data["approval_required"] = bool(data["approval_required"])
        data["legacy_id"] = data["id"]
        return data

    def _event(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["metadata"] = json.loads(data.get("metadata") or "{}")
        return data

    def _review(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return dict(row)

    @staticmethod
    def _store(name: str, value: Any) -> Any:
        if name == "evidence_refs":
            return json.dumps(value if value is not None else [], separators=(",", ":"))
        if name == "approval_required" and value is not None:
            return int(bool(value))
        return value

    def _insert_event(self, decision_id: int, event: dict[str, Any], before: dict | None, after: dict | None) -> None:
        def pair(name: str) -> tuple[Any, Any]:
            return (before or {}).get(name), (after or {}).get(name)

        (fs, ts), (fa, ta), (fx, tx) = pair("status"), pair("approval_status"), pair("action_status")
        self.conn.execute(
            "INSERT INTO decision_events (decision_id, event_type, actor, from_status, to_status, from_approval_status,"
            " to_approval_status, from_action_status, to_action_status, reason, metadata, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (decision_id, event["event_type"], event.get("actor", "system"), fs, ts, fa, ta, fx, tx,
             event.get("reason"), json.dumps(event.get("metadata") or {}, separators=(",", ":")), _now()))

    def _changed(self, before: dict[str, Any], fields: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in fields.items() if before.get(k) != v}

    # --- records -------------------------------------------------------------------------

    def list(self, *, status: list[str] | str | None = None, limit: int = 100, offset: int = 0,
             **filters: Any) -> list[dict[str, Any]]:
        where, params = ["1=1"], []
        statuses = [status] if isinstance(status, str) else list(status or [])
        if statuses:
            where.append(f"status IN ({','.join('?' * len(statuses))})")
            params += statuses
        for name in ("domain", "approval_status", "approval_required", "action_status", "source_type", "source_ref"):
            if filters.get(name) is not None:
                where.append(f"{name} = ?")
                params.append(self._store(name, filters[name]))
        if filters.get("review_due_on_or_before"):
            where.append("review_date <= ?")
            params.append(filters["review_due_on_or_before"])
        if filters.get("updated_since"):
            where.append("updated_at >= ?")
            params.append(filters["updated_since"])
        rows = self.conn.execute(f"SELECT * FROM decision_records WHERE {' AND '.join(where)}"
                                 " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", (*params, limit, offset))
        return [self._record(r) for r in rows]

    def all(self, **filters: Any) -> list[dict[str, Any]]:
        return self.list(limit=1_000_000, **filters)

    def stats(self, group_by: str = "status") -> dict[str, int]:
        return {r[0]: r[1] for r in self.conn.execute(f"SELECT {group_by}, count(*) FROM decision_records GROUP BY 1")}

    def get(self, decision_id: int) -> dict[str, Any] | None:
        return self._record(self.conn.execute("SELECT * FROM decision_records WHERE id = ?",
                                              (int(decision_id),)).fetchone())

    def by_dedupe(self, key: str) -> dict[str, Any] | None:
        return self._record(self.conn.execute("SELECT * FROM decision_records WHERE dedupe_key = ?", (key,)).fetchone())

    def create(self, fields: dict[str, Any], *, event: dict[str, Any] | None = None,
               idempotency_key: str | None = None) -> dict[str, Any]:
        data = {**DEFAULTS, **{k: v for k, v in fields.items() if k in FIELDS}}
        now = _now()
        try:
            cursor = self.conn.execute(
                f"INSERT INTO decision_records ({', '.join(data)}, created_at, updated_at)"
                f" VALUES ({', '.join('?' * len(data))}, ?, ?)", (*[self._store(k, v) for k, v in data.items()], now, now))
        except sqlite3.IntegrityError as exc:
            raise DecisionStoreError(409, "conflict") from exc
        row = self.get(cursor.lastrowid)
        self._insert_event(row["id"], event or {"event_type": "created", "actor": "api"}, None, row)
        self.conn.commit()
        return row

    def upsert(self, dedupe_key: str, fields: dict[str, Any], *, event: dict[str, Any] | None = None
               ) -> tuple[str, dict[str, Any]]:
        before = self.by_dedupe(dedupe_key)
        if before is None:
            created_event = {**(event or {"actor": "api"}), "event_type": "created"}
            return "created", self.create({**fields, "dedupe_key": dedupe_key}, event=created_event)
        data = self._changed(before, {k: v for k, v in fields.items() if k in FIELDS and k != "dedupe_key"})
        if not data:
            return "unchanged", before
        return "refreshed", self.update(before["id"], data, event=event or {"event_type": "refreshed", "actor": "api"})

    def update(self, decision_id: int, fields: dict[str, Any], *, event: dict[str, Any] | None = None,
               expected_version: int | None = None) -> dict[str, Any]:
        before = self.get(decision_id)
        if before is None:
            raise DecisionStoreError(404, "not_found")
        if expected_version is not None and before["version"] != expected_version:
            raise DecisionStoreError(409, "version_conflict")
        data = self._changed(before, {k: v for k, v in fields.items() if k in FIELDS})
        if data:
            assignments = ", ".join(f"{k} = ?" for k in data)
            try:
                changed = self.conn.execute(
                    f"UPDATE decision_records SET {assignments}, version = version + 1, updated_at = ?"
                    " WHERE id = ? AND version = ?",
                    (*[self._store(k, v) for k, v in data.items()], _now(), int(decision_id), before["version"]))
            except sqlite3.IntegrityError as exc:
                self.conn.rollback()
                raise DecisionStoreError(409, "conflict") from exc
            if changed.rowcount != 1:  # changed by someone else since it was read
                self.conn.rollback()
                raise DecisionStoreError(409, "version_conflict")
        after = self.get(decision_id)
        if data or event is not None:
            self._insert_event(int(decision_id), event or {"event_type": "updated", "actor": "api"}, before, after)
        self.conn.commit()
        return after

    def delete(self, decision_id: int) -> None:
        self.conn.execute("DELETE FROM decision_records WHERE id = ?", (int(decision_id),))
        self.conn.commit()

    # --- history -----------------------------------------------------------------------------

    def add_event(self, decision_id: int, event_type: str, *, actor: str = "system", reason: str | None = None,
                  metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        row = self.get(decision_id)
        if row is None:
            raise DecisionStoreError(404, "not_found")
        self._insert_event(int(decision_id), {"event_type": event_type, "actor": actor, "reason": reason,
                                              "metadata": metadata or {}}, row, row)
        self.conn.commit()
        return self.events(decision_id, limit=1)[0]

    def events(self, decision_id: int, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM decision_events WHERE decision_id = ? ORDER BY created_at DESC, id DESC"
                                 " LIMIT ?", (int(decision_id), limit))
        return [self._event(r) for r in rows]

    def history(self, decision_id: int) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM decision_events WHERE decision_id = ? ORDER BY id", (int(decision_id),))
        return [self._event(r) for r in rows]

    def recent_events(self, *, event_type: str | None = None, since: str | None = None,
                      limit: int = 100) -> list[dict[str, Any]]:
        where, params = ["1=1"], []
        if event_type:
            where.append("event_type = ?")
            params.append(event_type)
        if since:
            where.append("created_at >= ?")
            params.append(since)
        rows = self.conn.execute(f"SELECT * FROM decision_events WHERE {' AND '.join(where)}"
                                 " ORDER BY created_at DESC, id DESC LIMIT ?", (*params, limit))
        return [self._event(r) for r in rows]

    # --- reviews -----------------------------------------------------------------------------

    def reviews(self, *, status: str | None = None, decision_id: int | None = None,
                due_on_or_before: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        where, params = ["1=1"], []
        for name, value in (("status", status), ("decision_id", decision_id)):
            if value is not None:
                where.append(f"{name} = ?")
                params.append(value)
        if due_on_or_before:
            where.append("due_date <= ?")
            params.append(due_on_or_before)
        rows = self.conn.execute(f"SELECT * FROM decision_reviews WHERE {' AND '.join(where)} ORDER BY due_date, id"
                                 " LIMIT ?", (*params, limit))
        return [self._review(r) for r in rows]

    def review(self, review_id: int) -> dict[str, Any] | None:
        return self._review(self.conn.execute("SELECT * FROM decision_reviews WHERE id = ?",
                                              (int(review_id),)).fetchone())

    def put_review(self, decision_id: int, due_date: str, fields: dict[str, Any] | None = None
                   ) -> tuple[str, dict[str, Any]]:
        if self.get(decision_id) is None:
            raise DecisionStoreError(404, "not_found")
        data = {k: v for k, v in (fields or {}).items() if k in REVIEW_FIELDS}
        before = self._review(self.conn.execute("SELECT * FROM decision_reviews WHERE decision_id = ? AND due_date = ?",
                                                (int(decision_id), due_date)).fetchone())
        now = _now()
        if before is None:
            columns = ["decision_id", "due_date", *data, "created_at", "updated_at"]
            cursor = self.conn.execute(f"INSERT INTO decision_reviews ({', '.join(columns)})"
                                       f" VALUES ({', '.join('?' * len(columns))})",
                                       (int(decision_id), due_date, *data.values(), now, now))
            self.conn.commit()
            return "created", self._review(self.conn.execute("SELECT * FROM decision_reviews WHERE id = ?",
                                                             (cursor.lastrowid,)).fetchone())
        diff = {k: v for k, v in data.items() if before.get(k) != v}
        if not diff:
            return "unchanged", before
        return "updated", self.update_review(before["id"], diff)

    def update_review(self, review_id: int, fields: dict[str, Any], *, expected_version: int | None = None
                      ) -> dict[str, Any]:
        before = self._review(self.conn.execute("SELECT * FROM decision_reviews WHERE id = ?",
                                                (int(review_id),)).fetchone())
        if before is None:
            raise DecisionStoreError(404, "not_found")
        if expected_version is not None and before["version"] != expected_version:
            raise DecisionStoreError(409, "version_conflict")
        diff = {k: v for k, v in fields.items() if k in REVIEW_FIELDS and before.get(k) != v}
        if diff:
            assignments = ", ".join(f"{k} = ?" for k in diff)
            changed = self.conn.execute(
                f"UPDATE decision_reviews SET {assignments}, version = version + 1, updated_at = ?"
                " WHERE id = ? AND version = ?", (*diff.values(), _now(), int(review_id), before["version"]))
            if changed.rowcount != 1:
                self.conn.rollback()
                raise DecisionStoreError(409, "version_conflict")
            self.conn.commit()
        return self._review(self.conn.execute("SELECT * FROM decision_reviews WHERE id = ?",
                                              (int(review_id),)).fetchone())


def sqlite_decision_opener(conn: sqlite3.Connection):
    """A drop-in for ``open_decision_store`` that returns the double over ``conn``."""
    store = SqliteDecisionStore(conn)
    return lambda *_args, **_kwargs: store
