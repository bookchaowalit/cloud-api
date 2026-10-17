#!/usr/bin/env python3
"""Recurrence rules shared by recurring_gen.py and the SQLite task store.

Same rule language and next-date semantics as the Tasks API, so both
backends generate the same occurrences.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from datetime import date, timedelta
from typing import Any

FIXED_DAYS = {
    "daily": 1,
    "every day": 1,
    "weekly": 7,
    "every week": 7,
    "monthly": 30,
    "every month": 30,
    "biweekly": 14,
    "every 2 weeks": 14,
    "every 3 months": 90,
}
PATTERNS = (
    (r"every\s+(\d+)\s*months?", 30),
    (r"every\s+(\d+)\s*d", 1),
    (r"every\s+(\d+)\s*w", 7),
)


def recurrence_step(rule: str | None) -> timedelta | None:
    if not rule:
        return None
    rule = rule.strip().lower()
    if rule in FIXED_DAYS:
        return timedelta(days=FIXED_DAYS[rule])
    for pattern, days in PATTERNS:
        match = re.match(pattern, rule)
        if match:
            return timedelta(days=int(match.group(1)) * days)
    return None


def _day(value: Any) -> date | None:
    return date.fromisoformat(str(value)[:10]) if value not in (None, "") else None


def next_due_dates(
    parent: dict[str, Any], existing: Sequence[Sequence[Any]], until: date
) -> Iterator[tuple[int, date]]:
    """(occurrence, due date) pairs still to create up to ``until``.

    ``existing`` rows are (recurrence_occurrence, due_date, completed_at) in occurrence order.
    """
    step = recurrence_step(parent.get("recurrence_rule"))
    if step is None:
        return
    if existing:
        occurrence, due, completed = existing[-1]
        anchor = _day(due) or _day(completed) or _day(parent.get("due_date"))
        next_due = anchor + step if anchor else until
    else:
        occurrence = 0
        parent_due = _day(parent.get("due_date"))
        next_due = parent_due + step if parent_due else until
    while next_due <= until:
        occurrence += 1
        yield occurrence, next_due
        next_due += step
