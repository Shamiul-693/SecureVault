"""Actionable recommendations shown above the item list (computed locally)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .security_analyzer import SecurityReport

BACKUP_REMINDER_DAYS = 30


@dataclass(frozen=True)
class Recommendation:
    key: str            # stable id, includes a signature so it reappears when the situation changes
    title: str
    tag: str            # "Security" | "Backup" | "Efficiency"
    icon: str
    role: str           # palette colour name
    action: str         # "security" | "settings" | "backup"


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def build(
    report: SecurityReport,
    item_count: int,
    auto_lock_minutes: int,
    clipboard_seconds: int,
    last_backup_at: str | None,
    trash_count: int = 0,
    now: datetime | None = None,
) -> list[Recommendation]:
    now = now or datetime.now(timezone.utc)
    recs: list[Recommendation] = []
    if report.weak:
        n = len(report.weak)
        recs.append(Recommendation(f"weak:{n}", f"Replace {n} weak password{'s' if n != 1 else ''}",
                                   "Security", "alert", "danger", "security"))
    if report.reused_groups:
        n = report.reused_count
        recs.append(Recommendation(f"reused:{n}", f"{n} accounts share a password",
                                   "Security", "repeat", "warning", "security"))
    if item_count:
        last = _parse(last_backup_at)
        if last is None:
            recs.append(Recommendation("backup:never", "Create your first encrypted backup",
                                       "Backup", "download", "accent", "backup"))
        elif now - last > timedelta(days=BACKUP_REMINDER_DAYS):
            days = (now - last).days
            recs.append(Recommendation(f"backup:{last.date()}", f"Last backup was {days} days ago",
                                       "Backup", "download", "accent", "backup"))
    if auto_lock_minutes == 0:
        recs.append(Recommendation("autolock:off", "Turn on auto-lock", "Security", "clock", "accent", "settings"))
    elif auto_lock_minutes > 15:
        recs.append(Recommendation(f"autolock:{auto_lock_minutes}", "Adjust auto-lock time",
                                   "Security", "clock", "accent", "settings"))
    if clipboard_seconds == 0:
        recs.append(Recommendation("clipboard:off", "Turn on clipboard clearing", "Security", "copy", "accent", "settings"))
    if report.old:
        n = len(report.old)
        recs.append(Recommendation(f"old:{n}", f"Update {n} old password{'s' if n != 1 else ''}",
                                   "Efficiency", "clock", "warning", "security"))
    return recs


def load_dismissed(raw: str | None) -> set[str]:
    try:
        data = json.loads(raw or "[]")
        return {str(x) for x in data} if isinstance(data, list) else set()
    except (ValueError, TypeError):
        return set()


def dump_dismissed(keys: set[str]) -> str:
    return json.dumps(sorted(keys)[-100:])
