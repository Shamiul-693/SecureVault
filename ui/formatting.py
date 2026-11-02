"""Date and text formatting helpers for display."""
from __future__ import annotations

from datetime import datetime, timezone


def parse(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def fmt_datetime(iso: str | None) -> str:
    dt = parse(iso)
    return dt.astimezone().strftime("%d %b %Y, %H:%M") if dt else "—"


def fmt_relative(iso: str | None) -> str:
    dt = parse(iso)
    if not dt:
        return "—"
    seconds = (datetime.now(timezone.utc) - dt).total_seconds()
    if seconds < 60:
        return "just now"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)} min ago"
    hours = minutes / 60
    if hours < 24:
        return f"{int(hours)} h ago"
    days = int(hours / 24)
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{days} days ago"
    if days < 365:
        return f"{days // 30} mo ago"
    return f"{days // 365} yr ago"


def age_days(iso: str | None) -> int:
    dt = parse(iso)
    return int((datetime.now(timezone.utc) - dt).total_seconds() // 86400) if dt else 0


def elide(text: str, length: int = 48) -> str:
    return text if len(text) <= length else text[: length - 1] + "…"


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"
