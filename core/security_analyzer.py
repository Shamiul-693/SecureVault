"""Local password strength estimation and vault security analysis.

All analysis happens in memory on already-decrypted entries. Nothing here
logs, persists or transmits password values.
"""
from __future__ import annotations

import math
import re
import string
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Protocol

LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]

COMMON_PASSWORDS = frozenset(
    """
    password passw0rd p@ssw0rd p@ssword 123456 1234567 12345678 123456789 1234567890
    12345 1234 111111 000000 123123 654321 666666 121212 qwerty qwertyuiop qwerty123
    asdfgh asdfghjkl zxcvbnm qazwsx 1q2w3e4r 1qaz2wsx abc123 abcd1234 letmein welcome
    welcome1 admin admin123 administrator root toor login guest master monkey dragon
    shadow sunshine princess football baseball soccer cricket iloveyou trustno1 superman
    batman starwars freedom whatever secret hello hello123 charlie michael ashley
    jennifer computer internet samsung google facebook iphone bangladesh dhaka changeme
    default security mypassword password1 password123 pass1234 test test123 temp
    """.split()
)

_SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)
_YEAR = re.compile(r"(19|20)\d{2}")


@dataclass(frozen=True)
class StrengthResult:
    score: int                 # 0..4
    label: str
    entropy_bits: float
    feedback: tuple[str, ...] = ()

    @property
    def is_weak(self) -> bool:
        return self.score <= 1


def _charset_size(pw: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in pw):
        size += 26
    if any(c in string.ascii_uppercase for c in pw):
        size += 26
    if any(c in string.digits for c in pw):
        size += 10
    if any(c in string.punctuation or c == " " for c in pw):
        size += 33
    if any(ord(c) > 127 for c in pw):
        size += 100
    return max(size, 1)


def char_classes(pw: str) -> int:
    return sum(
        [
            any(c.islower() for c in pw),
            any(c.isupper() for c in pw),
            any(c.isdigit() for c in pw),
            any(not c.isalnum() for c in pw),
        ]
    )


def _sequence_chars(pw: str) -> int:
    """Number of characters that are part of runs of >= 3 sequential characters."""
    lower = pw.lower()
    flagged = [False] * len(lower)
    for seq in _SEQUENCES:
        for direction in (seq, seq[::-1]):
            for i in range(len(lower) - 2):
                if lower[i : i + 3] in direction:
                    j = i + 3
                    while j < len(lower) and lower[i : j + 1] in direction:
                        j += 1
                    for k in range(i, j):
                        flagged[k] = True
    return sum(flagged)


def _repeat_chars(pw: str) -> int:
    """Characters in runs of the same symbol (aaa) plus repeated blocks (abcabc)."""
    count = 0
    for match in re.finditer(r"(.)\1{2,}", pw):
        count += len(match.group(0)) - 1
    for unit in range(1, len(pw) // 2 + 1):
        if len(pw) % unit == 0 and pw[:unit] * (len(pw) // unit) == pw:
            return max(count, len(pw) - unit)
    return count


def estimate_strength(pw: str) -> StrengthResult:
    """Heuristic strength estimate (entropy with pattern penalties)."""
    if not pw:
        return StrengthResult(0, "Empty", 0.0, ("Password is empty",))

    feedback: list[str] = []
    lower = pw.lower()
    effective_len = len(pw) - 0.75 * _sequence_chars(pw) - 0.75 * _repeat_chars(pw)
    effective_len = max(effective_len, 1.0)
    entropy = effective_len * math.log2(_charset_size(pw))

    letters_only = re.sub(r"[^a-z]", "", lower)
    if lower in COMMON_PASSWORDS:
        entropy = min(entropy, 8.0)
        feedback.append("This is a very common password")
    elif len(letters_only) >= 4 and letters_only in COMMON_PASSWORDS:
        extra = len(pw) - len(letters_only)
        entropy = min(entropy, 18.0 + extra * 3.0)
        feedback.append("Based on a common word or password")
    if _sequence_chars(pw) >= 3:
        feedback.append("Avoid sequences like 'abc' or '123'")
    if _repeat_chars(pw) >= 2:
        feedback.append("Avoid repeated characters or patterns")
    if _YEAR.search(pw):
        entropy -= 16
        feedback.append("Avoid years and dates")
    if len(pw) < 12:
        feedback.append("Use at least 12 characters")
    if char_classes(pw) < 3 and len(pw) < 20:
        feedback.append("Mix upper and lower case, numbers and symbols")

    entropy = max(entropy, 0.0)
    if entropy < 28:
        score = 0
    elif entropy < 40:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4
    if len(pw) < 8:
        score = min(score, 1)
    elif len(pw) < 12:
        score = min(score, 2)
    return StrengthResult(score, LABELS[score], round(entropy, 1), tuple(feedback))


# --------------------------------------------------------------------------- vault report
class _EntryLike(Protocol):
    id: int | None
    title: str
    username: str
    password: str
    password_changed_at: str


@dataclass
class SecurityReport:
    total: int = 0
    weak: list = field(default_factory=list)
    reused_groups: list = field(default_factory=list)   # list[list[entry]]
    old: list = field(default_factory=list)
    score: int = 100                                     # 0..100

    @property
    def reused_count(self) -> int:
        return sum(len(g) for g in self.reused_groups)

    @property
    def issue_count(self) -> int:
        ids = {e.id for e in self.weak} | {e.id for e in self.old}
        ids |= {e.id for g in self.reused_groups for e in g}
        return len(ids)


def _parse_ts(value: str) -> datetime | None:
    try:
        ts = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def analyze(entries: Iterable[_EntryLike], old_days: int = 180, now: datetime | None = None) -> SecurityReport:
    """Find weak, reused and old passwords. Comparisons happen in memory only."""
    entries = list(entries)
    now = now or datetime.now(timezone.utc)
    report = SecurityReport(total=len(entries))
    if not entries:
        return report

    by_password: dict[str, list] = defaultdict(list)
    for entry in entries:
        if entry.password:
            by_password[entry.password].append(entry)
        if estimate_strength(entry.password).is_weak:
            report.weak.append(entry)
        changed = _parse_ts(entry.password_changed_at)
        if old_days > 0 and changed and now - changed > timedelta(days=old_days):
            report.old.append(entry)
    report.reused_groups = [group for group in by_password.values() if len(group) > 1]
    by_password.clear()

    weak_ids = {e.id for e in report.weak}
    reused_ids = {e.id for g in report.reused_groups for e in g}
    old_ids = {e.id for e in report.old}
    penalty = 0.0
    for entry in entries:
        p = 0.0
        if entry.id in weak_ids:
            p += 1.0
        if entry.id in reused_ids:
            p += 0.7
        if entry.id in old_ids:
            p += 0.3
        penalty += min(p, 1.0)
    report.score = max(0, round(100 * (1 - penalty / len(entries))))
    return report
