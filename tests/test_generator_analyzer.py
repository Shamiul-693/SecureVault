from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from core.password_generator import (
    AMBIGUOUS, DIGITS, LOWER, SYMBOLS, UPPER, GeneratorError, GeneratorOptions, entropy_bits, generate_password,
)
from core.security_analyzer import analyze, estimate_strength


def test_length_and_sets():
    for length in (8, 20, 64, 128):
        pw = generate_password(GeneratorOptions(length=length))
        assert len(pw) == length
        assert any(c in UPPER for c in pw) and any(c in LOWER for c in pw)
        assert any(c in DIGITS for c in pw) and any(c in SYMBOLS for c in pw)


def test_only_selected_sets():
    pw = generate_password(GeneratorOptions(length=40, uppercase=False, symbols=False))
    assert all(c in LOWER + DIGITS for c in pw)


def test_exclude_ambiguous():
    for _ in range(50):
        pw = generate_password(GeneratorOptions(length=64, exclude_ambiguous=True))
        assert not set(pw) & AMBIGUOUS


def test_randomness():
    assert len({generate_password() for _ in range(500)}) == 500


def test_invalid_options():
    with pytest.raises(GeneratorError):
        generate_password(GeneratorOptions(length=4))
    with pytest.raises(GeneratorError):
        generate_password(GeneratorOptions(uppercase=False, lowercase=False, digits=False, symbols=False))


def test_entropy():
    assert entropy_bits(GeneratorOptions(length=20)) > 120


def test_strength_estimates():
    assert estimate_strength("").score == 0
    assert estimate_strength("password").score == 0
    assert estimate_strength("123456789").score == 0
    assert estimate_strength("Password2024!").score <= 2
    assert estimate_strength("aaaaaaaaaaaaaaaaaa").score <= 1
    assert estimate_strength(generate_password(GeneratorOptions(length=20))).score == 4
    assert estimate_strength("Correct-Horse-Battery-42!").score >= 3


@dataclass
class E:
    id: int
    title: str
    username: str
    password: str
    password_changed_at: str


def test_analyze():
    now = datetime.now(timezone.utc)
    old = (now - timedelta(days=400)).isoformat()
    fresh = now.isoformat()
    strong = generate_password()
    entries = [
        E(1, "a", "", "password", fresh),
        E(2, "b", "", strong, fresh),
        E(3, "c", "", strong, old),
        E(4, "d", "", generate_password(), fresh),
    ]
    report = analyze(entries, old_days=180, now=now)
    assert [e.id for e in report.weak] == [1]
    assert [sorted(e.id for e in g) for g in report.reused_groups] == [[2, 3]]
    assert [e.id for e in report.old] == [3]
    assert report.issue_count == 3
    assert 0 <= report.score < 100
    assert analyze([]).score == 100
