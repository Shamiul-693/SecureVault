"""Cryptographically secure password generation (Python `secrets`)."""
from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~"
AMBIGUOUS = set("Il1|O0o`'\"")

MIN_LENGTH = 8
MAX_LENGTH = 128


class GeneratorError(ValueError):
    pass


@dataclass(frozen=True)
class GeneratorOptions:
    length: int = 20
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False

    def pools(self) -> list[str]:
        pools = []
        for enabled, chars in (
            (self.uppercase, UPPER),
            (self.lowercase, LOWER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ):
            if enabled:
                if self.exclude_ambiguous:
                    chars = "".join(c for c in chars if c not in AMBIGUOUS)
                pools.append(chars)
        return pools


def entropy_bits(options: GeneratorOptions) -> float:
    alphabet = set("".join(options.pools()))
    if not alphabet:
        return 0.0
    return round(options.length * math.log2(len(alphabet)), 1)


def generate_password(options: GeneratorOptions = GeneratorOptions()) -> str:
    """Generate a password containing at least one character from each selected set."""
    if not isinstance(options.length, int) or not MIN_LENGTH <= options.length <= MAX_LENGTH:
        raise GeneratorError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}")
    pools = options.pools()
    if not pools:
        raise GeneratorError("Select at least one character set")
    if options.length < len(pools):
        raise GeneratorError("Length is too short for the selected character sets")
    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(options.length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
