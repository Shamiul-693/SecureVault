"""Cryptographic engine.

Only well-established primitives are used:
  * Argon2id (argon2-cffi) for password-based key derivation
  * AES-256-GCM (pyca/cryptography) for authenticated encryption
  * secrets / os.urandom for all randomness

Ciphertext blob format (version 1):
    [1 byte version][12 byte random nonce][ciphertext || 16 byte GCM tag]

Every encryption call draws a fresh random 96-bit nonce. Associated data
(AAD) binds each ciphertext to its context (which entry, which field), so a
ciphertext cannot be swapped into another row or column undetected.
"""
from __future__ import annotations

import ctypes
import hmac
import secrets
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32        # 256-bit keys
NONCE_SIZE = 12      # 96-bit GCM nonce
TAG_SIZE = 16
SALT_SIZE = 16       # 128-bit salt
BLOB_VERSION = 1
_MIN_BLOB = 1 + NONCE_SIZE + TAG_SIZE


class CryptoError(Exception):
    """Base class for cryptographic failures."""


class DecryptionError(CryptoError):
    """Authentication of ciphertext failed (wrong key, tampering or corruption)."""


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters. Defaults follow OWASP guidance for interactive logins
    (well above the 19 MiB / t=2 minimum): 64 MiB memory, 3 passes, 4 lanes."""

    time_cost: int = 3
    memory_cost_kib: int = 65536
    parallelism: int = 4
    hash_len: int = KEY_SIZE

    def validate(self) -> None:
        # Upper bounds stop a tampered database from forcing a huge allocation.
        if not 1 <= self.time_cost <= 20:
            raise CryptoError("Invalid Argon2 time cost")
        if not 8192 <= self.memory_cost_kib <= 1_048_576:
            raise CryptoError("Invalid Argon2 memory cost")
        if not 1 <= self.parallelism <= 16:
            raise CryptoError("Invalid Argon2 parallelism")
        if self.hash_len != KEY_SIZE:
            raise CryptoError("Invalid Argon2 output length")

    def to_dict(self) -> dict[str, int]:
        return {
            "algorithm": "argon2id",  # type: ignore[dict-item]
            "time_cost": self.time_cost,
            "memory_cost_kib": self.memory_cost_kib,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KdfParams":
        if data.get("algorithm", "argon2id") != "argon2id":
            raise CryptoError("Unsupported key derivation algorithm")
        try:
            params = cls(
                time_cost=int(data["time_cost"]),
                memory_cost_kib=int(data["memory_cost_kib"]),
                parallelism=int(data["parallelism"]),
                hash_len=int(data.get("hash_len", KEY_SIZE)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CryptoError("Malformed key derivation parameters") from exc
        params.validate()
        return params


DEFAULT_KDF = KdfParams()


# --------------------------------------------------------------------------- helpers
def random_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)


def generate_key() -> bytearray:
    """A fresh random 256-bit key, held in a mutable buffer so it can be wiped."""
    return bytearray(secrets.token_bytes(KEY_SIZE))


def wipe(buffer: bytearray | None) -> None:
    """Overwrite a mutable buffer with zeros (best effort; see README limitations)."""
    if isinstance(buffer, bytearray) and len(buffer):
        ctypes.memset((ctypes.c_char * len(buffer)).from_buffer(buffer), 0, len(buffer))


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def _check_key(key: bytes | bytearray) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        raise CryptoError("Encryption key must be 32 bytes")


# --------------------------------------------------------------------------- KDF
def derive_key(password: str, salt: bytes, params: KdfParams = DEFAULT_KDF) -> bytearray:
    """Derive a 256-bit key-encryption key from the master password with Argon2id."""
    if not isinstance(password, str) or not password:
        raise CryptoError("Password must be a non-empty string")
    if len(salt) < SALT_SIZE:
        raise CryptoError("Salt too short")
    params.validate()
    secret = bytearray(password.encode("utf-8"))
    try:
        raw = hash_secret_raw(
            secret=bytes(secret),
            salt=bytes(salt),
            time_cost=params.time_cost,
            memory_cost=params.memory_cost_kib,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            type=Type.ID,
        )
    finally:
        wipe(secret)
    return bytearray(raw)


# --------------------------------------------------------------------------- AEAD
def encrypt(key: bytes | bytearray, plaintext: bytes, aad: bytes | None = None) -> bytes:
    """AES-256-GCM encrypt with a fresh random 96-bit nonce."""
    _check_key(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)
    return bytes([BLOB_VERSION]) + nonce + ciphertext


def decrypt(key: bytes | bytearray, blob: bytes, aad: bytes | None = None) -> bytes:
    """Verify and decrypt a blob produced by :func:`encrypt`."""
    _check_key(key)
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < _MIN_BLOB:
        raise DecryptionError("Ciphertext is malformed")
    if blob[0] != BLOB_VERSION:
        raise DecryptionError("Unsupported ciphertext version")
    nonce = bytes(blob[1 : 1 + NONCE_SIZE])
    body = bytes(blob[1 + NONCE_SIZE :])
    try:
        return AESGCM(bytes(key)).decrypt(nonce, body, aad)
    except InvalidTag as exc:
        raise DecryptionError("Authentication failed") from exc


def encrypt_str(key: bytes | bytearray, text: str, aad: bytes | None = None) -> bytes:
    return encrypt(key, text.encode("utf-8"), aad)


def decrypt_str(key: bytes | bytearray, blob: bytes, aad: bytes | None = None) -> str:
    return decrypt(key, blob, aad).decode("utf-8")


def wrap_key(kek: bytes | bytearray, key: bytes | bytearray, aad: bytes) -> bytes:
    """Encrypt (wrap) the vault key under a key-encryption key."""
    _check_key(key)
    return encrypt(kek, bytes(key), aad)


def unwrap_key(kek: bytes | bytearray, wrapped: bytes, aad: bytes) -> bytearray:
    """Decrypt the vault key. Raises DecryptionError on a wrong password."""
    key = bytearray(decrypt(kek, wrapped, aad))
    if len(key) != KEY_SIZE:
        wipe(key)
        raise DecryptionError("Unwrapped key has invalid length")
    return key
