"""Master password authentication and vault-key management.

Key hierarchy
    master password --Argon2id(salt, params)--> KEK (256-bit, never stored)
    KEK --AES-256-GCM wrap--> vault key (random 256-bit, stored only wrapped)
    vault key --AES-256-GCM--> every sensitive field

Changing the master password re-wraps the same vault key, so no entry
needs re-encryption. A wrong password is detected by the GCM tag on the
wrapped key failing to verify — no password hash or verifier is stored.
"""
from __future__ import annotations

import base64
import json
import logging
import time
from typing import Callable

from .database import Database
from .encryption import (
    DEFAULT_KDF,
    DecryptionError,
    KdfParams,
    derive_key,
    generate_key,
    generate_salt,
    unwrap_key,
    wipe,
    wrap_key,
)
from .security_analyzer import COMMON_PASSWORDS, char_classes, estimate_strength

log = logging.getLogger("securevault.auth")

MIN_MASTER_LENGTH = 12
MAX_MASTER_LENGTH = 1024
FREE_ATTEMPTS = 3
MAX_LOCKOUT_SECONDS = 300
VAULT_FORMAT = "1"
_WRAP_AAD = b"securevault/vault-key/v1|"


class AuthError(Exception):
    pass


class VaultNotInitializedError(AuthError):
    pass


class VaultAlreadyInitializedError(AuthError):
    pass


class WrongPasswordError(AuthError):
    def __init__(self, attempts: int, lockout_seconds: float):
        super().__init__("Incorrect master password")
        self.attempts = attempts
        self.lockout_seconds = lockout_seconds


class LockedOutError(AuthError):
    def __init__(self, retry_after: float):
        super().__init__(f"Too many failed attempts. Try again in {int(retry_after) + 1} seconds.")
        self.retry_after = retry_after


class WeakPasswordError(AuthError):
    def __init__(self, issues: list[str]):
        super().__init__("; ".join(issues))
        self.issues = issues


def validate_master_password(password: str) -> list[str]:
    """Return a list of problems; empty list means the password is acceptable."""
    issues: list[str] = []
    if len(password) < MIN_MASTER_LENGTH:
        issues.append(f"Use at least {MIN_MASTER_LENGTH} characters")
    if len(password) > MAX_MASTER_LENGTH:
        issues.append(f"Use at most {MAX_MASTER_LENGTH} characters")
    if password != password.strip():
        issues.append("Do not start or end with spaces")
    if char_classes(password) < 3 and len(password) < 20:
        issues.append("Use 3 of: lowercase, uppercase, numbers, symbols (or 20+ characters)")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This password is too common")
    if not issues and estimate_strength(password).score < 3:
        issues.append("Password is too predictable — avoid sequences, repeats and common words")
    return issues


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def wrap_aad(salt: bytes) -> bytes:
    return _WRAP_AAD + salt


class Authenticator:
    def __init__(
        self,
        db: Database,
        kdf_params: KdfParams = DEFAULT_KDF,
        clock: Callable[[], float] = time.time,
    ):
        self.db = db
        self.kdf_params = kdf_params
        self._clock = clock

    # ------------------------------------------------------------------ state
    def is_initialized(self) -> bool:
        return self.db.get_meta("wrapped_key") is not None

    def _failed_attempts(self) -> int:
        try:
            return int(self.db.get_meta("failed_attempts") or 0)
        except ValueError:
            return 0

    @staticmethod
    def _lockout_for(attempts: int) -> float:
        if attempts < FREE_ATTEMPTS:
            return 0.0
        return float(min(5 * 2 ** (attempts - FREE_ATTEMPTS), MAX_LOCKOUT_SECONDS))

    def lockout_remaining(self) -> float:
        attempts = self._failed_attempts()
        delay = self._lockout_for(attempts)
        if delay <= 0:
            return 0.0
        try:
            last = float(self.db.get_meta("last_failed_at") or 0)
        except ValueError:
            last = 0.0
        remaining = last + delay - self._clock()
        # Clamp clock manipulation (e.g. clock set backwards) to the max delay.
        return max(0.0, min(remaining, delay))

    # ------------------------------------------------------------------ setup
    def setup(self, master_password: str) -> bytearray:
        """Create a new vault. Returns the vault key (caller must wipe it on lock)."""
        if self.is_initialized():
            raise VaultAlreadyInitializedError("Vault is already set up")
        issues = validate_master_password(master_password)
        if issues:
            raise WeakPasswordError(issues)
        vault_key = generate_key()
        self._store_wrapped_key(master_password, vault_key, self.kdf_params, extra={
            "vault_format": VAULT_FORMAT,
            "failed_attempts": "0",
            "last_failed_at": "0",
        })
        log.info("New vault initialised")
        return vault_key

    def _store_wrapped_key(self, password: str, vault_key: bytearray, params: KdfParams, extra: dict | None = None) -> None:
        salt = generate_salt()
        kek = derive_key(password, salt, params)
        try:
            wrapped = wrap_key(kek, vault_key, wrap_aad(salt))
        finally:
            wipe(kek)
        values = {
            "kdf_params": json.dumps(params.to_dict(), sort_keys=True),
            "kdf_salt": _b64(salt),
            "wrapped_key": _b64(wrapped),
        }
        values.update(extra or {})
        self.db.set_meta_many(values)

    # ------------------------------------------------------------------ unlock
    def unlock(self, master_password: str) -> bytearray:
        """Return the vault key, or raise WrongPasswordError / LockedOutError."""
        if not self.is_initialized():
            raise VaultNotInitializedError("Vault has not been set up")
        remaining = self.lockout_remaining()
        if remaining > 0:
            raise LockedOutError(remaining)
        if not master_password:
            raise WrongPasswordError(self._failed_attempts(), 0.0)
        try:
            params = KdfParams.from_dict(json.loads(self.db.get_meta("kdf_params") or "{}"))
            salt = _unb64(self.db.get_meta("kdf_salt") or "")
            wrapped = _unb64(self.db.get_meta("wrapped_key") or "")
        except (ValueError, TypeError) as exc:
            raise AuthError("Vault metadata is corrupted") from exc

        kek = derive_key(master_password, salt, params)
        try:
            vault_key = unwrap_key(kek, wrapped, wrap_aad(salt))
        except DecryptionError:
            attempts = self._failed_attempts() + 1
            self.db.set_meta_many({"failed_attempts": str(attempts), "last_failed_at": str(self._clock())})
            log.warning("Failed unlock attempt (%d)", attempts)
            raise WrongPasswordError(attempts, self._lockout_for(attempts)) from None
        finally:
            wipe(kek)

        if self._failed_attempts():
            self.db.set_meta_many({"failed_attempts": "0", "last_failed_at": "0"})
        log.info("Vault unlocked")
        return vault_key

    def verify(self, master_password: str) -> bool:
        try:
            key = self.unlock(master_password)
        except WrongPasswordError:
            return False
        wipe(key)
        return True

    # ------------------------------------------------------------------ change
    def change_password(self, current_password: str, new_password: str) -> None:
        """Re-wrap the vault key under a new master password (and current KDF params)."""
        issues = validate_master_password(new_password)
        if issues:
            raise WeakPasswordError(issues)
        if new_password == current_password:
            raise WeakPasswordError(["New password must be different from the current one"])
        vault_key = self.unlock(current_password)
        try:
            self._store_wrapped_key(new_password, vault_key, self.kdf_params)
        finally:
            wipe(vault_key)
        log.info("Master password changed")
