"""Encrypted backup and restore.

Backup file format (.svbak, version 1)

    MAGIC  "SVBACKUP"            8 bytes
    VER    0x01                  1 byte
    HLEN   header length         4 bytes, big endian
    HEADER UTF-8 JSON            HLEN bytes  (no secrets: KDF params, salt,
                                              wrapped vault key, metadata)
    PAYLOAD encrypt(vault_key, sqlite_snapshot, AAD = MAGIC|VER|HLEN|HEADER)

The whole header is authenticated as AAD, so changing any header byte makes
decryption fail. The header carries the wrapped vault key from the time of
the backup, so a backup can be restored on a fresh installation with the
master password that was active when it was made. The SQLite snapshot itself
only contains ciphertext for sensitive fields — double protection.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .authentication import wrap_aad
from .database import REQUIRED_TABLES, SCHEMA_VERSION, Database
from .encryption import (
    DecryptionError,
    KdfParams,
    decrypt,
    derive_key,
    encrypt,
    unwrap_key,
    wipe,
)

log = logging.getLogger("securevault.backup")

MAGIC = b"SVBACKUP"
FORMAT_VERSION = 1
MAX_HEADER = 64 * 1024
MAX_BACKUP_SIZE = 512 * 1024 * 1024
EXTENSION = ".svbak"


class BackupError(Exception):
    pass


class BackupPasswordError(BackupError):
    pass


@dataclass(frozen=True)
class BackupInfo:
    path: Path
    created_at: str
    app_version: str
    entry_count: int
    size: int


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".svtmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def validate_snapshot(snapshot: bytes) -> int:
    """Check that bytes are a healthy SecureVault SQLite database. Returns entry count."""
    conn = sqlite3.connect(":memory:")
    try:
        try:
            conn.deserialize(snapshot)
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("Backup database failed its integrity check")
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not REQUIRED_TABLES.issubset(tables):
                raise BackupError("Backup is not a SecureVault database")
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if not 1 <= version <= SCHEMA_VERSION:
                raise BackupError("Backup was created by an unsupported version")
            if conn.execute("SELECT value FROM vault_metadata WHERE key='wrapped_key'").fetchone() is None:
                raise BackupError("Backup contains no vault key")
            return int(conn.execute("SELECT COUNT(*) FROM password_entries").fetchone()[0])
        except sqlite3.DatabaseError as exc:
            raise BackupError(f"Backup database is unreadable: {exc}") from exc
    finally:
        conn.close()


class BackupManager:
    def __init__(self, db: Database, backup_dir: Path, app_version: str = "1.0.0"):
        self.db = db
        self.backup_dir = Path(backup_dir)
        self.app_version = app_version

    # ------------------------------------------------------------------ create
    def create_backup(self, vault_key: bytearray, destination: Path | None = None, prefix: str = "SecureVault-backup") -> Path:
        snapshot = self.db.serialize()
        entry_count = validate_snapshot(snapshot)
        header = {
            "format": FORMAT_VERSION,
            "app": "SecureVault",
            "app_version": self.app_version,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "entry_count": entry_count,
            "kdf_params": json.loads(self.db.get_meta("kdf_params") or "{}"),
            "kdf_salt": self.db.get_meta("kdf_salt"),
            "wrapped_key": self.db.get_meta("wrapped_key"),
            "payload_sha256": hashlib.sha256(snapshot).hexdigest(),
        }
        if not header["wrapped_key"] or not header["kdf_salt"]:
            raise BackupError("Vault is not initialised")
        header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
        prefix_bytes = MAGIC + bytes([FORMAT_VERSION]) + len(header_bytes).to_bytes(4, "big") + header_bytes
        payload = encrypt(vault_key, snapshot, aad=prefix_bytes)
        path = Path(destination) if destination else self.backup_dir / f"{prefix}-{_timestamp()}{EXTENSION}"
        _atomic_write(path, prefix_bytes + payload)
        self.db.set_setting("last_backup_at", header["created_at"])
        log.info("Backup created (%d entries)", entry_count)
        return path

    # ------------------------------------------------------------------ read / verify
    @staticmethod
    def _parse(path: Path) -> tuple[dict, bytes, bytes]:
        path = Path(path)
        if not path.is_file():
            raise BackupError("Backup file not found")
        size = path.stat().st_size
        if size > MAX_BACKUP_SIZE:
            raise BackupError("Backup file is too large")
        data = path.read_bytes()
        if len(data) < len(MAGIC) + 5 or not data.startswith(MAGIC):
            raise BackupError("Not a SecureVault backup file")
        if data[len(MAGIC)] != FORMAT_VERSION:
            raise BackupError("Unsupported backup format version")
        hlen = int.from_bytes(data[len(MAGIC) + 1 : len(MAGIC) + 5], "big")
        start = len(MAGIC) + 5
        if hlen <= 0 or hlen > MAX_HEADER or start + hlen >= len(data):
            raise BackupError("Backup header is corrupted")
        header_bytes = data[start : start + hlen]
        try:
            header = json.loads(header_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackupError("Backup header is corrupted") from exc
        if not isinstance(header, dict) or header.get("app") != "SecureVault":
            raise BackupError("Not a SecureVault backup file")
        return header, data[: start + hlen], data[start + hlen :]

    def read_info(self, path: Path) -> BackupInfo:
        """Structural validation without a password (header only)."""
        header, _, _ = self._parse(path)
        return BackupInfo(
            path=Path(path),
            created_at=str(header.get("created_at", "unknown")),
            app_version=str(header.get("app_version", "?")),
            entry_count=int(header.get("entry_count", 0) or 0),
            size=Path(path).stat().st_size,
        )

    def decrypt_backup(self, path: Path, master_password: str) -> tuple[BackupInfo, bytes]:
        """Full verification: password, GCM authentication, SHA-256 and SQLite integrity."""
        header, prefix, payload = self._parse(path)
        try:
            params = KdfParams.from_dict(header["kdf_params"])
            salt = base64.b64decode(header["kdf_salt"], validate=True)
            wrapped = base64.b64decode(header["wrapped_key"], validate=True)
        except Exception as exc:
            raise BackupError("Backup header is corrupted") from exc
        kek = derive_key(master_password, salt, params)
        try:
            vault_key = unwrap_key(kek, wrapped, wrap_aad(salt))
        except DecryptionError:
            raise BackupPasswordError("Incorrect master password for this backup") from None
        finally:
            wipe(kek)
        try:
            snapshot = decrypt(vault_key, payload, aad=prefix)
        except DecryptionError:
            raise BackupError("Backup failed integrity verification (tampered or corrupted)") from None
        finally:
            wipe(vault_key)
        if hashlib.sha256(snapshot).hexdigest() != header.get("payload_sha256"):
            raise BackupError("Backup checksum mismatch")
        count = validate_snapshot(snapshot)
        info = self.read_info(path)
        return BackupInfo(info.path, info.created_at, info.app_version, count, info.size), snapshot

    def verify_backup(self, path: Path, master_password: str) -> BackupInfo:
        info, snapshot = self.decrypt_backup(path, master_password)
        del snapshot
        return info

    # ------------------------------------------------------------------ restore
    def _safety_copy(self, vault_key: bytearray | None) -> Path | None:
        """Automatic backup of the current vault before it is replaced."""
        if not self.db.is_open or self.db.get_meta("wrapped_key") is None:
            return None
        if vault_key is not None:
            return self.create_backup(vault_key, prefix="pre-restore")
        # Locked: keep the raw database (secrets inside are already encrypted).
        path = self.backup_dir / f"pre-restore-{_timestamp()}.db.bak"
        _atomic_write(path, self.db.serialize())
        return path

    def restore_backup(self, path: Path, master_password: str, current_vault_key: bytearray | None = None) -> Path | None:
        """Verify a backup, save a safety copy of the current vault, then swap the files.

        Returns the safety-copy path (or None if there was nothing to preserve).
        The caller must re-unlock: the restored vault uses the backup's master password.
        """
        _, snapshot = self.decrypt_backup(path, master_password)
        safety = self._safety_copy(current_vault_key)
        db_file = Path(self.db.path)
        self.db.close()
        try:
            _atomic_write(db_file, snapshot)
        finally:
            self.db.open()
        log.info("Vault restored from backup")
        return safety

    def list_backups(self) -> list[BackupInfo]:
        infos = []
        for p in sorted(self.backup_dir.glob(f"*{EXTENSION}"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                infos.append(self.read_info(p))
            except BackupError:
                continue
        return infos
