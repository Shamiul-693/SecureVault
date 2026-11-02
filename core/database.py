"""SQLite storage layer.

This module stores only ciphertext for sensitive fields; it never sees
plaintext credentials. Encryption/decryption is done by core.vault.

Design notes
  * All SQL is parameterised.
  * Explicit transactions (BEGIN IMMEDIATE ... COMMIT/ROLLBACK).
  * PRAGMA secure_delete overwrites deleted content inside the file.
  * PRAGMA integrity_check + foreign_key_check run at open.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 2

DEFAULT_CATEGORIES = [
    "Personal",
    "Social Media",
    "Email",
    "Banking & Finance",
    "Education",
    "Work",
    "Development",
    "Shopping",
    "Wi-Fi & Networks",
    "Other",
]
FALLBACK_CATEGORY = "Other"
MAX_CATEGORY_LEN = 40

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS application_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS categories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    is_default  INTEGER NOT NULL DEFAULT 0,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS password_entries (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid                TEXT NOT NULL UNIQUE,
    category_id         INTEGER NOT NULL REFERENCES categories(id) ON DELETE RESTRICT,
    title_enc           BLOB NOT NULL,
    url_enc             BLOB NOT NULL,
    username_enc        BLOB NOT NULL,
    password_enc        BLOB NOT NULL,
    notes_enc           BLOB NOT NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    password_changed_at TEXT NOT NULL,
    last_used_at        TEXT,
    use_count           INTEGER NOT NULL DEFAULT 0,
    favorite            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_entries_category ON password_entries(category_id);
"""

# Version 2: item types (login / secure note / card / personal info), folders, trash
_MIGRATION_V2 = [
    """CREATE TABLE IF NOT EXISTS folders (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
        created_at  TEXT NOT NULL
    )""",
    "ALTER TABLE password_entries ADD COLUMN item_type TEXT NOT NULL DEFAULT 'login'",
    "ALTER TABLE password_entries ADD COLUMN folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL",
    "ALTER TABLE password_entries ADD COLUMN deleted_at TEXT",
    "ALTER TABLE password_entries ADD COLUMN extra_enc BLOB",
    "CREATE INDEX IF NOT EXISTS idx_entries_folder ON password_entries(folder_id)",
]
ITEM_TYPES = ("login", "note", "card", "identity")

ENTRY_COLUMNS = (
    "id", "uuid", "category_id", "title_enc", "url_enc", "username_enc", "password_enc",
    "notes_enc", "created_at", "updated_at", "password_changed_at", "last_used_at",
    "use_count", "favorite", "item_type", "folder_id", "deleted_at", "extra_enc",
)
_UPDATABLE = {
    "category_id", "title_enc", "url_enc", "username_enc", "password_enc", "notes_enc",
    "updated_at", "password_changed_at", "favorite", "folder_id", "deleted_at", "extra_enc",
}
REQUIRED_TABLES = {"vault_metadata", "application_settings", "categories", "password_entries"}
MAX_FOLDER_LEN = 40


class DatabaseError(Exception):
    pass


class IntegrityCheckError(DatabaseError):
    pass


@dataclass(frozen=True)
class Folder:
    id: int
    name: str
    entry_count: int = 0


@dataclass(frozen=True)
class Category:
    id: int
    name: str
    is_default: bool
    entry_count: int = 0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_category_name(name: str, kind: str = "Category", limit: int = MAX_CATEGORY_LEN) -> str:
    cleaned = " ".join((name or "").split())
    if not cleaned:
        raise DatabaseError(f"{kind} name cannot be empty")
    if len(cleaned) > limit:
        raise DatabaseError(f"{kind} name must be at most {limit} characters")
    return cleaned


class Database:
    def __init__(self, path: Path | str):
        self.path = Path(path) if str(path) != ":memory:" else path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        self._in_tx = False

    # ------------------------------------------------------------------ lifecycle
    def open(self, check_integrity: bool = True) -> None:
        if self._conn is not None:
            return
        if isinstance(self.path, Path):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            conn = sqlite3.connect(str(self.path), isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = DELETE")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("PRAGMA secure_delete = ON")
        except sqlite3.DatabaseError as exc:
            raise IntegrityCheckError(f"Database file could not be opened: {exc}") from exc
        self._conn = conn
        try:
            if check_integrity:
                self.integrity_check()
            self._migrate()
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    @property
    def is_open(self) -> bool:
        return self._conn is not None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise DatabaseError("Database is not open")
        return self._conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Atomic unit of work. Nested calls join the outer transaction."""
        with self._lock:
            if self._in_tx:
                yield self.conn
                return
            self.conn.execute("BEGIN IMMEDIATE")
            self._in_tx = True
            try:
                yield self.conn
                self.conn.execute("COMMIT")
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            finally:
                self._in_tx = False

    def integrity_check(self) -> None:
        try:
            rows = self.conn.execute("PRAGMA integrity_check").fetchall()
            fk = self.conn.execute("PRAGMA foreign_key_check").fetchall()
        except sqlite3.DatabaseError as exc:
            raise IntegrityCheckError(f"Database is corrupted: {exc}") from exc
        result = [r[0] for r in rows]
        if result != ["ok"]:
            raise IntegrityCheckError("Database integrity check failed")
        if fk:
            raise IntegrityCheckError("Database foreign key check failed")

    def _migrate(self) -> None:
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise DatabaseError("This vault was created by a newer version of SecureVault")
        if version == 0:
            # executescript() would implicitly COMMIT, so statements run one by one
            # inside a single explicit transaction.
            with self.transaction() as c:
                for statement in _SCHEMA.strip().split(";"):
                    if statement.strip():
                        c.execute(statement)
                now = utc_now()
                for order, name in enumerate(DEFAULT_CATEGORIES):
                    c.execute(
                        "INSERT OR IGNORE INTO categories(name, is_default, sort_order, created_at) "
                        "VALUES (?, 1, ?, ?)",
                        (name, order, now),
                    )
                c.execute("PRAGMA user_version = 1")
            version = 1
        if version == 1:
            # Upgrade an existing vault in one transaction: either all of v2 applies or nothing does.
            with self.transaction() as c:
                for statement in _MIGRATION_V2:
                    c.execute(statement)
                c.execute("PRAGMA user_version = 2")
        tables = {r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not REQUIRED_TABLES.issubset(tables):
            raise IntegrityCheckError("Database schema is incomplete")

    def serialize(self) -> bytes:
        """Consistent snapshot of the whole database file (used for backups)."""
        with self._lock:
            return bytes(self.conn.serialize())

    # ------------------------------------------------------------------ metadata
    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM vault_metadata WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta_many(self, values: dict[str, str]) -> None:
        with self.transaction() as c:
            for key, value in values.items():
                c.execute(
                    "INSERT INTO vault_metadata(key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, str(value)),
                )

    def set_meta(self, key: str, value: str) -> None:
        self.set_meta_many({key: value})

    # ------------------------------------------------------------------ settings
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM application_settings WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO application_settings(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )

    # ------------------------------------------------------------------ categories
    def list_categories(self) -> list[Category]:
        rows = self.conn.execute(
            "SELECT c.id, c.name, c.is_default, COUNT(e.id) AS n "
            "FROM categories c LEFT JOIN password_entries e ON e.category_id = c.id AND e.deleted_at IS NULL "
            "GROUP BY c.id ORDER BY c.is_default DESC, c.sort_order, c.name COLLATE NOCASE"
        ).fetchall()
        return [Category(r["id"], r["name"], bool(r["is_default"]), r["n"]) for r in rows]

    def get_category(self, category_id: int) -> Category | None:
        for cat in self.list_categories():
            if cat.id == category_id:
                return cat
        return None

    def category_id_by_name(self, name: str) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM categories WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        return row[0] if row else None

    def fallback_category_id(self) -> int:
        cid = self.category_id_by_name(FALLBACK_CATEGORY)
        if cid is None:
            with self.transaction() as c:
                cur = c.execute(
                    "INSERT INTO categories(name, is_default, sort_order, created_at) VALUES (?, 1, 99, ?)",
                    (FALLBACK_CATEGORY, utc_now()),
                )
                cid = cur.lastrowid
        return int(cid)

    def add_category(self, name: str) -> int:
        name = validate_category_name(name)
        if self.category_id_by_name(name) is not None:
            raise DatabaseError(f"A category named '{name}' already exists")
        with self.transaction() as c:
            cur = c.execute(
                "INSERT INTO categories(name, is_default, sort_order, created_at) VALUES (?, 0, 100, ?)",
                (name, utc_now()),
            )
            return int(cur.lastrowid)

    def rename_category(self, category_id: int, name: str) -> None:
        name = validate_category_name(name)
        cat = self.get_category(category_id)
        if cat is None:
            raise DatabaseError("Category not found")
        if cat.is_default:
            raise DatabaseError("Default categories cannot be renamed")
        existing = self.category_id_by_name(name)
        if existing is not None and existing != category_id:
            raise DatabaseError(f"A category named '{name}' already exists")
        with self.transaction() as c:
            c.execute("UPDATE categories SET name = ? WHERE id = ?", (name, category_id))

    def delete_category(self, category_id: int) -> int:
        """Delete a custom category; its entries move to 'Other'. Returns moved count."""
        cat = self.get_category(category_id)
        if cat is None:
            raise DatabaseError("Category not found")
        if cat.is_default:
            raise DatabaseError("Default categories cannot be deleted")
        fallback = self.fallback_category_id()
        with self.transaction() as c:
            moved = c.execute(
                "UPDATE password_entries SET category_id = ? WHERE category_id = ?",
                (fallback, category_id),
            ).rowcount
            c.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        return moved

    # ------------------------------------------------------------------ entries (ciphertext rows)
    def insert_entry(self, row: dict[str, Any]) -> int:
        cols = [c for c in ENTRY_COLUMNS if c != "id" and c in row]
        sql = "INSERT INTO password_entries({}) VALUES ({})".format(
            ", ".join(cols), ", ".join("?" for _ in cols)
        )
        with self.transaction() as c:
            cur = c.execute(sql, tuple(row[col] for col in cols))
            return int(cur.lastrowid)

    def update_entry(self, entry_id: int, values: dict[str, Any]) -> None:
        bad = set(values) - _UPDATABLE
        if bad:
            raise DatabaseError(f"Cannot update columns: {sorted(bad)}")
        if not values:
            return
        assignments = ", ".join(f"{col} = ?" for col in values)  # column names are whitelisted
        with self.transaction() as c:
            cur = c.execute(
                f"UPDATE password_entries SET {assignments} WHERE id = ?",
                (*values.values(), entry_id),
            )
            if cur.rowcount != 1:
                raise DatabaseError("Entry not found")

    def delete_entry(self, entry_id: int) -> None:
        with self.transaction() as c:
            cur = c.execute("DELETE FROM password_entries WHERE id = ?", (entry_id,))
            if cur.rowcount != 1:
                raise DatabaseError("Entry not found")

    def get_entry_row(self, entry_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM password_entries WHERE id = ?", (entry_id,)
        ).fetchone()

    def get_entry_rows(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM password_entries ORDER BY id").fetchall()

    def entry_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM password_entries").fetchone()[0])

    def touch_entry_used(self, entry_id: int) -> None:
        with self.transaction() as c:
            c.execute(
                "UPDATE password_entries SET use_count = use_count + 1, last_used_at = ? WHERE id = ?",
                (utc_now(), entry_id),
            )

    # ------------------------------------------------------------------ folders
    def list_folders(self) -> list[Folder]:
        rows = self.conn.execute(
            "SELECT f.id, f.name, COUNT(e.id) AS n FROM folders f "
            "LEFT JOIN password_entries e ON e.folder_id = f.id AND e.deleted_at IS NULL "
            "GROUP BY f.id ORDER BY f.name COLLATE NOCASE"
        ).fetchall()
        return [Folder(r["id"], r["name"], r["n"]) for r in rows]

    def get_folder(self, folder_id: int) -> Folder | None:
        return next((f for f in self.list_folders() if f.id == folder_id), None)

    def _folder_id_by_name(self, name: str) -> int | None:
        row = self.conn.execute("SELECT id FROM folders WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
        return row[0] if row else None

    def add_folder(self, name: str) -> int:
        name = validate_category_name(name, "Folder", MAX_FOLDER_LEN)
        if self._folder_id_by_name(name) is not None:
            raise DatabaseError(f"A folder named '{name}' already exists")
        with self.transaction() as c:
            return int(c.execute("INSERT INTO folders(name, created_at) VALUES (?, ?)", (name, utc_now())).lastrowid)

    def rename_folder(self, folder_id: int, name: str) -> None:
        name = validate_category_name(name, "Folder", MAX_FOLDER_LEN)
        existing = self._folder_id_by_name(name)
        if existing is not None and existing != folder_id:
            raise DatabaseError(f"A folder named '{name}' already exists")
        with self.transaction() as c:
            if c.execute("UPDATE folders SET name = ? WHERE id = ?", (name, folder_id)).rowcount != 1:
                raise DatabaseError("Folder not found")

    def delete_folder(self, folder_id: int) -> None:
        """Delete a folder. Its items are kept and simply leave the folder."""
        with self.transaction() as c:
            c.execute("UPDATE password_entries SET folder_id = NULL WHERE folder_id = ?", (folder_id,))
            if c.execute("DELETE FROM folders WHERE id = ?", (folder_id,)).rowcount != 1:
                raise DatabaseError("Folder not found")

    # ------------------------------------------------------------------ trash
    def trashed_before(self, cutoff_iso: str) -> list[int]:
        rows = self.conn.execute(
            "SELECT id FROM password_entries WHERE deleted_at IS NOT NULL AND deleted_at < ?", (cutoff_iso,)
        ).fetchall()
        return [r[0] for r in rows]

    def delete_entries(self, ids: list[int]) -> int:
        if not ids:
            return 0
        with self.transaction() as c:
            return sum(c.execute("DELETE FROM password_entries WHERE id = ?", (i,)).rowcount for i in ids)
