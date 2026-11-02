"""Encrypted CRUD on top of core.database.

Item types
    login     — website / app account (username, password, URL)
    note      — secure note (title + notes)
    card      — payment card (cardholder, number, expiry, CVV, PIN in `extra`)
    identity  — personal info (name, email, phone, address, … in `extra`)

Every sensitive field (title, URL, username, password, notes and the
type-specific `extra` JSON) is encrypted with AES-256-GCM under the vault key.
The AAD binds each ciphertext to the entry's UUID and the field name, so
ciphertexts cannot be moved between rows or columns without detection.
Non-secret metadata (type, category, folder, timestamps) stays in clear so it
can be filtered without decrypting.
"""
from __future__ import annotations

import json
import logging
import re
import uuid as uuid_mod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .database import ITEM_TYPES, Database, DatabaseError, utc_now
from .encryption import DecryptionError, decrypt_str, encrypt_str, wipe

log = logging.getLogger("securevault.vault")

FIELDS = ("title", "url", "username", "password", "notes")
LIMITS = {"title": 200, "url": 2048, "username": 512, "password": 1024, "notes": 20000}
EXTRA_LIMIT = 1000  # per extra field
TRASH_RETENTION_DAYS = 30

TYPE_LABELS = {"login": "Password", "note": "Secure note", "card": "Credit card", "identity": "Personal info"}
TYPE_PLURALS = {"login": "Passwords", "note": "Secure notes", "card": "Credit cards", "identity": "Personal info"}

# Ordered (key, label, sensitive) per type for the `extra` dictionary.
EXTRA_FIELDS: dict[str, list[tuple[str, str, bool]]] = {
    "login": [],
    "note": [],
    "card": [
        ("cardholder", "Cardholder name", False),
        ("number", "Card number", True),
        ("expiry", "Expiry (MM/YY)", False),
        ("cvv", "Security code (CVV)", True),
        ("pin", "PIN", True),
    ],
    "identity": [
        ("full_name", "Full name", False),
        ("email", "Email", False),
        ("phone", "Phone", False),
        ("birthday", "Date of birth", False),
        ("address", "Address", False),
        ("company", "Company / institution", False),
        ("id_number", "ID / passport number", True),
    ],
}
SEARCHABLE_EXTRA = {"cardholder", "full_name", "email", "phone", "address", "company"}

SORT_OPTIONS = {
    "last_used": "Last used",
    "name_asc": "Name (A–Z)",
    "name_desc": "Name (Z–A)",
    "updated": "Recently updated",
    "created": "Recently added",
    "used": "Most used",
}

# Views: "all", "favorites", "trash", "type:<item_type>", "folder:<id>"
VIEW_ALL, VIEW_FAVORITES, VIEW_TRASH = "all", "favorites", "trash"


class VaultLockedError(Exception):
    pass


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    id: int
    uuid: str
    title: str
    url: str
    username: str
    password: str
    notes: str
    category_id: int
    category_name: str
    created_at: str
    updated_at: str
    password_changed_at: str
    last_used_at: str | None
    use_count: int
    favorite: bool
    item_type: str = "login"
    folder_id: int | None = None
    folder_name: str = ""
    deleted_at: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def in_trash(self) -> bool:
        return self.deleted_at is not None

    @property
    def is_login(self) -> bool:
        return self.item_type == "login"

    @property
    def subtitle(self) -> str:
        """One-line description for lists. Never contains a secret."""
        if self.item_type == "card":
            parts = [card_brand(self.extra.get("number", ""))]
            last4 = digits_only(self.extra.get("number", ""))[-4:]
            if last4:
                parts.append(f"•••• {last4}")
            if self.extra.get("expiry"):
                parts.append(f"exp {self.extra['expiry']}")
            return "  ".join(p for p in parts if p)
        if self.item_type == "identity":
            bits = [self.extra.get("full_name", ""), self.extra.get("email", "") or self.extra.get("phone", "")]
            return " · ".join(b for b in bits if b)
        if self.item_type == "note":
            first = next((line.strip() for line in self.notes.splitlines() if line.strip()), "")
            return first[:80] if first else "Secure note"
        return self.username

    def matches(self, query: str) -> bool:
        q = query.casefold()
        values = [self.title, self.username, self.url, self.notes, self.category_name, self.folder_name]
        values += [str(v) for k, v in self.extra.items() if k in SEARCHABLE_EXTRA]
        return any(q in value.casefold() for value in values)


def digits_only(text: str) -> str:
    return re.sub(r"\D", "", text or "")


def luhn_valid(number: str) -> bool:
    digits = digits_only(number)
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card_brand(number: str) -> str:
    d = digits_only(number)
    if not d:
        return "Card"
    if d.startswith("4"):
        return "Visa"
    if d[:2] in {"51", "52", "53", "54", "55"} or (len(d) >= 4 and 2221 <= int(d[:4]) <= 2720):
        return "Mastercard"
    if d[:2] in {"34", "37"}:
        return "Amex"
    if d.startswith(("6011", "65")) or d[:3] in {"644", "645", "646", "647", "648", "649"}:
        return "Discover"
    if d[:2] == "35":
        return "JCB"
    if d.startswith(("62", "81")):
        return "UnionPay"
    return "Card"


def _aad(entry_uuid: str, field_name: str) -> bytes:
    return f"securevault/entry/v1|{entry_uuid}|{field_name}".encode("utf-8")


def _clean(values: dict[str, str]) -> dict[str, str]:
    out = {}
    for name in FIELDS:
        if name not in values:
            continue
        value = values[name] if values[name] is not None else ""
        if not isinstance(value, str):
            raise ValidationError(f"{name} must be text")
        if name in ("title", "url", "username"):
            value = value.strip()
        if len(value) > LIMITS[name]:
            raise ValidationError(f"{name.capitalize()} is too long (max {LIMITS[name]} characters)")
        if name == "url" and any(ch.isspace() for ch in value):
            raise ValidationError("Website URL cannot contain spaces")
        out[name] = value
    return out


def _clean_extra(item_type: str, extra: dict | None) -> dict:
    allowed = {k: label for k, label, _ in EXTRA_FIELDS[item_type]}
    out: dict[str, str] = {}
    for key, value in (extra or {}).items():
        if key not in allowed:
            raise ValidationError(f"Unknown field for {TYPE_LABELS[item_type].lower()}: {key}")
        value = "" if value is None else str(value).strip()
        if len(value) > EXTRA_LIMIT:
            raise ValidationError(f"{allowed[key]} is too long")
        if value:
            out[key] = value
    if item_type == "card":
        number = out.get("number", "")
        if number:
            if not re.fullmatch(r"[\d \-]+", number):
                raise ValidationError("Card number may contain only digits and spaces")
            if not 12 <= len(digits_only(number)) <= 19:
                raise ValidationError("Card number must have 12–19 digits")
        expiry = out.get("expiry", "")
        if expiry:
            m = re.fullmatch(r"(\d{1,2})\s*/\s*(\d{2}|\d{4})", expiry)
            if not m or not 1 <= int(m.group(1)) <= 12:
                raise ValidationError("Expiry must look like MM/YY")
            out["expiry"] = f"{int(m.group(1)):02d}/{m.group(2)[-2:]}"
        for key, length in (("cvv", (3, 4)), ("pin", (4, 12))):
            val = out.get(key, "")
            if val and (not val.isdigit() or not length[0] <= len(val) <= length[1]):
                label = "Security code" if key == "cvv" else "PIN"
                raise ValidationError(f"{label} must be {length[0]}–{length[1]} digits")
    if item_type == "identity" and out.get("email") and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", out["email"]):
        raise ValidationError("Email address looks invalid")
    return out


def parse_view(view: str) -> tuple[str, str | int | None]:
    if view.startswith("type:"):
        return "type", view[5:]
    if view.startswith("folder:"):
        try:
            return "folder", int(view[7:])
        except ValueError:
            return "all", None
    if view in (VIEW_FAVORITES, VIEW_TRASH):
        return view, None
    return "all", None


class Vault:
    def __init__(self, db: Database):
        self.db = db
        self._key: bytearray | None = None
        self.corrupted_ids: set[int] = set()

    # ------------------------------------------------------------------ key handling
    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    def attach_key(self, key: bytearray) -> None:
        if not isinstance(key, bytearray) or len(key) != 32:
            raise ValueError("Vault key must be a 32-byte bytearray")
        self.lock()
        self._key = key

    @property
    def key(self) -> bytearray:
        if self._key is None:
            raise VaultLockedError("Vault is locked")
        return self._key

    def lock(self) -> None:
        if self._key is not None:
            wipe(self._key)
        self._key = None
        self.corrupted_ids.clear()

    # ------------------------------------------------------------------ helpers
    def _encrypt(self, entry_uuid: str, field_name: str, value: str) -> bytes:
        return encrypt_str(self.key, value, _aad(entry_uuid, field_name))

    def _encrypt_extra(self, entry_uuid: str, extra: dict) -> bytes | None:
        if not extra:
            return None
        return self._encrypt(entry_uuid, "extra", json.dumps(extra, sort_keys=True, ensure_ascii=False))

    def _row_to_entry(self, row, categories: dict[int, str], folders: dict[int, str]) -> Entry:
        values = {f: decrypt_str(self.key, row[f"{f}_enc"], _aad(row["uuid"], f)) for f in FIELDS}
        extra: dict = {}
        if row["extra_enc"] is not None:
            extra = json.loads(decrypt_str(self.key, row["extra_enc"], _aad(row["uuid"], "extra")))
        item_type = row["item_type"] if row["item_type"] in ITEM_TYPES else "login"
        return Entry(
            id=row["id"],
            uuid=row["uuid"],
            category_id=row["category_id"],
            category_name=categories.get(row["category_id"], "Other"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            password_changed_at=row["password_changed_at"],
            last_used_at=row["last_used_at"],
            use_count=row["use_count"],
            favorite=bool(row["favorite"]),
            item_type=item_type,
            folder_id=row["folder_id"],
            folder_name=folders.get(row["folder_id"], "") if row["folder_id"] else "",
            deleted_at=row["deleted_at"],
            extra=extra,
            **values,
        )

    def _lookups(self) -> tuple[dict[int, str], dict[int, str]]:
        return ({c.id: c.name for c in self.db.list_categories()}, {f.id: f.name for f in self.db.list_folders()})

    def _resolve_category(self, category_id: int | None) -> int:
        if category_id is None:
            return self.db.fallback_category_id()
        if self.db.get_category(category_id) is None:
            raise ValidationError("Selected category does not exist")
        return category_id

    def _resolve_folder(self, folder_id: int | None) -> int | None:
        if folder_id is None:
            return None
        if self.db.get_folder(folder_id) is None:
            raise ValidationError("Selected folder does not exist")
        return folder_id

    # ------------------------------------------------------------------ CRUD
    def add_entry(
        self,
        title: str,
        username: str = "",
        password: str = "",
        url: str = "",
        notes: str = "",
        category_id: int | None = None,
        favorite: bool = False,
        item_type: str = "login",
        folder_id: int | None = None,
        extra: dict | None = None,
    ) -> Entry:
        if item_type not in ITEM_TYPES:
            raise ValidationError("Unknown item type")
        values = _clean({"title": title, "username": username, "password": password, "url": url, "notes": notes})
        extra_clean = _clean_extra(item_type, extra)
        if not values["title"]:
            raise ValidationError("Name is required")
        cat_id = self._resolve_category(category_id)
        fol_id = self._resolve_folder(folder_id)
        entry_uuid = str(uuid_mod.uuid4())
        now = utc_now()
        row = {f"{f}_enc": self._encrypt(entry_uuid, f, values[f]) for f in FIELDS}
        row.update(
            uuid=entry_uuid, category_id=cat_id, created_at=now, updated_at=now,
            password_changed_at=now, use_count=0, favorite=int(bool(favorite)),
            item_type=item_type, folder_id=fol_id, extra_enc=self._encrypt_extra(entry_uuid, extra_clean),
        )
        entry_id = self.db.insert_entry(row)
        log.info("Entry %d created (%s)", entry_id, item_type)
        return self.get_entry(entry_id)

    def get_entry(self, entry_id: int) -> Entry:
        row = self.db.get_entry_row(entry_id)
        if row is None:
            raise DatabaseError("Entry not found")
        return self._row_to_entry(row, *self._lookups())

    def update_entry(self, entry_id: int, **changes) -> Entry:
        current = self.get_entry(entry_id)
        unknown = set(changes) - set(FIELDS) - {"category_id", "favorite", "folder_id", "extra", "item_type"}
        if unknown:
            raise ValidationError(f"Unknown fields: {sorted(unknown)}")
        if changes.get("item_type", current.item_type) != current.item_type:
            raise ValidationError("The item type cannot be changed")
        text_changes = _clean({k: v for k, v in changes.items() if k in FIELDS})
        if "title" in text_changes and not text_changes["title"]:
            raise ValidationError("Name is required")

        update: dict = {}
        for name, value in text_changes.items():
            if getattr(current, name) != value:
                update[f"{name}_enc"] = self._encrypt(current.uuid, name, value)
        if "extra" in changes:
            extra_clean = _clean_extra(current.item_type, changes["extra"])
            if extra_clean != current.extra:
                update["extra_enc"] = self._encrypt_extra(current.uuid, extra_clean)
        if "category_id" in changes and changes["category_id"] != current.category_id:
            update["category_id"] = self._resolve_category(changes["category_id"])
        if "folder_id" in changes and changes["folder_id"] != current.folder_id:
            update["folder_id"] = self._resolve_folder(changes["folder_id"])
        if "favorite" in changes and bool(changes["favorite"]) != current.favorite:
            update["favorite"] = int(bool(changes["favorite"]))
        if not update:
            return current
        now = utc_now()
        update["updated_at"] = now
        if "password_enc" in update:
            update["password_changed_at"] = now
        self.db.update_entry(entry_id, update)
        log.info("Entry %d updated", entry_id)
        return self.get_entry(entry_id)

    def set_folder(self, entry_ids: Iterable[int], folder_id: int | None) -> int:
        fol_id = self._resolve_folder(folder_id)
        count = 0
        for entry_id in entry_ids:
            self.db.update_entry(entry_id, {"folder_id": fol_id})
            count += 1
        return count

    # ---- trash
    def trash_entries(self, entry_ids: Iterable[int]) -> int:
        now = utc_now()
        count = 0
        with self.db.transaction():
            for entry_id in entry_ids:
                self.db.update_entry(entry_id, {"deleted_at": now})
                count += 1
        log.info("%d entr(ies) moved to trash", count)
        return count

    def trash_entry(self, entry_id: int) -> None:
        self.trash_entries([entry_id])

    def restore_entries(self, entry_ids: Iterable[int]) -> int:
        count = 0
        with self.db.transaction():
            for entry_id in entry_ids:
                self.db.update_entry(entry_id, {"deleted_at": None})
                count += 1
        log.info("%d entr(ies) restored from trash", count)
        return count

    def delete_entry(self, entry_id: int) -> None:
        """Permanent deletion (secure_delete overwrites the row inside the file)."""
        self.db.delete_entry(entry_id)
        log.info("Entry %d permanently deleted", entry_id)

    def delete_entries(self, entry_ids: Iterable[int]) -> int:
        count = self.db.delete_entries(list(entry_ids))
        log.info("%d entr(ies) permanently deleted", count)
        return count

    def empty_trash(self) -> int:
        ids = [r["id"] for r in self.db.get_entry_rows() if r["deleted_at"] is not None]
        return self.delete_entries(ids)

    def purge_trash(self, days: int = TRASH_RETENTION_DAYS, now: datetime | None = None) -> int:
        """Permanently delete items that have been in the trash longer than `days`."""
        cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=days)).isoformat(timespec="seconds")
        return self.delete_entries(self.db.trashed_before(cutoff))

    def mark_used(self, entry_id: int) -> None:
        self.db.touch_entry_used(entry_id)

    def list_entries(self, include_trash: bool = False) -> list[Entry]:
        """Decrypt entries. Entries failing authentication are skipped and reported."""
        self.key  # raises if locked
        categories, folders = self._lookups()
        entries: list[Entry] = []
        corrupted: set[int] = set()
        for row in self.db.get_entry_rows():
            if row["deleted_at"] is not None and not include_trash:
                continue
            try:
                entries.append(self._row_to_entry(row, categories, folders))
            except (DecryptionError, UnicodeDecodeError, ValueError):
                corrupted.add(row["id"])
                log.error("Entry %d failed integrity verification", row["id"])
        self.corrupted_ids = corrupted
        return entries

    # ------------------------------------------------------------------ query
    @staticmethod
    def in_view(entry: Entry, view: str) -> bool:
        kind, arg = parse_view(view)
        if kind == "trash":
            return entry.in_trash
        if entry.in_trash:
            return False
        if kind == "type":
            return entry.item_type == arg
        if kind == "folder":
            return entry.folder_id == arg
        if kind == "favorites":
            return entry.favorite
        return True

    @staticmethod
    def filter_sort(
        entries: Iterable[Entry],
        query: str = "",
        category_id: int | None = None,
        sort: str = "name_asc",
        view: str = VIEW_ALL,
    ) -> list[Entry]:
        result = [
            e for e in entries
            if Vault.in_view(e, view)
            and (category_id is None or e.category_id == category_id)
            and (not query or e.matches(query))
        ]
        if sort == "name_desc":
            result.sort(key=lambda e: e.title.casefold(), reverse=True)
        elif sort == "updated":
            result.sort(key=lambda e: e.updated_at, reverse=True)
        elif sort == "created":
            result.sort(key=lambda e: e.created_at, reverse=True)
        elif sort == "used":
            result.sort(key=lambda e: (e.use_count, e.last_used_at or ""), reverse=True)
        elif sort == "last_used":
            result.sort(key=lambda e: (e.last_used_at or "", e.updated_at), reverse=True)
        else:
            result.sort(key=lambda e: e.title.casefold())
        return result

    def search(self, query: str = "", category_id: int | None = None, sort: str = "name_asc", view: str = VIEW_ALL) -> list[Entry]:
        return self.filter_sort(self.list_entries(include_trash=(view == VIEW_TRASH)), query, category_id, sort, view)

    def counts(self, entries: Iterable[Entry]) -> dict[str, int]:
        """Counts for the sidebar (entries must include trash)."""
        out = {"all": 0, "favorites": 0, "trash": 0, **{f"type:{t}": 0 for t in ITEM_TYPES}}
        for e in entries:
            if e.in_trash:
                out["trash"] += 1
                continue
            out["all"] += 1
            out[f"type:{e.item_type}"] += 1
            if e.favorite:
                out["favorites"] += 1
        return out


def active_logins(entries: Iterable[Entry]) -> list[Entry]:
    """Entries the password analyzer should look at."""
    return [e for e in entries if e.is_login and not e.in_trash and e.password]


__all__ = [
    "Entry", "Vault", "VaultLockedError", "ValidationError", "SORT_OPTIONS", "TYPE_LABELS", "TYPE_PLURALS",
    "EXTRA_FIELDS", "active_logins", "card_brand", "luhn_valid", "digits_only", "parse_view",
]
