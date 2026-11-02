"""Item types, folders, trash, schema migration and recommendations."""
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from core.database import Database, DatabaseError
from core.recommendations import build, dump_dismissed, load_dismissed
from core.security_analyzer import analyze
from core.vault import ValidationError, Vault, active_logins, card_brand, luhn_valid
from tests.conftest import MASTER

V1_SCHEMA = """
CREATE TABLE vault_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE application_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    is_default INTEGER NOT NULL DEFAULT 0, sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE password_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT NOT NULL UNIQUE,
    category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE RESTRICT, title_enc BLOB NOT NULL,
    url_enc BLOB NOT NULL, username_enc BLOB NOT NULL, password_enc BLOB NOT NULL, notes_enc BLOB NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, password_changed_at TEXT NOT NULL, last_used_at TEXT,
    use_count INTEGER NOT NULL DEFAULT 0, favorite INTEGER NOT NULL DEFAULT 0);
"""


def test_v1_vault_upgrades_and_keeps_data(tmp_path):
    from core.authentication import Authenticator
    from core.encryption import encrypt_str
    from tests.conftest import FAST_KDF
    path = tmp_path / "old.db"
    # Build a genuine version-1 vault with one encrypted entry
    conn = sqlite3.connect(path)
    conn.executescript(V1_SCHEMA)
    conn.execute("INSERT INTO categories(name, is_default, sort_order, created_at) VALUES ('Other',1,0,'2025-01-01')")
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()
    db = Database(path)
    db.open()  # migrates to v2
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == 2
    auth = Authenticator(db, kdf_params=FAST_KDF)
    key = auth.setup(MASTER)
    aad = lambda f: f"securevault/entry/v1|u-1|{f}".encode()  # noqa: E731
    db.conn.execute(
        "INSERT INTO password_entries(uuid, category_id, title_enc, url_enc, username_enc, password_enc, notes_enc,"
        " created_at, updated_at, password_changed_at) VALUES ('u-1', 1, ?, ?, ?, ?, ?, '2025', '2025', '2025')",
        tuple(encrypt_str(key, v, aad(f)) for f, v in
              (("title", "Gmail"), ("url", ""), ("username", "me"), ("password", "pw"), ("notes", ""))))
    v = Vault(db)
    v.attach_key(key)
    [e] = v.list_entries()
    assert (e.title, e.item_type, e.folder_id, e.in_trash, e.extra) == ("Gmail", "login", None, False, {})
    db.close()


def test_card_roundtrip_validation_and_encryption(unlocked_vault, db):
    v = unlocked_vault
    card = v.add_entry("My Visa", item_type="card", notes="bank card",
                       extra={"cardholder": "Shamiul Islam", "number": "4242 4242 4242 4242",
                              "expiry": "7/29", "cvv": "123", "pin": "9876"})
    got = v.get_entry(card.id)
    assert got.extra["number"] == "4242 4242 4242 4242" and got.extra["expiry"] == "07/29"
    assert got.subtitle == "Visa  •••• 4242  exp 07/29"
    assert "123" not in got.subtitle and "4242 4242" not in got.subtitle
    for bad in ({"number": "12ab"}, {"number": "1234"}, {"expiry": "13/30"}, {"cvv": "12"}, {"pin": "x1"}):
        with pytest.raises(ValidationError):
            v.add_entry("Bad", item_type="card", extra=bad)
    with pytest.raises(ValidationError):
        v.add_entry("Bad", item_type="card", extra={"unknown": "x"})
    db.close()
    raw = open(db.path, "rb").read()
    for secret in (b"4242 4242", b"Shamiul", b"9876", b"bank card", b"My Visa"):
        assert secret not in raw


def test_note_and_identity(unlocked_vault):
    v = unlocked_vault
    note = v.add_entry("Wi-Fi router", item_type="note", notes="admin / hunter2\nport 8080")
    assert v.get_entry(note.id).subtitle == "admin / hunter2"
    ident = v.add_entry("Me", item_type="identity",
                        extra={"full_name": "Shamiul Islam", "email": "s@example.com", "phone": "017", "id_number": "X1"})
    assert v.get_entry(ident.id).subtitle == "Shamiul Islam · s@example.com"
    with pytest.raises(ValidationError):
        v.add_entry("Me2", item_type="identity", extra={"email": "not-an-email"})
    assert [e.title for e in v.search("shamiul")] == ["Me"]
    assert v.search("X1") == []  # sensitive extra fields are not searchable
    with pytest.raises(ValidationError):
        v.update_entry(note.id, item_type="card")


def test_extra_ciphertext_swap_detected(unlocked_vault, db):
    a = unlocked_vault.add_entry("A", item_type="card", extra={"number": "4242424242424242"})
    b = unlocked_vault.add_entry("B", item_type="card", extra={"number": "5555555555554444"})
    db.conn.execute("UPDATE password_entries SET extra_enc = ? WHERE id = ?", (db.get_entry_row(a.id)["extra_enc"], b.id))
    assert [e.id for e in unlocked_vault.list_entries()] == [a.id]
    assert unlocked_vault.corrupted_ids == {b.id}


def test_trash_restore_purge(unlocked_vault, db):
    v = unlocked_vault
    a = v.add_entry("A", "u", "p")
    b = v.add_entry("B", "u", "p")
    v.trash_entries([a.id])
    assert [e.title for e in v.list_entries()] == ["B"]
    assert [e.title for e in v.search(view="trash")] == ["A"]
    assert db.list_categories()[0].entry_count >= 0
    v.restore_entries([a.id])
    assert {e.title for e in v.list_entries()} == {"A", "B"}
    v.trash_entries([a.id, b.id])
    assert v.purge_trash(days=30) == 0
    assert v.purge_trash(days=30, now=datetime.now(timezone.utc) + timedelta(days=31)) == 2
    assert db.entry_count() == 0
    c = v.add_entry("C", "u", "p")
    v.trash_entry(c.id)
    assert v.empty_trash() == 1


def test_folders(unlocked_vault, db):
    v = unlocked_vault
    fid = db.add_folder("Family")
    with pytest.raises(DatabaseError):
        db.add_folder("family")
    with pytest.raises(DatabaseError):
        db.add_folder("  ")
    a = v.add_entry("A", "u", "p", folder_id=fid)
    b = v.add_entry("B", "u", "p")
    assert v.get_entry(a.id).folder_name == "Family"
    v.set_folder([b.id], fid)
    assert {e.title for e in v.search(view=f"folder:{fid}")} == {"A", "B"}
    assert db.list_folders()[0].entry_count == 2
    v.trash_entry(b.id)
    assert db.list_folders()[0].entry_count == 1
    db.rename_folder(fid, "Home")
    assert v.get_entry(a.id).folder_name == "Home"
    db.delete_folder(fid)
    assert v.get_entry(a.id).folder_id is None  # item kept
    with pytest.raises(ValidationError):
        v.add_entry("X", folder_id=9999)


def test_views_counts_and_sorting(unlocked_vault):
    v = unlocked_vault
    v.add_entry("Login", "u", "p", favorite=True)
    v.add_entry("Note", item_type="note", notes="n")
    v.add_entry("Card", item_type="card", extra={"number": "4242424242424242"})
    t = v.add_entry("Gone", "u", "p")
    v.trash_entry(t.id)
    allx = v.list_entries(include_trash=True)
    counts = v.counts(allx)
    assert counts == {"all": 3, "favorites": 1, "trash": 1, "type:login": 1, "type:note": 1, "type:card": 1, "type:identity": 0}
    assert [e.title for e in v.search(view="type:note")] == ["Note"]
    assert [e.title for e in v.search(view="favorites")] == ["Login"]
    first = v.search(sort="name_asc")[0]
    v.mark_used(v.search("Note")[0].id)
    assert v.search(sort="last_used")[0].title == "Note"
    assert first.title == "Card"


def test_analyzer_only_sees_active_logins(unlocked_vault):
    v = unlocked_vault
    v.add_entry("Weak", "u", "password")
    v.add_entry("Note", item_type="note", notes="password")
    t = v.add_entry("Trashed", "u", "password")
    v.trash_entry(t.id)
    report = analyze(active_logins(v.list_entries(include_trash=True)))
    assert [e.title for e in report.weak] == ["Weak"]
    assert report.reused_groups == []


def test_card_helpers():
    assert luhn_valid("4242 4242 4242 4242") and not luhn_valid("4242 4242 4242 4241")
    assert card_brand("5555555555554444") == "Mastercard" and card_brand("378282246310005") == "Amex"
    assert card_brand("") == "Card"


def test_recommendations():
    from core.security_analyzer import SecurityReport
    now = datetime(2026, 11, 2, tzinfo=timezone.utc)
    empty = build(SecurityReport(), 0, 5, 20, None, now=now)
    assert empty == []
    recs = build(SecurityReport(total=3, weak=[1, 2]), 3, 0, 0, None, now=now)
    keys = [r.key for r in recs]
    assert keys == ["weak:2", "backup:never", "autolock:off", "clipboard:off"]
    recent = build(SecurityReport(total=1), 1, 5, 20, (now - timedelta(days=3)).isoformat(), now=now)
    assert recent == []
    stale = build(SecurityReport(total=1), 1, 60, 20, (now - timedelta(days=45)).isoformat(), now=now)
    assert [r.action for r in stale] == ["backup", "settings"]
    assert load_dismissed(dump_dismissed({"a", "b"})) == {"a", "b"}
    assert load_dismissed("garbage") == set()


def test_backup_sets_last_backup(unlocked_vault, db, tmp_path):
    from core.backup_manager import BackupManager
    assert db.get_setting("last_backup_at") is None
    BackupManager(db, tmp_path / "b").create_backup(unlocked_vault.key)
    assert db.get_setting("last_backup_at")
