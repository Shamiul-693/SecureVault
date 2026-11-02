import sqlite3

import pytest

from core.database import DEFAULT_CATEGORIES, Database, DatabaseError, IntegrityCheckError
from core.vault import ValidationError, Vault, VaultLockedError


def test_schema_and_default_categories(db):
    names = [c.name for c in db.list_categories()]
    for name in DEFAULT_CATEGORIES:
        assert name in names
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == 2
    assert db.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_crud_roundtrip(unlocked_vault):
    v = unlocked_vault
    cat = v.db.category_id_by_name("Email")
    e = v.add_entry("Gmail", "me@gmail.com", "P@ss-Gm4il!", "https://mail.google.com", "recovery: phone", cat)
    got = v.get_entry(e.id)
    assert (got.title, got.username, got.password, got.url, got.notes) == (
        "Gmail", "me@gmail.com", "P@ss-Gm4il!", "https://mail.google.com", "recovery: phone")
    assert got.category_name == "Email"

    updated = v.update_entry(e.id, password="N3w-Passw0rd!", notes="")
    assert updated.password == "N3w-Passw0rd!"
    assert updated.password_changed_at >= got.password_changed_at
    same = v.update_entry(e.id, title="Gmail")
    assert same.updated_at == updated.updated_at  # no-op update

    v.delete_entry(e.id)
    with pytest.raises(DatabaseError):
        v.get_entry(e.id)


def test_no_plaintext_in_database_file(unlocked_vault, db):
    unlocked_vault.add_entry("MyBankName", "account-user-xyz", "SuperSecretValue#991", "https://bank.example", "pin hint")
    db.close()
    raw = open(db.path, "rb").read()
    for secret in (b"MyBankName", b"account-user-xyz", b"SuperSecretValue#991", b"bank.example", b"pin hint"):
        assert secret not in raw


def test_validation(unlocked_vault):
    with pytest.raises(ValidationError):
        unlocked_vault.add_entry("   ", "u", "p")
    with pytest.raises(ValidationError):
        unlocked_vault.add_entry("x", url="has space.com")
    with pytest.raises(ValidationError):
        unlocked_vault.add_entry("x", password="a" * 2000)
    with pytest.raises(ValidationError):
        unlocked_vault.add_entry("x", category_id=99999)


def test_locked_vault_refuses(db):
    v = Vault(db)
    with pytest.raises(VaultLockedError):
        v.add_entry("x")
    with pytest.raises(VaultLockedError):
        v.list_entries()


def test_ciphertext_swap_detected(unlocked_vault, db):
    a = unlocked_vault.add_entry("A", "ua", "pa")
    b = unlocked_vault.add_entry("B", "ub", "pb")
    row_a = db.get_entry_row(a.id)
    # move A's password ciphertext into B's row -> AAD mismatch
    db.conn.execute("UPDATE password_entries SET password_enc = ? WHERE id = ?", (row_a["password_enc"], b.id))
    entries = unlocked_vault.list_entries()
    assert [e.id for e in entries] == [a.id]
    assert unlocked_vault.corrupted_ids == {b.id}


def test_search_filter_sort(unlocked_vault):
    v = unlocked_vault
    dev = v.db.category_id_by_name("Development")
    v.add_entry("GitHub", "dev@x.com", "a", category_id=dev)
    v.add_entry("facebook", "fb@x.com", "b")
    v.add_entry("Azure DevOps", "dev@x.com", "c", category_id=dev)
    assert [e.title for e in v.search("dev@")] == ["Azure DevOps", "GitHub"]
    assert [e.title for e in v.search(category_id=dev, sort="name_desc")] == ["GitHub", "Azure DevOps"]
    assert [e.title for e in v.search("FACE")] == ["facebook"]
    gh = v.search("GitHub")[0]
    v.mark_used(gh.id)
    assert v.search(sort="used")[0].title == "GitHub"


def test_categories(unlocked_vault, db):
    cid = db.add_category("Gaming")
    with pytest.raises(DatabaseError):
        db.add_category("gaming")
    with pytest.raises(DatabaseError):
        db.add_category("   ")
    e = unlocked_vault.add_entry("Steam", "u", "p", category_id=cid)
    db.rename_category(cid, "Games")
    assert unlocked_vault.get_entry(e.id).category_name == "Games"
    with pytest.raises(DatabaseError):
        db.delete_category(db.category_id_by_name("Email"))
    moved = db.delete_category(cid)
    assert moved == 1
    assert unlocked_vault.get_entry(e.id).category_name == "Other"


def test_transaction_rollback(db):
    with pytest.raises(RuntimeError):
        with db.transaction() as c:
            c.execute("INSERT INTO application_settings(key, value) VALUES ('k', 'v')")
            raise RuntimeError("boom")
    assert db.get_setting("k") is None


def test_settings(db):
    assert db.get_setting("theme", "dark") == "dark"
    db.set_setting("theme", "light")
    assert db.get_setting("theme") == "light"


def test_corrupted_file_detected(tmp_path):
    path = tmp_path / "bad.db"
    path.write_bytes(b"this is definitely not a sqlite database" * 100)
    with pytest.raises(IntegrityCheckError):
        Database(path).open()


def test_parameterized_queries_resist_injection(unlocked_vault, db):
    evil = "x'); DROP TABLE password_entries; --"
    db.add_category(evil[:40])
    e = unlocked_vault.add_entry(evil, evil, evil)
    assert unlocked_vault.get_entry(e.id).title == evil
    assert db.entry_count() == 1
    with pytest.raises(DatabaseError):
        db.update_entry(e.id, {"id; DROP TABLE x": 1})
    assert isinstance(db.conn, sqlite3.Connection)
