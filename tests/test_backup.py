import pytest

from core.authentication import Authenticator
from core.backup_manager import MAGIC, BackupError, BackupManager, BackupPasswordError
from core.database import Database
from core.vault import Vault
from tests.conftest import FAST_KDF, MASTER


@pytest.fixture
def manager(db, tmp_path):
    return BackupManager(db, tmp_path / "backups")


def test_backup_roundtrip_and_restore(unlocked_vault, manager, db, auth):
    unlocked_vault.add_entry("Gmail", "me", "pw-1")
    path = manager.create_backup(unlocked_vault.key)
    assert path.exists() and path.read_bytes().startswith(MAGIC)
    assert b"pw-1" not in path.read_bytes() and b"Gmail" not in path.read_bytes()

    info = manager.verify_backup(path, MASTER)
    assert info.entry_count == 1

    unlocked_vault.add_entry("Later", "x", "y")
    assert db.entry_count() == 2
    safety = manager.restore_backup(path, MASTER, unlocked_vault.key)
    assert safety is not None and safety.exists()  # automatic pre-restore backup
    assert db.entry_count() == 1
    key = auth.unlock(MASTER)
    vault = Vault(db)
    vault.attach_key(key)
    assert [e.title for e in vault.list_entries()] == ["Gmail"]
    # the safety copy still contains the newer state
    assert manager.verify_backup(safety, MASTER).entry_count == 2


def test_wrong_password_rejected(unlocked_vault, manager):
    path = manager.create_backup(unlocked_vault.key)
    with pytest.raises(BackupPasswordError):
        manager.verify_backup(path, "Wrong-Password-123!")


def test_tampering_detected(unlocked_vault, manager):
    unlocked_vault.add_entry("A", "b", "c")
    path = manager.create_backup(unlocked_vault.key)
    data = bytearray(path.read_bytes())
    data[-10] ^= 0x01  # payload
    path.write_bytes(bytes(data))
    with pytest.raises(BackupError):
        manager.verify_backup(path, MASTER)

    path2 = manager.create_backup(unlocked_vault.key)
    data = path2.read_bytes().replace(b'"entry_count": 1', b'"entry_count": 7')
    path2.write_bytes(data)  # header is authenticated as AAD
    with pytest.raises(BackupError):
        manager.verify_backup(path2, MASTER)


def test_invalid_files(manager, tmp_path):
    bad = tmp_path / "x.svbak"
    bad.write_bytes(b"hello world")
    with pytest.raises(BackupError):
        manager.read_info(bad)
    with pytest.raises(BackupError):
        manager.read_info(tmp_path / "missing.svbak")


def test_failed_restore_keeps_current_vault(unlocked_vault, manager, db):
    unlocked_vault.add_entry("Keep", "me", "x")
    path = manager.create_backup(unlocked_vault.key)
    with pytest.raises(BackupPasswordError):
        manager.restore_backup(path, "Wrong-Password-123!", unlocked_vault.key)
    assert db.entry_count() == 1 and db.is_open


def test_restore_after_master_password_change(unlocked_vault, manager, auth, db):
    unlocked_vault.add_entry("Old", "u", "p")
    path = manager.create_backup(unlocked_vault.key)
    auth.change_password(MASTER, "Brand-New-Master-Pass-99!")
    # Backup still opens with the password active when it was made
    assert manager.verify_backup(path, MASTER).entry_count == 1


def test_restore_onto_fresh_install(unlocked_vault, manager, tmp_path):
    unlocked_vault.add_entry("Moved", "u", "p")
    path = manager.create_backup(unlocked_vault.key)
    fresh_db = Database(tmp_path / "fresh" / "vault.db")
    fresh_db.open()
    fresh = BackupManager(fresh_db, tmp_path / "fresh" / "backups")
    assert fresh.restore_backup(path, MASTER) is None  # nothing to preserve
    key = Authenticator(fresh_db, kdf_params=FAST_KDF).unlock(MASTER)
    v = Vault(fresh_db)
    v.attach_key(key)
    assert v.list_entries()[0].title == "Moved"
    fresh_db.close()


def test_locked_restore_makes_raw_safety_copy(unlocked_vault, manager):
    path = manager.create_backup(unlocked_vault.key)
    safety = manager.restore_backup(path, MASTER, None)
    assert safety.name.endswith(".db.bak")


def test_list_backups(unlocked_vault, manager):
    manager.create_backup(unlocked_vault.key)
    assert len(manager.list_backups()) == 1
