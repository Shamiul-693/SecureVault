import pytest

from core.authentication import (
    Authenticator,
    LockedOutError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
    WeakPasswordError,
    WrongPasswordError,
    validate_master_password,
)
from core.encryption import wipe
from tests.conftest import FAST_KDF, MASTER


def test_validation_rules():
    assert validate_master_password(MASTER) == []
    assert validate_master_password("short1!A")
    assert validate_master_password("alllowercaseletters")
    assert validate_master_password("Password123!")  # common base + short
    assert validate_master_password("aaaaaaaaaaaaaaaaaaaaaaaa")
    assert validate_master_password(" " + MASTER)


def test_setup_and_unlock(auth, db):
    assert not auth.is_initialized()
    with pytest.raises(VaultNotInitializedError):
        auth.unlock(MASTER)
    key = auth.setup(MASTER)
    assert auth.is_initialized() and len(key) == 32
    key2 = auth.unlock(MASTER)
    assert key2 == key
    with pytest.raises(VaultAlreadyInitializedError):
        auth.setup(MASTER)


def test_master_password_never_stored(auth, db):
    auth.setup(MASTER)
    raw = db.serialize()
    assert MASTER.encode() not in raw
    assert MASTER.encode("utf-16-le") not in raw


def test_weak_password_rejected(auth):
    with pytest.raises(WeakPasswordError):
        auth.setup("password")
    assert not auth.is_initialized()


def test_wrong_password(auth):
    auth.setup(MASTER)
    with pytest.raises(WrongPasswordError) as info:
        auth.unlock("Wrong-Horse-Battery-42!")
    assert info.value.attempts == 1
    assert auth.verify(MASTER)
    assert not auth.verify("nope")


def test_lockout_after_repeated_failures(db):
    now = [1000.0]
    auth = Authenticator(db, kdf_params=FAST_KDF, clock=lambda: now[0])
    auth.setup(MASTER)
    for _ in range(3):
        with pytest.raises(WrongPasswordError):
            auth.unlock("bad password value")
    # Locked even for the correct password
    with pytest.raises(LockedOutError) as info:
        auth.unlock(MASTER)
    assert 0 < info.value.retry_after <= 5
    now[0] += 6
    key = auth.unlock(MASTER)  # succeeds and resets the counter
    assert auth.lockout_remaining() == 0
    wipe(key)


def test_lockout_persists_across_instances(db):
    now = [5000.0]
    a1 = Authenticator(db, kdf_params=FAST_KDF, clock=lambda: now[0])
    a1.setup(MASTER)
    for _ in range(4):
        with pytest.raises((WrongPasswordError, LockedOutError)):
            a1.unlock("bad password value")
            now[0] += 6
    a2 = Authenticator(db, kdf_params=FAST_KDF, clock=lambda: now[0])
    assert a2.lockout_remaining() > 0


def test_change_password_keeps_vault_key(auth, unlocked_vault):
    original_key = bytes(unlocked_vault.key)
    entry = unlocked_vault.add_entry("GitHub", "me", "gh-pass")
    new = "Another-Strong-Passphrase-77#"
    auth.change_password(MASTER, new)
    with pytest.raises(WrongPasswordError):
        auth.unlock(MASTER)
    key = auth.unlock(new)
    assert bytes(key) == original_key
    assert unlocked_vault.get_entry(entry.id).password == "gh-pass"


def test_change_password_requires_current(auth):
    auth.setup(MASTER)
    with pytest.raises(WrongPasswordError):
        auth.change_password("wrong current pass", "Another-Strong-Passphrase-77#")
    with pytest.raises(WeakPasswordError):
        auth.change_password(MASTER, "weak")
    with pytest.raises(WeakPasswordError):
        auth.change_password(MASTER, MASTER)


def test_tampered_metadata_detected(auth, db):
    auth.setup(MASTER)
    import base64
    wrapped = bytearray(base64.b64decode(db.get_meta("wrapped_key")))
    wrapped[-3] ^= 0xFF
    db.set_meta("wrapped_key", base64.b64encode(bytes(wrapped)).decode())
    with pytest.raises(WrongPasswordError):
        auth.unlock(MASTER)
