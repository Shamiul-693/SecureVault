import pytest

from core.encryption import (
    DEFAULT_KDF,
    NONCE_SIZE,
    CryptoError,
    DecryptionError,
    KdfParams,
    decrypt,
    decrypt_str,
    derive_key,
    encrypt,
    encrypt_str,
    generate_key,
    generate_salt,
    unwrap_key,
    wipe,
    wrap_key,
)
from tests.conftest import FAST_KDF


def test_roundtrip():
    key = generate_key()
    blob = encrypt_str(key, "s3cret ✓ পাসওয়ার্ড", b"aad")
    assert decrypt_str(key, blob, b"aad") == "s3cret ✓ পাসওয়ার্ড"


def test_nonce_unique_and_ciphertext_differs():
    key = generate_key()
    blobs = {encrypt(key, b"same plaintext") for _ in range(200)}
    assert len(blobs) == 200
    nonces = {b[1 : 1 + NONCE_SIZE] for b in blobs}
    assert len(nonces) == 200


def test_wrong_key_fails():
    blob = encrypt(generate_key(), b"data")
    with pytest.raises(DecryptionError):
        decrypt(generate_key(), blob)


def test_tampering_detected():
    key = generate_key()
    blob = bytearray(encrypt(key, b"important data"))
    blob[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt(key, bytes(blob))
    blob = bytearray(encrypt(key, b"important data"))
    blob[5] ^= 0x01  # nonce
    with pytest.raises(DecryptionError):
        decrypt(key, bytes(blob))


def test_aad_mismatch_fails():
    key = generate_key()
    blob = encrypt(key, b"x", b"entry-1|password")
    with pytest.raises(DecryptionError):
        decrypt(key, blob, b"entry-2|password")


def test_malformed_blob():
    key = generate_key()
    for bad in (b"", b"\x01short", b"\x02" + b"\x00" * 40):
        with pytest.raises(DecryptionError):
            decrypt(key, bad)


def test_key_size_enforced():
    with pytest.raises(CryptoError):
        encrypt(b"short", b"x")


def test_derive_key_deterministic_and_salted():
    salt = generate_salt()
    k1 = derive_key("master password", salt, FAST_KDF)
    k2 = derive_key("master password", salt, FAST_KDF)
    k3 = derive_key("master password", generate_salt(), FAST_KDF)
    k4 = derive_key("master passworD", salt, FAST_KDF)
    assert k1 == k2 and len(k1) == 32
    assert k1 != k3 and k1 != k4


def test_wrap_unwrap():
    kek, key = generate_key(), generate_key()
    wrapped = wrap_key(kek, key, b"ctx")
    assert unwrap_key(kek, wrapped, b"ctx") == key
    with pytest.raises(DecryptionError):
        unwrap_key(generate_key(), wrapped, b"ctx")


def test_wipe_zeroes_buffer():
    key = generate_key()
    wipe(key)
    assert key == bytearray(32)


def test_kdf_param_bounds():
    DEFAULT_KDF.validate()
    assert DEFAULT_KDF.memory_cost_kib >= 19456 and DEFAULT_KDF.time_cost >= 2
    with pytest.raises(CryptoError):
        KdfParams(memory_cost_kib=10_000_000).validate()
    with pytest.raises(CryptoError):
        KdfParams.from_dict({"algorithm": "pbkdf2", "time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1})
    assert KdfParams.from_dict(FAST_KDF.to_dict()) == FAST_KDF
