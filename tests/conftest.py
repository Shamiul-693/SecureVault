"""Shared fixtures. Tests use reduced Argon2 cost for speed; production uses DEFAULT_KDF."""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.database import Database  # noqa: E402
from core.encryption import KdfParams  # noqa: E402

FAST_KDF = KdfParams(time_cost=1, memory_cost_kib=8192, parallelism=1)
MASTER = "Correct-Horse-Battery-42!"


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "vault.db")
    database.open()
    yield database
    database.close()


@pytest.fixture
def auth(db):
    from core.authentication import Authenticator
    return Authenticator(db, kdf_params=FAST_KDF)


@pytest.fixture
def unlocked_vault(db, auth):
    from core.vault import Vault
    key = auth.setup(MASTER)
    vault = Vault(db)
    vault.attach_key(key)
    yield vault
    vault.lock()
