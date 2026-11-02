"""Application-wide configuration: paths, defaults and logging.

Nothing in this module ever handles secrets. Logging is configured so that
only operational events are written; callers must never pass passwords,
keys or decrypted vault data to the logger.
"""
from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

APP_NAME = "SecureVault"
APP_VERSION = "1.0.0"
APP_DEVELOPER = "Shamiul Islam"
APP_ID = "SecureVault.PasswordManager.1"  # Windows AppUserModelID (taskbar grouping)
DB_FILENAME = "vault.db"
BACKUP_EXTENSION = ".svbak"
PORTABLE_FLAG = "portable.flag"

# ---- User-adjustable defaults (stored in application_settings) ----
DEFAULT_SETTINGS: dict[str, str] = {
    "theme": "dark",                 # "dark" | "light"
    "auto_lock_minutes": "5",        # 0 = never
    "clipboard_clear_seconds": "20", # 0 = never
    "old_password_days": "180",
}

AUTO_LOCK_CHOICES = [1, 2, 5, 10, 15, 30, 60, 0]
CLIPBOARD_CHOICES = [10, 20, 30, 60, 120, 0]


def is_frozen() -> bool:
    """True when running from a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False))


def app_base_dir() -> Path:
    """Directory containing the executable (frozen) or the project root (source)."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_dir() -> Path:
    """Bundled read-only resources (icons). Works from source and from PyInstaller."""
    meipass = getattr(sys, "_MEIPASS", None)
    base = Path(meipass) if meipass else Path(__file__).resolve().parent.parent
    return base / "resources"


def is_portable() -> bool:
    """Portable mode: a file named portable.flag next to the EXE keeps data beside it."""
    return (app_base_dir() / PORTABLE_FLAG).exists()


def data_dir() -> Path:
    """Per-user data directory. Created with restrictive permissions where supported."""
    override = os.environ.get("SECUREVAULT_DATA_DIR")
    if override:
        path = Path(override)
    elif is_portable():
        path = app_base_dir() / "SecureVaultData"
    elif sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        path = Path(local) / APP_NAME
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        path = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return path


def db_path() -> Path:
    return data_dir() / DB_FILENAME


def backup_dir() -> Path:
    path = data_dir() / "backups"
    path.mkdir(parents=True, exist_ok=True)
    return path


def log_dir() -> Path:
    path = data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure a rotating log file. Secrets are never logged by design."""
    logger = logging.getLogger("securevault")
    if logger.handlers:
        return logger
    logger.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    try:
        file_handler = RotatingFileHandler(
            log_dir() / "securevault.log", maxBytes=512_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except OSError:
        pass
    if not is_frozen() and sys.stderr is not None:
        console = logging.StreamHandler()
        console.setFormatter(fmt)
        logger.addHandler(console)
    logger.propagate = False
    return logger
