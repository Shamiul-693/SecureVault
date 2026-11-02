"""Application controller: wires core services to the UI and owns the lock state.

Lifecycle
    start ─► LoginWindow ─(vault key)─► MainWindow
               ▲                             │
               └──── lock (manual / idle) ◄──┘
On lock the vault key is wiped, the clipboard is cleared if it still holds a
copied secret, open dialogs are dismissed and the main window (with every
decrypted value it displayed) is destroyed.
"""
from __future__ import annotations

import logging
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QEvent, QLockFile, QObject, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont, QIcon
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from core.authentication import Authenticator
from core.backup_manager import BackupManager
from core.database import Database, IntegrityCheckError
from core.encryption import DEFAULT_KDF, KdfParams
from core.vault import Vault

from . import config
from .clipboard import ClipboardManager

log = logging.getLogger("securevault.app")

_ACTIVITY_EVENTS = {
    QEvent.KeyPress, QEvent.MouseButtonPress, QEvent.MouseMove, QEvent.Wheel, QEvent.TouchBegin,
}


class ActivityFilter(QObject):
    """Application-wide event filter that records the time of the last user input."""

    def __init__(self, controller: "AppController"):
        super().__init__()
        self.controller = controller

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 (Qt API)
        if event.type() in _ACTIVITY_EVENTS:
            self.controller.last_activity = time.monotonic()
        return False


class AppContext(QObject):
    """Facade handed to every UI component."""

    toast = Signal(str)

    def __init__(self, controller: "AppController"):
        super().__init__()
        self.controller = controller
        self.db: Database = controller.db
        self.auth: Authenticator = controller.auth
        self.vault: Vault = controller.vault
        self.backups: BackupManager = controller.backups
        self.clipboard: ClipboardManager = controller.clipboard

    # ---- appearance
    @property
    def theme(self) -> str:
        value = self.db.get_setting("theme", config.DEFAULT_SETTINGS["theme"])
        return value if value in ("dark", "light") else "dark"

    @property
    def palette(self):
        from ui.theme import get_palette
        return get_palette(self.theme)

    def set_theme(self, name: str) -> None:
        self.controller.apply_theme(name, rebuild=True)

    # ---- settings
    def setting_int(self, key: str) -> int:
        try:
            return int(self.db.get_setting(key, config.DEFAULT_SETTINGS[key]))
        except (TypeError, ValueError):
            return int(config.DEFAULT_SETTINGS[key])

    def set_setting(self, key: str, value) -> None:
        self.db.set_setting(key, str(value))

    @property
    def unlocked(self) -> bool:
        return self.vault.is_unlocked

    # ---- actions
    def lock(self, message: str = "") -> None:
        self.controller.lock(message)

    def notify(self, text: str) -> None:
        self.toast.emit(text)

    def navigate(self, page: str) -> None:
        if self.controller.main_window:
            self.controller.main_window.navigate(page)

    def navigate_view(self, view: str, select_id: int | None = None) -> None:
        if self.controller.main_window:
            self.controller.main_window.navigate(f"view:{view}", select_id=select_id)

    def data_changed(self) -> None:
        """Items, folders or counts changed — refresh the sidebar."""
        if self.controller.main_window:
            self.controller.main_window.refresh_sidebar()

    def create_backup(self) -> bool:
        """One-click encrypted backup into the default backups folder."""
        from core.backup_manager import BackupError
        try:
            path = self.backups.create_backup(self.vault.key)
        except (BackupError, OSError) as exc:
            QMessageBox.critical(None, config.APP_NAME, f"The backup could not be created:\n{exc}")
            return False
        self.notify(f"Encrypted backup saved: {path.name}")
        return True

    def open_entry(self, entry_id: int, edit: bool = False) -> None:
        if self.controller.main_window:
            self.controller.main_window.open_entry(entry_id, edit)

    def copy_secret(self, text: str, what: str, entry_id: int | None, sensitive: bool = True) -> None:
        self.clipboard.copy(text, what, sensitive)
        if entry_id is not None:
            try:
                self.vault.mark_used(entry_id)
            except Exception:  # usage stats are non-critical
                log.exception("Could not update usage counter")
        secs = self.clipboard.timeout_seconds
        if sensitive and secs > 0:
            self.notify(f"{what} copied · clipboard clears in {secs}s")
        else:
            self.notify(f"{what} copied")

    def open_url(self, url: str) -> None:
        """Open only http(s) links — never file:// or custom protocol handlers."""
        qurl = QUrl.fromUserInput(url)
        if qurl.scheme().lower() in ("http", "https"):
            QDesktopServices.openUrl(qurl)
        else:
            self.notify("Only http/https links can be opened")


class AppController(QObject):
    def __init__(self, qapp: QApplication, db_file: Path | None = None, kdf_params: KdfParams = DEFAULT_KDF):
        super().__init__()
        self.qapp = qapp
        self.db = Database(db_file or config.db_path())
        self.auth = Authenticator(self.db, kdf_params=kdf_params)
        self.vault = Vault(self.db)
        self.backups = BackupManager(self.db, Path(self.db.path).parent / "backups", config.APP_VERSION)
        self.clipboard = ClipboardManager(self)
        self.ctx = AppContext(self)
        self.login_window = None
        self.main_window = None
        self.last_activity = time.monotonic()

        self._activity = ActivityFilter(self)
        qapp.installEventFilter(self._activity)
        self._idle_timer = QTimer(self)
        self._idle_timer.setInterval(1000)
        self._idle_timer.timeout.connect(self._check_idle)
        qapp.aboutToQuit.connect(self.shutdown)

    # ------------------------------------------------------------------ startup
    def open_database(self) -> bool:
        try:
            self.db.open()
            return True
        except IntegrityCheckError as exc:
            log.error("Database failed integrity check: %s", exc)
            return self._handle_corrupt_database(str(exc))

    def _handle_corrupt_database(self, reason: str) -> bool:
        box = QMessageBox()
        box.setIcon(QMessageBox.Critical)
        box.setWindowTitle(config.APP_NAME)
        box.setText("Your vault database appears to be damaged.")
        box.setInformativeText(
            f"{reason}\n\nSecureVault can move the damaged file aside (it is kept, not deleted) and start "
            "fresh — you can then restore from a backup on the next screen.")
        move = box.addButton("Move aside and continue", QMessageBox.AcceptRole)
        box.addButton("Quit", QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is not move:
            return False
        path = Path(self.db.path)
        aside = path.with_name(f"{path.name}.corrupt-{datetime.now():%Y%m%d-%H%M%S}")
        path.replace(aside)
        log.warning("Damaged database moved to %s", aside.name)
        self.db.open()
        return True

    def start(self) -> bool:
        if not self.open_database():
            return False
        self.apply_theme(self.ctx.theme, rebuild=False)
        self.clipboard.timeout_seconds = self.ctx.setting_int("clipboard_clear_seconds")
        self.show_login()
        return True

    def apply_theme(self, name: str, rebuild: bool) -> None:
        from ui.theme import build_stylesheet, get_palette
        if name not in ("dark", "light"):
            name = "dark"
        self.db.set_setting("theme", name)
        self.qapp.setStyleSheet(build_stylesheet(get_palette(name)))
        if rebuild and self.main_window is not None:
            page = self.main_window.current_page()
            old = self.main_window
            self.main_window = self._make_main_window(old)
            self.main_window.navigate(page)
            old.hide()
            old.deleteLater()

    # ------------------------------------------------------------------ windows
    def _make_main_window(self, previous=None):
        from ui.main_window import MainWindow
        window = MainWindow(self.ctx)
        if previous is not None:
            window.setGeometry(previous.geometry())
            if previous.isMaximized():
                window.showMaximized()
            else:
                window.show()
        else:
            window.show()
        return window

    def show_login(self, message: str = "") -> None:
        from ui.login_window import LoginWindow
        old = self.login_window
        self.login_window = LoginWindow(self.ctx, message)
        self.login_window.unlocked.connect(self.on_unlocked)
        if old is not None:
            self.login_window.setGeometry(old.geometry())
        elif self.main_window is not None:
            self.login_window.setGeometry(self.main_window.geometry())
        self.login_window.show()
        self.login_window.raise_()
        self.login_window.activateWindow()
        if old is not None:
            old.hide()
            old.deleteLater()

    def on_unlocked(self, key: bytearray) -> None:
        self.vault.attach_key(key)
        try:
            purged = self.vault.purge_trash()
            if purged:
                log.info("Purged %d item(s) older than 30 days from the trash", purged)
        except Exception:
            log.exception("Trash purge failed")
        self.clipboard.timeout_seconds = self.ctx.setting_int("clipboard_clear_seconds")
        login = self.login_window
        self.main_window = self._make_main_window(login if login is not None and login.isVisible() else None)
        if login is not None:
            login.hide()
            login.deleteLater()
            self.login_window = None
        self.last_activity = time.monotonic()
        self._idle_timer.start()

    def lock(self, message: str = "") -> None:
        if not self.vault.is_unlocked and self.main_window is None:
            return
        log.info("Vault locked")
        self._idle_timer.stop()
        # Dismiss any open modal dialogs / message boxes first
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QDialog) and widget.isVisible():
                widget.reject()
        self.vault.lock()
        self.clipboard.clear_if_ours()
        self.show_login(message or "Vault locked.")
        if self.main_window is not None:
            self.main_window.hide()
            self.main_window.deleteLater()
            self.main_window = None

    def _check_idle(self) -> None:
        minutes = self.ctx.setting_int("auto_lock_minutes")
        if self.vault.is_unlocked and minutes > 0 and time.monotonic() - self.last_activity > minutes * 60:
            self.lock(f"Locked automatically after {minutes} minute{'s' if minutes != 1 else ''} of inactivity.")

    def shutdown(self) -> None:
        self.clipboard.clear_if_ours()
        self.vault.lock()
        self.db.close()
        log.info("Application closed")


# --------------------------------------------------------------------------- entry point
def _install_excepthook(logger: logging.Logger) -> None:
    def hook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        # Tracebacks contain code locations and exception messages, never local variable values.
        logger.error("Unhandled exception:\n%s", "".join(traceback.format_exception(exc_type, exc, tb)))
        if QApplication.instance() is not None:
            try:
                QMessageBox.critical(
                    None, config.APP_NAME,
                    "An unexpected error occurred. SecureVault will keep running.\n\n"
                    f"{exc_type.__name__}: {exc}\n\nDetails were written to:\n{config.log_dir() / 'securevault.log'}")
            except Exception:
                pass
    sys.excepthook = hook


def _set_windows_app_id() -> None:
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(config.APP_ID)
        except Exception:
            pass


def run(argv: list[str]) -> int:
    logger = config.setup_logging()
    _install_excepthook(logger)
    _set_windows_app_id()
    logger.info("Starting %s %s", config.APP_NAME, config.APP_VERSION)

    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    qapp = QApplication(argv)
    qapp.setApplicationName(config.APP_NAME)
    qapp.setApplicationVersion(config.APP_VERSION)
    qapp.setOrganizationName(config.APP_NAME)
    icon_file = config.resource_dir() / "icons" / ("securevault.ico" if sys.platform == "win32" else "securevault.png")
    if icon_file.exists():
        qapp.setWindowIcon(QIcon(str(icon_file)))
    font = QFont("Segoe UI" if sys.platform == "win32" else qapp.font().family(), 10)
    qapp.setFont(font)

    lock_file = QLockFile(str(config.data_dir() / "securevault.lock"))
    lock_file.setStaleLockTime(0)
    if not lock_file.tryLock(100):
        QMessageBox.information(None, config.APP_NAME, "SecureVault is already running.")
        return 0

    try:
        controller = AppController(qapp)
        if not controller.start():
            return 1
    except Exception as exc:  # fatal startup error
        logger.exception("Fatal startup error")
        QMessageBox.critical(None, config.APP_NAME, f"SecureVault could not start:\n\n{exc}")
        return 1
    code = qapp.exec()
    lock_file.unlock()
    return code
