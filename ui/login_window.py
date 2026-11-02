"""First-run setup and unlock screen."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QFileDialog, QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from app.config import APP_DEVELOPER, APP_NAME, APP_VERSION
from core.authentication import (
    MIN_MASTER_LENGTH,
    AuthError,
    LockedOutError,
    WeakPasswordError,
    WrongPasswordError,
    validate_master_password,
)
from core.backup_manager import BackupError, BackupPasswordError

from . import icons
from .dialogs import PasswordPromptDialog
from .formatting import fmt_datetime
from .widgets import PasswordField, fit_to_screen, StrengthMeter, busy, confirm, error, info, label, make_button, set_error

if TYPE_CHECKING:
    from app.application import AppContext


class LoginWindow(QWidget):
    unlocked = Signal(object)  # bytearray vault key

    def __init__(self, ctx: "AppContext", message: str = "", parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.setObjectName("LoginRoot")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(480, 540)
        fit_to_screen(self, 1320, 820)
        self._countdown = QTimer(self)
        self._countdown.setInterval(500)
        self._countdown.timeout.connect(self._update_lockout)
        self._build(message)

    # ------------------------------------------------------------------ layout
    def _build(self, message: str) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.addStretch(1)
        row = QHBoxLayout()
        row.addStretch(1)
        self.card = QFrame()
        self.card.setObjectName("LoginCard")
        self.card.setFixedWidth(440)
        row.addWidget(self.card)
        row.addStretch(1)
        outer.addLayout(row)
        outer.addStretch(1)
        footer = label(f"{APP_NAME} {APP_VERSION}  ·  Developed by {APP_DEVELOPER}  ·  Offline · Argon2id + AES-256-GCM", "Muted")
        footer.setAlignment(Qt.AlignCenter)
        outer.addWidget(footer)

        lay = QVBoxLayout(self.card)
        lay.setContentsMargins(36, 34, 36, 30)
        lay.setSpacing(12)

        logo = QLabel()
        logo.setPixmap(icons.pixmap("shield-check", self.ctx.palette.accent, 52))
        logo.setAlignment(Qt.AlignCenter)
        lay.addWidget(logo)
        title = label(APP_NAME, "PageTitle")
        title.setAlignment(Qt.AlignCenter)
        lay.addWidget(title)

        self.setup_mode = not self.ctx.auth.is_initialized()
        subtitle = label(
            "Create a master password to protect your new vault" if self.setup_mode else "Enter your master password to unlock",
            "PageSubtitle", wrap=True)
        subtitle.setAlignment(Qt.AlignCenter)
        lay.addWidget(subtitle)

        if message:
            note = label(message, "SuccessLabel" if "restored" in message.lower() else "Muted", wrap=True)
            note.setAlignment(Qt.AlignCenter)
            lay.addWidget(note)
        lay.addSpacing(8)

        self.password = PasswordField(self.ctx, "Master password")
        self.password.setMinimumHeight(42)
        lay.addWidget(self.password)

        if self.setup_mode:
            self.confirm = PasswordField(self.ctx, "Confirm master password")
            self.confirm.setMinimumHeight(42)
            lay.addWidget(self.confirm)
            self.meter = StrengthMeter(self.ctx)
            lay.addWidget(self.meter)
            self.password.textChanged.connect(self.meter.update_password)
            req = label(
                f"At least {MIN_MASTER_LENGTH} characters, mixing letters, numbers and symbols — "
                "or a long passphrase. It cannot be recovered if forgotten.", "Muted", wrap=True)
            lay.addWidget(req)
            self.confirm.returnPressed.connect(self.submit)
        self.password.returnPressed.connect(self.submit if not self.setup_mode else self.confirm.setFocus)

        self.error = label("", "ErrorLabel", wrap=True)
        self.error.hide()
        lay.addWidget(self.error)

        self.submit_btn = make_button(
            self.ctx, "Create vault" if self.setup_mode else "Unlock", "primary",
            "shield" if self.setup_mode else "unlock")
        self.submit_btn.setMinimumHeight(42)
        self.submit_btn.clicked.connect(self.submit)
        lay.addWidget(self.submit_btn)

        if self.setup_mode:
            restore = make_button(self.ctx, "Restore from a backup…", "ghost", "upload")
            restore.clicked.connect(self.restore_from_backup)
            lay.addWidget(restore, alignment=Qt.AlignCenter)

        QShortcut(QKeySequence(Qt.Key_Escape), self, activated=self.password.secure_clear)
        QTimer.singleShot(0, self.password.setFocus)
        if not self.setup_mode:
            self._update_lockout()

    # ------------------------------------------------------------------ helpers
    def _show_error(self, text: str) -> None:
        self.error.setText(text)
        self.error.setVisible(bool(text))
        set_error(self.password, bool(text))

    def _update_lockout(self) -> None:
        remaining = self.ctx.auth.lockout_remaining() if not self.setup_mode else 0
        if remaining > 0:
            self.submit_btn.setEnabled(False)
            self.password.setEnabled(False)
            self._show_error(f"Too many failed attempts. Try again in {int(remaining) + 1} s.")
            if not self._countdown.isActive():
                self._countdown.start()
        else:
            if self._countdown.isActive():
                self._countdown.stop()
                self._show_error("")
                self.password.setFocus()
            self.submit_btn.setEnabled(True)
            self.password.setEnabled(True)

    def _clear_fields(self) -> None:
        self.password.secure_clear()
        if self.setup_mode:
            self.confirm.secure_clear()

    # ------------------------------------------------------------------ actions
    def submit(self) -> None:
        if self.setup_mode:
            self._do_setup()
        else:
            self._do_unlock()

    def _do_unlock(self) -> None:
        pw = self.password.text()
        if not pw:
            self._show_error("Enter your master password.")
            return
        try:
            with busy():
                key = self.ctx.auth.unlock(pw)
        except WrongPasswordError as exc:
            self.password.selectAll()
            msg = "Incorrect master password."
            if exc.lockout_seconds:
                msg += f" Locked for {int(exc.lockout_seconds)} seconds."
            self._show_error(msg)
            self._update_lockout()
            return
        except LockedOutError:
            self._update_lockout()
            return
        except AuthError as exc:
            self._show_error(str(exc))
            return
        self._clear_fields()
        self._show_error("")
        self.unlocked.emit(key)

    def _do_setup(self) -> None:
        pw, conf = self.password.text(), self.confirm.text()
        issues = validate_master_password(pw)
        if issues:
            self._show_error("\n".join(f"• {i}" for i in issues))
            return
        if pw != conf:
            self._show_error("The passwords do not match.")
            set_error(self.confirm, True)
            return
        set_error(self.confirm, False)
        if not confirm(
            self, "Create vault",
            "Your master password cannot be recovered or reset.\n\n"
            "If you forget it, the data in this vault is permanently inaccessible. "
            "Make sure you remember it (or store it safely offline).",
            "I understand — create vault",
        ):
            return
        try:
            with busy():
                key = self.ctx.auth.setup(pw)
        except WeakPasswordError as exc:
            self._show_error("\n".join(f"• {i}" for i in exc.issues))
            return
        self._clear_fields()
        self.unlocked.emit(key)

    def restore_from_backup(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Restore SecureVault backup", str(self.ctx.backups.backup_dir), "SecureVault backup (*.svbak)")
        if not path:
            return
        try:
            meta = self.ctx.backups.read_info(path)
        except BackupError as exc:
            error(self, "Invalid backup", str(exc))
            return
        dlg = PasswordPromptDialog(
            self.ctx, "Restore backup",
            f"Backup created {fmt_datetime(meta.created_at)} with {meta.entry_count} accounts.\n"
            "Enter the master password that was in use when this backup was created.",
            "Restore", self)
        if dlg.exec() != PasswordPromptDialog.Accepted:
            return
        password = dlg.take_password()
        try:
            with busy():
                self.ctx.backups.restore_backup(path, password, None)
        except BackupPasswordError as exc:
            error(self, "Restore failed", str(exc))
            return
        except (BackupError, OSError) as exc:
            error(self, "Restore failed", f"The backup could not be restored:\n{exc}")
            return
        info(self, "Backup restored", "Your vault was restored. Unlock it with the backup's master password.")
        self.ctx.controller.show_login("Vault restored from backup.")
