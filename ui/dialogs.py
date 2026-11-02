"""Small modal dialogs: password prompt and master-password change."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QVBoxLayout

from core.authentication import (
    LockedOutError,
    WeakPasswordError,
    WrongPasswordError,
    validate_master_password,
)

from .widgets import PasswordField, StrengthMeter, busy, label, make_button

if TYPE_CHECKING:
    from app.application import AppContext


class _BaseDialog(QDialog):
    def __init__(self, ctx: "AppContext", title: str, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle(title)
        self.setModal(True)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(24, 22, 24, 20)
        self.root.setSpacing(12)
        self.root.addWidget(label(title, "SectionTitle"))
        self.error = label("", "ErrorLabel", wrap=True)
        self.error.hide()

    def show_error(self, text: str) -> None:
        self.error.setText(text)
        self.error.setVisible(bool(text))

    def add_buttons(self, ok_text: str) -> None:
        self.root.addWidget(self.error)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel = make_button(self.ctx, "Cancel")
        cancel.clicked.connect(self.reject)
        self.ok = make_button(self.ctx, ok_text, "primary")
        self.ok.setDefault(True)
        self.ok.clicked.connect(self.on_accept)
        row.addWidget(cancel)
        row.addWidget(self.ok)
        self.root.addLayout(row)

    def on_accept(self) -> None:  # pragma: no cover - overridden
        self.accept()


class PasswordPromptDialog(_BaseDialog):
    """Ask for a password (e.g. the master password of a backup file)."""

    def __init__(self, ctx: "AppContext", title: str, message: str, ok_text: str = "Continue", parent=None):
        super().__init__(ctx, title, parent)
        self.setMinimumWidth(440)
        self.root.addWidget(label(message, "Muted", wrap=True))
        self.field = PasswordField(ctx, "Master password")
        self.root.addWidget(self.field)
        self.add_buttons(ok_text)
        self.field.returnPressed.connect(self.on_accept)

    def on_accept(self) -> None:
        if not self.field.text():
            self.show_error("Please enter the password.")
            return
        self.accept()

    def take_password(self) -> str:
        value = self.field.text()
        self.field.secure_clear()
        return value


class ChangePasswordDialog(_BaseDialog):
    def __init__(self, ctx: "AppContext", parent=None):
        super().__init__(ctx, "Change master password", parent)
        self.setMinimumWidth(480)
        self.root.addWidget(label(
            "Your vault key is re-wrapped with the new password; stored entries are not re-encrypted. "
            "Existing backups keep opening with the password that was active when they were created.",
            "Muted", wrap=True))
        self.current = PasswordField(ctx, "Current master password")
        self.new = PasswordField(ctx, "New master password")
        self.confirm = PasswordField(ctx, "Confirm new master password")
        for w in (self.current, self.new, self.confirm):
            self.root.addWidget(w)
        self.meter = StrengthMeter(ctx)
        self.root.addWidget(self.meter)
        self.new.textChanged.connect(self.meter.update_password)
        self.add_buttons("Change password")

    def on_accept(self) -> None:
        cur, new, conf = self.current.text(), self.new.text(), self.confirm.text()
        if not cur:
            self.show_error("Enter your current master password.")
            return
        if new != conf:
            self.show_error("The new passwords do not match.")
            return
        issues = validate_master_password(new)
        if issues:
            self.show_error("\n".join(f"• {i}" for i in issues))
            return
        try:
            with busy():
                self.ctx.auth.change_password(cur, new)
        except WrongPasswordError:
            self.show_error("The current master password is incorrect.")
            self.current.selectAll()
            return
        except LockedOutError as exc:
            self.show_error(str(exc))
            return
        except WeakPasswordError as exc:
            self.show_error("\n".join(f"• {i}" for i in exc.issues))
            return
        for w in (self.current, self.new, self.confirm):
            w.secure_clear()
        self.accept()
