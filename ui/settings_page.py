"""Settings: security options, appearance, backup & restore, storage info."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.config import APP_DEVELOPER, APP_NAME, APP_VERSION, AUTO_LOCK_CHOICES, BACKUP_EXTENSION, CLIPBOARD_CHOICES, is_portable
from core.backup_manager import BackupError, BackupPasswordError
from core.database import IntegrityCheckError
from core.encryption import DEFAULT_KDF

from . import icons
from .dialogs import ChangePasswordDialog, PasswordPromptDialog
from .formatting import fmt_datetime, human_size
from .widgets import Card, PageHeader, busy, confirm, error, info, label, make_button

if TYPE_CHECKING:
    from app.application import AppContext

OLD_DAYS_CHOICES = [90, 180, 365, 730]


class SettingsPage(QWidget):
    def __init__(self, ctx: "AppContext", parent=None):
        super().__init__(parent)
        self.ctx = ctx
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        outer.addWidget(scroll)
        content = QWidget()
        scroll.setWidget(content)
        root = QVBoxLayout(content)
        root.setContentsMargins(28, 20, 28, 20)
        root.setSpacing(18)
        root.addWidget(PageHeader("Settings", "Security, appearance, backups and storage"))

        root.addWidget(self._security_card())
        root.addWidget(self._appearance_card())
        root.addWidget(self._backup_card())
        root.addWidget(self._storage_card())
        root.addWidget(self._about_card())
        root.addStretch(1)

    # ------------------------------------------------------------------ cards
    def _card(self, title: str, icon_name: str) -> Card:
        card = Card(margins=22)
        head = QHBoxLayout()
        pic = label()
        pic.setPixmap(icons.pixmap(icon_name, self.ctx.palette.accent, 18))
        head.addWidget(pic)
        head.addWidget(label(title, "SectionTitle"))
        head.addStretch(1)
        card.layout_.addLayout(head)
        return card

    def _form(self) -> QFormLayout:
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        form.setHorizontalSpacing(24)
        form.setVerticalSpacing(12)
        form.setFieldGrowthPolicy(QFormLayout.FieldsStayAtSizeHint)
        return form

    def _security_card(self) -> Card:
        card = self._card("Security", "lock")
        form = self._form()
        self.autolock = QComboBox()
        for m in AUTO_LOCK_CHOICES:
            self.autolock.addItem("Never" if m == 0 else f"{m} minute{'s' if m != 1 else ''}", m)
        self._select(self.autolock, self.ctx.setting_int("auto_lock_minutes"))
        self.autolock.currentIndexChanged.connect(
            lambda: self._save("auto_lock_minutes", self.autolock.currentData(), "Auto-lock updated"))
        form.addRow("Auto-lock after inactivity", self.autolock)

        self.clip = QComboBox()
        for s in CLIPBOARD_CHOICES:
            self.clip.addItem("Never" if s == 0 else f"{s} seconds", s)
        self._select(self.clip, self.ctx.setting_int("clipboard_clear_seconds"))
        self.clip.currentIndexChanged.connect(self._clip_changed)
        form.addRow("Clear copied passwords after", self.clip)

        self.old_days = QComboBox()
        for d in OLD_DAYS_CHOICES:
            self.old_days.addItem(f"{d} days", d)
        self._select(self.old_days, self.ctx.setting_int("old_password_days"))
        self.old_days.currentIndexChanged.connect(
            lambda: self._save("old_password_days", self.old_days.currentData(), "Old-password threshold updated"))
        form.addRow("Flag passwords as old after", self.old_days)
        card.layout_.addLayout(form)

        row = QHBoxLayout()
        change = make_button(self.ctx, "Change master password", None, "key")
        change.clicked.connect(self.change_password)
        lock = make_button(self.ctx, "Lock vault now", "primary", "lock")
        lock.clicked.connect(self.ctx.lock)
        row.addWidget(change)
        row.addWidget(lock)
        row.addStretch(1)
        card.layout_.addLayout(row)
        return card

    def _appearance_card(self) -> Card:
        card = self._card("Appearance", "sun")
        row = QHBoxLayout()
        self.theme_group = QButtonGroup(self)
        for key, text in (("dark", "Dark"), ("light", "Light")):
            rb = QRadioButton(text)
            rb.setProperty("theme_key", key)
            rb.setChecked(self.ctx.theme == key)
            self.theme_group.addButton(rb)
            row.addWidget(rb)
        row.addStretch(1)
        self.theme_group.buttonClicked.connect(self._theme_clicked)
        card.layout_.addLayout(row)
        return card

    def _backup_card(self) -> Card:
        card = self._card("Backup & restore", "download")
        card.layout_.addWidget(label(
            "Backups are encrypted with AES-256-GCM and can only be opened with the master password that was "
            "active when the backup was made. Keep a copy on a USB drive or another disk. "
            "Before any restore, the current vault is backed up automatically.", "Muted", wrap=True))
        row = QHBoxLayout()
        create = make_button(self.ctx, "Create backup", "primary", "download")
        create.clicked.connect(lambda: self.create_backup(False))
        create_as = make_button(self.ctx, "Back up to…", None, "folder")
        create_as.clicked.connect(lambda: self.create_backup(True))
        verify = make_button(self.ctx, "Verify backup…", None, "shield-check")
        verify.clicked.connect(self.verify_backup)
        restore = make_button(self.ctx, "Restore…", "danger", "upload")
        restore.clicked.connect(self.restore_backup)
        for b in (create, create_as, verify, restore):
            row.addWidget(b)
        row.addStretch(1)
        card.layout_.addLayout(row)

        head = QHBoxLayout()
        head.addWidget(label("RECENT BACKUPS IN DEFAULT FOLDER", "FieldLabel"))
        head.addStretch(1)
        open_dir = make_button(self.ctx, "Open folder", "ghost", "folder")
        open_dir.clicked.connect(lambda: self._open_dir(self.ctx.backups.backup_dir))
        head.addWidget(open_dir)
        card.layout_.addLayout(head)
        self.backup_list = QListWidget()
        self.backup_list.setMaximumHeight(170)
        self.backup_list.setMinimumHeight(110)
        card.layout_.addWidget(self.backup_list)
        return card

    def _storage_card(self) -> Card:
        card = self._card("Data & storage", "database")
        form = self._form()
        path = label(str(self.ctx.db.path), "FieldValue", wrap=True)
        path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        form.addRow("Vault database", path)
        mode = "Portable (data stored next to the EXE)" if is_portable() else "Installed (per-user local app data)"
        form.addRow("Storage mode", label(mode))
        k = DEFAULT_KDF
        form.addRow("Encryption", label(
            f"AES-256-GCM per field · Argon2id ({k.memory_cost_kib // 1024} MiB, {k.time_cost} passes, {k.parallelism} lanes)"))
        card.layout_.addLayout(form)
        row = QHBoxLayout()
        open_btn = make_button(self.ctx, "Open data folder", None, "folder")
        open_btn.clicked.connect(lambda: self._open_dir(Path(self.ctx.db.path).parent))
        check = make_button(self.ctx, "Run integrity check", None, "shield-check")
        check.clicked.connect(self.integrity_check)
        row.addWidget(open_btn)
        row.addWidget(check)
        row.addStretch(1)
        card.layout_.addLayout(row)
        return card

    def _about_card(self) -> Card:
        card = self._card("About", "shield")
        card.layout_.addWidget(label(
            f"{APP_NAME} {APP_VERSION} — offline password manager. No cloud, no telemetry, no network access.\n"
            f"Developed by {APP_DEVELOPER}.\n"
            "Built on established cryptography (Argon2id, AES-256-GCM via pyca/cryptography). "
            "It has not been independently security-audited; keep regular backups.", "Muted", wrap=True))
        return card

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _select(combo: QComboBox, value: int) -> None:
        idx = combo.findData(value)
        combo.setCurrentIndex(idx if idx >= 0 else 0)

    def _save(self, key: str, value, message: str) -> None:
        self.ctx.set_setting(key, value)
        self.ctx.notify(message)

    def _clip_changed(self) -> None:
        self._save("clipboard_clear_seconds", self.clip.currentData(), "Clipboard timeout updated")
        self.ctx.clipboard.timeout_seconds = int(self.clip.currentData())

    def _theme_clicked(self, button) -> None:
        key = button.property("theme_key")
        if key != self.ctx.theme:
            # defer: the whole window (including this page) is rebuilt with the new theme
            QTimer.singleShot(0, lambda: self.ctx.set_theme(key))

    def _open_dir(self, path: Path) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def refresh(self) -> None:
        self.backup_list.clear()
        try:
            backups = self.ctx.backups.list_backups()[:20]
        except OSError:
            backups = []
        for b in backups:
            item = QListWidgetItem(
                icons.icon("download", self.ctx.palette.muted),
                f"{b.path.name}    ·    {fmt_datetime(b.created_at)}    ·    {b.entry_count} accounts    ·    {human_size(b.size)}")
            item.setToolTip(str(b.path))
            self.backup_list.addItem(item)
        if not backups:
            item = QListWidgetItem("No backups yet — create one now and copy it to a safe place.")
            item.setFlags(Qt.NoItemFlags)
            self.backup_list.addItem(item)

    # ------------------------------------------------------------------ actions
    def change_password(self) -> None:
        dlg = ChangePasswordDialog(self.ctx, self)
        if dlg.exec() == ChangePasswordDialog.Accepted:
            info(self, "Master password changed",
                 "Your master password was changed.\n\nExisting backups still open with the old password. "
                 "Create a fresh backup now so your newest backup uses the new password.")
            self.ctx.notify("Master password changed")

    def create_backup(self, choose_location: bool) -> None:
        dest = None
        if choose_location:
            path, _ = QFileDialog.getSaveFileName(
                self, "Save encrypted backup",
                str(self.ctx.backups.backup_dir / f"SecureVault-backup{BACKUP_EXTENSION}"),
                f"SecureVault backup (*{BACKUP_EXTENSION})")
            if not path:
                return
            if not self.ctx.unlocked:
                return
            dest = Path(path)
            if dest.suffix.lower() != BACKUP_EXTENSION:
                dest = dest.with_suffix(BACKUP_EXTENSION)
        try:
            with busy():
                out = self.ctx.backups.create_backup(self.ctx.vault.key, dest)
        except (BackupError, OSError) as exc:
            error(self, "Backup failed", f"The backup could not be created:\n{exc}")
            return
        self.ctx.notify(f"Encrypted backup saved: {out.name}")
        self.refresh()

    def _pick_backup(self, title: str):
        path, _ = QFileDialog.getOpenFileName(
            self, title, str(self.ctx.backups.backup_dir), f"SecureVault backup (*{BACKUP_EXTENSION})")
        if not path or not self.ctx.unlocked:
            return None
        try:
            return self.ctx.backups.read_info(Path(path))
        except BackupError as exc:
            error(self, "Invalid backup", str(exc))
            return None

    def _ask_backup_password(self, meta, ok_text: str):
        dlg = PasswordPromptDialog(
            self.ctx, "Backup password",
            f"Backup from {fmt_datetime(meta.created_at)} · {meta.entry_count} accounts.\n"
            "Enter the master password that was in use when this backup was created.", ok_text, self)
        if dlg.exec() != PasswordPromptDialog.Accepted:
            return None
        return dlg.take_password()

    def verify_backup(self) -> None:
        meta = self._pick_backup("Verify backup")
        if not meta:
            return
        password = self._ask_backup_password(meta, "Verify")
        if password is None:
            return
        try:
            with busy():
                result = self.ctx.backups.verify_backup(meta.path, password)
        except (BackupError, OSError) as exc:
            error(self, "Verification failed", str(exc))
            return
        info(self, "Backup verified",
             f"✔ Password correct\n✔ Authenticated encryption verified (not tampered)\n"
             f"✔ Database integrity OK\n\n{result.entry_count} accounts · created {fmt_datetime(result.created_at)}")

    def restore_backup(self) -> None:
        meta = self._pick_backup("Restore from backup")
        if not meta:
            return
        if not confirm(
            self, "Restore backup",
            f"Replace your current vault with the backup from {fmt_datetime(meta.created_at)} "
            f"({meta.entry_count} accounts)?\n\nYour current vault will be saved automatically as a "
            "“pre-restore” backup first. The vault will lock after restoring; unlock it with the backup's "
            "master password.", "Restore", danger=True):
            return
        password = self._ask_backup_password(meta, "Restore")
        if password is None or not self.ctx.unlocked:
            return
        try:
            with busy():
                safety = self.ctx.backups.restore_backup(meta.path, password, self.ctx.vault.key)
        except BackupPasswordError as exc:
            error(self, "Restore failed", str(exc))
            return
        except (BackupError, OSError, IntegrityCheckError) as exc:
            error(self, "Restore failed", f"The backup could not be restored. Your vault was not changed.\n\n{exc}")
            return
        note = f" Previous vault saved as {safety.name}." if safety else ""
        QTimer.singleShot(0, lambda: self.ctx.lock(f"Vault restored from backup.{note} Unlock with the backup's master password."))

    def integrity_check(self) -> None:
        try:
            with busy():
                self.ctx.db.integrity_check()
                self.ctx.vault.list_entries()
        except IntegrityCheckError as exc:
            error(self, "Integrity check failed", f"{exc}\n\nRestore from a recent backup.")
            return
        bad = len(self.ctx.vault.corrupted_ids)
        if bad:
            error(self, "Integrity check", f"{bad} entr(ies) failed authentication (corrupted or tampered). "
                                           "Restore from a recent backup.")
        else:
            info(self, "Integrity check", "✔ Database structure OK\n✔ Every entry decrypted and authenticated")
