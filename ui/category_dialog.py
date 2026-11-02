"""Manage custom categories."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QInputDialog, QListWidget, QListWidgetItem, QVBoxLayout

from core.database import MAX_CATEGORY_LEN, DatabaseError

from . import icons
from .widgets import confirm, error, label, make_button

if TYPE_CHECKING:
    from app.application import AppContext


class CategoryDialog(QDialog):
    def __init__(self, ctx: "AppContext", parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.changed = False
        self.setWindowTitle("Categories")
        self.setModal(True)
        self.setMinimumSize(440, 480)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 20)
        root.setSpacing(12)
        root.addWidget(label("Categories", "PageTitle"))
        root.addWidget(label("Default categories are fixed. Add your own, rename or delete them — "
                             "accounts in a deleted category move to “Other”.", "Muted", wrap=True))
        self.list = QListWidget()
        self.list.itemSelectionChanged.connect(self._update_buttons)
        self.list.itemDoubleClicked.connect(lambda _: self.rename())
        root.addWidget(self.list, 1)

        row = QHBoxLayout()
        add = make_button(ctx, "Add", "primary", "plus")
        add.clicked.connect(self.add)
        self.rename_btn = make_button(ctx, "Rename", None, "edit")
        self.rename_btn.clicked.connect(self.rename)
        self.delete_btn = make_button(ctx, "Delete", "danger", "trash")
        self.delete_btn.clicked.connect(self.delete)
        close = make_button(ctx, "Close")
        close.clicked.connect(self.accept)
        for b in (add, self.rename_btn, self.delete_btn):
            row.addWidget(b)
        row.addStretch(1)
        row.addWidget(close)
        root.addLayout(row)
        self.reload()

    def reload(self, select_id: int | None = None) -> None:
        self.list.clear()
        for cat in self.ctx.db.list_categories():
            text = f"{cat.name}   ·   {cat.entry_count} account{'s' if cat.entry_count != 1 else ''}"
            item = QListWidgetItem(icons.icon("lock" if cat.is_default else "tag", self.ctx.palette.muted), text)
            item.setData(Qt.UserRole, cat)
            if cat.is_default:
                item.setToolTip("Default category")
            self.list.addItem(item)
            if cat.id == select_id:
                self.list.setCurrentItem(item)
        self._update_buttons()

    def _selected(self):
        item = self.list.currentItem()
        return item.data(Qt.UserRole) if item else None

    def _update_buttons(self) -> None:
        cat = self._selected()
        custom = cat is not None and not cat.is_default
        self.rename_btn.setEnabled(custom)
        self.delete_btn.setEnabled(custom)

    def add(self) -> None:
        name, ok = QInputDialog.getText(self, "New category", f"Category name (max {MAX_CATEGORY_LEN} characters):")
        if not ok:
            return
        try:
            cid = self.ctx.db.add_category(name)
        except DatabaseError as exc:
            error(self, "Cannot add category", str(exc))
            return
        self.changed = True
        self.reload(cid)

    def rename(self) -> None:
        cat = self._selected()
        if not cat or cat.is_default:
            return
        name, ok = QInputDialog.getText(self, "Rename category", "New name:", text=cat.name)
        if not ok:
            return
        try:
            self.ctx.db.rename_category(cat.id, name)
        except DatabaseError as exc:
            error(self, "Cannot rename category", str(exc))
            return
        self.changed = True
        self.reload(cat.id)

    def delete(self) -> None:
        cat = self._selected()
        if not cat or cat.is_default:
            return
        extra = f"\n\n{cat.entry_count} account(s) will move to “Other”." if cat.entry_count else ""
        if not confirm(self, "Delete category", f"Delete the category “{cat.name}”?{extra}", "Delete", danger=True):
            return
        try:
            self.ctx.db.delete_category(cat.id)
        except DatabaseError as exc:
            error(self, "Cannot delete category", str(exc))
            return
        self.changed = True
        self.reload()
