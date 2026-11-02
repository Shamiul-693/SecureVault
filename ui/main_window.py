"""Main window: sidebar navigation + stacked pages + toast notifications."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QPropertyAnimation, Qt, QTimer
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QFrame,
    QInputDialog,
    QMenu,
    QScrollArea,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.config import APP_DEVELOPER, APP_NAME, APP_VERSION

from . import icons
from .dashboard import DashboardPage
from .generator_page import GeneratorPage
from .security_page import SecurityPage
from .settings_page import SettingsPage
from .vault_page import VaultPage
from core.database import DatabaseError

from .widgets import confirm, error, fit_to_screen, label, tool_button

if TYPE_CHECKING:
    from app.application import AppContext

ITEM_VIEWS = [
    ("all", "All items", "layers"),
    ("type:login", "Passwords", "key"),
    ("type:note", "Secure notes", "note"),
    ("type:card", "Credit cards", "card"),
    ("type:identity", "Personal info", "user"),
    ("favorites", "Favourites", "star"),
    ("trash", "Trash", "trash"),
]
TOOLS = [
    ("generator", "Password generator", "wand"),
    ("security", "Password health", "health"),
    ("settings", "Settings", "settings"),
]
SHORTCUTS = ["dashboard", "view:all", "generator", "security", "settings"]
PAGE_KEYS = ("dashboard", "vault", "generator", "security", "settings")


class Toast(QLabel):
    def __init__(self, parent: QWidget, ctx: "AppContext"):
        super().__init__(parent)
        p = ctx.palette
        self.setStyleSheet(
            f"background: {p.surface_alt}; color: {p.text}; border: 1px solid {p.border};"
            "border-radius: 10px; padding: 10px 18px; font-weight: 600;")
        self.setAlignment(Qt.AlignCenter)
        self.hide()
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._anim = QPropertyAnimation(self._effect, b"opacity", self)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._fade_out)

    def show_message(self, text: str, ms: int = 2800) -> None:
        self.setText(text)
        self.adjustSize()
        parent = self.parentWidget()
        self.move((parent.width() - self.width()) // 2, parent.height() - self.height() - 28)
        self._anim.stop()
        self._effect.setOpacity(1.0)
        self.show()
        self.raise_()
        self._timer.start(ms)

    def _fade_out(self) -> None:
        self._anim.setDuration(350)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.0)
        self._anim.finished.connect(self.hide)
        self._anim.start()


class NavItem(QPushButton):
    """Sidebar entry: icon, text and a right-aligned count."""

    def __init__(self, ctx: "AppContext", key: str, text: str, icon_name: str):
        super().__init__()
        self.ctx = ctx
        self.key = key
        self.icon_name = icon_name
        self.setObjectName("NavButton")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(34)
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 0, 10, 0)
        row.setSpacing(10)
        self.icon_label = QLabel()
        self.text_label = QLabel(text)
        self.count_label = QLabel("")
        for w in (self.icon_label, self.text_label, self.count_label):
            w.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        row.addWidget(self.icon_label)
        row.addWidget(self.text_label, 1)
        row.addWidget(self.count_label)
        self.set_active(False)

    def set_text(self, text: str) -> None:
        self.text_label.setText(text)

    def set_count(self, n: int | None) -> None:
        self.count_label.setText("" if not n else str(n))

    def set_active(self, active: bool) -> None:
        p = self.ctx.palette
        color = p.accent if active else p.muted
        self.setChecked(active)
        self.icon_label.setPixmap(icons.pixmap(self.icon_name, color, 17))
        self.text_label.setStyleSheet(f"color: {p.accent if active else p.text}; font-weight: {700 if active else 500};")
        self.count_label.setStyleSheet(f"color: {color}; font-size: 8.5pt;")


class MainWindow(QMainWindow):
    def __init__(self, ctx: "AppContext"):
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(900, 540)
        fit_to_screen(self, 1320, 820)
        self.current_key = "dashboard"
        self.nav_items: dict[str, NavItem] = {}

        central = QWidget()
        central.setObjectName("PageRoot")
        central.setAttribute(Qt.WA_StyledBackground, True)
        self.setCentralWidget(central)
        row = QHBoxLayout(central)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        row.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.dashboard_page = DashboardPage(ctx)
        self.vault_page = VaultPage(ctx)
        self.generator_page = GeneratorPage(ctx)
        self.security_page = SecurityPage(ctx)
        self.settings_page = SettingsPage(ctx)
        self.pages = {
            "dashboard": self.dashboard_page,
            "vault": self.vault_page,
            "generator": self.generator_page,
            "security": self.security_page,
            "settings": self.settings_page,
        }
        for key in PAGE_KEYS:
            self.stack.addWidget(self.pages[key])
        content = QVBoxLayout()
        content.setContentsMargins(0, 0, 0, 0)
        content.setSpacing(0)
        content.addWidget(self.stack, 1)
        content.addWidget(self._build_footer())
        row.addLayout(content, 1)

        self.toast = Toast(central, ctx)
        ctx.toast.connect(self.toast.show_message)

        QShortcut(QKeySequence("Ctrl+L"), self, activated=ctx.lock)
        for i, key in enumerate(SHORTCUTS):
            QShortcut(QKeySequence(f"Ctrl+{i + 1}"), self, activated=lambda k=key: self.navigate(k))
        self.refresh_sidebar()
        self.navigate("dashboard")

    # ------------------------------------------------------------------ sidebar
    def _section(self, layout: QVBoxLayout, text: str, action=None) -> None:
        row = QHBoxLayout()
        row.setContentsMargins(12, 12, 4, 2)
        row.addWidget(label(text.upper(), "FieldLabel"))
        row.addStretch(1)
        if action is not None:
            row.addWidget(action)
        layout.addLayout(row)

    def _add_nav(self, layout: QVBoxLayout, key: str, text: str, icon_name: str, tip: str = "") -> NavItem:
        item = NavItem(self.ctx, key, text, icon_name)
        if tip:
            item.setToolTip(tip)
        item.clicked.connect(lambda _=False, k=key: self.navigate(k))
        layout.addWidget(item)
        self.nav_items[key] = item
        return item

    def _build_sidebar(self) -> QWidget:
        p = self.ctx.palette
        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(236)
        outer = QVBoxLayout(side)
        outer.setContentsMargins(12, 18, 12, 14)
        outer.setSpacing(6)

        brand = QHBoxLayout()
        brand.setContentsMargins(6, 0, 0, 0)
        logo = QLabel()
        logo.setPixmap(icons.pixmap("shield-check", p.accent, 30))
        brand.addWidget(logo)
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(label(APP_NAME, "BrandTitle"))
        names.addWidget(label("Offline password vault", "BrandSubtitle"))
        brand.addLayout(names)
        brand.addStretch(1)
        outer.addLayout(brand)
        outer.addSpacing(8)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        host = QWidget()
        scroll.setWidget(host)
        nav = QVBoxLayout(host)
        nav.setContentsMargins(0, 0, 4, 0)
        nav.setSpacing(2)
        self._add_nav(nav, "dashboard", "Dashboard", "dashboard", "Dashboard (Ctrl+1)")

        self._section(nav, "Items")
        for view, text, icon_name in ITEM_VIEWS:
            self._add_nav(nav, f"view:{view}", text, icon_name, "All items (Ctrl+2)" if view == "all" else "")

        add_folder = tool_button(self.ctx, "folder-plus", "New folder", "muted", 16)
        add_folder.clicked.connect(self.new_folder)
        self._section(nav, "Folders", add_folder)
        self.folders_layout = QVBoxLayout()
        self.folders_layout.setSpacing(2)
        nav.addLayout(self.folders_layout)

        self._section(nav, "Tools")
        for i, (key, text, icon_name) in enumerate(TOOLS):
            self._add_nav(nav, key, text, icon_name, f"{text} (Ctrl+{i + 3})")
        nav.addStretch(1)
        outer.addWidget(scroll, 1)

        dark = self.ctx.theme == "dark"
        theme_btn = QPushButton(" Light" if dark else " Dark")
        theme_btn.setToolTip("Switch to light mode" if dark else "Switch to dark mode")
        theme_btn.setObjectName("SidebarFooterButton")
        theme_btn.setIcon(icons.icon("sun" if dark else "moon", p.muted))
        theme_btn.setCursor(Qt.PointingHandCursor)
        theme_btn.clicked.connect(lambda: QTimer.singleShot(0, lambda: self.ctx.set_theme("light" if dark else "dark")))
        lock_btn = QPushButton(" Lock")
        lock_btn.setObjectName("SidebarFooterButton")
        lock_btn.setIcon(icons.icon("lock", p.accent))
        lock_btn.setToolTip("Lock now (Ctrl+L)")
        lock_btn.setCursor(Qt.PointingHandCursor)
        lock_btn.clicked.connect(lambda: QTimer.singleShot(0, self.ctx.lock))
        foot = QHBoxLayout()
        foot.setSpacing(6)
        foot.addWidget(theme_btn)
        foot.addWidget(lock_btn)
        outer.addLayout(foot)
        return side

    def refresh_sidebar(self) -> None:
        """Rebuild folder entries and update item counts."""
        if not self.ctx.vault.is_unlocked:
            return
        entries = self.ctx.vault.list_entries(include_trash=True)
        counts = self.ctx.vault.counts(entries)
        for view, _, _ in ITEM_VIEWS:
            self.nav_items[f"view:{view}"].set_count(counts.get(view, 0))
        for key in [k for k in self.nav_items if k.startswith("view:folder:")]:
            self.nav_items.pop(key)
        while self.folders_layout.count():
            w = self.folders_layout.takeAt(0).widget()
            if w:
                w.hide()
                w.deleteLater()
        folders = self.ctx.db.list_folders()
        for f in folders:
            item = self._add_nav(self.folders_layout, f"view:folder:{f.id}", f.name, "folder")
            item.set_count(f.entry_count)
            item.setContextMenuPolicy(Qt.CustomContextMenu)
            item.customContextMenuRequested.connect(lambda _pos, fid=f.id, it=item: self._folder_menu(fid, it))
            item.setToolTip("Right-click to rename or delete")
        if not folders:
            hint = label("No folders yet", "Muted")
            hint.setContentsMargins(14, 2, 0, 2)
            self.folders_layout.addWidget(hint)
        for key, item in self.nav_items.items():
            item.set_active(key == self.current_key or (self.current_key == "vault" and key == f"view:{self.vault_page.view}"))

    # ------------------------------------------------------------------ folders
    def new_folder(self) -> None:
        name, ok = QInputDialog.getText(self, "New folder", "Folder name:")
        if not ok:
            return
        try:
            fid = self.ctx.db.add_folder(name)
        except DatabaseError as exc:
            error(self, "Cannot create folder", str(exc))
            return
        self.refresh_sidebar()
        self.navigate(f"view:folder:{fid}")
        self.ctx.notify(f"Folder “{name.strip()}” created")

    def _folder_menu(self, folder_id: int, item: NavItem) -> None:
        menu = QMenu(self)
        p = self.ctx.palette
        menu.addAction(icons.icon("edit", p.muted), "Rename…", lambda: self.rename_folder(folder_id))
        menu.addAction(icons.icon("trash", p.danger), "Delete folder…", lambda: self.delete_folder(folder_id))
        menu.exec(item.mapToGlobal(item.rect().bottomLeft()))

    def rename_folder(self, folder_id: int) -> None:
        folder = self.ctx.db.get_folder(folder_id)
        if not folder:
            return
        name, ok = QInputDialog.getText(self, "Rename folder", "New name:", text=folder.name)
        if not ok:
            return
        try:
            self.ctx.db.rename_folder(folder_id, name)
        except DatabaseError as exc:
            error(self, "Cannot rename folder", str(exc))
            return
        self.ctx.data_changed()
        if self.current_key == "vault":
            self.vault_page.refresh()

    def delete_folder(self, folder_id: int) -> None:
        folder = self.ctx.db.get_folder(folder_id)
        if not folder:
            return
        extra = f"\n\nIts {folder.entry_count} item(s) will be kept — they just leave the folder." if folder.entry_count else ""
        if not confirm(self, "Delete folder", f"Delete the folder “{folder.name}”?{extra}", "Delete folder", danger=True):
            return
        self.ctx.db.delete_folder(folder_id)
        self.ctx.notify(f"Folder “{folder.name}” deleted")
        if self.current_key == "vault" and self.vault_page.view == f"folder:{folder_id}":
            self.navigate("view:all")
        else:
            self.ctx.data_changed()

    def _build_footer(self) -> QWidget:
        footer = QFrame()
        footer.setObjectName("AppFooter")
        footer.setAttribute(Qt.WA_StyledBackground, True)
        footer.setStyleSheet(
            f"#AppFooter {{ border-top: 1px solid {self.ctx.palette.border}; background: {self.ctx.palette.bg}; }}")
        lay = QHBoxLayout(footer)
        lay.setContentsMargins(28, 8, 28, 8)
        lay.addWidget(label(f"© {APP_NAME} {APP_VERSION}  ·  Developed by {APP_DEVELOPER}", "Muted"))
        lay.addStretch(1)
        lay.addWidget(label("Offline · AES-256-GCM · Argon2id", "Muted"))
        return footer

    # ------------------------------------------------------------------ navigation
    def navigate(self, key: str, select_id: int | None = None) -> None:
        if key.startswith("view:"):
            self.current_key = "vault"
            self.stack.setCurrentWidget(self.vault_page)
            self.vault_page.set_view(key[5:], select_id=select_id)
        elif key in self.pages:
            self.current_key = key
            self.stack.setCurrentWidget(self.pages[key])
            if key == "vault":
                self.vault_page.refresh(select_id=select_id)
            else:
                self.pages[key].refresh()
        else:
            return
        self.refresh_sidebar()

    def current_page(self) -> str:
        if self.current_key == "vault":
            return f"view:{self.vault_page.view}"
        return self.current_key

    def open_entry(self, entry_id: int, edit: bool = False) -> None:
        self.current_key = "vault"
        self.stack.setCurrentWidget(self.vault_page)
        self.vault_page.select_entry(entry_id)
        self.refresh_sidebar()
        if edit:
            self.vault_page.edit_entry(entry_id)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.toast.isVisible():
            parent = self.toast.parentWidget()
            self.toast.move((parent.width() - self.toast.width()) // 2, parent.height() - self.toast.height() - 28)
