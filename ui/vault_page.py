"""Items page: recommendations, searchable multi-select list and a detail panel.

Shows one "view" at a time: all items, a single item type, favourites, a
folder, or the trash.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, QItemSelectionModel, QRect, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QFontMetrics, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QStyle,
    QStyledItemDelegate,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import recommendations as recs_mod
from core.database import DatabaseError
from core.security_analyzer import analyze
from core.vault import (
    EXTRA_FIELDS,
    SORT_OPTIONS,
    TYPE_LABELS,
    TYPE_PLURALS,
    VIEW_ALL,
    VIEW_TRASH,
    Entry,
    Vault,
    active_logins,
    digits_only,
    parse_view,
)

from . import avatars, icons
from .account_dialog import ItemDialog
from .category_dialog import CategoryDialog
from .formatting import elide, fmt_datetime, fmt_relative
from .widgets import Card, StrengthMeter, confirm, divider, error, label, make_button, tool_button

if TYPE_CHECKING:
    from app.application import AppContext

MASK = "•" * 12
ROLE_ENTRY = Qt.UserRole + 1


# --------------------------------------------------------------------------- list delegate
class TitleDelegate(QStyledItemDelegate):
    """Paints avatar + title + muted subtitle in the first column."""

    def __init__(self, page: "VaultPage"):
        super().__init__(page)
        self.page = page

    def paint(self, painter, option, index) -> None:
        entry: Entry | None = index.data(ROLE_ENTRY)
        if entry is None:
            return super().paint(painter, option, index)
        p = self.page.ctx.palette
        painter.save()
        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, QColor(p.selection))
        elif option.state & QStyle.State_MouseOver:
            painter.fillRect(option.rect, QColor(p.surface_alt))
        r = option.rect
        size = 32
        painter.drawPixmap(r.left() + 10, r.top() + (r.height() - size) // 2, avatars.avatar(entry, size))
        x = r.left() + 10 + size + 12
        width = max(r.right() - x - 8, 10)
        title_font = QFont(option.font)
        title_font.setBold(True)
        sub_font = QFont(option.font)
        sub_font.setPointSizeF(max(option.font.pointSizeF() - 1, 7))
        title = entry.title + ("  ★" if entry.favorite else "")
        tm = QFontMetrics(title_font)
        sm = QFontMetrics(sub_font)
        top = r.top() + (r.height() - tm.height() - sm.height() - 2) // 2
        painter.setFont(title_font)
        painter.setPen(QColor(p.text))
        painter.drawText(QRect(x, top, width, tm.height()), Qt.AlignLeft | Qt.AlignVCenter,
                         tm.elidedText(title, Qt.ElideRight, width))
        painter.setFont(sub_font)
        painter.setPen(QColor(p.muted))
        painter.drawText(QRect(x, top + tm.height() + 2, width, sm.height()), Qt.AlignLeft | Qt.AlignVCenter,
                         sm.elidedText(entry.subtitle or TYPE_LABELS[entry.item_type], Qt.ElideRight, width))
        painter.restore()

    def sizeHint(self, option, index) -> QSize:
        return QSize(240, 54)


# --------------------------------------------------------------------------- recommendation card
class RecommendationCard(QFrame):
    def __init__(self, page: "VaultPage", rec: recs_mod.Recommendation):
        super().__init__()
        self.page = page
        self.rec = rec
        p = page.ctx.palette
        self.setObjectName("RecCard")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(
            f"#RecCard {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: 12px; }}"
            f"#RecCard:hover {{ border-color: {p.accent}; }}")
        self.setFixedHeight(74)
        self.setMinimumWidth(210)
        self.setMaximumWidth(290)
        self.setToolTip("Click to fix")
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 8, 6, 8)
        row.setSpacing(10)
        badge = QLabel()
        badge.setFixedSize(36, 36)
        badge.setAlignment(Qt.AlignCenter)
        badge.setStyleSheet(f"background: {getattr(p, rec.role, p.accent)}; border-radius: 9px;")
        badge.setPixmap(icons.pixmap(rec.icon, "#ffffff", 18))
        row.addWidget(badge)
        col = QVBoxLayout()
        col.setSpacing(3)
        title = label(rec.title, wrap=True)
        title.setStyleSheet("font-weight: 600;")
        col.addWidget(title)
        tag_row = QHBoxLayout()
        tag_row.addWidget(label(rec.tag, "Chip"))
        tag_row.addStretch(1)
        col.addLayout(tag_row)
        row.addLayout(col, 1)
        close = tool_button(page.ctx, "x", "Dismiss", "muted", 14)
        close.clicked.connect(lambda: page.dismiss_recommendation(rec))
        row.addWidget(close, 0, Qt.AlignTop)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.page.run_recommendation(self.rec)
        super().mouseReleaseEvent(event)


# --------------------------------------------------------------------------- detail panel
class DetailPanel(Card):
    def __init__(self, page: "VaultPage"):
        super().__init__(margins=20, spacing=8)
        self.page = page
        self.ctx = page.ctx
        self.entry: Entry | None = None
        self.revealed: set[str] = set()

        self.stack = QStackedWidget()
        self.layout_.addWidget(self.stack)

        empty = QWidget()
        el = QVBoxLayout(empty)
        el.addStretch(1)
        pic = QLabel()
        pic.setPixmap(icons.pixmap("vault", self.ctx.palette.border, 56))
        pic.setAlignment(Qt.AlignCenter)
        el.addWidget(pic)
        self.empty_msg = label("Select an item to see its details", "Muted", wrap=True)
        self.empty_msg.setAlignment(Qt.AlignCenter)
        el.addWidget(self.empty_msg)
        el.addStretch(1)
        self.stack.addWidget(empty)

        body = QWidget()
        self.body = QVBoxLayout(body)
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(8)
        head = QHBoxLayout()
        head.setSpacing(12)
        self.avatar = QLabel()
        head.addWidget(self.avatar, 0, Qt.AlignTop)
        tcol = QVBoxLayout()
        tcol.setSpacing(4)
        self.title = label("", "SectionTitle", wrap=True)
        self.title.setStyleSheet("font-size: 14pt;")
        tcol.addWidget(self.title)
        chips = QHBoxLayout()
        chips.setSpacing(6)
        self.type_chip = label("", "Chip")
        self.cat_chip = label("", "Chip")
        self.folder_chip = label("", "Chip")
        for c in (self.type_chip, self.cat_chip, self.folder_chip):
            chips.addWidget(c)
        chips.addStretch(1)
        tcol.addLayout(chips)
        head.addLayout(tcol, 1)
        self.fav_btn = tool_button(self.ctx, "star", "Toggle favourite", "muted", 18)
        self.fav_btn.clicked.connect(self.toggle_favorite)
        head.addWidget(self.fav_btn, 0, Qt.AlignTop)
        self.body.addLayout(head)
        self.body.addWidget(divider())
        self.fields_host = QWidget()
        self.fields = QVBoxLayout(self.fields_host)
        self.fields.setContentsMargins(0, 0, 0, 0)
        self.fields.setSpacing(6)
        self.body.addWidget(self.fields_host)
        self.meta = label("", "Muted", wrap=True)
        self.body.addWidget(self.meta)
        self.body.addStretch(1)
        self.actions = QHBoxLayout()
        self.body.addLayout(self.actions)
        self.stack.addWidget(body)

    # ---- building helpers
    def _clear_layout(self, layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().hide()
                item.widget().deleteLater()
            elif item.layout():
                self._clear_layout(item.layout())

    def _value_row(self, caption: str, value: str, *, key: str, sensitive: bool = False, mono: bool = False,
                   copy_label: str = "", open_url: bool = False, masked: str = MASK) -> None:
        self.fields.addWidget(label(caption.upper(), "FieldLabel"))
        row = QHBoxLayout()
        shown = value if (not sensitive or key in self.revealed) else masked
        if open_url and value:
            shown = elide(value, 46)
        val = label(shown or "—", "MonoValue" if mono else "FieldValue", wrap=not mono)
        val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        if open_url:
            val.setToolTip(value)
        row.addWidget(val, 1)
        if value and sensitive:
            eye = tool_button(self.ctx, "eye-off" if key in self.revealed else "eye", "Show / hide", "muted")
            eye.clicked.connect(lambda: self._toggle(key))
            row.addWidget(eye)
        if value and open_url:
            ob = tool_button(self.ctx, "external", "Open website", "muted")
            ob.clicked.connect(lambda: self._open(value))
            row.addWidget(ob)
        if value and copy_label:
            cb = tool_button(self.ctx, "copy", f"Copy {copy_label.lower()}", "muted")
            cb.clicked.connect(lambda: self._copy(value, copy_label, sensitive))
            row.addWidget(cb)
        self.fields.addLayout(row)

    def _notes_block(self, notes: str, tall: bool = False) -> None:
        if not notes and not tall:
            return
        head = QHBoxLayout()
        head.addWidget(label("NOTE" if tall else "NOTES", "FieldLabel"))
        head.addStretch(1)
        if notes:
            cb = tool_button(self.ctx, "copy", "Copy note", "muted")
            cb.clicked.connect(lambda: self._copy(notes, "Note", True))
            head.addWidget(cb)
        self.fields.addLayout(head)
        box = QPlainTextEdit(notes)
        box.setReadOnly(True)
        box.setMinimumHeight(60)
        box.setMaximumHeight(260 if tall else 100)
        self.fields.addWidget(box)

    # ---- show
    def show_entry(self, entry: Entry | None, keep_reveal: bool = False) -> None:
        if not keep_reveal or entry is None or self.entry is None or entry.id != self.entry.id:
            self.revealed = set()
        self.entry = entry
        self._clear_layout(self.fields)
        self._clear_layout(self.actions)
        if entry is None:
            self.stack.setCurrentIndex(0)
            self.setMinimumHeight(0)
            return
        self.stack.setCurrentIndex(1)
        p = self.ctx.palette
        self.avatar.setPixmap(avatars.avatar(entry, 44))
        self.title.setText(entry.title)
        self.type_chip.setText(TYPE_LABELS[entry.item_type])
        self.cat_chip.setText(entry.category_name)
        self.folder_chip.setText(entry.folder_name)
        self.folder_chip.setVisible(bool(entry.folder_name))
        self.fav_btn.setIcon(icons.icon("star", p.warning if entry.favorite else p.muted, 18))
        self.fav_btn.setVisible(not entry.in_trash)

        t = entry.item_type
        if t == "login":
            self._value_row("Username / email", entry.username, key="username", copy_label="Username")
            self._value_row("Password", entry.password, key="password", sensitive=True, mono=True, copy_label="Password")
            meter = StrengthMeter(self.ctx, show_feedback=False)
            meter.update_password(entry.password)
            self.fields.addWidget(meter)
            self._value_row("Website", entry.url, key="url", copy_label="Website", open_url=True)
            self._notes_block(entry.notes)
        elif t == "note":
            self._notes_block(entry.notes, tall=True)
        else:
            shown = 0
            for key, caption, sensitive in EXTRA_FIELDS[t]:
                value = entry.extra.get(key, "")
                if not value:
                    continue
                shown += 1
                masked = f"•••• •••• •••• {digits_only(value)[-4:]}" if key == "number" else MASK
                self._value_row(caption, value, key=key, sensitive=sensitive, mono=key in {"number", "cvv", "pin"},
                                copy_label=caption.split(" (")[0], masked=masked)
            if not shown:
                self.fields.addWidget(label("No details saved yet.", "Muted"))
            self._notes_block(entry.notes)

        lines = [f"Created {fmt_datetime(entry.created_at)}", f"Updated {fmt_datetime(entry.updated_at)}"]
        if t == "login":
            lines.append(f"Password changed {fmt_relative(entry.password_changed_at)}")
        lines.append(f"Last used {fmt_relative(entry.last_used_at) if entry.last_used_at else 'never'} · {entry.use_count}×")
        if entry.in_trash:
            lines.append(f"In trash since {fmt_relative(entry.deleted_at)} — deleted permanently after 30 days")
        self.meta.setText("\n".join(lines))

        if entry.in_trash:
            restore = make_button(self.ctx, "Restore", "primary", "restore")
            restore.clicked.connect(lambda: self.page.restore_items([entry.id]))
            forever = make_button(self.ctx, "Delete forever", "danger", "trash")
            forever.clicked.connect(lambda: self.page.delete_forever([entry.id]))
            self.actions.addWidget(restore)
            self.actions.addWidget(forever)
        else:
            edit = make_button(self.ctx, "Edit", "primary", "edit")
            edit.clicked.connect(lambda: self.page.edit_entry(entry.id))
            trash = make_button(self.ctx, "Move to trash", "danger", "trash")
            trash.clicked.connect(lambda: self.page.trash_items([entry.id]))
            self.actions.addWidget(edit)
            self.actions.addWidget(trash)
        self.actions.addStretch(1)
        # let the surrounding scroll area scroll instead of squeezing the fields
        QTimer.singleShot(0, self._fit_height)

    def _fit_height(self) -> None:
        """Once the new field widgets are polished, stop the scroll area from squeezing them."""
        if self.entry is not None:
            self.setMinimumHeight(self.stack.currentWidget().minimumSizeHint().height() + 44)

    # ---- actions
    def _toggle(self, key: str) -> None:
        self.revealed ^= {key}
        self.show_entry(self.entry, keep_reveal=True)

    def _copy(self, value: str, what: str, sensitive: bool) -> None:
        if self.entry:
            self.ctx.copy_secret(value, what, None if self.entry.in_trash else self.entry.id, sensitive=sensitive)

    def _open(self, url: str) -> None:
        if self.entry:
            self.ctx.open_url(url)
            if not self.entry.in_trash:
                self.ctx.vault.mark_used(self.entry.id)

    def toggle_favorite(self) -> None:
        if self.entry and not self.entry.in_trash:
            self.ctx.vault.update_entry(self.entry.id, favorite=not self.entry.favorite)
            self.ctx.data_changed()
            self.page.refresh(select_id=self.entry.id)

    def primary_secret(self) -> tuple[str, str] | None:
        e = self.entry
        if not e:
            return None
        if e.item_type == "login" and e.password:
            return e.password, "Password"
        if e.item_type == "card" and e.extra.get("number"):
            return e.extra["number"], "Card number"
        if e.item_type == "note" and e.notes:
            return e.notes, "Note"
        return None


# --------------------------------------------------------------------------- page
class VaultPage(QWidget):
    def __init__(self, ctx: "AppContext", parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.view = VIEW_ALL
        self.entries: list[Entry] = []
        self.visible: list[Entry] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 18, 28, 14)
        root.setSpacing(12)

        # ---- header
        header = QHBoxLayout()
        tcol = QVBoxLayout()
        tcol.setSpacing(2)
        self.title = label("All items", "PageTitle")
        self.subtitle = label("", "PageSubtitle")
        tcol.addWidget(self.title)
        tcol.addWidget(self.subtitle)
        header.addLayout(tcol)
        header.addStretch(1)
        self.cat_btn = make_button(ctx, "Categories", None, "tag")
        self.cat_btn.clicked.connect(self.manage_categories)
        header.addWidget(self.cat_btn)
        self.empty_trash_btn = make_button(ctx, "Empty trash", "danger", "trash")
        self.empty_trash_btn.clicked.connect(self.empty_trash)
        header.addWidget(self.empty_trash_btn)
        self.add_btn = make_button(ctx, "Add item", "primary", "plus")
        self.add_menu = QMenu(self)
        for t, icon_name in (("login", "key"), ("note", "note"), ("card", "card"), ("identity", "user")):
            self.add_menu.addAction(icons.icon(icon_name, ctx.palette.muted), TYPE_LABELS[t],
                                    lambda k=t: self.add_item(k))
        self.add_btn.clicked.connect(self._add_clicked)
        header.addWidget(self.add_btn)
        root.addLayout(header)

        # ---- recommendations
        self.recs_host = QWidget()
        rl = QVBoxLayout(self.recs_host)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)
        self.recs_title = label("", "FieldLabel")
        rl.addWidget(self.recs_title)
        self.recs_row = QHBoxLayout()
        self.recs_row.setSpacing(10)
        rl.addLayout(self.recs_row)
        self.recs_host.hide()
        root.addWidget(self.recs_host)

        # ---- toolbar
        bar = QHBoxLayout()
        bar.setSpacing(10)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search items…   (Ctrl+F)")
        self.search.addAction(icons.icon("search", ctx.palette.muted), QLineEdit.LeadingPosition)
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.apply_filter)
        bar.addWidget(self.search, 1)
        self.category = QComboBox()
        self.category.setMinimumWidth(170)
        self.category.currentIndexChanged.connect(self.apply_filter)
        bar.addWidget(self.category)
        self.sort = QComboBox()
        for key, text in SORT_OPTIONS.items():
            self.sort.addItem(text, key)
        self.sort.setMinimumWidth(150)
        self.sort.currentIndexChanged.connect(self.apply_filter)
        bar.addWidget(self.sort)
        root.addLayout(bar)

        # ---- bulk action bar
        self.bulk = QFrame()
        self.bulk.setObjectName("Card")
        bl = QHBoxLayout(self.bulk)
        bl.setContentsMargins(14, 6, 10, 6)
        self.bulk_label = label("")
        self.bulk_label.setStyleSheet("font-weight: 600;")
        bl.addWidget(self.bulk_label)
        bl.addStretch(1)
        self.bulk_folder = make_button(ctx, "Move to folder", None, "folder")
        self.bulk_fav = make_button(ctx, "Favourite", None, "star")
        self.bulk_trash = make_button(ctx, "Move to trash", "danger", "trash")
        self.bulk_restore = make_button(ctx, "Restore", "primary", "restore")
        self.bulk_delete = make_button(ctx, "Delete forever", "danger", "trash")
        self.bulk_clear = make_button(ctx, "Clear", "ghost", "x")
        self.bulk_folder.clicked.connect(self._bulk_folder_menu)
        self.bulk_fav.clicked.connect(self._bulk_favorite)
        self.bulk_trash.clicked.connect(lambda: self.trash_items(self.selected_ids()))
        self.bulk_restore.clicked.connect(lambda: self.restore_items(self.selected_ids()))
        self.bulk_delete.clicked.connect(lambda: self.delete_forever(self.selected_ids()))
        self.bulk_clear.clicked.connect(lambda: self.table.clearSelection())
        for b in (self.bulk_folder, self.bulk_fav, self.bulk_trash, self.bulk_restore, self.bulk_delete, self.bulk_clear):
            bl.addWidget(b)
        self.bulk.hide()
        root.addWidget(self.bulk)

        # ---- list + details
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["TITLE", "CATEGORY", "LAST USED"])
        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.setMouseTracking(True)
        self.table.verticalHeader().setDefaultSectionSize(56)
        self.table.setItemDelegateForColumn(0, TitleDelegate(self))
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        h.setHighlightSections(False)
        h.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table.cellDoubleClicked.connect(self._double_clicked)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.installEventFilter(self)
        splitter.addWidget(self.table)

        self.detail = DetailPanel(self)
        detail_scroll = QScrollArea()
        detail_scroll.setWidget(self.detail)
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setFrameShape(QFrame.NoFrame)
        detail_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        detail_scroll.setMinimumWidth(330)
        splitter.addWidget(detail_scroll)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([620, 400])
        root.addWidget(splitter, 1)

        self.hint = label("", "Muted")
        self.hint.setAlignment(Qt.AlignCenter)
        root.addWidget(self.hint)

        QShortcut(QKeySequence.Find, self, activated=self.focus_search)
        QShortcut(QKeySequence.New, self, activated=lambda: self.add_item(self._default_type()))
        self.sort.setCurrentIndex(self.sort.findData("last_used"))

    # ------------------------------------------------------------------ view
    def set_view(self, view: str, select_id: int | None = None) -> None:
        if view != self.view:
            self.view = view
            self.search.blockSignals(True)
            self.search.clear()
            self.search.blockSignals(False)
            self.table.clearSelection()
            self.detail.show_entry(None)
        self.refresh(select_id=select_id)

    def _view_title(self) -> str:
        kind, arg = parse_view(self.view)
        if kind == "type":
            return TYPE_PLURALS.get(arg, "Items")
        if kind == "folder":
            folder = self.ctx.db.get_folder(arg)
            return folder.name if folder else "Folder"
        return {"favorites": "Favourites", "trash": "Trash"}.get(kind, "All items")

    def _default_type(self) -> str:
        kind, arg = parse_view(self.view)
        return arg if kind == "type" else "login"

    # ------------------------------------------------------------------ data
    def refresh(self, select_id: int | None = None) -> None:
        kind, arg = parse_view(self.view)
        if kind == "folder" and self.ctx.db.get_folder(arg) is None:
            self.view = VIEW_ALL
        current = select_id if select_id is not None else None
        self.entries = self.ctx.vault.list_entries(include_trash=True)
        self._reload_categories()
        in_trash = self.view == VIEW_TRASH
        self.title.setText(self._view_title())
        self.empty_trash_btn.setVisible(in_trash and any(e.in_trash for e in self.entries))
        self.add_btn.setVisible(not in_trash)
        self.cat_btn.setVisible(not in_trash)
        self._build_recommendations()
        self.apply_filter(select_id=current)

    def _reload_categories(self) -> None:
        selected = self.category.currentData()
        self.category.blockSignals(True)
        self.category.clear()
        self.category.addItem(icons.icon("grid", self.ctx.palette.muted), "All categories", None)
        for cat in self.ctx.db.list_categories():
            self.category.addItem(f"{cat.name}  ({cat.entry_count})", cat.id)
        idx = self.category.findData(selected)
        self.category.setCurrentIndex(idx if idx >= 0 else 0)
        self.category.blockSignals(False)

    def apply_filter(self, *_args, select_id: int | None = None) -> None:
        keep = {select_id} if select_id is not None else set(self.selected_ids())
        self.visible = Vault.filter_sort(
            self.entries, self.search.text().strip(), self.category.currentData(), self.sort.currentData(), self.view)
        in_trash = self.view == VIEW_TRASH
        muted = QColor(self.ctx.palette.muted)
        self.table.blockSignals(True)
        self.table.clearSelection()
        self.table.setRowCount(len(self.visible))
        first = -1
        sel = self.table.selectionModel()
        for row, e in enumerate(self.visible):
            name = QTableWidgetItem(e.title)
            name.setData(Qt.UserRole, e.id)
            name.setData(ROLE_ENTRY, e)
            name.setToolTip(e.url or e.title)
            self.table.setItem(row, 0, name)
            cat = QTableWidgetItem(e.category_name)
            cat.setForeground(muted)
            self.table.setItem(row, 1, cat)
            when = e.deleted_at if in_trash else e.last_used_at
            used = QTableWidgetItem(fmt_relative(when) if when else "Never")
            used.setForeground(muted)
            used.setToolTip(fmt_datetime(when) if when else "Not used yet")
            self.table.setItem(row, 2, used)
            if e.id in keep:
                sel.select(self.table.model().index(row, 0),
                           QItemSelectionModel.Select | QItemSelectionModel.Rows)
                first = row if first < 0 else first
        self.table.setHorizontalHeaderLabels(["TITLE", "CATEGORY", "DELETED" if in_trash else "LAST USED"])
        self.table.blockSignals(False)
        if first >= 0:
            self.table.setCurrentCell(first, 0, QItemSelectionModel.NoUpdate)
            self.table.scrollToItem(self.table.item(first, 0))
        self._selection_changed()

        n = len([e for e in self.entries if Vault.in_view(e, self.view)])
        noun = "item" if n == 1 else "items"
        self.subtitle.setText(f"{n} {noun} · deleted permanently after 30 days" if in_trash
                              else f"{n} {noun} · encrypted with AES-256-GCM")
        if self.ctx.vault.corrupted_ids:
            self.hint.setText(f"⚠ {len(self.ctx.vault.corrupted_ids)} item(s) failed integrity verification and are "
                              "hidden. Restore from a backup if this persists.")
            self.hint.setStyleSheet(f"color: {self.ctx.palette.danger};")
            return
        self.hint.setStyleSheet("")
        if n == 0:
            self.hint.setText("Trash is empty." if in_trash else "Nothing here yet — click “Add item”.")
        elif not self.visible:
            self.hint.setText("No items match your search.")
        else:
            self.hint.setText("Tip: Ctrl/Shift-click to select several items" if len(self.visible) > 1 else "")

    def selected_ids(self) -> list[int]:
        if not hasattr(self, "table"):
            return []
        ids = []
        for idx in sorted(self.table.selectionModel().selectedRows(), key=lambda i: i.row()):
            item = self.table.item(idx.row(), 0)
            if item is not None:
                ids.append(item.data(Qt.UserRole))
        return ids

    def _entry(self, entry_id: int | None) -> Entry | None:
        return next((e for e in self.entries if e.id == entry_id), None)

    def _selection_changed(self) -> None:
        ids = self.selected_ids()
        multi = len(ids) > 1
        self.bulk.setVisible(multi)
        if multi:
            in_trash = self.view == VIEW_TRASH
            self.bulk_label.setText(f"{len(ids)} selected")
            for b in (self.bulk_folder, self.bulk_fav, self.bulk_trash):
                b.setVisible(not in_trash)
            for b in (self.bulk_restore, self.bulk_delete):
                b.setVisible(in_trash)
            self.bulk_folder.setEnabled(bool(self.ctx.db.list_folders()))
            self.bulk_folder.setToolTip("" if self.bulk_folder.isEnabled() else "Create a folder in the sidebar first")
            self.detail.empty_msg.setText(f"{len(ids)} items selected")
            self.detail.show_entry(None)
            return
        self.detail.empty_msg.setText("Select an item to see its details")
        self.detail.show_entry(self._entry(ids[0]) if ids else None)

    def select_entry(self, entry_id: int) -> None:
        entry = self._entry(entry_id) or next(
            (e for e in self.ctx.vault.list_entries(include_trash=True) if e.id == entry_id), None)
        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        self.category.setCurrentIndex(0)
        if entry is None:
            self.refresh()
            return
        target = VIEW_TRASH if entry.in_trash else (self.view if Vault.in_view(entry, self.view) else VIEW_ALL)
        if target != self.view:
            self.ctx.navigate_view(target, select_id=entry_id)
        else:
            self.refresh(select_id=entry_id)

    def focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    # ------------------------------------------------------------------ recommendations
    def _build_recommendations(self) -> None:
        while self.recs_row.count():
            item = self.recs_row.takeAt(0)
            if item.widget():
                item.widget().hide()
                item.widget().deleteLater()
        if self.view != VIEW_ALL:
            self.recs_host.hide()
            return
        active = [e for e in self.entries if not e.in_trash]
        report = analyze(active_logins(active), old_days=self.ctx.setting_int("old_password_days"))
        recs = recs_mod.build(
            report, len(active), self.ctx.setting_int("auto_lock_minutes"),
            self.ctx.setting_int("clipboard_clear_seconds"), self.ctx.db.get_setting("last_backup_at"))
        dismissed = recs_mod.load_dismissed(self.ctx.db.get_setting("dismissed_recommendations"))
        recs = [r for r in recs if r.key not in dismissed]
        if not recs:
            self.recs_host.hide()
            return
        self.recs_title.setText(f"RECOMMENDATIONS ({len(recs)})")
        for rec in recs[:3]:
            self.recs_row.addWidget(RecommendationCard(self, rec))
        self.recs_row.addStretch(1)
        self.recs_host.show()

    def dismiss_recommendation(self, rec: recs_mod.Recommendation) -> None:
        dismissed = recs_mod.load_dismissed(self.ctx.db.get_setting("dismissed_recommendations"))
        dismissed.add(rec.key)
        self.ctx.db.set_setting("dismissed_recommendations", recs_mod.dump_dismissed(dismissed))
        self._build_recommendations()

    def run_recommendation(self, rec: recs_mod.Recommendation) -> None:
        if rec.action == "backup":
            if self.ctx.create_backup():
                self._build_recommendations()
        else:
            self.ctx.navigate(rec.action)

    # ------------------------------------------------------------------ actions
    def _add_clicked(self) -> None:
        kind, _ = parse_view(self.view)
        if kind == "type":
            self.add_item(self._default_type())
        else:
            self.add_menu.exec(self.add_btn.mapToGlobal(self.add_btn.rect().bottomLeft()))

    def add_item(self, item_type: str = "login") -> None:
        kind, arg = parse_view(self.view)
        dlg = ItemDialog(self.ctx, None, item_type, self.category.currentData(),
                         arg if kind == "folder" else None, self)
        if dlg.exec() == ItemDialog.Accepted and dlg.saved_entry:
            saved = dlg.saved_entry
            self.ctx.notify(f"“{saved.title}” added")
            self.ctx.data_changed()
            if Vault.in_view(saved, self.view):
                self.refresh(select_id=saved.id)
            else:
                self.ctx.navigate_view(VIEW_ALL, select_id=saved.id)

    def add_entry(self) -> None:  # used by the dashboard button
        self.add_item("login")

    def edit_entry(self, entry_id: int | None) -> None:
        if entry_id is None:
            return
        try:
            entry = self.ctx.vault.get_entry(entry_id)
        except DatabaseError:
            return
        if entry.in_trash:
            return
        dlg = ItemDialog(self.ctx, entry, parent=self)
        if dlg.exec() == ItemDialog.Accepted and dlg.saved_entry:
            self.ctx.notify(f"“{dlg.saved_entry.title}” saved")
            self.ctx.data_changed()
            self.select_entry(entry_id)

    def _double_clicked(self, row: int, _col: int) -> None:
        item = self.table.item(row, 0)
        entry = self._entry(item.data(Qt.UserRole)) if item else None
        if entry is None:
            return
        if entry.in_trash:
            self.restore_items([entry.id])
        else:
            self.edit_entry(entry.id)

    def _names(self, ids: list[int]) -> str:
        if len(ids) == 1:
            e = self._entry(ids[0])
            return f"“{e.title}”" if e else "1 item"
        return f"{len(ids)} items"

    def _after_change(self, message: str) -> None:
        self.table.clearSelection()
        self.detail.show_entry(None)
        self.ctx.notify(message)
        self.ctx.data_changed()
        self.refresh()

    def trash_items(self, ids: list[int]) -> None:
        if not ids:
            return
        names = self._names(ids)
        try:
            self.ctx.vault.trash_entries(ids)
        except DatabaseError as exc:
            error(self, "Move to trash failed", str(exc))
            return
        self._after_change(f"{names} moved to trash")

    def restore_items(self, ids: list[int]) -> None:
        if ids:
            names = self._names(ids)
            self.ctx.vault.restore_entries(ids)
            self._after_change(f"{names} restored")

    def delete_forever(self, ids: list[int]) -> None:
        if not ids:
            return
        names = self._names(ids)
        if not confirm(self, "Delete permanently",
                       f"Permanently delete {names}?\n\nThis cannot be undone (unless you restore a backup).",
                       "Delete forever", danger=True):
            return
        self.ctx.vault.delete_entries(ids)
        self._after_change(f"{names} deleted permanently")

    def empty_trash(self) -> None:
        n = len([e for e in self.entries if e.in_trash])
        if n and confirm(self, "Empty trash", f"Permanently delete all {n} item(s) in the trash?\n\n"
                         "This cannot be undone.", "Empty trash", danger=True):
            self.ctx.vault.empty_trash()
            self._after_change("Trash emptied")

    def move_to_folder(self, ids: list[int], folder_id: int | None) -> None:
        if not ids:
            return
        names = self._names(ids)
        self.ctx.vault.set_folder(ids, folder_id)
        folder = self.ctx.db.get_folder(folder_id) if folder_id else None
        self.ctx.notify(f"{names} moved to {folder.name if folder else 'no folder'}")
        self.ctx.data_changed()
        self.refresh(select_id=ids[0] if len(ids) == 1 else None)

    def _folder_menu(self, ids: list[int]) -> QMenu:
        menu = QMenu(self)
        menu.addAction(icons.icon("x", self.ctx.palette.muted), "No folder", lambda: self.move_to_folder(ids, None))
        menu.addSeparator()
        for f in self.ctx.db.list_folders():
            menu.addAction(icons.icon("folder", self.ctx.palette.muted), f.name,
                           lambda fid=f.id: self.move_to_folder(ids, fid))
        return menu

    def _bulk_folder_menu(self) -> None:
        self._folder_menu(self.selected_ids()).exec(self.bulk_folder.mapToGlobal(self.bulk_folder.rect().bottomLeft()))

    def _bulk_favorite(self) -> None:
        ids = self.selected_ids()
        make_fav = not all(e.favorite for e in (self._entry(i) for i in ids) if e)
        for i in ids:
            self.ctx.vault.update_entry(i, favorite=make_fav)
        self.ctx.notify(f"{len(ids)} items {'added to' if make_fav else 'removed from'} favourites")
        self.ctx.data_changed()
        self.refresh()

    def manage_categories(self) -> None:
        dlg = CategoryDialog(self.ctx, self)
        dlg.exec()
        if dlg.changed:
            self.refresh()

    def _context_menu(self, pos) -> None:
        row = self.table.rowAt(pos.y())
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            return
        if item.data(Qt.UserRole) not in self.selected_ids():
            self.table.clearSelection()
            self.table.selectRow(row)
        ids = self.selected_ids()
        p = self.ctx.palette
        menu = QMenu(self)
        if self.view == VIEW_TRASH:
            menu.addAction(icons.icon("restore", p.muted), "Restore", lambda: self.restore_items(ids))
            menu.addAction(icons.icon("trash", p.danger), "Delete forever…", lambda: self.delete_forever(ids))
        else:
            entry = self._entry(ids[0]) if len(ids) == 1 else None
            if entry is not None:
                if entry.item_type == "login":
                    if entry.username:
                        menu.addAction(icons.icon("user", p.muted), "Copy username",
                                       lambda: self.ctx.copy_secret(entry.username, "Username", entry.id, sensitive=False))
                    if entry.password:
                        menu.addAction(icons.icon("copy", p.muted), "Copy password",
                                       lambda: self.ctx.copy_secret(entry.password, "Password", entry.id))
                    if entry.url:
                        menu.addAction(icons.icon("external", p.muted), "Open website",
                                       lambda: self.ctx.open_url(entry.url))
                else:
                    secret = self.detail.primary_secret()
                    if secret:
                        menu.addAction(icons.icon("copy", p.muted), f"Copy {secret[1].lower()}",
                                       lambda: self.ctx.copy_secret(secret[0], secret[1], entry.id))
                menu.addSeparator()
                menu.addAction(icons.icon("edit", p.muted), "Edit…", lambda: self.edit_entry(entry.id))
            folders = self._folder_menu(ids)
            folders.setTitle("Move to folder")
            folders.setIcon(icons.icon("folder", p.muted))
            menu.addMenu(folders)
            menu.addSeparator()
            menu.addAction(icons.icon("trash", p.danger), "Move to trash", lambda: self.trash_items(ids))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def eventFilter(self, obj, event) -> bool:
        if obj is self.table and event.type() == QEvent.KeyPress:
            ids = self.selected_ids()
            if ids and event.key() == Qt.Key_Delete:
                (self.delete_forever if self.view == VIEW_TRASH else self.trash_items)(ids)
                return True
            if len(ids) == 1 and event.key() in (Qt.Key_Return, Qt.Key_Enter):
                self._double_clicked(self.table.currentRow(), 0)
                return True
            if len(ids) == 1 and event.matches(QKeySequence.Copy):
                secret = self.detail.primary_secret()
                if secret and self.detail.entry and not self.detail.entry.in_trash:
                    self.ctx.copy_secret(secret[0], secret[1], self.detail.entry.id)
                return True
        return super().eventFilter(obj, event)
