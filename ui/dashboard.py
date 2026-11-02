"""Dashboard: vault overview."""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core.security_analyzer import analyze
from core.vault import Entry, active_logins

from . import icons
from .formatting import elide, fmt_relative
from .widgets import Card, PageHeader, StatCard, label, make_button

if TYPE_CHECKING:
    from app.application import AppContext


class EntryList(QListWidget):
    """Compact list of entries; activating an item opens it in the vault."""

    def __init__(self, ctx: "AppContext", empty_text: str):
        super().__init__()
        self.ctx = ctx
        self.empty_text = empty_text
        self.setFrameShape(QFrame.NoFrame)
        self.setStyleSheet("QListWidget { border: none; background: transparent; }")
        self.setMinimumHeight(170)
        self.setIconSize(QSize(18, 18))
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setSpacing(1)
        self.itemActivated.connect(self._open)
        self.itemClicked.connect(self._open)

    def set_entries(self, entries: list[Entry], meta) -> None:
        self.clear()
        p = self.ctx.palette
        if not entries:
            item = QListWidgetItem(self.empty_text)
            item.setFlags(Qt.NoItemFlags)
            self.addItem(item)
            return
        for e in entries:
            sub = meta(e)
            text = f"{elide(e.title, 34)}   ·   {sub}\n{elide(e.subtitle, 40) or e.category_name}"
            item = QListWidgetItem(icons.icon("star" if e.favorite else "key", p.warning if e.favorite else p.accent), text)
            item.setData(Qt.UserRole, e.id)
            self.addItem(item)

    def _open(self, item: QListWidgetItem) -> None:
        entry_id = item.data(Qt.UserRole)
        if entry_id is not None:
            self.ctx.open_entry(entry_id)


class DashboardPage(QWidget):
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

        self.header = PageHeader("Dashboard", "")
        add = make_button(ctx, "Add item", "primary", "plus")
        add.clicked.connect(self._add)
        self.header.add_action(add)
        root.addWidget(self.header)

        stats = QHBoxLayout()
        stats.setSpacing(14)
        self.s_accounts = StatCard(ctx, "key", "Saved items")
        self.s_categories = StatCard(ctx, "tag", "Categories in use")
        self.s_score = StatCard(ctx, "shield-check", "Security score", "success")
        self.s_weak = StatCard(ctx, "alert", "Weak passwords", "danger")
        self.s_reused = StatCard(ctx, "repeat", "Reused passwords", "warning")
        for card in (self.s_accounts, self.s_categories, self.s_score, self.s_weak, self.s_reused):
            stats.addWidget(card)
        root.addLayout(stats)

        grid = QGridLayout()
        grid.setSpacing(16)
        self.recent_added = EntryList(ctx, "No accounts yet")
        self.recent_updated = EntryList(ctx, "No accounts yet")
        self.frequent = EntryList(ctx, "Copy a password to see your most-used accounts here")
        grid.addWidget(self._list_card("Recently added", "plus", self.recent_added), 0, 0)
        grid.addWidget(self._list_card("Recently updated", "clock", self.recent_updated), 0, 1)
        grid.addWidget(self._list_card("Frequently used", "star", self.frequent), 1, 0)
        grid.addWidget(self._security_card(), 1, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        root.addLayout(grid)
        root.addStretch(1)

    def _list_card(self, title: str, icon_name: str, widget: QWidget) -> Card:
        card = Card()
        head = QHBoxLayout()
        pic = label()
        pic.setPixmap(icons.pixmap(icon_name, self.ctx.palette.muted, 17))
        head.addWidget(pic)
        head.addWidget(label(title, "SectionTitle"))
        head.addStretch(1)
        card.layout_.addLayout(head)
        card.layout_.addWidget(widget)
        return card

    def _security_card(self) -> Card:
        card = Card()
        head = QHBoxLayout()
        pic = label()
        pic.setPixmap(icons.pixmap("shield", self.ctx.palette.muted, 17))
        head.addWidget(pic)
        head.addWidget(label("Password security overview", "SectionTitle"))
        head.addStretch(1)
        card.layout_.addLayout(head)
        self.score_bar = QProgressBar()
        self.score_bar.setRange(0, 100)
        self.score_bar.setTextVisible(False)
        card.layout_.addWidget(self.score_bar)
        self.summary = label("", None, wrap=True)
        self.summary.setTextFormat(Qt.RichText)
        card.layout_.addWidget(self.summary)
        card.layout_.addStretch(1)
        btn = make_button(self.ctx, "Open security center", None, "shield-check")
        btn.clicked.connect(lambda: self.ctx.navigate("security"))
        card.layout_.addWidget(btn, 0, Qt.AlignLeft)
        return card

    def _add(self) -> None:
        self.ctx.navigate_view("all")
        self.ctx.controller.main_window.vault_page._add_clicked()

    def refresh(self) -> None:
        entries = self.ctx.vault.list_entries()
        old_days = self.ctx.setting_int("old_password_days")
        report = analyze(active_logins(entries), old_days=old_days)
        hour = datetime.now().hour
        greet = "Good morning" if hour < 12 else "Good afternoon" if hour < 18 else "Good evening"
        self.header.set_subtitle(f"{greet} — here is the state of your vault")

        self.s_accounts.set_value(len(entries))
        self.s_categories.set_value(len({e.category_id for e in entries}))
        self.s_score.set_value(f"{report.score}%" if entries else "—")
        self.s_weak.set_value(len(report.weak))
        self.s_reused.set_value(report.reused_count)

        self.recent_added.set_entries(
            sorted(entries, key=lambda e: e.created_at, reverse=True)[:4], lambda e: f"added {fmt_relative(e.created_at)}")
        self.recent_updated.set_entries(
            sorted(entries, key=lambda e: e.updated_at, reverse=True)[:4], lambda e: f"updated {fmt_relative(e.updated_at)}")
        used = [e for e in entries if e.use_count > 0 or e.favorite]
        used.sort(key=lambda e: (e.favorite, e.use_count, e.last_used_at or ""), reverse=True)
        self.frequent.set_entries(used[:4], lambda e: f"used {e.use_count}×")

        p = self.ctx.palette
        color = p.success if report.score >= 80 else p.warning if report.score >= 50 else p.danger
        self.score_bar.setValue(report.score if entries else 0)
        self.score_bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; }}")
        if not entries:
            self.summary.setText("Add accounts to see a security analysis.")
        else:
            def line(n, text, col):
                return f'<span style="color:{col if n else p.success}; font-weight:600">{n}</span> {text}'
            self.summary.setText(
                f'<p style="font-size:15pt; font-weight:700; margin:0">{report.score}<span style="font-size:10pt; color:{p.muted}">/100</span></p>'
                + "<br>".join([
                    line(len(report.weak), "weak passwords", p.danger),
                    line(report.reused_count, "accounts sharing a password", p.warning),
                    line(len(report.old), f"passwords older than {old_days} days", p.warning),
                ]))
        del entries
