"""Security center: weak, reused and old password analysis (never displays passwords)."""
from __future__ import annotations

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
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.security_analyzer import analyze, estimate_strength
from core.vault import active_logins

from . import icons
from .formatting import age_days, elide
from .widgets import Card, PageHeader, StatCard, label, make_button

if TYPE_CHECKING:
    from app.application import AppContext


class SecurityPage(QWidget):
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

        header = PageHeader("Password health", "Analysis runs locally, in memory — passwords are never shown or logged here")
        rescan = make_button(ctx, "Re-scan", None, "refresh")
        rescan.clicked.connect(self.refresh)
        header.add_action(rescan)
        root.addWidget(header)

        top = QHBoxLayout()
        top.setSpacing(14)
        score_card = Card(margins=20)
        score_card.setMinimumWidth(300)
        score_card.layout_.addWidget(label("SECURITY SCORE", "FieldLabel"))
        self.score = label("—", "BigNumber")
        score_card.layout_.addWidget(self.score)
        self.score_bar = QProgressBar()
        self.score_bar.setRange(0, 100)
        self.score_bar.setTextVisible(False)
        score_card.layout_.addWidget(self.score_bar)
        self.verdict = label("", "Muted", wrap=True)
        score_card.layout_.addWidget(self.verdict)
        top.addWidget(score_card, 2)
        self.s_weak = StatCard(ctx, "alert", "Weak", "danger")
        self.s_reused = StatCard(ctx, "repeat", "Reused", "warning")
        self.s_old = StatCard(ctx, "clock", "Old", "warning")
        for c in (self.s_weak, self.s_reused, self.s_old):
            top.addWidget(c, 1)
        root.addLayout(top)

        grid = QGridLayout()
        grid.setSpacing(16)
        self.weak_list = self._make_list()
        self.old_list = self._make_list()
        self.reused_tree = QTreeWidget()
        self.reused_tree.setHeaderHidden(True)
        self.reused_tree.setFrameShape(QFrame.NoFrame)
        self.reused_tree.setStyleSheet("QTreeWidget { border: none; background: transparent; }")
        self.reused_tree.setMinimumHeight(170)
        self.reused_tree.setIconSize(QSize(18, 18))
        self.reused_tree.itemActivated.connect(self._tree_open)
        self.reused_tree.itemDoubleClicked.connect(self._tree_open)
        grid.addWidget(self._section("Weak passwords", "Easy to guess or crack. Replace with generated passwords.", "alert", self.weak_list), 0, 0)
        grid.addWidget(self._section("Reused passwords", "One breach exposes every account that shares a password.", "repeat", self.reused_tree), 0, 1)
        self.old_section = self._section("Old passwords", "", "clock", self.old_list)
        grid.addWidget(self.old_section, 1, 0, 1, 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        root.addLayout(grid)
        root.addWidget(label("Tip: double-click an account to edit it and set a new password.", "Muted"))
        root.addStretch(1)

    def _make_list(self) -> QListWidget:
        lst = QListWidget()
        lst.setFrameShape(QFrame.NoFrame)
        lst.setStyleSheet("QListWidget { border: none; background: transparent; }")
        lst.setMinimumHeight(170)
        lst.setIconSize(QSize(18, 18))
        lst.itemDoubleClicked.connect(self._list_open)
        lst.itemActivated.connect(self._list_open)
        return lst

    def _section(self, title: str, hint: str, icon_name: str, widget: QWidget) -> Card:
        card = Card()
        head = QHBoxLayout()
        pic = label()
        pic.setPixmap(icons.pixmap(icon_name, self.ctx.palette.muted, 17))
        head.addWidget(pic)
        title_label = label(title, "SectionTitle")
        head.addWidget(title_label)
        head.addStretch(1)
        card.layout_.addLayout(head)
        hint_label = label(hint, "Muted", wrap=True)
        card.layout_.addWidget(hint_label)
        card.hint_label = hint_label
        card.layout_.addWidget(widget)
        return card

    def _list_open(self, item: QListWidgetItem) -> None:
        entry_id = item.data(Qt.UserRole)
        if entry_id is not None:
            self.ctx.open_entry(entry_id, edit=True)

    def _tree_open(self, item: QTreeWidgetItem, _col: int = 0) -> None:
        entry_id = item.data(0, Qt.UserRole)
        if entry_id is not None:
            self.ctx.open_entry(entry_id, edit=True)

    def _empty(self, lst: QListWidget, text: str) -> None:
        item = QListWidgetItem(icons.icon("check", self.ctx.palette.success), text)
        item.setFlags(Qt.NoItemFlags)
        lst.addItem(item)

    def refresh(self) -> None:
        entries = active_logins(self.ctx.vault.list_entries())
        old_days = self.ctx.setting_int("old_password_days")
        report = analyze(entries, old_days=old_days)
        p = self.ctx.palette

        color = p.success if report.score >= 80 else p.warning if report.score >= 50 else p.danger
        self.score.setText(f"{report.score}/100" if entries else "—")
        self.score.setStyleSheet(f"color: {color};" if entries else "")
        self.score_bar.setValue(report.score if entries else 0)
        self.score_bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; }}")
        if not entries:
            self.verdict.setText("Your vault is empty.")
        elif report.issue_count == 0:
            self.verdict.setText("Excellent — no weak, reused or old passwords found.")
        else:
            self.verdict.setText(f"{report.issue_count} of {report.total} accounts need attention.")
        self.s_weak.set_value(len(report.weak))
        self.s_reused.set_value(report.reused_count)
        self.s_old.set_value(len(report.old))
        self.s_old.caption.setText(f"Older than {old_days} days")
        self.old_section.hint_label.setText(
            f"Passwords not changed for more than {old_days} days (configurable in Settings).")

        self.weak_list.clear()
        for e in sorted(report.weak, key=lambda x: estimate_strength(x.password).score):
            s = estimate_strength(e.password)
            item = QListWidgetItem(icons.icon("alert", p.danger),
                                   f"{elide(e.title, 40)}   ·   {s.label}" + (f"\n{elide(e.username, 40)}" if e.username else ""))
            item.setData(Qt.UserRole, e.id)
            self.weak_list.addItem(item)
        if not report.weak:
            self._empty(self.weak_list, "No weak passwords")

        self.reused_tree.clear()
        for group in sorted(report.reused_groups, key=len, reverse=True):
            parent = QTreeWidgetItem([f"Same password used by {len(group)} accounts"])
            parent.setIcon(0, icons.icon("repeat", p.warning))
            for e in group:
                child = QTreeWidgetItem([f"{elide(e.title, 40)}" + (f"  ·  {elide(e.username, 30)}" if e.username else "")])
                child.setData(0, Qt.UserRole, e.id)
                child.setIcon(0, icons.icon("key", p.muted))
                parent.addChild(child)
            self.reused_tree.addTopLevelItem(parent)
            parent.setExpanded(True)
        if not report.reused_groups:
            item = QTreeWidgetItem(["No reused passwords"])
            item.setIcon(0, icons.icon("check", p.success))
            item.setFlags(Qt.NoItemFlags)
            self.reused_tree.addTopLevelItem(item)

        self.old_list.clear()
        for e in sorted(report.old, key=lambda x: x.password_changed_at):
            item = QListWidgetItem(icons.icon("clock", p.warning),
                                   f"{elide(e.title, 50)}   ·   changed {age_days(e.password_changed_at)} days ago")
            item.setData(Qt.UserRole, e.id)
            self.old_list.addItem(item)
        if not report.old:
            self._empty(self.old_list, "No old passwords")
        del entries, report
