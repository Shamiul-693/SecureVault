"""Reusable themed widgets and dialog helpers."""
from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Iterator

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QGuiApplication
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core.security_analyzer import estimate_strength

from . import icons
from .theme import strength_color

if TYPE_CHECKING:
    from app.application import AppContext


def repolish(widget: QWidget) -> None:
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def make_button(
    ctx: "AppContext", text: str, variant: str | None = None, icon_name: str | None = None, tooltip: str = ""
) -> QPushButton:
    btn = QPushButton(text)
    btn.setCursor(Qt.PointingHandCursor)
    if variant:
        btn.setProperty("variant", variant)
    if icon_name:
        p = ctx.palette
        color = {"primary": p.accent_text, "danger": p.danger, "ghost": p.muted}.get(variant or "", p.text)
        btn.setIcon(icons.icon(icon_name, color))
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


def tool_button(ctx: "AppContext", icon_name: str, tooltip: str, role: str = "muted", size: int = 17) -> QToolButton:
    btn = QToolButton()
    btn.setCursor(Qt.PointingHandCursor)
    btn.setIcon(icons.icon(icon_name, getattr(ctx.palette, role), size))
    btn.setToolTip(tooltip)
    btn.setAutoRaise(True)
    return btn


def label(text: str = "", object_name: str | None = None, wrap: bool = False) -> QLabel:
    lab = QLabel(text)
    if object_name:
        lab.setObjectName(object_name)
    lab.setWordWrap(wrap)
    return lab


def divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    line.setFrameShape(QFrame.NoFrame)
    return line


class Card(QFrame):
    def __init__(self, parent: QWidget | None = None, margins: int = 18, spacing: int = 12):
        super().__init__(parent)
        self.setObjectName("Card")
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(margins, margins, margins, margins)
        self.layout_.setSpacing(spacing)


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        col = QVBoxLayout()
        col.setSpacing(2)
        col.addWidget(label(title, "PageTitle"))
        self.subtitle = label(subtitle, "PageSubtitle")
        col.addWidget(self.subtitle)
        row.addLayout(col)
        row.addStretch(1)
        self.actions = QHBoxLayout()
        self.actions.setSpacing(8)
        row.addLayout(self.actions)

    def set_subtitle(self, text: str) -> None:
        self.subtitle.setText(text)

    def add_action(self, widget: QWidget) -> None:
        self.actions.addWidget(widget)


class StatCard(Card):
    def __init__(self, ctx: "AppContext", icon_name: str, title: str, role: str = "accent"):
        super().__init__(margins=16, spacing=6)
        top = QHBoxLayout()
        badge = QLabel()
        badge.setObjectName("StatIcon")
        badge.setFixedSize(36, 36)
        badge.setAlignment(Qt.AlignCenter)
        badge.setPixmap(icons.pixmap(icon_name, getattr(ctx.palette, role), 18))
        top.addWidget(badge)
        top.addStretch(1)
        self.layout_.addLayout(top)
        self.value = label("0", "BigNumber")
        self.layout_.addWidget(self.value)
        self.caption = label(title, "Muted")
        self.layout_.addWidget(self.caption)
        self.setMinimumWidth(150)

    def set_value(self, value) -> None:
        self.value.setText(str(value))


class StrengthMeter(QWidget):
    def __init__(self, ctx: "AppContext", show_feedback: bool = True, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self.bar = QProgressBar()
        self.bar.setRange(0, 5)
        self.bar.setTextVisible(False)
        layout.addWidget(self.bar)
        row = QHBoxLayout()
        self.text = label("", "Muted")
        row.addWidget(self.text)
        row.addStretch(1)
        self.entropy = label("", "Muted")
        row.addWidget(self.entropy)
        layout.addLayout(row)
        self.feedback = label("", "Muted", wrap=True)
        self.feedback.setVisible(show_feedback)
        self._show_feedback = show_feedback
        layout.addWidget(self.feedback)
        self.update_password("")

    def update_password(self, password: str) -> None:
        result = estimate_strength(password)
        color = strength_color(self.ctx.palette, result.score) if password else self.ctx.palette.border
        self.bar.setValue(result.score + 1 if password else 0)
        self.bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; }}")
        self.text.setText(f"Strength: {result.label}" if password else "Strength: —")
        self.text.setStyleSheet(f"color: {color};" if password else "")
        self.entropy.setText(f"~{result.entropy_bits:.0f} bits" if password else "")
        if self._show_feedback:
            self.feedback.setText(" · ".join(result.feedback[:2]) if password else "")
            self.feedback.setVisible(bool(password and result.feedback))


class PasswordField(QLineEdit):
    """Password input with a show/hide toggle."""

    visibilityChanged = Signal(bool)

    def __init__(self, ctx: "AppContext", placeholder: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.setEchoMode(QLineEdit.Password)
        self.setPlaceholderText(placeholder)
        self.setClearButtonEnabled(False)
        self._toggle = QAction(icons.icon("eye", ctx.palette.muted), "Show password", self)
        self._toggle.triggered.connect(self.toggle_visibility)
        self.addAction(self._toggle, QLineEdit.TrailingPosition)
        self.setMinimumHeight(38)

    def toggle_visibility(self) -> None:
        self.set_revealed(self.echoMode() == QLineEdit.Password)

    def set_revealed(self, revealed: bool) -> None:
        self.setEchoMode(QLineEdit.Normal if revealed else QLineEdit.Password)
        name = "eye-off" if revealed else "eye"
        self._toggle.setIcon(icons.icon(name, self.ctx.palette.muted))
        self._toggle.setText("Hide password" if revealed else "Show password")
        self.visibilityChanged.emit(revealed)

    def secure_clear(self) -> None:
        self.clear()
        self.set_revealed(False)


def set_error(widget: QWidget, has_error: bool) -> None:
    widget.setProperty("error", "true" if has_error else "false")
    repolish(widget)


# --------------------------------------------------------------------------- dialogs
def confirm(parent: QWidget, title: str, text: str, ok_text: str = "Confirm", danger: bool = False) -> bool:
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setIcon(QMessageBox.Warning if danger else QMessageBox.Question)
    box.setText(text)
    ok = box.addButton(ok_text, QMessageBox.AcceptRole)
    cancel = box.addButton("Cancel", QMessageBox.RejectRole)
    if danger:
        ok.setProperty("variant", "danger")
    else:
        ok.setProperty("variant", "primary")
    box.setDefaultButton(cancel if danger else ok)
    box.exec()
    return box.clickedButton() is ok


def info(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.information(parent, title, text)


def error(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.critical(parent, title, text)


@contextmanager
def busy() -> Iterator[None]:
    """Wait cursor during short blocking work such as Argon2 key derivation."""
    QGuiApplication.setOverrideCursor(Qt.WaitCursor)
    QApplication.processEvents()
    try:
        yield
    finally:
        QGuiApplication.restoreOverrideCursor()


def fit_to_screen(window: QWidget, width: int, height: int) -> None:
    """Resize to the preferred size, but never larger than 92% of the usable screen area."""
    screen = window.screen() or QGuiApplication.primaryScreen()
    if screen is not None:
        area = screen.availableGeometry()
        width = min(width, int(area.width() * 0.92))
        height = min(height, int(area.height() * 0.92))
    window.resize(max(width, window.minimumWidth()), max(height, window.minimumHeight()))


def expanding() -> QSizePolicy:
    return QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
