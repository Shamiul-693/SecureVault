"""Password generator page."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QScrollArea,
    QCheckBox,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QSlider,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core.password_generator import MAX_LENGTH, MIN_LENGTH, GeneratorError, GeneratorOptions, entropy_bits, generate_password

from .widgets import Card, PageHeader, StrengthMeter, label, make_button, tool_button

if TYPE_CHECKING:
    from app.application import AppContext


class GeneratorPage(QWidget):
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
        root.addWidget(PageHeader("Password generator", "Cryptographically secure passwords from Python's secrets module"))

        # ---- output card
        out = Card(margins=22)
        row = QHBoxLayout()
        self.output = QLineEdit()
        self.output.setObjectName("GeneratedPassword")
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(58)
        row.addWidget(self.output, 1)
        regen = tool_button(ctx, "refresh", "Generate another (Ctrl+R)", "text", 20)
        regen.setShortcut("Ctrl+R")
        regen.clicked.connect(self.generate)
        row.addWidget(regen)
        out.layout_.addLayout(row)
        self.meter = StrengthMeter(ctx, show_feedback=False)
        self.meter.entropy.hide()
        out.layout_.addWidget(self.meter)
        actions = QHBoxLayout()
        self.entropy = label("", "Muted")
        actions.addWidget(self.entropy)
        actions.addStretch(1)
        copy = make_button(ctx, "Copy password", "primary", "copy")
        copy.clicked.connect(self.copy)
        actions.addWidget(copy)
        out.layout_.addLayout(actions)
        root.addWidget(out)

        # ---- options card
        opts = Card(margins=22)
        opts.layout_.addWidget(label("Options", "SectionTitle"))
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(12)
        grid.addWidget(label("LENGTH", "FieldLabel"), 0, 0)
        self.slider = QSlider(Qt.Horizontal)
        self.slider.setRange(MIN_LENGTH, 64)
        self.spin = QSpinBox()
        self.spin.setRange(MIN_LENGTH, MAX_LENGTH)
        self.spin.setFixedWidth(90)
        self.spin.setAlignment(Qt.AlignCenter)
        grid.addWidget(self.slider, 0, 1)
        grid.addWidget(self.spin, 0, 2)

        self.upper = QCheckBox("Uppercase (A–Z)")
        self.lower = QCheckBox("Lowercase (a–z)")
        self.digits = QCheckBox("Numbers (0–9)")
        self.symbols = QCheckBox("Symbols (!@#$%…)")
        self.ambiguous = QCheckBox("Exclude ambiguous characters (I l 1 | O 0 o ` ' \")")
        self.sets = (self.upper, self.lower, self.digits, self.symbols)
        for i, box in enumerate(self.sets):
            box.setChecked(True)
            grid.addWidget(box, 1 + i // 2, i % 2)
        grid.addWidget(self.ambiguous, 3, 0, 1, 3)
        grid.setColumnStretch(1, 1)
        opts.layout_.addLayout(grid)
        self.opt_error = label("", "ErrorLabel")
        self.opt_error.hide()
        opts.layout_.addWidget(self.opt_error)
        root.addWidget(opts)

        tips = Card(margins=22)
        tips.layout_.addWidget(label("Good practice", "SectionTitle"))
        tips.layout_.addWidget(label(
            "• Use a unique password for every account — reuse lets one breach unlock many accounts.\n"
            "• 16+ characters with all character sets is excellent for websites; use 20+ for email and banking.\n"
            "• Generated passwords are never stored or logged unless you save them in an account.",
            "Muted", wrap=True))
        root.addWidget(tips)
        root.addStretch(1)

        self.slider.setValue(20)
        self.spin.setValue(20)
        self.slider.valueChanged.connect(self._slider_changed)
        self.spin.valueChanged.connect(self._spin_changed)
        for box in (*self.sets, self.ambiguous):
            box.toggled.connect(self._option_toggled)
        self.generate()

    def _slider_changed(self, value: int) -> None:
        if self.spin.value() != value:
            self.spin.setValue(value)

    def _spin_changed(self, value: int) -> None:
        if self.slider.value() != value and value <= self.slider.maximum():
            self.slider.blockSignals(True)
            self.slider.setValue(value)
            self.slider.blockSignals(False)
        elif value > self.slider.maximum():
            self.slider.blockSignals(True)
            self.slider.setValue(self.slider.maximum())
            self.slider.blockSignals(False)
        self.generate()

    def _option_toggled(self, checked: bool) -> None:
        if not any(b.isChecked() for b in self.sets):
            sender = self.sender()
            sender.blockSignals(True)
            sender.setChecked(True)
            sender.blockSignals(False)
            self.opt_error.setText("At least one character set must stay selected.")
            self.opt_error.show()
            return
        self.opt_error.hide()
        self.generate()

    def options(self) -> GeneratorOptions:
        return GeneratorOptions(
            length=self.spin.value(),
            uppercase=self.upper.isChecked(),
            lowercase=self.lower.isChecked(),
            digits=self.digits.isChecked(),
            symbols=self.symbols.isChecked(),
            exclude_ambiguous=self.ambiguous.isChecked(),
        )

    def generate(self) -> None:
        opts = self.options()
        try:
            pw = generate_password(opts)
        except GeneratorError as exc:
            self.opt_error.setText(str(exc))
            self.opt_error.show()
            return
        self.output.setText(pw)
        self.meter.update_password(pw)
        self.entropy.setText(f"{opts.length} characters · {entropy_bits(opts):.0f} bits of entropy")

    def copy(self) -> None:
        if self.output.text():
            self.ctx.copy_secret(self.output.text(), "Generated password", None)

    def refresh(self) -> None:
        pass
