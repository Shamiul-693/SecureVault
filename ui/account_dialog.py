"""Add / edit item dialog for every item type (password, secure note, credit card, personal info)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core.database import DatabaseError
from core.password_generator import GeneratorOptions, generate_password
from core.vault import EXTRA_FIELDS, LIMITS, TYPE_LABELS, Entry, ValidationError, card_brand, digits_only, luhn_valid

from . import icons
from .widgets import PasswordField, StrengthMeter, confirm, label, make_button, set_error, tool_button

if TYPE_CHECKING:
    from app.application import AppContext

TYPE_ORDER = ["login", "note", "card", "identity"]
TYPE_ICONS = {"login": "key", "note": "note", "card": "card", "identity": "user"}
PLACEHOLDERS = {
    "cardholder": "Name as printed on the card", "number": "1234 5678 9012 3456", "expiry": "MM/YY",
    "cvv": "3–4 digits", "pin": "Optional", "full_name": "Full name", "email": "name@example.com",
    "phone": "+880 1XXX-XXXXXX", "birthday": "DD/MM/YYYY", "address": "Street, city, postcode, country",
    "company": "Company, university or school", "id_number": "NID / passport / student ID",
}


def normalise_url(url: str) -> str:
    url = url.strip()
    if url and "://" not in url and "." in url and " " not in url:
        return "https://" + url
    return url


def _field_label(text: str, required: bool = False):
    return label(text.upper() + (" *" if required else ""), "FieldLabel")


class ItemDialog(QDialog):
    def __init__(self, ctx: "AppContext", entry: Entry | None = None, item_type: str = "login",
                 default_category: int | None = None, default_folder: int | None = None, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.entry = entry
        self.saved_entry: Entry | None = None
        self.item_type = entry.item_type if entry else item_type
        self.setModal(True)
        self.setMinimumWidth(560)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 18)
        root.setSpacing(12)
        self.heading = label("", "PageTitle")
        root.addWidget(self.heading)

        # ---- type switcher (only when creating)
        self.type_group = QButtonGroup(self)
        self.type_buttons: dict[str, QPushButton] = {}
        if entry is None:
            row = QHBoxLayout()
            row.setSpacing(6)
            for key in TYPE_ORDER:
                btn = QPushButton(f" {TYPE_LABELS[key]}")
                btn.setCheckable(True)
                btn.setCursor(Qt.PointingHandCursor)
                btn.setIcon(icons.icon(TYPE_ICONS[key], ctx.palette.muted))
                btn.setProperty("variant", "ghost")
                btn.clicked.connect(lambda _=False, k=key: self.set_type(k))
                self.type_group.addButton(btn)
                self.type_buttons[key] = btn
                row.addWidget(btn)
            row.addStretch(1)
            root.addLayout(row)

        # ---- scrollable form body
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget()
        scroll.setWidget(body)
        form = QVBoxLayout(body)
        form.setContentsMargins(0, 0, 6, 0)
        form.setSpacing(6)
        root.addWidget(scroll, 1)

        self.title = QLineEdit()
        self.title.setMaxLength(LIMITS["title"])
        self.title_label = _field_label("Name", True)
        form.addWidget(self.title_label)
        form.addWidget(self.title)

        meta = QGridLayout()
        meta.setHorizontalSpacing(12)
        meta.setVerticalSpacing(6)
        self.category = QComboBox()
        for cat in ctx.db.list_categories():
            self.category.addItem(cat.name, cat.id)
        self.folder = QComboBox()
        self.folder.addItem("No folder", None)
        for f in ctx.db.list_folders():
            self.folder.addItem(icons.icon("folder", ctx.palette.muted), f.name, f.id)
        meta.addWidget(_field_label("Category"), 0, 0)
        meta.addWidget(_field_label("Folder"), 0, 1)
        meta.addWidget(self.category, 1, 0)
        meta.addWidget(self.folder, 1, 1)
        form.addLayout(meta)

        self.groups = QStackedWidget()
        self.group_index: dict[str, int] = {}
        self._build_login_group()
        self._build_extra_group("card")
        self._build_extra_group("identity")
        empty = QWidget()
        self.group_index["note"] = self.groups.addWidget(empty)
        form.addWidget(self.groups)

        self.notes_label = _field_label("Notes")
        form.addWidget(self.notes_label)
        self.notes = QPlainTextEdit()
        form.addWidget(self.notes)
        self.favorite = QCheckBox("Mark as favourite")
        form.addWidget(self.favorite)
        form.addStretch(1)

        self.error = label("", "ErrorLabel", wrap=True)
        self.error.hide()
        root.addWidget(self.error)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = make_button(ctx, "Cancel")
        cancel.clicked.connect(self.reject)
        self.save_btn = make_button(ctx, "Save changes" if entry else "Add", "primary", "check")
        self.save_btn.setDefault(True)
        self.save_btn.clicked.connect(self.save)
        buttons.addWidget(cancel)
        buttons.addWidget(self.save_btn)
        root.addLayout(buttons)

        self._load(entry, default_category, default_folder)
        self.set_type(self.item_type)
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is not None:
            self.setMaximumHeight(int(screen.availableGeometry().height() * 0.94))
        self.resize(600, min(720, self.maximumHeight()))

    # ------------------------------------------------------------------ groups
    def _build_login_group(self) -> None:
        w = QWidget()
        g = QVBoxLayout(w)
        g.setContentsMargins(0, 6, 0, 0)
        g.setSpacing(6)
        self.username = QLineEdit()
        self.username.setPlaceholderText("Username or email")
        self.username.setMaxLength(LIMITS["username"])
        self.password = PasswordField(self.ctx, "Password")
        self.password.setMaxLength(LIMITS["password"])
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://example.com")
        self.url.setMaxLength(LIMITS["url"])
        g.addWidget(_field_label("Username / email"))
        g.addWidget(self.username)
        g.addWidget(_field_label("Password", True))
        row = QHBoxLayout()
        row.addWidget(self.password, 1)
        gen = tool_button(self.ctx, "wand", "Generate a strong password", "accent", 19)
        gen.clicked.connect(self.generate)
        row.addWidget(gen)
        g.addLayout(row)
        self.meter = StrengthMeter(self.ctx)
        g.addWidget(self.meter)
        self.password.textChanged.connect(self.meter.update_password)
        g.addWidget(_field_label("Website URL"))
        g.addWidget(self.url)
        self.group_index["login"] = self.groups.addWidget(w)

    def _build_extra_group(self, item_type: str) -> None:
        w = QWidget()
        grid = QGridLayout(w)
        grid.setContentsMargins(0, 6, 0, 0)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)
        fields: dict[str, QLineEdit] = {}
        row = 0
        col = 0
        for key, text, sensitive in EXTRA_FIELDS[item_type]:
            widget = PasswordField(self.ctx, PLACEHOLDERS.get(key, "")) if sensitive else QLineEdit()
            if not sensitive:
                widget.setPlaceholderText(PLACEHOLDERS.get(key, ""))
            widget.setMaxLength(1000)
            fields[key] = widget
            wide = key in {"cardholder", "number", "address", "full_name", "company", "id_number"}
            if wide and col == 1:
                row += 2
                col = 0
            span = 2 if wide else 1
            grid.addWidget(_field_label(text), row, col, 1, span)
            grid.addWidget(widget, row + 1, col, 1, span)
            if wide or col == 1:
                row += 2
                col = 0
            else:
                col = 1
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        if item_type == "card":
            self.card_fields = fields
            self.card_hint = label("", "Muted")
            grid.addWidget(self.card_hint, row + 2, 0, 1, 2)
            fields["number"].textChanged.connect(self._card_number_changed)
        else:
            self.identity_fields = fields
        self.group_index[item_type] = self.groups.addWidget(w)

    def _card_number_changed(self, text: str) -> None:
        digits = digits_only(text)
        if not digits:
            self.card_hint.setText("")
        elif len(digits) >= 12:
            ok = luhn_valid(digits)
            self.card_hint.setText(f"{card_brand(digits)} · {'number looks valid' if ok else 'check the number — checksum does not match'}")
            self.card_hint.setStyleSheet(f"color: {self.ctx.palette.success if ok else self.ctx.palette.warning};")
        else:
            self.card_hint.setText(card_brand(digits))
            self.card_hint.setStyleSheet("")

    def set_type(self, item_type: str) -> None:
        self.item_type = item_type
        for key, btn in self.type_buttons.items():
            btn.setChecked(key == item_type)
            btn.setIcon(icons.icon(TYPE_ICONS[key], self.ctx.palette.accent if key == item_type else self.ctx.palette.muted))
        self.groups.setCurrentIndex(self.group_index[item_type])
        # size the stacked widget to the visible page only
        for i in range(self.groups.count()):
            page = self.groups.widget(i)
            page.setVisible(i == self.groups.currentIndex())
        self.groups.setFixedHeight(self.groups.currentWidget().sizeHint().height())
        verb = "Edit" if self.entry else "Add"
        self.heading.setText(f"{verb} {TYPE_LABELS[item_type].lower()}")
        self.setWindowTitle(self.heading.text())
        is_note = item_type == "note"
        self.notes_label.setText("NOTE *" if is_note else "NOTES")
        self.notes.setFixedHeight(220 if is_note else 84)
        self.notes.setPlaceholderText(
            "Write anything private — Wi-Fi details, recovery codes, licence keys… (encrypted)" if is_note
            else "Security questions, recovery codes, hints… (encrypted)")
        self.title.setPlaceholderText({
            "login": "e.g. Gmail, GitHub, BUBT portal", "note": "e.g. Router admin, Recovery codes",
            "card": "e.g. DBBL Visa (leave empty to name automatically)", "identity": "e.g. My details, Passport",
        }[item_type])
        self.title_label.setText("NAME" if item_type == "card" else "NAME *")
        self.title.setFocus()

    # ------------------------------------------------------------------ data
    def _load(self, entry: Entry | None, default_category: int | None, default_folder: int | None) -> None:
        cat_id, folder_id = default_category, default_folder
        if entry:
            self.title.setText(entry.title)
            self.url.setText(entry.url)
            self.username.setText(entry.username)
            self.password.setText(entry.password)
            self.notes.setPlainText(entry.notes)
            self.favorite.setChecked(entry.favorite)
            cat_id, folder_id = entry.category_id, entry.folder_id
            fields = {"card": getattr(self, "card_fields", {}), "identity": getattr(self, "identity_fields", {})}.get(entry.item_type, {})
            for key, widget in fields.items():
                widget.setText(entry.extra.get(key, ""))
        idx = self.category.findData(cat_id) if cat_id is not None else -1
        if idx < 0:
            default_name = {"card": "Banking & Finance", "identity": "Personal"}.get(self.item_type, "Personal")
            idx = max(self.category.findText(default_name), 0)
        self.category.setCurrentIndex(idx)
        fidx = self.folder.findData(folder_id) if folder_id is not None else 0
        self.folder.setCurrentIndex(max(fidx, 0))

    def generate(self) -> None:
        self.password.setText(generate_password(GeneratorOptions(length=20)))
        self.password.set_revealed(True)

    def _fail(self, text: str, widget=None) -> None:
        self.error.setText(text)
        self.error.show()
        for w in (self.title, self.password, self.url, self.notes):
            set_error(w, w is widget)
        if widget is not None:
            widget.setFocus()

    def _extra(self) -> dict:
        fields = {"card": self.card_fields, "identity": self.identity_fields}.get(self.item_type, {})
        return {key: w.text() for key, w in fields.items()}

    def save(self) -> None:
        t = self.item_type
        values = {
            "title": self.title.text().strip(),
            "notes": self.notes.toPlainText(),
            "category_id": self.category.currentData(),
            "folder_id": self.folder.currentData(),
            "favorite": self.favorite.isChecked(),
        }
        if t == "login":
            values.update(username=self.username.text().strip(), password=self.password.text(),
                          url=normalise_url(self.url.text()))
            if not values["password"]:
                self._fail("Password is required.", self.password)
                return
        else:
            values.update(username="", password="", url="")
        if t in ("card", "identity"):
            values["extra"] = self._extra()
        if t == "card":
            number = digits_only(values["extra"].get("number", ""))
            if not values["title"]:
                values["title"] = f"{card_brand(number)}{' •••• ' + number[-4:] if number else ''}"
            if len(number) >= 12 and not luhn_valid(number) and not confirm(
                    self, "Check card number", "This card number fails the standard checksum, so it may contain a "
                    "typo.\n\nSave it anyway?", "Save anyway"):
                return
        if t == "note" and not values["notes"].strip():
            self._fail("The note is empty.", self.notes)
            return
        if not values["title"]:
            self._fail("Name is required.", self.title)
            return
        try:
            if self.entry:
                self.saved_entry = self.ctx.vault.update_entry(self.entry.id, **values)
            else:
                self.saved_entry = self.ctx.vault.add_entry(item_type=t, **values)
        except ValidationError as exc:
            self._fail(str(exc), self.url if "URL" in str(exc) else None)
            return
        except DatabaseError as exc:
            self._fail(f"Could not save: {exc}")
            return
        self._clear_secrets()
        self.accept()

    def _clear_secrets(self) -> None:
        self.password.secure_clear()
        for w in list(getattr(self, "card_fields", {}).values()) + list(getattr(self, "identity_fields", {}).values()):
            w.clear()

    def reject(self) -> None:
        self._clear_secrets()
        super().reject()


# Backwards-compatible name
AccountDialog = ItemDialog
