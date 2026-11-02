"""Dark and light themes as Qt stylesheets built from a small palette."""
from __future__ import annotations

import sys
from dataclasses import dataclass

from app.config import resource_dir


@dataclass(frozen=True)
class Palette:
    name: str
    bg: str
    sidebar: str
    surface: str
    surface_alt: str
    border: str
    text: str
    muted: str
    accent: str
    accent_hover: str
    accent_text: str
    accent_soft: str
    danger: str
    danger_soft: str
    warning: str
    success: str
    selection: str


DARK = Palette(
    name="dark",
    bg="#0f1419", sidebar="#0b0f14", surface="#171d25", surface_alt="#1e2631",
    border="#2a3441", text="#e6ebf1", muted="#8a96a6",
    accent="#4f8cff", accent_hover="#6a9eff", accent_text="#ffffff", accent_soft="#1c2c48",
    danger="#ef5d5d", danger_soft="#3a1d22", warning="#f0b54a", success="#3ecf8e",
    selection="#24324a",
)

LIGHT = Palette(
    name="light",
    bg="#f4f6fa", sidebar="#ffffff", surface="#ffffff", surface_alt="#f0f3f8",
    border="#dde3ec", text="#18212d", muted="#667386",
    accent="#2f6fed", accent_hover="#255fd1", accent_text="#ffffff", accent_soft="#e5eeff",
    danger="#d64545", danger_soft="#fde8e8", warning="#c98a12", success="#1f9d63",
    selection="#dce8ff",
)

THEMES = {"dark": DARK, "light": LIGHT}
STRENGTH_COLORS = ["danger", "danger", "warning", "success", "success"]

FONT_FAMILY = "Segoe UI" if sys.platform == "win32" else "Inter, Segoe UI, Helvetica Neue, Arial"
MONO_FAMILY = "Cascadia Mono, Consolas, Menlo, DejaVu Sans Mono, monospace"


def get_palette(name: str) -> Palette:
    return THEMES.get(name, DARK)


def strength_color(p: Palette, score: int) -> str:
    return getattr(p, STRENGTH_COLORS[max(0, min(score, 4))])


def _icon_url(name: str) -> str:
    return (resource_dir() / "icons" / name).as_posix()


def build_stylesheet(p: Palette) -> str:
    check = _icon_url("check.svg")
    chevron = _icon_url("chevron-down.svg")
    return f"""
* {{ font-family: {FONT_FAMILY}; font-size: 10pt; color: {p.text}; }}
QWidget {{ background: transparent; }}
QMainWindow, QDialog, #LoginRoot, #PageRoot {{ background: {p.bg}; }}
QToolTip {{ background: {p.surface_alt}; color: {p.text}; border: 1px solid {p.border}; padding: 6px; border-radius: 6px; }}

/* ---------- Sidebar ---------- */
#Sidebar {{ background: {p.sidebar}; border-right: 1px solid {p.border}; }}
#BrandTitle {{ font-size: 13pt; font-weight: 700; }}
#BrandSubtitle {{ color: {p.muted}; font-size: 8.5pt; }}
#NavButton {{
    text-align: left; padding: 10px 14px; border: none; border-radius: 10px;
    color: {p.muted}; font-weight: 600; background: transparent;
}}
#NavButton:hover {{ background: {p.surface_alt}; color: {p.text}; }}
#NavButton:checked {{ background: {p.accent_soft}; color: {p.accent}; }}
#SidebarFooterButton {{
    text-align: left; padding: 9px 14px; border: 1px solid {p.border}; border-radius: 10px;
    color: {p.text}; background: {p.surface};
}}
#SidebarFooterButton:hover {{ border-color: {p.accent}; }}

/* ---------- Typography ---------- */
#PageTitle {{ font-size: 18pt; font-weight: 700; }}
#PageSubtitle {{ color: {p.muted}; }}
#SectionTitle {{ font-size: 11.5pt; font-weight: 700; }}
#Muted, QLabel[muted="true"] {{ color: {p.muted}; }}
#FieldLabel {{ color: {p.muted}; font-size: 8.5pt; font-weight: 600; letter-spacing: 0.5px; }}
#FieldValue {{ font-size: 10.5pt; }}
#MonoValue {{ font-family: {MONO_FAMILY}; font-size: 11pt; }}
#BigNumber {{ font-size: 22pt; font-weight: 700; }}
#ErrorLabel {{ color: {p.danger}; }}
#SuccessLabel {{ color: {p.success}; }}
#Chip {{ background: {p.accent_soft}; color: {p.accent}; border-radius: 9px; padding: 2px 10px; font-size: 8.5pt; font-weight: 600; }}

/* ---------- Cards ---------- */
#Card {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: 14px; }}
#LoginCard {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: 18px; }}
#StatIcon {{ background: {p.accent_soft}; border-radius: 10px; }}
#Divider {{ background: {p.border}; max-height: 1px; min-height: 1px; }}

/* ---------- Buttons ---------- */
QPushButton {{
    background: {p.surface_alt}; border: 1px solid {p.border}; border-radius: 9px;
    padding: 8px 16px; font-weight: 600;
}}
QPushButton:hover {{ border-color: {p.accent}; }}
QPushButton:pressed {{ background: {p.selection}; }}
QPushButton:disabled {{ color: {p.muted}; border-color: {p.border}; background: {p.surface}; }}
QPushButton[variant="primary"] {{ background: {p.accent}; color: {p.accent_text}; border: 1px solid {p.accent}; }}
QPushButton[variant="primary"]:hover {{ background: {p.accent_hover}; border-color: {p.accent_hover}; }}
QPushButton[variant="primary"]:disabled {{ background: {p.accent_soft}; color: {p.muted}; border-color: {p.accent_soft}; }}
QPushButton[variant="danger"] {{ background: {p.danger_soft}; color: {p.danger}; border: 1px solid {p.danger_soft}; }}
QPushButton[variant="danger"]:hover {{ border-color: {p.danger}; }}
QPushButton[variant="ghost"] {{ background: transparent; border: 1px solid transparent; color: {p.muted}; padding: 6px 10px; }}
QPushButton[variant="ghost"]:hover {{ background: {p.surface_alt}; color: {p.text}; }}
QToolButton {{ background: transparent; border: none; border-radius: 7px; padding: 5px; }}
QToolButton:hover {{ background: {p.surface_alt}; }}

/* ---------- Inputs ---------- */
QLineEdit, QPlainTextEdit, QSpinBox, QComboBox {{
    background: {p.surface_alt}; border: 1px solid {p.border}; border-radius: 9px;
    padding: 8px 10px; selection-background-color: {p.accent}; selection-color: {p.accent_text};
}}
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus {{ border: 1px solid {p.accent}; }}
QLineEdit[error="true"] {{ border: 1px solid {p.danger}; }}
QLineEdit:read-only {{ color: {p.text}; }}
#GeneratedPassword {{ font-family: {MONO_FAMILY}; font-size: 15pt; padding: 14px; letter-spacing: 1px; }}
QComboBox::drop-down {{ border: none; width: 28px; }}
QComboBox::down-arrow {{ image: url("{chevron}"); width: 14px; height: 14px; }}
QComboBox QAbstractItemView {{
    background: {p.surface}; border: 1px solid {p.border}; selection-background-color: {p.selection};
    selection-color: {p.text}; outline: none; padding: 4px;
}}
QSpinBox::up-button, QSpinBox::down-button {{ width: 18px; border: none; }}
QCheckBox, QRadioButton {{ spacing: 8px; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 18px; height: 18px; }}
QCheckBox::indicator {{ border: 1px solid {p.border}; border-radius: 5px; background: {p.surface_alt}; }}
QCheckBox::indicator:checked {{ background: {p.accent}; border-color: {p.accent}; image: url("{check}"); }}
QRadioButton::indicator {{ border: 1px solid {p.border}; border-radius: 9px; background: {p.surface_alt}; }}
QRadioButton::indicator:checked {{ background: {p.accent}; border: 4px solid {p.surface_alt}; outline: 1px solid {p.accent}; }}

QSlider::groove:horizontal {{ height: 6px; background: {p.surface_alt}; border-radius: 3px; border: 1px solid {p.border}; }}
QSlider::sub-page:horizontal {{ background: {p.accent}; border-radius: 3px; }}
QSlider::handle:horizontal {{ background: {p.accent_text}; border: 2px solid {p.accent}; width: 16px; height: 16px; margin: -6px 0; border-radius: 9px; }}

QProgressBar {{ background: {p.surface_alt}; border: none; border-radius: 3px; max-height: 6px; min-height: 6px; text-align: center; }}
QProgressBar::chunk {{ border-radius: 3px; }}

/* ---------- Lists & tables ---------- */
QTableWidget, QListWidget, QTreeWidget {{
    background: {p.surface}; border: 1px solid {p.border}; border-radius: 12px;
    gridline-color: transparent; outline: none; alternate-background-color: {p.surface_alt};
}}
QTableWidget::item, QListWidget::item, QTreeWidget::item {{ padding: 8px 6px; border: none; }}
QTableWidget::item:selected, QListWidget::item:selected, QTreeWidget::item:selected {{
    background: {p.selection}; color: {p.text};
}}
QListWidget::item:hover, QTreeWidget::item:hover {{ background: {p.surface_alt}; }}
QHeaderView::section {{
    background: {p.surface}; color: {p.muted}; border: none; border-bottom: 1px solid {p.border};
    padding: 8px 6px; font-weight: 600; font-size: 8.5pt;
}}
QTableCornerButton::section {{ background: {p.surface}; border: none; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {p.border}; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {p.muted}; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {p.border}; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QScrollArea {{ border: none; background: transparent; }}
QSplitter::handle {{ background: transparent; width: 12px; }}

QMessageBox {{ background: {p.surface}; }}
QMessageBox QLabel {{ min-width: 320px; }}
QMenu {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: 8px; padding: 4px; }}
QMenu::item {{ padding: 7px 18px; border-radius: 6px; }}
QMenu::item:selected {{ background: {p.selection}; }}
"""
