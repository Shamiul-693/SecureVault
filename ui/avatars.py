"""Item avatars: rounded tiles with initials or a type glyph, drawn locally.

No favicons are fetched — SecureVault never contacts websites. The colour is
derived deterministically from the site/domain so the same service always
gets the same tile.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from urllib.parse import urlparse

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPixmap

from core.vault import Entry, card_brand

from . import icons

COLORS = [
    "#4f8cff", "#7c5cff", "#e5484d", "#f76b15", "#ffb224", "#30a46c", "#12a594",
    "#0091ff", "#d6409f", "#8e4ec6", "#3e63dd", "#46a758", "#ad7f58", "#e54666",
]
TYPE_GLYPH = {"note": ("note", "#f0b54a"), "card": ("card", "#3e63dd"), "identity": ("user", "#30a46c")}
BRAND_COLORS = {"Visa": "#1a1f71", "Mastercard": "#eb001b", "Amex": "#2e77bc", "Discover": "#f76f20",
                "JCB": "#0b4ea2", "UnionPay": "#d10429"}


def site_key(entry: Entry) -> str:
    if entry.url:
        host = urlparse(entry.url if "://" in entry.url else "https://" + entry.url).hostname or ""
        parts = [p for p in host.split(".") if p and p != "www"]
        if len(parts) >= 2:
            return parts[-2] if parts[-2] not in {"co", "com", "ac", "edu", "gov", "org", "net"} or len(parts) < 3 else parts[-3]
        if parts:
            return parts[0]
    return entry.title


def initials(text: str) -> str:
    words = [w for w in "".join(c if c.isalnum() else " " for c in text).split() if w]
    if not words:
        return "?"
    if len(words) == 1:
        return words[0][:2].capitalize() if len(words[0]) > 1 else words[0][0].upper()
    return (words[0][0] + words[1][0]).upper()


def color_for(key: str) -> str:
    digest = hashlib.sha256(key.casefold().encode("utf-8")).digest()
    return COLORS[digest[0] % len(COLORS)]


@lru_cache(maxsize=1024)
def _tile(text: str, bg: str, glyph: str | None, size: int, dpr: float = 2.0) -> QPixmap:
    pm = QPixmap(int(size * dpr), int(size * dpr))
    pm.fill(Qt.transparent)
    pm.setDevicePixelRatio(dpr)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    path = QPainterPath()
    path.addRoundedRect(QRectF(0, 0, size, size), size * 0.26, size * 0.26)
    p.fillPath(path, QColor(bg))
    if glyph:
        p.drawPixmap(int(size * 0.2), int(size * 0.2), icons.pixmap(glyph, "#ffffff", int(size * 0.6)))
    else:
        font = QFont()
        font.setBold(True)
        font.setPixelSize(int(size * (0.5 if len(text) == 1 else 0.42 if len(text) == 2 else 0.27)))
        p.setFont(font)
        p.setPen(QColor("#ffffff"))
        p.drawText(QRectF(0, 0, size, size), Qt.AlignCenter, text)
    p.end()
    return pm


def avatar(entry: Entry, size: int = 34) -> QPixmap:
    if entry.item_type == "card":
        brand = card_brand(entry.extra.get("number", ""))
        if brand in BRAND_COLORS:
            label = {"Mastercard": "MC", "UnionPay": "UP"}.get(brand, brand[:4].upper() if brand != "Visa" else "VISA")
            return _tile(label[:4], BRAND_COLORS[brand], None, size)
    if entry.item_type in TYPE_GLYPH:
        glyph, bg = TYPE_GLYPH[entry.item_type]
        return _tile("", bg, glyph, size)
    key = site_key(entry)
    return _tile(initials(key), color_for(key), None, size)
