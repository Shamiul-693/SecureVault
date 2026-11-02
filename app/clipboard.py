"""Clipboard handling with automatic clearing.

* Copies are cleared after a configurable timeout — but only if the
  clipboard still holds what SecureVault put there (we never wipe something
  the user copied afterwards).
* On Windows, copied secrets are tagged so they are excluded from
  Clipboard History (Win+V) and cloud clipboard sync.
* We keep only an HMAC fingerprint of the copied text (with a random
  per-session key), never a second plaintext copy.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sys

from PySide6.QtCore import QByteArray, QMimeData, QObject, QTimer, Signal
from PySide6.QtGui import QGuiApplication

_WIN_FORMATS = {
    # Registered clipboard formats honoured by Windows 10/11 clipboard history & cloud sync.
    'application/x-qt-windows-mime;value="ExcludeClipboardContentFromMonitorProcessing"': b"\x00",
    'application/x-qt-windows-mime;value="CanIncludeInClipboardHistory"': b"\x00\x00\x00\x00",
    'application/x-qt-windows-mime;value="CanUploadToCloudClipboard"': b"\x00\x00\x00\x00",
}


class ClipboardManager(QObject):
    copied = Signal(str)   # human label, e.g. "Password"
    cleared = Signal()

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._session_key = secrets.token_bytes(32)
        self._fingerprint: bytes | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.clear_if_ours)
        self.timeout_seconds = 20

    def _fp(self, text: str) -> bytes:
        return hmac.new(self._session_key, text.encode("utf-8"), hashlib.sha256).digest()

    def copy(self, text: str, what: str = "Text", sensitive: bool = True) -> None:
        clipboard = QGuiApplication.clipboard()
        mime = QMimeData()
        mime.setText(text)
        if sensitive and sys.platform == "win32":
            for fmt, value in _WIN_FORMATS.items():
                mime.setData(fmt, QByteArray(value))
        clipboard.setMimeData(mime)
        if sensitive:
            self._fingerprint = self._fp(text)
            if self.timeout_seconds > 0:
                self._timer.start(self.timeout_seconds * 1000)
            else:
                self._timer.stop()
        self.copied.emit(what)

    def clear_if_ours(self) -> None:
        self._timer.stop()
        if self._fingerprint is None:
            return
        clipboard = QGuiApplication.clipboard()
        current = clipboard.text()
        if current and hmac.compare_digest(self._fp(current), self._fingerprint):
            clipboard.clear()
            self.cleared.emit()
        self._fingerprint = None

    @property
    def pending(self) -> bool:
        return self._fingerprint is not None
