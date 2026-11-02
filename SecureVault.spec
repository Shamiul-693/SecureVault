# -*- mode: python ; coding: utf-8 -*-
# PyInstaller build specification for SecureVault.
#   Build:  pyinstaller --noconfirm --clean SecureVault.spec
#   Output: dist\SecureVault.exe   (single file, no console window)
import sys
from pathlib import Path

ROOT = Path(SPECPATH)
ICON = str(ROOT / "resources" / "icons" / "securevault.ico")
IS_WIN = sys.platform == "win32"

# Large Qt modules SecureVault never uses — excluded to keep the EXE small.
EXCLUDES = [
    "tkinter", "unittest", "pydoc", "PIL",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
    "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets", "PySide6.Qt3DCore",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets", "PySide6.QtCharts",
    "PySide6.QtDataVisualization", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    "PySide6.QtBluetooth", "PySide6.QtPositioning", "PySide6.QtSensors",
    "PySide6.QtSerialPort", "PySide6.QtWebSockets", "PySide6.QtNetworkAuth",
    "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtSql", "PySide6.QtTest",
]

a = Analysis(
    ["main.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[(str(ROOT / "resources"), "resources")],
    hiddenimports=["_cffi_backend", "argon2.low_level", "PySide6.QtSvg"],
    hookspath=[],
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SecureVault",
    debug=False,
    strip=False,
    upx=False,            # UPX-packed EXEs trigger antivirus false positives
    console=False,        # windowed: no terminal window
    disable_windowed_traceback=False,
    icon=ICON if IS_WIN else None,
    version=str(ROOT / "version_info.txt") if IS_WIN else None,
)
