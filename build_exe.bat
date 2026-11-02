@echo off
REM ============================================================
REM  SecureVault - Windows build script
REM  Creates a virtual environment, installs dependencies,
REM  runs the test suite and builds dist\SecureVault.exe
REM ============================================================
setlocal
cd /d "%~dp0"

echo [1/5] Checking Python...
where py >nul 2>nul
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 (
    echo ERROR: Python 3.11 or newer is required. Install it from https://www.python.org/downloads/
    exit /b 1
)

echo [2/5] Creating virtual environment (.venv)...
if not exist ".venv\Scripts\python.exe" (
    %PY% -m venv .venv || (echo ERROR: could not create venv & exit /b 1)
)
call ".venv\Scripts\activate.bat"

echo [3/5] Installing dependencies...
python -m pip install --upgrade pip >nul
pip install -r requirements-dev.txt || (echo ERROR: dependency install failed & exit /b 1)

echo [4/5] Running tests...
set QT_QPA_PLATFORM=offscreen
python -m pytest -q || (echo ERROR: tests failed - build aborted & exit /b 1)
set QT_QPA_PLATFORM=

echo [5/5] Building SecureVault.exe...
pyinstaller --noconfirm --clean SecureVault.spec || (echo ERROR: PyInstaller build failed & exit /b 1)

echo.
echo ============================================================
echo  Build complete:  %CD%\dist\SecureVault.exe
echo  Optional portable mode: put an empty file named
echo  portable.flag next to the EXE.
echo ============================================================
endlocal
