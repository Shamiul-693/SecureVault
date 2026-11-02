@echo off
REM Run SecureVault from source (after build_exe.bat or manual venv setup)
cd /d "%~dp0"
call ".venv\Scripts\activate.bat" && python main.py
