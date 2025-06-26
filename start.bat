@echo off
REM admin check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo execute in admin mode
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

cd /d "%~dp0"

call .venv\Scripts\activate.bat
python content/main.py

pause
