@echo off
REM 관리자 권한으로 실행되었는지 확인
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo 관리자 권한으로 다시 실행합니다...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

cd /d "%~dp0"

REM 가상환경의 main.py 실행
call .venv\Scripts\activate.bat
python content/main.py

pause