@echo off
REM 가상환경 생성
python -m venv .venv

REM 가상환경의 pip로 requirements 설치
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt

REM 완료 메시지
echo.
echo 설치 완료!
pause