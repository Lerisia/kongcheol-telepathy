@echo off
pip install virtualenv

python -m venv .venv

call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt

echo.
echo install fin
pause
