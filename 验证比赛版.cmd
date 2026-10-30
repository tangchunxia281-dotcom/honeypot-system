@echo off
chcp 65001 >nul
cd /d "%~dp0"
".venv-local\Scripts\python.exe" -X utf8 scripts\verify_competition.py
echo.
echo Exit code: %errorlevel%
pause
