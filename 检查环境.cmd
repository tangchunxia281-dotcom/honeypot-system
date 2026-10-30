@echo off
chcp 65001 >nul
cd /d "%~dp0"
".venv-local\Scripts\python.exe" -X utf8 scripts\competition.py doctor
echo.
echo Exit code: %errorlevel%
pause
