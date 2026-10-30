@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -X utf8 scripts\setup_local.py
echo.
echo Exit code: %errorlevel%
pause
