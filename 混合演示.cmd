@echo off
chcp 65001 >nul
cd /d "%~dp0"
".venv-local\Scripts\python.exe" -X utf8 scripts\mixed_attack_demo.py --business --gap 4
echo.
echo Exit code: %errorlevel%
pause
