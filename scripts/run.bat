@echo off
if /I "%~1"=="demo" (
    set ROOT_DIR=%~dp0..
    cd /d %ROOT_DIR%
    chcp 65001 >nul
    uv --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [错误] 未检测到 `uv` 工具，无法执行答辩演示脚本。
        exit /b 1
    )
    shift
    if "%~1"=="" (
        uv run python scripts\demo\defense_demo.py --reuse-running
    ) else (
        uv run python scripts\demo\defense_demo.py %*
    )
    exit /b %errorlevel%
)

set ROOT_DIR=%~dp0..
cd /d %ROOT_DIR%
chcp 65001
cls
title 蜜罐防御系统

echo ========================================================
echo     网络威胁态势感知与蜜罐诱捕系统 - 启动脚本
echo ========================================================
echo.

if not defined HONEYPOT_CONFIG set HONEYPOT_CONFIG=%cd%\honeypot.ini

if not exist "%HONEYPOT_CONFIG%" (
    copy /Y honeypot.ini.example "%HONEYPOT_CONFIG%" >nul
    echo [Init] 已生成根目录配置文件: %HONEYPOT_CONFIG%
    echo [Info] 请编辑 honeypot.ini（尤其是 [app] production_mode、[admin] password、[alerting] webhook_url）后重新运行。
    pause
    exit /b 1
)

echo [1/3] 正在检查 UV 环境...
uv --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到 `uv` 工具。
    echo 请先安装 uv（推荐使用官方安装方式）。
    echo 参考 https://github.com/astral-sh/uv 获取安装指南。
    pause
    exit /b 1
)

if not exist .secret_key (
    uv run python -c "import os; print(os.urandom(32).hex())" > .secret_key
    echo [Init] 已生成 .secret_key
)

echo [2/3] 正在同步环境与依赖...
uv sync

echo [Check] 校验统一配置: %HONEYPOT_CONFIG%
uv run python -c "from app_config import config, describe_config_source, validate_runtime_config, is_production; validate_runtime_config(); c=config['default']; print('[Config] source=' + describe_config_source()); print('[Config] mode=' + ('production' if is_production() else 'development')); print('[Config] db=' + str(c.DB_TYPE))"
if %errorlevel% neq 0 (
    echo [错误] 配置校验失败，请检查 honeypot.ini。
    pause
    exit /b 1
)

echo.
echo [3/3] 启动主控制系统...
echo [Run ] uv run python main.py
uv run python main.py

pause
