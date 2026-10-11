@echo off
chcp 65001 >nul
title 清理 Visual Studio 残留

REM 自动请求管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>&1
    exit /b
)

echo ================================================
echo   清理 Visual Studio 残留文件
echo ================================================
echo.
echo 将删除以下内容:
echo   1. C:\Program Files\Microsoft Visual Studio\2022  (半截安装的残留)
echo   2. C:\ProgramData\Microsoft\VisualStudio\Packages   (包缓存)
echo   3. D:\VS2022-Cache                                  (安装引导程序缓存)
echo   4. 用户配置残留
echo.
echo 注意: 这些是本次未完成的安装产生的残留，
echo       删除后你可以自行下载安装全新的 Visual Studio。
echo.
pause

echo.
echo [1/5] 停止可能残留的 VS 进程...
taskkill /F /IM vs_installer.exe >nul 2>&1
taskkill /F /IM setup.exe >nul 2>&1
taskkill /F /IM vs_Community.exe >nul 2>&1
echo     完成

echo.
echo [2/5] 删除安装目录...
if exist "C:\Program Files\Microsoft Visual Studio\2022" (
    rmdir /s /q "C:\Program Files\Microsoft Visual Studio\2022"
    if exist "C:\Program Files\Microsoft Visual Studio\2022" (
        echo     [警告] 部分文件未能删除
    ) else (
        echo     [OK] 已删除
    )
) else (
    echo     [跳过] 不存在
)

echo.
echo [3/5] 删除包缓存...
if exist "C:\ProgramData\Microsoft\VisualStudio\Packages" (
    rmdir /s /q "C:\ProgramData\Microsoft\VisualStudio\Packages"
    echo     [OK] 已删除
) else (
    echo     [跳过] 不存在
)

echo.
echo [4/5] 删除 D 盘引导程序缓存...
if exist "D:\VS2022-Cache" (
    rmdir /s /q "D:\VS2022-Cache"
    echo     [OK] 已删除
) else (
    echo     [跳过] 不存在
)
if exist "D:\VS2022-Shared" (
    rmdir /s /q "D:\VS2022-Shared"
    echo     [OK] 已删除
) else (
    echo     [跳过] VS2022-Shared 不存在
)

echo.
echo [5/5] 删除用户配置残留...
if exist "%LOCALAPPDATA%\Microsoft\VisualStudio\Packages" (
    rmdir /s /q "%LOCALAPPDATA%\Microsoft\VisualStudio\Packages"
    echo     [OK] 已删除 Packages
) else (
    echo     [跳过] Packages 不存在
)

echo.
echo ================================================
echo   清理完成
echo ================================================
echo.
echo 现在你可以自行下载安装 Visual Studio 了。
echo 官方下载地址: https://visualstudio.microsoft.com/zh-hans/downloads/
echo.
pause
