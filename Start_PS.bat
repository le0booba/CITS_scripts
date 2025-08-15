@echo off

fsutil dirty query %systemdrive% >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo This script requires ADMIN permissions
    echo Please, run it as Administrator
    echo.
    pause
    exit /b 1
)

powershell -NoProfile -NoExit -ExecutionPolicy Bypass -Command "& {Set-Location -Path '%~dp0'; Get-ExecutionPolicy -List}"