@echo off
REM ============================================
REM  OpenClaw Installer for Windows
REM  Right-click → Run as Administrator
REM ============================================

echo.
echo ============================================
echo   OpenClaw + ClawMoat Installer
echo   Powered by ClawMoat
echo ============================================
echo.
echo This will set up WSL2, Ubuntu, and your
echo AI agent. It takes about 10 minutes.
echo.
pause

REM Check for admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo ERROR: Please right-click this file and
    echo select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

REM Download and run PowerShell setup
echo.
echo Downloading installer...
powershell -ExecutionPolicy Bypass -Command "& { irm https://raw.githubusercontent.com/darfaz/openclaw-deploy/main/setup-windows.ps1 | iex }"

echo.
echo ============================================
echo   Almost done! Open Ubuntu from Start Menu
echo   and run:
echo.
echo   1. claude login
echo   2. openclaw gateway restart
echo.
echo   Then message your bot!
echo ============================================
echo.
pause
