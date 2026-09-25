@echo off
title Wi-Fi Captive Portal
cd /d "%~dp0"
echo ========================================================
echo  Starting Cyberpunk Wi-Fi Captive Portal...
echo  Local URL: http://localhost:5000
echo ========================================================
"%~dp0venv\Scripts\python.exe" "%~dp0app.py"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Server process ended with code %ERRORLEVEL%
)
pause
