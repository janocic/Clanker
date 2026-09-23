@echo off
setlocal

:: Self-elevate (deleting firewall rules needs Administrator).
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Trazim Administrator ovlasti...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo === Uklanjam sva guard-block firewall pravila ===
.venv\Scripts\python.exe -m guard.main unblock-all

echo.
pause
