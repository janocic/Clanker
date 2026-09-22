@echo off
setlocal

:: Self-elevate to Administrator - WinDivert (DNS blocker) needs it,
:: and this way you never have to manually open an admin terminal.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Trazim Administrator ovlasti...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

echo.
echo === Git pull ===
git pull

echo.
echo === Python ovisnosti ===
call .venv\Scripts\python.exe -m pip install -r requirements.txt --quiet

echo.
echo === Web dashboard (npm install/build) ===
cd web
call npm.cmd install --silent
if errorlevel 1 goto :npmfail
call npm.cmd run build
if errorlevel 1 goto :npmfail
cd ..

echo.
echo === Pokretanje Clanker ===
echo.
.venv\Scripts\python.exe -m guard.main dns

pause
exit /b 0

:npmfail
echo.
echo NPM korak nije uspio - provjeri gresku iznad.
cd ..
pause
exit /b 1
