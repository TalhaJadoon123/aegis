@echo off
REM Start Aegis without typing anything.
REM Double-click this file. Aegis opens in its own window.
setlocal
set "PATH=C:\node22\node-v22.23.3-win-x64;%PATH%"
cd /d "%~dp0"

echo.
echo   Starting Aegis...
echo   The dashboard opens in a moment. Close the window to stop it.
echo.

node --experimental-strip-types --import ./tools/register-ts.mjs packages/cli/src/bin.ts desktop %*

echo.
echo   Aegis stopped.
pause