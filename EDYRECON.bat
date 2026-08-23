@echo off
chcp 65001 >nul
title EDY RECON - OSINT + BRUTE FORCE - SURFACE
cd /d "%~dp0"

set "VENV_PY=%~dp0.venv\Scripts\python.exe"
if exist "%VENV_PY%" goto :venv_ok

echo [X] Ambiente virtual .venv nao encontrado.
echo     Rode primeiro: instalar_windows.bat
pause
exit /b 1

:venv_ok
"%VENV_PY%" -B "%~dp0edyrecon.py" %*
set "EDYRECON_EXIT=%ERRORLEVEL%"

echo.
echo [*] EDY RECON encerrado.
pause
exit /b %EDYRECON_EXIT%
