@echo off
chcp 65001 >nul
title EDY RECON - Instalador Windows (Kali: use kali_install.sh)
cd /d "%~dp0"

echo =====================================================================
echo   EDY RECON - OSINT + BRUTE FORCE - SURFACE
echo   Instalador / atualizador para Windows
echo   Uso:  clique duas vezes neste arquivo  (ou:  instalar_windows.bat)
echo =====================================================================
echo.

rem ---------------------------------------------------------------
rem 1) Python 3 (apenas bootstrap do ambiente isolado)
rem ---------------------------------------------------------------
where py >nul 2>nul
if not errorlevel 1 goto :usar_py
where python >nul 2>nul
if not errorlevel 1 goto :usar_python

echo [X] Python 3 nao encontrado. Este instalador nao altera o Python global.
echo     Instale Python 3 por uma fonte oficial e execute novamente.
pause
exit /b 1

:usar_py
if not exist ".venv\Scripts\python.exe" py -3 -m venv .venv
goto :venv_criada

:usar_python
if not exist ".venv\Scripts\python.exe" python -m venv .venv

:venv_criada
if not exist ".venv\Scripts\python.exe" goto :falha_venv
set "VENV_PY=%CD%\.venv\Scripts\python.exe"
echo [OK] Ambiente virtual encontrado:
"%VENV_PY%" --version
echo.

rem ---------------------------------------------------------------
rem 2) Dependencias Python
rem ---------------------------------------------------------------
echo [*] Instalando somente as dependencias declaradas em requirements.txt na .venv...
"%VENV_PY%" -m pip install -r requirements.txt
if errorlevel 1 goto :falha_deps
"%VENV_PY%" -m pip check
if errorlevel 1 goto :falha_deps
echo [OK] Dependencias isoladas instaladas e verificadas.
echo.

rem ---------------------------------------------------------------
rem 3) Atalho na Area de Trabalho
rem ---------------------------------------------------------------
echo [*] Criando atalho "EDY RECON" na Area de Trabalho...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
 "$ws=New-Object -ComObject WScript.Shell;" ^
 "$d=[Environment]::GetFolderPath('Desktop');" ^
 "$s=$ws.CreateShortcut($d+'\EDY RECON.lnk');" ^
 "$s.TargetPath='%~dp0EDYRECON.bat';" ^
 "$s.WorkingDirectory='%~dp0';" ^
 "$s.Description='EDY RECON - OSINT + BRUTE FORCE - SURFACE';" ^
 "$s.Save()"

if exist "%USERPROFILE%\Desktop\EDY RECON.lnk" goto :atalho_ok
if exist "%OneDrive%\Desktop\EDY RECON.lnk" goto :atalho_ok
echo     aviso: atalho nao detectado - crie manualmente apontando para EDYRECON.bat
:atalho_ok
echo.

rem ---------------------------------------------------------------
rem 4) Fim
rem ---------------------------------------------------------------
echo =====================================================================
echo   [OK] Instalacao concluida!
echo        Agora e so executar:   EDYRECON.bat
echo        ou usar o atalho "EDY RECON" na Area de Trabalho
echo.
echo   Dicas:
echo     - Wordlists extras: menu 10 - CONFIGURACOES - item 3
echo     - Kali Linux: copie esta pasta e rode:  sudo bash kali_install.sh
echo =====================================================================
pause
exit /b 0

:falha_deps
echo [X] Falha ao instalar as dependencias. Verifique a internet e tente de novo.
pause
exit /b 1

:falha_venv
echo [X] Nao foi possivel criar .venv. Verifique se o modulo venv esta disponivel.
pause
exit /b 1
