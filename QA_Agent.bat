@echo off
setlocal EnableDelayedExpansion
title QA Automation Agent
cd /d "%~dp0"

echo.
echo   ============================================================
echo     QA AUTOMATION AGENT  -  Panel de Control
echo     auditoria local y autonoma  ^|  nada sale de tu maquina
echo   ============================================================
echo.

set "PYTHON_EXE="

rem --- prefer the project's virtual environment ---
if exist ".venv\Scripts\pythonw.exe" set "PYTHON_EXE=.venv\Scripts\pythonw.exe"
if exist ".venv\Scripts\python.exe"  set "PYTHON_EXE=.venv\Scripts\python.exe"

rem --- fall back to any Python on PATH ---
if not defined PYTHON_EXE (
    where pythonw >nul 2>nul && set "PYTHON_EXE=pythonw"
)
if not defined PYTHON_EXE (
    where python >nul 2>nul && set "PYTHON_EXE=python"
)

if not defined PYTHON_EXE (
    echo   [X] No se encontro Python.
    echo       Instala Python 3.10+ o crea el entorno:
    echo           python -m venv .venv
    echo           .venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 2
)

rem --- tkinter guard (fails before opening a window that cannot render) ---
"%PYTHON_EXE%" -c "import tkinter" >nul 2>nul
if errorlevel 1 (
    echo   [X] Este Python no tiene tkinter ^(interfaz grafica^).
    echo       Reinstala Python marcando la opcion "tcl/tk and IDLE".
    echo.
    pause
    exit /b 2
)

echo   [OK] Entorno listo. Abriendo el panel de control...
echo.
start "" "%PYTHON_EXE%" gui.py
exit /b 0
