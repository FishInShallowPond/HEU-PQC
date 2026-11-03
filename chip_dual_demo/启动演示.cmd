@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto use_python
py -3 -B main.py %*
goto finished
:use_python
python -B main.py %*
:finished
if errorlevel 1 pause
endlocal
