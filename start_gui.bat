@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "PY=C:\Users\ss\.workbuddy\binaries\python\versions\3.14.3\pythonw.exe"
if not exist "%PY%" set "PY=pythonw"
start "" "%PY%" "%~dp0projector.py" --gui
