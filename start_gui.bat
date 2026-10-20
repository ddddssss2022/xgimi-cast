@echo off
chcp 65001 >nul
cd /d "%~dp0"

where pythonw >nul 2>&1
if %errorlevel%==0 (
    start "" pythonw "%~dp0projector.py" --gui
    exit /b
)

where python >nul 2>&1
if %errorlevel%==0 (
    start "" python "%~dp0projector.py" --gui
    exit /b
)

echo 没有找到 pythonw / python，请确认 Python 已加入 PATH。
echo 也可以手动运行: python projector.py --gui
pause
