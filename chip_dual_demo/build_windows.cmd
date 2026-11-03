@echo off
setlocal
cd /d "%~dp0"
python -m PyInstaller --noconfirm --onefile --windowed --noupx --exclude-module numpy --additional-hooks-dir packaging_hooks --name LC01_DualChip_Demo_v2 --distpath bin --workpath build --specpath build main.py
if errorlevel 1 (
  echo Build failed. Install pyinstaller and requirements first.
  pause
  exit /b 1
)
echo Created: %~dp0bin\LC01_DualChip_Demo_v2.exe
pause
