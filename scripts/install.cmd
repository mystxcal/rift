@echo off
setlocal
title Install RIFT
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if errorlevel 1 (
  echo.
  echo RIFT installation failed.
  pause
  exit /b 1
)
echo.
echo RIFT is installed. Open a new terminal and run: rift doctor
pause
