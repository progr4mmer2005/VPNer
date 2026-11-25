@echo off
rem Builds VPNer into the dist folder: double-click it.
rem PowerShell scripts are blocked by default in Windows, so build.ps1 is
rem run with the execution policy bypassed for this one run only; no
rem Windows setting is changed.
chcp 65001 >nul
cd /d "%~dp0"
tasklist /fi "imagename eq vpner.exe" | find /i "vpner.exe" >nul && goto running
tasklist /fi "imagename eq mihomo.exe" | find /i "mihomo.exe" >nul && goto running
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
if errorlevel 1 (echo. & echo Сборка не удалась, смотрите сообщения выше.) else (echo. & echo Готово: dist\vpner.exe)
echo.
pause
exit /b
:running
echo VPNer запущен. Закройте его через значок в трее ^(Выход^) и запустите сборку снова.
echo.
pause
