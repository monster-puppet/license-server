@echo off
setlocal

set "version=2024"

set "regKey=HKEY_LOCAL_MACHINE\SOFTWARE\Autodesk\Maya\%version%\Setup\InstallPath"
set "current_folder=%~dp0"
set "maya_root_path=%current_folder%Tools\Maya"

:: Check if the Maya Registry Key exists
reg query "%regKey%" /v MAYA_INSTALL_LOCATION > nul 2>&1
if errorlevel 1 (
    echo Error: Maya installation path for version %version% not found.
    echo Please check your Maya installation.
    pause
    exit /b 1
)

for /f "tokens=2*" %%a in ('reg query "%regKey%" /v MAYA_INSTALL_LOCATION') do (
    set "mayaPath=%%b"
)

:: find maya installation path
if not exist "%mayaPath%\bin\maya.exe" (
    echo Error: Maya executable not found at "%mayaPath%\bin\maya.exe".
    echo Please check your Maya installation.
    pause
    exit /b 1
)

:: install external python packages
"%mayaPath%\bin\mayapy.exe" -m pip install --upgrade pip
"%mayaPath%\bin\mayapy.exe" -m pip install -r "%maya_root_path%\requirements.txt"

:: Find all .mod files
for /r "%maya_root_path%" %%i in (*.mod) do (
    echo Module detected in: %%~dpi
)

echo.
echo Launching Maya %version%...
echo.

:: End local and set environment for Maya
endlocal & (
    set "MAYA_MODULE_PATH=%current_folder%Tools\Maya"
    set "MAYA_SCRIPT_PATH=%current_folder%Tools\Maya\scripts"
    set "MAYA_PROJECT=R:\"
    cd /d "%mayaPath%\bin"
    "%mayaPath%\bin\maya.exe"
)
