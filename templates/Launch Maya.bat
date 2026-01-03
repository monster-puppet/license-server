@echo off

set "version=2024"

set "regKey=HKEY_LOCAL_MACHINE\SOFTWARE\Autodesk\Maya\%version%\Setup\InstallPath"
set "current_folder=%~dp0"
set "maya_root_path=%current_folder%Tools\Maya"
set "MAYA_MODULE_PATH=%current_folder%Tools\Maya"
set "MAYA_PROJECT=R:\"

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
"%mayaPath%\bin\mayapy.exe" -m pip install -r "R:\Tools\Maya\requirements.txt"

:: Find all .mod files and add their directories
for /r "%MAYA_MODULE_PATH%" %%i in (*.mod) do (
    echo Module detected in: %%~dpi
)

echo.
echo MAYA_MODULE_PATH = %MAYA_MODULE_PATH%
echo.

:: Launch Maya directly (not with start) so it inherits environment
cd /d "%mayaPath%\bin"
"%mayaPath%\bin\maya.exe"
