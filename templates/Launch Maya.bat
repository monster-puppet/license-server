@echo off
setlocal

set "version=2024"

call :getRegKey regKey
set "current_folder=%~dp0"
set "maya_root_path=%current_folder%Tools\Maya"
set "MAYA_MODULE_PATH=%current_folder%Tools\Maya"

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

:: Recursively find all .mod files and extend MAYA_MODULE_PATH
setlocal enabledelayedexpansion
for /r "%MAYA_MODULE_PATH%" %%i in (*.mod) do (
    set "module_dir=%%~dpi"
    set "module_dir=!module_dir:~0,-1!"
    echo Module detected in: !module_dir!
    set "MAYA_MODULE_PATH=!MAYA_MODULE_PATH!;!module_dir!"
)

set "MAYA_PROJECT=R:\"

:: Launch Maya - use endlocal with variable passthrough
for /f "delims=" %%M in ("!MAYA_MODULE_PATH!") do (
    for /f "delims=" %%P in ("!mayaPath!") do (
        endlocal
        endlocal
        set "MAYA_MODULE_PATH=%%M"
        set "MAYA_PROJECT=R:\"
        cd /d "%%P\bin"
        start "" /min "%%P\bin\maya.exe"
    )
)
goto :eof

:getRegKey
set "%1=HKEY_LOCAL_MACHINE\SOFTWARE\Autodesk\Maya\%version%\Setup\InstallPath"
goto :eof
