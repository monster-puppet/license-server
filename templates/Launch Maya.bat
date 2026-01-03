@echo off
setlocal enabledelayedexpansion

set "version=2024"

set "regKey=HKEY_LOCAL_MACHINE\SOFTWARE\Autodesk\Maya\!version!\Setup\InstallPath"
set "current_folder=%~dp0"
set "maya_root_path=%current_folder%Tools\Maya"

set "MAYA_MODULE_PATH=!maya_root_path!"

:: Check if the Maya Registry Key exists
reg query "!regKey!" /v MAYA_INSTALL_LOCATION > nul 2>&1
if errorlevel 1 (
    echo Error: Maya installation path for version !version! not found.
    echo Please check your Maya installation.
) else (
    for /f "tokens=2*" %%a in ('reg query "!regKey!" /v MAYA_INSTALL_LOCATION') do (
        set "mayaPath=%%b"
    )

    :: find maya installation path
    if exist "!mayaPath!\bin\maya.exe" (
        :: install external python packages
        "!mayaPath!\bin\mayapy.exe" -m pip install --upgrade pip
        "!mayaPath!\bin\mayapy.exe" -m pip install -r "R:\Tools\Maya\requirements.txt"

        :: Recursively find all .mod files and extend MAYA_MODULE_PATH
        for /r "%MAYA_MODULE_PATH%" %%i in (*.mod) do (
            set "module_dir=%%~dpi"
            set "module_dir=!module_dir:~0,-1!"
            echo Module detected in: !module_dir!
            set "MAYA_MODULE_PATH=!MAYA_MODULE_PATH!;!module_dir!"
        )
        set "MAYA_PROJECT=R:\"
        :: Launch Maya and inject environment variables
        cd /d "!mayaPath!\bin" 
        start "" /min "!mayaPath!\bin\maya.exe"
    ) else (
        echo Error: Maya executable not found at "!mayaPath!\bin\maya.exe".
        echo Please check your Maya installation.
    )
)
