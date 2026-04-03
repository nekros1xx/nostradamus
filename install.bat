@echo off
:: Nostradamus installer - Windows
:: Usage: install.bat [--uninstall]

setlocal enabledelayedexpansion

set "INSTALL_DIR=%USERPROFILE%\.nostradamus"

if "%1"=="--uninstall" (
    echo Uninstalling nostradamus...
    if exist "%INSTALL_DIR%" rmdir /s /q "%INSTALL_DIR%"
    :: Remove from PATH
    echo Removed %INSTALL_DIR%
    echo Please manually remove %INSTALL_DIR% from your PATH if you added it.
    goto :end
)

echo.
echo  _  _         _               _
echo ^| \^| ^|___ ___^| ^|_ _ _ __ _ __^| ^|__ _ _ __ _  _ ___
echo ^| .` / _ (_-^<^|  _^| '_/ _` / _` / _` ^| '  \ ^|^| (_-^<
echo ^|_^|\_\___/__/ \__^|_^| \__,_\__,_\__,_^|_^|_^|_\_,_/__/
echo.
echo Installing nostradamus...
echo.

:: Check Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    where python3 >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo ERROR: Python 3 is required but not found.
        echo Download from https://www.python.org/downloads/
        goto :end
    )
    set "PYTHON=python3"
) else (
    set "PYTHON=python"
)

:: Verify Python 3
%PYTHON% -c "import sys; exit(0 if sys.version_info[0]>=3 else 1)" 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python 3 is required.
    goto :end
)

:: Copy files
echo [1/3] Copying files to %INSTALL_DIR%...
if exist "%INSTALL_DIR%" rmdir /s /q "%INSTALL_DIR%"
xcopy /s /e /i /q "%~dp0" "%INSTALL_DIR%" >nul

:: Create batch launcher
echo [2/3] Creating launcher...
(
    echo @echo off
    echo %PYTHON% "%INSTALL_DIR%\nostradamus.py" %%*
) > "%INSTALL_DIR%\nostradamus.bat"

:: Add to PATH
echo [3/3] Configuring PATH...

:: Check if already in PATH
echo %PATH% | find /i "%INSTALL_DIR%" >nul
if %ERRORLEVEL% equ 0 (
    echo Already in PATH.
) else (
    :: Add to user PATH permanently
    for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USERPATH=%%b"
    if defined USERPATH (
        setx PATH "%USERPATH%;%INSTALL_DIR%" >nul 2>nul
    ) else (
        setx PATH "%INSTALL_DIR%" >nul 2>nul
    )
    set "PATH=%PATH%;%INSTALL_DIR%"
    echo Added to PATH. Restart your terminal for changes to take effect.
)

echo.
echo Installed successfully!
echo   Location: %INSTALL_DIR%
echo   Command:  nostradamus
echo.
echo Try it (open a new terminal first):
echo   nostradamus --version
echo   nostradamus -u "http://target.com/page?id=1" --batch --dbs

:end
endlocal
