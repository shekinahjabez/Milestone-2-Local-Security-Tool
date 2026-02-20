@echo off
REM =============================================================
REM Local Security Tool - Portable Edition
REM Windows Launcher
REM =============================================================
REM Integrated Security Suite:
REM   - Network Port Scanner
REM   - Network Traffic Analyzer (Real-Time Monitoring)
REM
REM Runs directly from this folder. No installation required.
REM Copy the entire folder to a USB drive and run from there.
REM
REM Right-click -> "Run as administrator" for packet capture.
REM =============================================================

echo ============================================
echo        LOCAL SECURITY TOOL
echo        Portable Edition
echo ============================================
echo   Integrated Modules:
echo     [1] Network Port Scanner
echo     [2] Network Traffic Analyzer
echo ============================================
echo.

cd /d "%~dp0"

SET APP_EXE=%~dp0App\LocalSecurityTool\LocalSecurityTool.exe
SET APP_PY=%~dp0App\suite_main.py

REM Prefer compiled binary
IF EXIST "%APP_EXE%" (
    echo Running compiled Local Security Tool...
    "%APP_EXE%" %*
    GOTO :EOF
)

REM Fall back to Python source
IF NOT EXIST "%APP_PY%" GOTO :notfound

echo Running from Python source...
echo.

WHERE py >nul 2>nul
IF NOT ERRORLEVEL 1 (
    py -3 "%APP_PY%" %*
    GOTO :EOF
)

WHERE python >nul 2>nul
IF NOT ERRORLEVEL 1 (
    python "%APP_PY%" %*
    GOTO :EOF
)

echo Error: Python 3 is required but not found in PATH.
echo Please install Python and enable "Add Python to PATH".
pause
GOTO :EOF

:notfound
echo Error: Local Security Tool application not found.
echo.
echo Expected:
echo   EXE: %APP_EXE%
echo   PY:  %APP_PY%
echo.
echo Make sure folder structure is intact:
echo   LocalSecurityTool\
echo     LocalSecurityTool.bat
echo     App\suite_main.py
pause