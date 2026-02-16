@echo off
REM =============================================================
REM NetworkTraffic Analyzer - Portable Edition
REM Windows Launcher
REM =============================================================
REM Part of a suite of security utilities.
REM Runs the app directly from this folder with no installation.
REM Copy the entire NetworkTrafficAnalyzerPortable\ folder to a
REM USB drive and run from there.
REM
REM Right-click -> "Run as administrator" for packet capture.
REM
REM Usage:
REM   NetworkTrafficAnalyzerPortable.bat          (GUI mode)
REM   NetworkTrafficAnalyzerPortable.bat --cli    (CLI mode)
REM =============================================================

echo ============================================
echo   NetworkTraffic Analyzer
echo   Portable Edition
echo ============================================
echo.

SET APP_EXE=%~dp0App\NetworkTrafficAnalyzer\NetworkTrafficAnalyzer.exe
SET APP_PY=%~dp0App\NetworkTrafficAnalyzer\main.py

REM Prefer compiled binary
if exist "%APP_EXE%" (
    echo Running compiled binary...
    "%APP_EXE%" %*
    goto :end
)

REM Fall back to Python source
if not exist "%APP_PY%" goto :notfound

echo Running from source...

REM Try py.exe (Python Launcher) first — most reliable on Windows
where py >nul 2>&1
if not errorlevel 1 (
    py -3 "%APP_PY%" %*
    goto :end
)

REM Fall back to python.exe
where python >nul 2>&1
if not errorlevel 1 (
    python "%APP_PY%" %*
    goto :end
)

echo Error: Python 3 is required but not found in PATH.
echo Install Python from https://www.python.org and ensure
echo "Add Python to PATH" is checked during installation.
pause
goto :end

:notfound
echo Error: Application not found in App\NetworkTrafficAnalyzer\
echo.
echo Expected location:
echo   EXE: %APP_EXE%
echo   PY:  %APP_PY%
echo.
echo Current directory: %CD%
echo Launcher directory: %~dp0
echo.
echo Make sure the folder structure is intact:
echo   NetworkTrafficAnalyzerPortable\
echo     NetworkTrafficAnalyzerPortable.bat
echo     App\NetworkTrafficAnalyzer\main.py
pause

:end
