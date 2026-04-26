@echo off
setlocal enabledelayedexpansion
title Cybersecurity Companion - Build Script
cd /d "%~dp0"

echo.
echo =============================================
echo   Cybersecurity Companion - Build Script
echo =============================================
echo.

:: -----------------------------------------------
:: Step 1 – Clean PyQt environment
:: -----------------------------------------------
echo [1/5] Removing mismatched PyQt6 packages...
echo.
venv\Scripts\pip.exe uninstall -y PyQt6 PyQt6-WebEngine PyQt6-Qt6 PyQt6-sip >nul 2>&1
echo  [OK] PyQt packages cleared.
echo.

:: -----------------------------------------------
:: Step 2 – Install all required packages together
:: -----------------------------------------------
echo [2/5] Installing all required packages (in one step for version matching)...
echo.

:: Installing together forces pip to resolve matching Qt6 DLL versions
venv\Scripts\pip.exe install markdown beautifulsoup4 tldextract python-whois dnspython requests numpy scipy pandas scikit-learn joblib Pillow psutil pyinstaller PyQt6 PyQt6-WebEngine --quiet

if %ERRORLEVEL% NEQ 0 (
    echo  ERROR: Failed to install packages.
    pause & exit /b 1
)
echo  [OK] Dependencies installed successfully.

echo.
echo  NOTE: torch/sentence_transformers intentionally NOT bundled.
echo  AI assistant runs in keyword-search mode inside the .exe.
echo  All other features work at full capability.
echo.

:: -----------------------------------------------
:: Step 3 – Verify all critical imports
:: -----------------------------------------------
echo [3/5] Verifying critical imports...
echo.

venv\Scripts\python.exe -c "import markdown; print('  markdown:', markdown.__version__)"
if %ERRORLEVEL% NEQ 0 ( echo  ERROR: markdown & pause & exit /b 1 )

venv\Scripts\python.exe -c "from bs4 import BeautifulSoup; print('  beautifulsoup4: OK')"
if %ERRORLEVEL% NEQ 0 ( echo  ERROR: bs4 & pause & exit /b 1 )

venv\Scripts\python.exe -c "import tldextract; print('  tldextract:', tldextract.__version__)"
if %ERRORLEVEL% NEQ 0 ( echo  ERROR: tldextract & pause & exit /b 1 )

venv\Scripts\python.exe -c "import sklearn; print('  sklearn:', sklearn.__version__)"
if %ERRORLEVEL% NEQ 0 ( echo  ERROR: sklearn & pause & exit /b 1 )

venv\Scripts\python.exe -c "import scipy; print('  scipy:', scipy.__version__)"
if %ERRORLEVEL% NEQ 0 ( echo  ERROR: scipy & pause & exit /b 1 )

venv\Scripts\python.exe -c "import PyQt6; print('  PyQt6: OK')"
if %ERRORLEVEL% NEQ 0 ( echo  ERROR: PyQt6 & pause & exit /b 1 )

venv\Scripts\python.exe -c "import requests; print('  requests:', requests.__version__)"
if %ERRORLEVEL% NEQ 0 ( echo  ERROR: requests & pause & exit /b 1 )

venv\Scripts\python.exe -c "import PyQt6.QtWebEngineCore; print('  PyQt6.QtWebEngineCore: OK')"
if %ERRORLEVEL% NEQ 0 ( echo  ERROR: PyQt6-WebEngine not installed correctly & pause & exit /b 1 )

venv\Scripts\python.exe -c "import PyQt6.QtWebEngineWidgets; print('  PyQt6.QtWebEngineWidgets: OK')"
if %ERRORLEVEL% NEQ 0 ( echo  ERROR: PyQt6.QtWebEngineWidgets & pause & exit /b 1 )

echo.

:: -----------------------------------------------
:: Step 4 – Clean old build artifacts
:: -----------------------------------------------
echo [4/5] Cleaning previous build artifacts...

if exist build\CybersecurityCompanion (
    rmdir /s /q build\CybersecurityCompanion
    echo  Removed build\CybersecurityCompanion
)
if exist dist\CybersecurityCompanion.exe (
    del /f /q dist\CybersecurityCompanion.exe
    echo  Removed dist\CybersecurityCompanion.exe
)
echo  Clean complete.
echo.

:: -----------------------------------------------
:: Step 5 – PyInstaller build
:: -----------------------------------------------
echo [5/5] Running PyInstaller (may take a few minutes)...
echo.

venv\Scripts\python.exe -m PyInstaller build.spec -y --clean
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  ========================================
    echo   BUILD FAILED - Check output above
    echo  ========================================
    pause & exit /b 1
)

echo.
echo =============================================
echo   BUILD COMPLETE!
echo   Output: dist\CybersecurityCompanion.exe
echo =============================================
echo.
echo Launching the application...
start "" "dist\CybersecurityCompanion.exe"
pause
