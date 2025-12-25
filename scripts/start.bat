@echo off
echo ========================================
echo Shadow Ops - Starting Application
echo ========================================
echo.

:: Navigate to project root from scripts/
cd /d "%~dp0.."

:: Navigate to web directory
cd web
echo Starting Flask server on http://localhost:5000
echo Press Ctrl+C to stop the server
echo.

python app.py

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to start application!
    pause
    exit /b 1
)
