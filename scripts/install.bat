@echo off
echo ========================================
echo Shadow Ops - Installing Dependencies
echo ========================================
echo.

echo Installing required Python packages...
pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to install dependencies!
    echo Make sure you're running this in Anaconda Prompt.
    pause
    exit /b 1
)

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo Next step: Run setup_database.bat to initialize the database
echo.
pause
