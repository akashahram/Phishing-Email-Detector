@echo off
echo ========================================
echo Shadow Ops - Database Setup
echo ========================================
echo.

echo Creating database tables...
python -c "from web.database import Database; from config import get_config; db = Database(get_config().DATABASE_URL); db.create_all(); print('Database initialized successfully!')"

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to initialize database!
    echo Make sure you've installed dependencies first.
    pause
    exit /b 1
)

echo.
echo ========================================
echo Database Setup Complete!
echo ========================================
echo.
echo Next step: Run start_app.bat to start the application
echo.
pause
