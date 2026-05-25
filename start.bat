@echo off
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo Node.js not found. Please install it from https://nodejs.org
    pause
    exit /b 1
)
start "" http://localhost:7823
node "%~dp0router-cleanup.js"
pause
