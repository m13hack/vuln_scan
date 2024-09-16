@echo off
echo Installing necessary dependencies...

REM Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Python is not installed. Please install Python and try again.
    exit /b 1
)

REM Check if pip is installed
pip --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo pip is not installed. Installing pip...
    python -m ensurepip --upgrade
)

echo Installing Python modules from requirements.txt...
pip install -r requirements.txt

if %ERRORLEVEL% NEQ 0 (
    echo Failed to install one or more dependencies. Please check the error messages above.
    exit /b 1
)

echo All dependencies installed successfully.
exit /b 0
