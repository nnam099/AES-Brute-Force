@echo off
echo ============================================
echo   AES Brute-Force Demo
echo ============================================
echo.

:: Kiem tra Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python khong tim thay! Hay cai Python 3.8+
    pause
    exit /b 1
)

:: Cai thu vien neu chua co
echo [*] Kiem tra thu vien...
pip install pycryptodome matplotlib -q

echo.
echo [*] Khoi chay ung dung...
cd src
python main.py

pause
