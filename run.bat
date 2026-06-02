@echo off
echo ============================================
echo   Minh hoa vet can AES
echo ============================================
echo.

:: Kiem tra Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [LOI] Khong tim thay Python! Hay cai Python 3.8+
    pause
    exit /b 1
)

:: Cai thu vien neu chua co
echo [*] Dang kiem tra va cai thu vien...
pip install -r requirements.txt -q

echo.
echo [*] Dang khoi chay ung dung...
cd src
python main.py

pause
