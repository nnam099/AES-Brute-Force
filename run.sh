#!/bin/bash
echo "============================================"
echo "  Minh hoa vet can AES"
echo "============================================"
echo ""

# Kiem tra Python
if ! command -v python3 &>/dev/null; then
    echo "[LOI] Khong tim thay Python3! Hay cai Python 3.8+"
    exit 1
fi

echo "[*] Dang kiem tra va cai thu vien..."
pip3 install -r requirements.txt -q

echo ""
echo "[*] Dang khoi chay ung dung..."
cd src
python3 main.py
