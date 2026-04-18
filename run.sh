#!/bin/bash
echo "============================================"
echo "  AES Brute-Force Demo"
echo "============================================"
echo ""

# Kiem tra Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python3 khong tim thay! Hay cai Python 3.8+"
    exit 1
fi

echo "[*] Kiem tra thu vien..."
pip3 install pycryptodome matplotlib -q

echo ""
echo "[*] Khoi chay ung dung..."
cd src
python3 main.py
