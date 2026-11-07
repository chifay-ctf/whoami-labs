#!/usr/bin/env bash
# Verificación de la credencial recuperada vía hashdump.
# El hash NTLM de "XXXXX" debe coincidir con el de student/Zero.
set -u
TARGET="${1:-172.16.202.133}"

echo "[*] Hash NTLM calculado para la contraseña XXXXX:"
python3 -c "import hashlib; print(hashlib.new('md4','XXXXX'.encode('utf-16le')).hexdigest())"

echo
echo "[*] Autenticación SMB con student:XXXXX contra ${TARGET}:"
smbclient "//${TARGET}/Users" -U 'student%XXXXX' -m SMB2 -c 'ls'
