#!/usr/bin/env bash
# Verificación de la credencial recuperada vía hashdump.
# El hash NTLM de "MS17-010" debe coincidir con el de student/Zero.
set -u
TARGET="${1:-172.16.202.133}"

echo "[*] Hash NTLM calculado para la contraseña MS17-010:"
python3 -c "import hashlib; print(hashlib.new('md4','MS17-010'.encode('utf-16le')).hexdigest())"

echo
echo "[*] Autenticación SMB con student:MS17-010 contra ${TARGET}:"
smbclient "//${TARGET}/Users" -U 'student%MS17-010' -m SMB2 -c 'ls'
