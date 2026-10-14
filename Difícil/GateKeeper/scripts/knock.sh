#!/bin/bash
# Port knocking GATEKEEPER: 1337 -> 2048 -> 4096 abre el puerto 33333 (SSH)
for p in 1337 2048 4096; do
  timeout 2 bash -c "echo >/dev/tcp/172.17.0.2/$p" 2>/dev/null
  sleep 0.4
done
echo "[+] knock enviado: 1337 -> 2048 -> 4096"
