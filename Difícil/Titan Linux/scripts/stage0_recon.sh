#!/bin/bash
cd "/home/chifay/Whoami-Labs/Titan Linux" || exit 1
SSH="sshpass -p password123 ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no ubuntu@192.168.60.132"
clear
printf '\033]0;TITAN ETAPA 0 RECON\007'
echo "=================================================================="
echo " TITAN LINUX - ETAPA 0: RECONOCIMIENTO Y ACCESO INICIAL"
echo " Fecha: $(date)"
echo "=================================================================="
echo
echo '$ ip -brief addr'
ip -brief addr
echo
echo '$ nmap -sn 192.168.60.0/24'
nmap -sn 192.168.60.0/24 2>/dev/null | grep -E 'Nmap scan report|MAC Address'
echo
echo '$ nmap -sV -p22 192.168.60.132'
nmap -sV -p22 192.168.60.132 2>/dev/null | grep -E '22/tcp|Service Info'
echo
echo '$ ssh ubuntu@192.168.60.132 "id; hostname; cat /etc/os-release"'
$SSH 'id; hostname; grep PRETTY_NAME /etc/os-release' 2>&1 | tee "evidencias/term_etapa0_acceso.txt"
echo
echo '$ sudo -l'
$SSH 'echo password123 | sudo -S -l' 2>&1 | grep -vE '^\[sudo\]|^Matching|^    env_|^$' | tee -a "evidencias/term_etapa0_acceso.txt"
echo
echo "### FIN ETAPA 0 ###"
touch /tmp/opencode/stage0.done
sleep 3600
