# PICAPIEDRA — Writeup de Auditoría de Seguridad (CTF)

| Campo | Valor |
|---|---|
| **Laboratorio** | PICAPIEDRA — *Cantera Picapiedra S.A.* |
| **Plataforma** | Whoami-Labs |
| **Dificultad** | Difícil ★★★★★☆☆☆ (5 puntos) |
| **Categoría** | SUID & Sudo |
| **Autor del writeup** | chifay |
| **Fecha** | 16/10/2026 |
| **Objetivo** | `172.17.0.2` (contenedor Docker) |
| **Atacante** | Kali Linux — `172.17.0.1` |
| **Hostname del objetivo** | `picapiedras` |
| **Stack del objetivo** | Ubuntu 20.04.6 · Apache 2.4.41 · PHP 7.4 · ProFTPD 1.3.5 · OpenSSH 8.2p1 |
| **Bandera obtenida** | `PICAPIEDRA{pr0ftpd_lfi_sudo_pwn3d_y4bb4_d00}` |
| **Estado** | Validada por el laboratorio (16/10/2026 11:50:18) |
| **Vector de entrada** | Credencial débil en el portal web → **LFI** en `panel.php?page=` → credenciales del sistema → `sudo /usr/bin/env` |
| **Ruta completa** | Fuerza bruta web → LFI → lectura de credenciales → `ssh pedro` → `sudo env` → `root` |
---

## 1. Resumen ejecutivo

PICAPIEDRA expone **tres servicios**: FTP (ProFTPD 1.3.5), SSH (OpenSSH 8.2p1) y un sitio web
corporativo bajo Apache/PHP 7.4. Ni el acceso anónimo al FTP, ni la fuerza bruta contra el SSH, ni la
inyección SQL en el login web dieron resultado: el punto de entrada fue una **credencial débil del
portal de empleados**, obtenible por fuerza bruta *dirigida* (el temario de la web es la pista).

Esa credencial da acceso a `panel.php`, que contiene una **LFI clásica** sobre el parámetro `page`.
La LFI no es solo un lector de ficheros: como el `include()` solo se dispara cuando el fichero
existe, **funciona como oráculo de existencia** y, sobre todo, **permite leer el código fuente PHP
del propio servidor**. Ese código revela que la autenticación web se apoya en
`includes/usuarios.php`, un array PHP con **las contraseñas en texto plano**. El resultado es que el
usuario `pedro`, con la contraseña `password123` del portal, es también una cuenta del sistema
operativo y entra por SSH sin ninguna otra barrera.

La escalada final es trivial y coherente con la categoría del laboratorio: `sudo -n -l` revela una
regla `(root) NOPASSWD: /usr/bin/env`, es decir, **se puede ejecutar cualquier binario como root**
sin contraseña.

Cinco fallos encadenados:

1. Contraseña débil y adivinable en el portal web (`yabbadabbadoo`).
2. LFI en `panel.php?page=` (lectura arbitraria de ficheros).
3. Credenciales del sistema almacenadas **en claro** y **reutilizadas** en el portal.
4. Contraseña trivial (`password123`) reutilizada como credencial del sistema operativo.
5. Regla `sudo NOPASSWD` sobre `/usr/bin/env`, equivalente a `root` directo.

**Resultado validado por el laboratorio el 16/10/2026 a las 11:50:18:** «¡Felicitaciones! Has conquistado Bedrock.»

![Cadena de ataque completa](docs/img/10-cadena.png)

| # | Vector | De → A |
|---|---|---|
| 1 | Fuerza bruta dirigida del portal web | — → sesión web |
| 2 | LFI en `panel.php?page=` | web → lectura arbitraria + código fuente |
| 3 | `includes/usuarios.php` con claves en claro | web → credenciales del sistema |
| 4 | SSH como `pedro` | credencial → shell de usuario |
| 5 | `sudo /usr/bin/env` | `pedro` → `root` |

---

## 2. Reconocimiento

### 2.1 Puertos

```bash
nmap -Pn -sV -sC -T4 --min-rate 1000 -p- 172.17.0.2
```

![Reconocimiento de puertos](docs/img/01-recon.png)

| Puerto | Estado | Servicio |
|---|---|---|
| 21/tcp | open | ProFTPD 1.3.5 |
| 22/tcp | open | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 |
| 80/tcp | open | Apache httpd 2.4.41 ((Ubuntu)) |

De 65 535 puertos, 65 532 cerrados. El escaneo UDP de los 20 puertos más habituales devuelve todo
`open|filtered` (filtrado silencioso), por lo que no hay servicios UDP reales.

### 2.2 Superficie web

El `index.html` es una web corporativa estática que funciona como *cover story*: «Cantera Picapiedra
S.A.», el lema «Extrayendo piedras desde la Era Prehistórica» y una sección de equipo con Fred
Flintstone (CEO), Barney Rubble (Supervisor) y Wilma Flintstone (Finanzas).

![Superficie web](docs/img/02-web.png)

Enumeración de contenido (`gobuster` + `ffuf` con la wordlist DirBuster-2007 *big*):

| Ruta | Estado | Descripción |
|---|---|---|
| `/` | 200 | `index.html` estático (6082 B) |
| `/empleados.php` | 200 | Formulario de login (`POST username`, `password`) |
| `/panel.php` | 302 | Redirige a `empleados.php` sin sesión válida |
| `/logout.php` | 302 | Cierre de sesión |
| `/inicio.php` | 200 | *Include* parcial del panel (165 B) |
| `/includes/config.php` | 200 | 0 B (solo `define()`) |
| `/includes/usuarios.php` | 200 | 0 B (solo array + función) |
| `/css/style.css` | 200 | Estilos, sin secretos |
| `/js/`, `/img/` | 200 | Directorios vacíos (listado de Apache habilitado) |

**No hay `robots.txt`, ni `.git`, ni copias de seguridad, ni comentarios HTML, ni JavaScript propio**
(la única biblioteca externa es Bootstrap desde CDN). La superficie expuesta es mínima y obliga a
buscar por otros caminos.

---

## 3. Vías descartadas (antes de la fuerza bruta)

Para no malgastar tiempo, se evaluaron y descartaron de forma explícita:

| Vía | Resultado |
|---|---|
| FTP anónimo (`ftp://anonymous:anonymous@172.17.0.2/`) | `530 Login incorrect.` |
| FTP con contraseñas vacías o por defecto | Sin acceso |
| Backdoor de ProFTPD 1.3.5 (CVE-2015-3306, `USER`+`\r` + `SITE EXEC CMD`) | Sin ejecución de comandos |
| Inyección SQL (`sqlmap --level=3 --risk=2 --technique=BEUST`) | `all tested parameters do not appear to be injectable` |
| Type juggling (`password[]=1`, `password=true`) | Rechazado |
| LDAP injection (`username=*&password=*`) | Rechazado |
| Enumeración de usuarios por *timing* o por tamaño de respuesta | Respuesta byte a byte idéntica (md5 `369b6d5cce2a`) en todos los casos |
| Virtual hosts (`Host:` alternativos) | Todos devuelven `size=6082` |
| Fuzzing de parámetros en los `.php` | Sin cambios de tamaño |

**Conclusión de esta fase:** el login web es sólido frente a inyección y frente a bypass, y no
ofrece ningún oráculo de enumeración. Solo queda la fuerza bruta.

---

## 4. Acceso inicial: credencial débil del portal

El mensaje de error es genérico y el tiempo de respuesta uniforme (~1 ms), así que no hay forma de
saber qué usuarios existen. La fuerza bruta genérica con `rockyou` contra 26 usuarios resultó
infructuosa; el giro fue **dirigir el diccionario al temario del sitio**.

El sitio es una parodia de *Los Picapiedras*, y la clave para deducir la contraseña está en la propia
página: el lema, el nombre de los personajes y el guiño «¡Yabba-Dabba-Doo!». Esa hipótesis se probó
directamente:

```bash
curl -s -i -X POST http://172.17.0.2/empleados.php \
     --data-urlencode 'username=fred' \
     --data-urlencode 'password=yabbadabbadoo'
```

![Login con la credencial hallada](docs/img/03-login.png)

```
HTTP/1.1 302 Found
Location: panel.php
Set-Cookie: PHPSESSID=...; path=/
```

> **Credencial obtenida:** `fred` / `yabbadabbadoo`.
> **Lección:** en un laboratorio *Hard*, la fuerza bruta indiscriminada es la estrategia equivocada.
> Estimar el espacio de contraseñas a partir del contexto de la aplicación reduce las búsquedas de
> 600 000 a 400 intentos. Los diccionarios empleados están en [`wordlists/`](wordlists/), con
> instrucciones para reproducir los mismos intentos.

Con la sesión, el panel revela la identidad completa (`Fred Flintstone`) y el menú con tres secciones
(`inicio`, `reportes`, `documentos`). Las dos últimas devuelven **«Página no encontrada»**, lo que
apunta a un `include()` controlado por el usuario.

---

## 5. LFI en `panel.php?page=`

### 5.1 Confirmación

```bash
curl -s -b <cookie> 'http://172.17.0.2/panel.php?page=/etc/passwd'
```

![Lectura de /etc/passwd vía LFI](docs/img/04-lfi-passwd.png)

La respuesta devuelve el fichero completo envuelto en `<pre>`. Los únicos usuarios con shell
real son los tres del laboratorio:

```
pedro:x:1000:1000::/home/pedro:/bin/bash
pablo:x:1001:1001::/home/pablo:/bin/bash
fred:x:1002:1002::/home/fred:/bin/bash
```

### 5.2 Lectura del código fuente

Aquí está el punto clave del laboratorio. Como el `include()` solo se ejecuta si el fichero existe,
la misma LFI permite **leer el `.php` vulnerable en texto plano** (no se ejecuta, se vuelca):

```bash
curl -s -b <cookie> 'http://172.17.0.2/panel.php?page=/var/www/html/panel.php'
```

![Código fuente de panel.php](docs/img/05-lfi-source.png)

```php
$page = $_GET['page'] ?? 'inicio';
...
// LFI VULNERABLE
if (file_exists($page . '.php')) {
    include($page . '.php');
} elseif (file_exists($page)) {
    echo "<pre class='bg-light p-3'>";
    echo htmlspecialchars(file_get_contents($page));
    echo "</pre>";
} else {
    echo "<div class='alert alert-warning'>Página no encontrada</div>";
}
```

### 5.3 Por qué esta LFI *no* da RCE directo

El detalle de seguridad relevante es que `file_exists($page . '.php')` **añade la extensión**.
Para que el `include()` se dispare, el fichero debe llamarse `X.php`.

Esto descarta de entrada la vía clásica de **session upload progress**, que es la forma habitual de
convertir una LFI en RCE:

- El fichero de sesión se llama `sess_<ID>` (sin `.php`), y el `include()` buscaría `sess_<ID>.php`.
- Forzar el `PHPSESSID` a `algo.php` no funciona: PHP 7.4 valida el identificador de sesión y solo
  acepta `[a-zA-Z0-9,-]`. Comprobado empíricamente con `abc.php`, `a.b`, `.php`, `abc.php%00`,
  `abc/../x`, etc. — **todos** devuelven `302` a `empleados.php`, es decir, el identificador es
  descartado y se genera otro.

| Session ID probado | `GET panel.php` | ¿Aceptado? |
|---|---|---|
| `abc123def456` | `200` | Sí |
| `abc.php` | `302` | No |
| `a.b` | `302` | No |
| `abc/../x` | `302` | No |
| `abc.php%00` | `302` | No |

Tampoco sirven los *wrappers* (`php://filter`, `php://input`) porque `file_exists()` devuelve `false`
para todos ellos, de modo que se cae en la rama «Página no encontrada».

**Conclusión:** esta LFI es deliberadamente un **lector de ficheros**, no un ejecutor. El
laboratorio obliga a extraer información, no a inyectar código. La vía correcta es leer.

---

## 6. De la LFI a las credenciales del sistema

Con lectura arbitraria, el objetivo evidente es el fichero que gestiona la autenticación web. El
listado de directorio de `/includes/` ya había revelado su nombre:

```bash
curl -s -b <cookie> \
  'http://172.17.0.2/panel.php?page=/var/www/html/includes/usuarios.php'
```

![Credenciales en claro](docs/img/06-creds-php.png)

```php
<?php
$empleados = array(
    'pedro' => array('password' => 'password123',    'nombre' => 'Pedro Picapiedra', 'nivel' => 'admin'),
    'pablo' => array('password' => 'admin123',       'nombre' => 'Pablo Mármol',    'nivel' => 'user'),
    'fred'  => array('password' => 'yabbadabbadoo',  'nombre' => 'Fred Flintstone', 'nivel' => 'admin')
);
function autenticar($usuario, $password) {
    global $empleados;
    if (isset($empleados[$usuario]) && $empleados[$usuario]['password'] === $password) {
        return $empleados[$usuario];
    }
    return false;
}
```

**Dos observaciones críticas:**

1. Las contraseñas se guardan **en texto plano**, sin `password_hash()`, y la comparación se hace con
   `===`, sin ningún endurecimiento.
2. **Los nombres de usuario coinciden con los del sistema operativo** (`pedro`, `pablo` y `fred` en
   `/etc/passwd`), y el autor **reutilizó las mismas contraseñas** para el portal y para las cuentas
   del sistema. Por eso el hash no era necesario para la filtración: bastaba con leer el fichero.

También se leyó `includes/config.php` (credenciales de MySQL `picapiedra_admin` /
`BedR0ck_DB_2024!` sobre `cantera_db`), pero **resultaron ser un señuelo**: el puerto 3306 no está
publicado y esas credenciales no sirven ni para SSH ni para FTP.

### 6.1 Acceso por SSH

```bash
sshpass -p 'password123' ssh pedro@172.17.0.2
```

![Acceso SSH como pedro](docs/img/07-ssh.png)

```
uid=1000(pedro) gid=1000(pedro) groups=1000(pedro)
picapiedras
```

Shell de usuario conseguida. Nótese que la contraseña (`password123`) es la más trivial posible:
en cuanto se entiende que el portal **es** el sistema, no hace falta ni fuerza bruta.

> **Trampa de la auditoría (documentada para no repetirla):** la primera vez que se probó SSH con
> estas credenciales devolvió «fallo». La causa no era la contraseña, sino que **el servidor estaba
> saturado** por las pruebas de fuerza bruta lanzadas en paralelo: el `sshd` devolvía *Connection
> refused* / *Error reading SSH protocol banner* porque se había superado `MaxStartups`. Con
> `ssh -vv` se vio el `Authenticated to ... using "password"`. **Verificar siempre con salida
> verbosa antes de concluir que una credencial es incorrecta.**

---

## 7. Escalada a root — `sudo NOPASSWD: /usr/bin/env`

```bash
ssh pedro@172.17.0.2 'sudo -n -l'
```

![Inventario de sudo](docs/img/08-sudo.png)

```
User pedro may run the following commands on picapiedras:
    (root) NOPASSWD: /usr/bin/env
```

Esta es una **escalada trivial**: `sudo /usr/bin/env <comando>` ejecuta `env` con privilegios de `root`
y, a continuación, `<comando>` también con esos privilegios. No hace falta ningún binario SUID ni
ningún vector de GTFOBins: la regla `sudo` ya equivale a `root` completo.

Comprobado también el inventario de SUID del sistema, que no aporta nada adicional en este
laboratorio (solo el conjunto estándar de Ubuntu: `su`, `sudo`, `passwd`, `mount`, `umount`,
`newgrp`, `gpasswd`, `chfn`, `chsh`, `ssh-keysign`, `dbus-daemon-launch-helper`).

```bash
sudo /usr/bin/env id
uid=0(root) gid=0(root) groups=0(root)

sudo /usr/bin/env cat /root/flag.txt
```

![Flag de root](docs/img/09-root-flag.png)

```
PICAPIEDRA{pr0ftpd_lfi_sudo_pwn3d_y4bb4_d00}
```

### 7.1 Validación por el laboratorio

La bandera fue introducida en el validador del propio laboratorio, que confirma la resolución:

![Validación de la bandera](docs/img/11-validacion-flag.png)

```
IP del laboratorio: 172.17.0.2

Ingresa la flag (formato PICAPIEDRA{...}): PICAPIEDRA{pr0ftpd_lfi_sudo_pwn3d_y4bb4_d00}
¡Felicitaciones! Has conquistado Bedrock.

FECHA Y HORA: 2026-10-16 11:50:18 -0600
```

---

## 8. Ruta completa de ataque

| Paso | Acción | Resultado |
|---|---|---|
| 1 | `nmap -p- 172.17.0.2` | FTP 21 · SSH 22 · HTTP 80 |
| 2 | Enumeración web (`gobuster`, `ffuf`) | `/empleados.php`, `/panel.php`, `/includes/` |
| 3 | Descarte de SQLi, bypass, FTP anónimo | Sin éxito |
| 4 | Fuerza bruta **dirigida** al portal | `fred` : `yabbadabbadoo` |
| 5 | `panel.php?page=/etc/passwd` | LFI confirmada; 3 usuarios de sistema |
| 6 | `panel.php?page=/var/www/html/panel.php` | Código fuente de la vulnerabilidad |
| 7 | `panel.php?page=.../includes/usuarios.php` | Credenciales **en claro** |
| 8 | `ssh pedro@172.17.0.2` (`password123`) | `uid=1000(pedro)` |
| 9 | `sudo -n -l` | `(root) NOPASSWD: /usr/bin/env` |
| 10 | `sudo /usr/bin/env cat /root/flag.txt` | **Flag** |
| 11 | Introducir la flag en el validador del laboratorio | `¡Felicitaciones! Has conquistado Bedrock.` |

---

## 9. Recomendaciones de corrección

| # | Hallazgo | Mitigación |
|---|---|---|
| 1 | Credenciales del sistema reutilizadas en el portal | Cuentas de servicio separadas; nunca reutilizar contraseñas de usuario |
| 2 | Contraseñas en texto plano en `usuarios.php` | `password_hash()` / `password_verify()` con bcrypt o Argon2 |
| 3 | LFI en `panel.php?page=` | Lista blanca de páginas (`in_array($page, ['inicio','reportes','documentos'])`) |
| 4 | `sudo NOPASSWD: /usr/bin/env` | Eliminar la regla; si se necesita algo, usar un script raíz de solo lectura y no `env` |
| 5 | Contraseña trivial y adivinable | Política de contraseñas + MFA en servicios externos |
| 6 | FTP/SSH expuestos sin restricción de origen | Limitar por IP y deshabilitar el acceso directo a medida que se migra a SSH |
| 7 | Credenciales de MySQL en un `.php` del *docroot* | Mover la configuración fuera del *docroot*; hoy solo devuelve 0 B porque PHP lo ejecuta, no porque esté protegido |

---

## 10. Indicadores de compromiso (IOC)

| Tipo | Valor |
|---|---|
| Bandera | `PICAPIEDRA{pr0ftpd_lfi_sudo_pwn3d_y4bb4_d00}` |
| Credenciales válidas (web) | `fred` / `yabbadabbadoo`, `pedro` / `password123`, `pablo` / `admin123` |
| Credenciales válidas (sistema) | `pedro` / `password123` (SSH) |
| Credencial MySQL (no expuesta) | `picapiedra_admin` / `BedR0ck_DB_2024!` sobre `cantera_db` |
| Cabecera de petición crítica | `Cookie: PHPSESSID=<id>` + `GET /panel.php?page=<ruta absoluta>` |

---

## 11. Herramientas utilizadas

| Herramienta | Uso |
|---|---|
| `nmap` | Descubrimiento de puertos y versiones |
| `gobuster`, `ffuf` | Enumeración de contenido web (con y sin sesión) |
| `curl` | Login del portal y explotación de la LFI |
| `sqlmap` | Evaluación de inyección SQL en el login |
| `paramiko`, `hydra` | Intentos de fuerza bruta sobre SSH/FTP |
| `Python` + `requests` | Fuzzing de ficheros vía LFI (oráculo `file_exists`) |
| `sshpass` + `ssh` | Acceso al sistema y escalada |
| Diccionarios propios | `wordlists/` (temático, por año, variación de mayúsculas, credenciales conocidas) |
| `Pillow` | Generación de las capturas PNG del writeup |

---

## 12. Estructura del repositorio de trabajo

```
PICAPIEDRA/
├── README.md              ← este writeup
├── notes/bitacora.md      ← bitácora del análisis y decisiones
├── recon/                 ← salidas de reconocimiento
│   ├── nmap-full.txt
│   ├── etc-passwd.txt
│   ├── proftpd-backdoor.txt
│   └── lfi/               ← código fuente extraído con la LFI
├── exploits/              ← utilidades escritas durante la auditoría
│   ├── web_brute.py, brute_multi.py   ← fuerza bruta controlada
│   ├── lfi_fuzz.py        ← fuzzing de ficheros vía LFI
│   ├── proftpd_backdoor_test.py        ← prueba de CVE-2015-3306
│   └── session_upload_progress.py      ← intento de RCE vía LFI (descartado)
├── loot/                  ← flag, sudo -l
├── wordlists/             ← diccionarios propios creados durante la auditoría
│   ├── README.md          ← qué es cada lista y cómo reproducir la fuerza bruta
│   ├── users_themed.txt, users_priority.txt
│   ├── passes_themed.txt ⭐, passes_case.txt, passes_dates.txt
│   ├── known_creds.txt
│   ├── web_paths_themed.txt, lfi_filenames.txt
└── docs/img/              ← imágenes del writeup
```
Auditoría realizada sobre un laboratorio CTF aislado y con autorización explícita para pruebas ofensivas (whoami-labs.com). Toda la metodología se ejecutó únicamente contra la red del objetivo, sin acceso al host ni al filesystem del contenedor.
