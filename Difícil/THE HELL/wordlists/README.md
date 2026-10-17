# wordlists/ — Diccionarios usados en THE HELL

A diferencia de PICAPIEDRA (donde el vector fue una credencial débil y hubo fuerza bruta), aquí
**no hubo fuerza bruta**. El vector fue *mass assignment* → *JWT forgery* → endpoint oculto → SUID.

Aun así se usaron cuatro diccionarios pequeños, todos escritos a mano durante la auditoría.
Están aquí para que `exploits/jwt_rce.py` y `exploits/find_admin_composed.py` sean
**reproducibles**: ambos leen de esta carpeta, así que se puede cambiar el comportamiento del ataque
editando un `.txt`.

> `exploits/find_admin.py` (el cazador v1) mantiene sus listas **incrustadas en el código**, tal como
> estaban durante la auditoría. Los ficheros de esta carpeta son su copia exacta —se pueden
> regenerar desde el script con `ast.parse`—, pero el v1 no los consume.

---

## Diccionarios usados en la auditoría

### `jwt_secret_fields.txt` — 25 campos

Nombres de campo candidatos donde el servidor podría leer el secreto de firma de la configuración,
para inyectarlo por mass assignment en `POST /v1/onboarding/config`.

```
jwt_secret   jwtSecret   JWT_SECRET   jwt_key   jwtKey
secret       SECRET      secret_key   secretKey signing_key  signingKey
token_secret tokenSecret app_secret   appSecret auth_secret authSecret
session_secret  sessionSecret  encryption_key  signing_secret
hmac_secret  admin_secret  api_secret   API_SECRET
```

**El que engancha es `jwt_secret`** (el primero de la lista).

### `jwt_admin_claims.txt` — 10 claims

Formas de declarar privilegios dentro del JWT. Se prueban combinadas con cada nombre de campo.

```
{"role": "admin"}              {"role": "administrator"}
{"isAdmin": true}             {"admin": true}
{"scope": "admin"}            {"scopes": ["admin"]}
{"sub": "admin"}              {"user": "admin", "role": "admin"}
{"username": "admin", "admin": true}   {"sub": "admin", "role": "admin"}
```

**El que funciona es `{"role": "admin"}`**, y solo cuando el token va firmado con el secreto inyectado.

### `admin_path_prefixes.txt` — 19 prefijos

Prefijos de ruta para el cazador de endpoints administrativos (`find_admin.py`).

```
/v1/admin  /v1/internal  /v1/manage  /v1/system  /v1/private  /v1/staff
/v1/ops    /v1/ops/admin  /admin      /internal   /api/admin   /_admin
/v1/panel  /panel/admin   /v1/backoffice  /v1/config/admin
/v1/onboarding/admin  /v1/salon/admin  /v1/debug
```

### `admin_path_verbs.txt` — 36 verbos ⚠️ insuficiente

Sufijos de ruta con los que se combinaron los prefijos anteriores: `19 × 36 = 684 rutas × 2 métodos`.
**Esta lista es la razón del atasco**: contiene solo verbos *atómicos*.

```
(la primera línea del fichero está en blanco: es el verbo "", que prueba el prefijo pelado)
/exec  /run  /console  /eval  /shell  /cmd  /command  /config  /dashboard
/index  /query  /data  /import  /export  /backup  /restore  /logs  /log
/audit  /users  /user  /settings  /status  /health  /info  /secret
/token  /jwt  /key  /keys  /flag  /panel  /home  /main  /api
```

Esa primera línea en blanco **no es un descuido**: `find_admin.py` genera las rutas con
`prefijo + sufijo`, y el sufijo `""` hace que se pruebe `/v1/admin` a secas, sin verbo detrás. Por
eso el fichero son 36 líneas y no 35. `find_admin_composed.py` la lee con `keep_empty=True`; si se
descartara, faltarían las 19 rutas de prefijo pelado.

El endpoint real era **`/v1/admin/run-job`**: un verbo *compuesto con sustantivo*. `/v1/admin/run`
devolvía 404 y nunca se probó `/v1/admin/run-job`.

---

## Propuesta de mejora (NO se usó en la auditoría)

Lo siguiente es la lección del caso, no un diccionario que llegué a usar. Sirve para que el
writeup sea reproducible **y** para no repetir el error.

### `admin_path_verbs_composed.txt` — 70 verbos compuestos

Generar el diccionario como **verbo + sustantivo**, no solo el verbo. Extracto de las 70 entradas
del fichero:

```
run-job        run-task      run-script    run-backup
start-job      start-worker  start-service  stop-service
list-users     list-tokens   list-jobs     get-report
get-config     get-report    get-user      fetch-users
import-csv     import-config export-data   export-report
reset-password create-user   delete-user   update-settings
sync-schedule  cancel-job    retry-job     build-image
deploy-app     release-lock  rotate-key    revoke-token
```

Combinado con los 19 prefijos de `admin_path_prefixes.txt` son 1 330 rutas adicionales en formato
verbo-sustantivo, justo la familia que faltaba. El total del cazador corregido es
`19 × 106 = 2 014 rutas × 2 métodos`.

```bash
# Reproducir el cazador con los dos repertorios
python3 exploits/find_admin.py                       # atómicos (los que usé)
python3 exploits/find_admin_composed.py              # compuestos (la lección)
```

---

## Reproducir la cadena de ataque

```bash
# Fase 1+2+3: inyectar el secreto, forjar el JWT y ejecutar el primer comando
python3 exploits/jwt_rce.py
```

`jwt_rce.py` lee `jwt_secret_fields.txt` y `jwt_admin_claims.txt` de esta carpeta y barre
`(campo, claim)` hasta que la respuesta pasa de `403` a `400`, que es la prueba de que la inyección
agarró. Si los ficheros no están, el script usa una copia incrustada de ambas listas, así que nunca
se rompe por un `git clone` incompleto. Editar los `.txt` cambia el comportamiento del exploit sin
tocar el código.

Los claims están en JSON estricto (`true`, no `True`) porque el script los parsea con `json.loads`.

> **Detalle operativo:** el objetivo limita a ~25 ms por petición y no hay rate limiting, así que
> estos barridos son seguros. En PICAPIEDRA el `sshd` sí saturaba con muchos hilos; aquí no hay SSH.

---

## Nota sobre por qué el fuzzer de 220k rutas no encontró el endpoint

Se probaron 220 545 palabras × 4 extensiones (`html`, `js`, `json`, `txt`) sobre la raíz, y `run-job`
no aparece ni en DirBuster ni en SecLists (comprobado con `grep` sobre la lista).

Conviene ser precisos con el motivo, porque la primera versión de esta nota lo simplificaba de más:
DirBuster **sí** incluye palabras con guion, el 8,81 % de la lista (19 425 entradas). Lo que no
incluye son verbos en su forma de **endpoint REST**, porque sus guiones separan segmentos de CMS y
sitios (`cgi-bin`, `wp-content`, `wp-login`, `used-cars`, `privacy-policy`, `contact-us`), nunca
`verbo-sustantivo` de una API (`run-job`, `list-users`, `import-csv`). Las wordlists de rutas están
diseñadas para descubrir directorios y ficheros, no nombres de acción REST: hace falta generarlas a
mano para esa familia.