# BOARD — Whoami-Labs

> **Versión pública:** la flag, los hashes, el token del panel, la cuenta de mantenimiento y las contraseñas aparecen redactados o difuminados.

Auditoría de seguridad del laboratorio **BOARD** (`172.17.0.2`), con cadena completa de compromiso: enumeración web, análisis de codificaciones, credenciales débiles, escape de `rbash` y abuso de un binario SUID.

**Resultado:** lectura de `/root/flag.txt` con privilegios de `root`.

```text
BOARD{REDACTED}
```

## Entregables

| Archivo | Descripción |
|---|---|
| `WRITEUP_BOARD.md` | Writeup completo en Markdown (fuente principal) |
| `screenshots/` | Ocho capturas de terminal con las pruebas ejecutadas |

## Cadena de ataque

1. Reconocimiento: `22/tcp` (OpenSSH 8.9p1) y `80/tcp` (Apache 2.4.52).
2. Enumeración web: listado de directorio en `/docs/`.
3. Descarga de `database.sql`, `hash.txt` y `notes.txt`.
4. Crackeo de hashes MD5 (valores omitidos) y decodificación ROT13/César.
5. Token del panel: `[REDACTED]`.
6. Credenciales SSH débiles: `board:[REDACTED]`.
7. Shell restringida `rbash` y escape con `bash --noprofile --norc`.
8. Enumeración SUID y abuso de `/usr/local/bin/.syslog-helper`.
9. Lectura de `/root/flag.txt`.

## Estructura

```text
BOARD/
├── README.md
├── WRITEUP_BOARD.md / .html / .pdf
└── screenshots/        # capturas 01–08
```

Los artefactos originales (`nmap/`, `web/`, `ssh/`, `privesc/`, `loot/`) no se publican porque contienen credenciales, hashes e información sensible. Se conservan únicamente en el entorno local de laboratorio.

## Capturas

| Captura | Contenido |
|---|---|
| `screenshots/01_recon.png` | Escaneo de puertos y versiones |
| `screenshots/02_web_enum.png` | Enumeración web y `/docs/` |
| `screenshots/03_disclosure.png` | Archivos internos expuestos |
| `screenshots/04_decode_panel.png` | ROT13, César y panel `[REDACTED]` |
| `screenshots/05_hydra.png` | Hydra y credencial `[REDACTED]` |
| `screenshots/06_ssh_rbash.png` | Acceso SSH y restricciones |
| `screenshots/07_escape.png` | Escape de `rbash` |
| `screenshots/08_suid_flag.png` | SUID y lectura de la flag |

## Reproducir el PDF

El PDF se regenera desde el HTML incluido con `weasyprint`:

```bash
cd BOARD
weasyprint WRITEUP_BOARD.html WRITEUP_BOARD.pdf
```

> **Aviso:** las credenciales, hashes y rutas documentadas pertenecen exclusivamente al entorno de laboratorio. No deben reutilizarse fuera de un entorno autorizado.
