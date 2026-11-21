# DREAMLAND — Writeup de auditoría de seguridad

Writeup del laboratorio **DREAMLAND** (`172.17.0.2`), realizado en un entorno de laboratorio autorizado.

## Resultado

Se obtuvo acceso inicial como `www-data` a través de una carga de archivos sin validación en el servidor y se escaló a `root` mediante un binario SUID con secuestro de `PATH`.

| Flag | Valor |
|---|---|
| Usuario | `user{REDACTED}` |
| Root | `root{REDACTED}` |

> Los valores completos de las flags se han redactado en el texto y difuminado en las capturas.

## Contenido

| Ruta | Descripción |
|---|---|
| `report/DREAMLAND_writeup.md` | Informe completo en Markdown |
| `screenshots/` | Capturas de la terminal Kali con la cadena de explotación |

## Cadena de explotación

1. Enumeración de servicios y aplicaciones web.
2. Descubrimiento de `/upload.php` en Kirby (puerto `8080`).
3. Bypass de la validación client-side y carga de una webshell PHP.
4. Ejecución de comandos como `www-data`.
5. Descubrimiento de `/usr/local/bin/backup_kirby` (SUID root).
6. Secuestro de `PATH` mediante un `tar` malicioso.
7. Obtención de la flag de usuario y de una shell con `euid=0(root)`.
8. Lectura de `/root/flag.txt`.

## Hallazgos principales

- Validación exclusivamente client-side en la carga de archivos de `/upload.php`.
- Binario SUID `/usr/local/bin/backup_kirby` que ejecuta `tar` por ruta relativa.
- Kirby 5.4.3 desactualizado, con avisos de seguridad publicados.
- Instalador del panel Kirby accesible mediante manipulación de la cabecera `Host`.

## Aviso

Este material se publica con fines educativos y de documentación técnica. Las pruebas se realizaron en un laboratorio autorizado y las flags originales fueron redactadas antes de su publicación.
