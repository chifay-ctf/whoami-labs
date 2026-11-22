# RECON — Writeup de auditoría ofensiva

Writeup del laboratorio **RECON** de [Whoami-Labs](https://whoami-labs.com/laboratorios/recon).

| Campo | Valor |
|---|---|
| Objetivo | `172.17.0.2` |
| Dificultad | Difícil (5 puntos) |
| Resultado | Compromiso total (`root`) |
| Entorno | Laboratorio autorizado |

## Resumen

El reconocimiento identificó tres servicios expuestos: SSH, HTTP y RDP. El portal **ORION** permitía el acceso con credenciales débiles. Desde la sesión autenticada se explotó una inyección SQL en el inventario y una carga de archivos sin restricciones que derivó en ejecución remota de código como `www-data`.

La enumeración local reveló una regla `sudo` que permitía ejecutar `python3` como `sentinel` sin contraseña. El binario `/sbin/sys-daemon` (PID 1, legible por todos) contenía el script de inicialización codificado en base64, con la contraseña de `sentinel`, las reglas `sudo` y la ubicación de la flag. Con esa contraseña se obtuvo acceso como `root` y se leyó `/root/flag.txt`.

## Cadena de ataque

```text
credenciales débiles → SQLi → upload PHP → RCE www-data
      → sudo python3 → sentinel → secretos en sys-daemon → root
```

## Contenido

| Archivo | Descripción |
|---|---|
| `RECON-Auditoria.md` | Fuente del informe en Markdown. |
| `screenshots/` | Capturas del terminal (01–14). |

## Redacción

Esta es una versión pública. Las contraseñas y la flag han sido redactadas tanto en el texto como en las capturas del terminal. La flag se muestra como `RECON{REDACTED}` y las credenciales como `usuario:REDACTED`.

## Hallazgos principales

- Credenciales débiles en el portal de acceso.
- Inyección SQL en el buscador de inventario.
- Carga de archivos sin restricciones con ejecución de PHP.
- Regla `sudo` `NOPASSWD` de `www-data` a `sentinel`.
- Secretos embebidos en un binario world-readable.
- `sentinel` con `sudo ALL`.
- RDP expuesto con autenticación de usuarios del sistema.
- Listado de directorios y `server-status` accesible.

## Recomendaciones

- Rotar credenciales y eliminar secretos de binarios y scripts.
- Sustituir las reglas `sudo` amplias por comandos específicos.
- Corregir la SQLi con consultas preparadas.
- Validar extensiones y tipo MIME en las cargas; almacenar fuera del web root.
- Aplicar mínimo privilegio, MFA y monitoreo de autenticaciones.
- Restringir SSH/RDP a la red de gestión.
- Deshabilitar el listado de directorios y restringir `/server-status`.

## Aviso

El contenido se publica con fines educativos y de documentación de un laboratorio autorizado. No debe utilizarse para atacar sistemas sin autorización.
