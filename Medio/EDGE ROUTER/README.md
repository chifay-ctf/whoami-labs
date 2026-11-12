# Whoami-Labs — Edge Router

Writeup de auditoría de seguridad sobre el laboratorio **Whoami-EdgeRouter v2.4** (Track IoT Firmware Penetration Testing) de [Whoami-Labs](https://whoami-labs.com/).

**Autor:** chifay

## Contenido

| Archivo | Descripción |
|---|---|
| [`writeup.md`](writeup.md) | Informe completo en Markdown |
| [`screenshots/`](screenshots/) | Capturas de terminal de la auditoría |

## Resumen

El laboratorio simula un router perimetral MIPS32 con un portal HTTP de gestión que publica el firmware sin autenticación. La auditoría encadena la extracción del firmware, la obtención y crackeo del hash de `admin_support`, una inyección de comandos en `/cgi-bin/system_test.cgi` y una escalada a `root` mediante una regla `sudo` excesiva.

La cadena completa se documenta paso a paso, junto con los hallazgos, su severidad y las recomendaciones de remediación.

## Nota de redacción

Esta es una versión pública del informe. En el texto, las credenciales, el hash, el fingerprint SSH y la flag originales han sido sustituidos por placeholders; en las capturas de pantalla, los valores reales aparecen difuminados:

- `<PASSWORD_REDACTADA>` — contraseña obtenida
- `<HASH_REDACTADO>` — hash de `/etc/shadow`
- `SHA256:<REDACTADO>` — fingerprint de la clave SSH
- `Whoami{REDACTADO}` — flag

El usuario `admin_support` se mantiene visible porque es necesario para explicar la cadena de explotación. Los archivos de evidencia originales no se publican.

## Descargo de responsabilidad

El contenido tiene fines exclusivamente educativos. Todas las pruebas se realizaron en un entorno de laboratorio local y autorizado. No utilices estas técnicas contra sistemas sin permiso explícito.
