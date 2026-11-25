# STING — Writeup público

**Analista:** chifay  
**Plataforma:** Whoami-Labs  
**Dificultad:** Insane  
**Objetivo:** `172.17.0.2`  
**Resultado:** Compromiso total del host y captura de la flag.

> Versión pública del informe. Las contraseñas, los hashes, las API keys y el contenido de la flag están redactados en el texto y difuminados en las capturas. Solo se muestra el prefijo `H0N3YTR4P` de la flag.

## Cadena de ataque

1. **Reconocimiento:** puertos 21, 22, 9000, 1433 y 27017 son señuelos; los servicios reales son HTTP (80/8080) y SSH (31337).
2. **SQL injection:** bypass del login y volcado de la base de datos `sting_db`.
3. **LFI:** bypass del filtro de `logs.php` con `....//` y lectura de archivos internos.
4. **Credenciales reutilizadas:** acceso SSH como `beekeeper`.
5. **Privesc:** abuso de comodines en `sudo /bin/tar` para obtener una shell con SUID root.
6. **Flag:** lectura del archivo final como `root`.

## Contenido

| Ruta | Descripción |
|---|---|
| [`WRITEUP.md`](WRITEUP.md) | Informe completo con comandos, hallazgos y remediación |
| [`screenshots/`](screenshots/) | 11 capturas (10 de terminal y 1 de validación) con los secretos difuminados |
| [`exploits/sqli_extract.py`](exploits/sqli_extract.py) | Extractor booleano para la SQLi |
| [`exploits/tar_wildcard.sh`](exploits/tar_wildcard.sh) | Script de escalada por comodines en `tar` |

## Flag

```text
H0N3YTR4P{REDACTED}
```
