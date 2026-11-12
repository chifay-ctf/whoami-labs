# Titan Linux — Writeup público (CPENT Victim)

Auditoría de seguridad del laboratorio **Titan Linux** de [Whoami-Labs](https://whoami-labs.com/laboratorios/titan-linux): una víctima Ubuntu 24.04.1 LTS con tres vectores independientes de escalada a `root` y una red interna oculta accesible mediante pivoting.

> **Entorno autorizado:** todas las pruebas se realizaron sobre una máquina virtual de laboratorio propia. No utilices estas técnicas contra sistemas de terceros sin autorización escrita.

---

## Resumen del compromiso

| Fase | Resultado |
|------|-----------|
| Reconocimiento | `22/tcp` — OpenSSH 9.6p1 Ubuntu |
| Acceso inicial | Credenciales SSH débiles obtenidas con Hydra |
| Escalada 1 | `cap_setuid=ep` en `/usr/bin/python3.12` → `root` |
| Escalada 2 | `env_keep += LD_PRELOAD` + `NOPASSWD: /usr/bin/find` → `root` |
| Escalada 3 | `status_check` SUID + PATH hijacking → `root` |
| Pivoting | Interfaz `dummy0` (`10.10.50.1/24`) + túnel SOCKS SSH → bóveda interna |

**Flags:** `CPENT{REDACTADO}` (root) y `CPENT{REDACTADO}` (pivoting).

---

## Contenido del repositorio

| Ruta | Descripción |
|------|-------------|
| [`writeup/INFORME_FINAL.md`](writeup/INFORME_FINAL.md) | Informe completo en Markdown |
| [`writeup/INFORME_FINAL.html`](writeup/INFORME_FINAL.html) | Versión HTML autocontenida (imágenes embebidas) |
| [`writeup/INFORME_FINAL.pdf`](writeup/INFORME_FINAL.pdf) | Informe imprimible en PDF |
| [`capturas/`](capturas/) | Capturas de terminal usadas en el informe |
| [`evidencias/`](evidencias/) | Salidas en crudo de los comandos principales |
| [`scripts/libhijack.c`](scripts/libhijack.c) | PoC de la biblioteca usada en el secuestro `LD_PRELOAD` |
| [`scripts/md_to_html.py`](scripts/md_to_html.py) | Conversor de Markdown a HTML autocontenido |

---

## Vectores explotados

| # | Técnica | MITRE ATT&CK | Resultado |
|---|---------|--------------|-----------|
| 1 | `cap_setuid` en Python 3.12 | T1548 — Abuse Elevation Control | `root` |
| 2 | `LD_PRELOAD` + `sudo find` | T1574.006 — Dynamic Linker Hijacking | `root` |
| 3 | PATH hijacking en SUID `status_check` | T1574.007 — Path Interception | `root` |
| 4 | Descubrimiento de subred oculta y pivoting SOCKS | T1018 / T1090 — Discovery / Proxy | Acceso a red interna |

El detalle de cada fase, la kill chain consolidada, la matriz de riesgo y las recomendaciones de remediación están en el [informe final](writeup/INFORME_FINAL.md).

---

## Redacción de información sensible

Al tratarse de una publicación, se ha aplicado la siguiente redacción:

- **Flags:** se conserva el prefijo `CPENT{` y el cierre `}`, pero el contenido interno está redactado en el informe y difuminado en las capturas.
- **Credenciales:** las contraseñas están redactadas en el texto y difuminadas en las imágenes.
- **Archivos no publicados:** notas internas, listas de contraseñas, loot con flags, transcripción de la sesión y capturas de trabajo no referenciadas por el informe.

---

## Reproducir el informe

Desde la raíz del repositorio:

```bash
python3 scripts/md_to_html.py

URL=$(python3 -c 'from pathlib import Path; print(Path("writeup/INFORME_FINAL.html").resolve().as_uri())')
chromium --headless=new --no-sandbox --disable-gpu --no-pdf-header-footer \
  --print-to-pdf=writeup/INFORME_FINAL.pdf "$URL"
```

Dependencias: `python3`, el paquete `markdown` y Chromium (o un navegador compatible con impresión headless).

---

## Aviso legal

Este repositorio tiene fines exclusivamente educativos y documentales. El laboratorio Titan Linux pertenece a Whoami-Labs y fue desplegado en un entorno controlado. El autor no se responsabiliza del uso indebido de las técnicas descritas.
