# JANUS — Writeup público

Auditoría blackbox del laboratorio **JANUS** (`172.17.0.2`), disponible en
[Whoami-Labs](https://whoami-labs.com/laboratorios/janus).

> **Versión pública:** las flags y credenciales/tokens están redactados; las capturas
> están redactadas en las zonas sensibles. Los artefactos crudos de explotación no se publican.

- **Informe completo:** [`WRITEUP_JANUS.md`](WRITEUP_JANUS.md)
- **Capturas:** [`screenshots/`](screenshots/)

## Resultado

Compromiso total del contenedor hasta `root` y validación de ambas flags.

```text
Usuario: Janus{REDACTED}
Root:    Janus{REDACTED}
```

## Cadena principal

```text
Next.js 3000 (SSRF por Host) → Admin API Flask 127.0.0.1:4000
→ Command Injection → shell svc-janus → SUID syscheck (PATH Hijacking) → root
```

## Hallazgo adicional

El portal legacy `8080`, etiquetado como `RABBIT HOLE 1` e “inútil para la progresión”,
corre como `root`; su LFI permite leer directamente `/root/root.txt` y la flag de usuario.
Es un atajo crítico, no un simple señuelo.

## Capturas

1. `screenshots/01_recon_servicios.png` — Nmap, cabeceras, FTP anónimo.
2. `screenshots/02_decoys_lfi.png` — Portal legacy, LFI, `RABBIT HOLE 1`, prompt injection.
3. `screenshots/03_ssrf_rce.png` — SSRF, API interna, `cmd=id`.
4. `screenshots/04_user_flag_suid.png` — Flag de usuario, SUID, `syscheck`.
5. `screenshots/05_privesc_root.png` — Reverse shell, PATH Hijacking, root.
6. `screenshots/06_lfi_flags.png` — LFI con Node root, flags directas.
7. `screenshots/07_validacion_flags.png` — Validación de ambas flags en la plataforma.

## Sanitización

- Flags: el contenido entre llaves se reemplazó por `REDACTED`.
- API key y JWT falsos: no se reproducen.
- Capturas: cajas `REDACTED` sobre las flags.
- `loot/`, `logs/` y `recon/`: no se publican porque contienen artefactos crudos.
