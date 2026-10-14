# GATEKEEPER — Notas de ejecución

## Objetivo
Comprometer el host `172.17.0.2` y leer `/root/flag.txt`.
Categoría: **SUID & Sudo** — Dificultad **Hard**.

## Enfoque
Auditoría **100 % black-box**: solo interacciones de red (nmap, HTTP, TCP knocks, SSH).
Sin acceso al host ni al filesystem del contenedor.

## Entorno
- Atacante: Kali en VMware, interfaz `docker0` = `172.17.0.1/16`
- Objetivo: `172.17.0.2` (hostname de red `metasploitable.vm`)

## Servicios

| Puerto | Estado | Veredicto |
|--------|--------|-----------|
| 80 | open (Apache 2.4.52) | Real — superficie principal |
| 3306 | open (mysql?) | Señuelo (error sin handshake, siempre `@'localhost'`) |
| 5432 | open (postgresql?) | Señuelo (rechaza sin startup packet) |
| 33333 | filtered | SSH real, bloqueado hasta port-knock |

## Hallazgos web

- `/admin/` → solo `index.html` "Under Construction"
- `/backups/` → listado habilitado; contiene dotfiles:
  - `/backups/.env` (base64) → `GKP1337P2048P4096TRON`  [semilla de knock]
  - `/backups/.backup` → audit log; disclose el usuario `mauricio`

## Ruta de ataque (resumen)

```
.env → knock 1337/2048/4096 → SSH 33333
     → mauricio:143143 (spray) → login
     → ls /home → developer, mauricio, sysadmin
     → clave dividida world-readable → login sysadmin
     → cat /tmp/.current_otp → ./.system_auth → sudo auth_root → root
     → flag
```

## Notas técnicas

- El puerto 33333 se reabre re-ejecutando la secuencia de knock si expira.
- El timing de SSH no permite enumerar usuarios (válido vs inválido indistinguible);
  la enumeración real ocurre *después* del primer login.
- El brute online de rockyou contra SSH es inviable (rate-limit ~200/min); la credencial
  válida es débil y se encuentra con un spray dirigido.

## Flag

```
GATEKEEPER{0TP_4uth3nt1c4t10n_M4st3r_2026}
```
