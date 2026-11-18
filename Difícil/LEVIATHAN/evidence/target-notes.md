# Metadatos del objetivo

- IP: `172.17.0.2`
- Hostname: `e27cbd55ae81`
- Contenedor: `leviathan` (Docker, red bridge `172.17.0.0/16`)
- Puerto expuesto: `80/tcp` (HTTP, Express)
- Directorio de la aplicación: `/app`
- Usuario del proceso Node: `leviathan` (UID 1000)
- Kernel visible: `7.2.15+kali-amd64` (kernel del host compartido por Docker)
- Usuarios relevantes: `root` (UID 0), `leviathan` (UID 1000)
- Sudo: `leviathan ALL=(root) NOPASSWD: /opt/scripts/backup.sh`
- Script vulnerable: `/opt/scripts/backup.sh` (hace `source` de `/home/leviathan/.backup_config`)
- Aplicación: Node.js/Express, EJS 3.1.9, body-parser 1.20.2, Express 4.18.2

## Flags obtenidas

- Usuario: `Leviathan{REDACTED}`
- Root: `Leviathan{REDACTED}`
