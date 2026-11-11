# Shadow Pivot — Writeup público

Writeup de la auditoría del laboratorio **Shadow Pivot** de Whoami-Labs: una cadena de pivoting en tres segmentos con cuatro flags.

## Cadena explotada

1. **Edge (`172.25.1.10`)** — SSTI en Flask/Jinja2 (`POST /api/reports/generator`) y ejecución de comandos como `webops`.
2. **Pivot (`172.25.2.20`)** — token de cluster filtrado y deserialización YAML insegura (`yaml.load`) en la API interna.
3. **Vault (`172.25.3.30`)** — LFI en la consola PHP, clave privada SSH expuesta, acceso como `vaultadmin` y escalada a root con `sudo NOPASSWD: /usr/bin/find`.

**Resultado:** 4 / 4 flags y validación de la flag de root en la plataforma.

## Contenido

```text
GitHub/
├── README.md
├── WRITEUP.md
├── scans/
│   ├── nmap_allports_edge.txt
│   ├── nmap_services.txt
│   ├── pivot_ports.txt
│   └── vault_ports.txt
└── screenshots/               # 20 capturas (01–20)
```

El informe completo, con la metodología, las evidencias y las recomendaciones, está en [`WRITEUP.md`](WRITEUP.md).

## Nota de redacción

Esta es una **versión pública sanitizada**:

- Las flags se sustituyen por marcadores como `PivotLabs{EDGE_USER_REDACTED}`.
- El token de cluster, las contraseñas y el material de clave privada se reemplazan por `<REDACTED_...>`.
- Las capturas `06`, `07`, `11`, `16`, `17`, `19` y `20` tienen difuminadas las regiones con flags, tokens o claves.
- No se publican scripts de explotación, claves SSH, notas internas ni el resto del material sensible del workspace.

## Aviso

Este contenido documenta una auditoría realizada en un laboratorio autorizado con fines educativos. No debe utilizarse contra sistemas sin permiso explícito.
