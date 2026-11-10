# Titan Linux - CPENT Victim | Informe de auditoría

Auditoría de seguridad del laboratorio **Titan Linux** (https://whoami-labs.com/laboratorios/titan-linux),
víctima Ubuntu 24.04.1 LTS desplegada en `192.168.60.132` y atacada desde Kali `192.168.60.128`.

## Entregables principales

| Archivo | Descripción |
|---------|-------------|
| `writeup/INFORME_FINAL.md` | Informe final completo en Markdown |
| `notas/flags_loot.txt` | Registro de credenciales, flags y comandos clave |
| `loot/flag_pivoting_desde_kali.txt` | Flag de pivoting obtenida desde Kali |
| `loot/flag_root.txt` | Flag de root |

## Estructura

```
Titan Linux/
├── capturas/                  # Capturas de pantalla de la terminal Kali
├── evidencias/                # Salida en crudo (TXT/HTML) de cada comando
├── loot/                      # Flags y loot extraído
├── notas/                     # usuarios.txt, passwords_lab.txt, flags_loot.txt
├── scripts/                   # Scripts de explotación y generación del informe
│   ├── stage0_recon.sh
│   ├── stage1_cap_setuid.sh
│   ├── stage2_ld_preload.sh
│   ├── stage3_path_suid.sh
│   ├── stage4_pivoting.sh
│   ├── stage5_pivot_kali.sh
│   └── libhijack.c
└── writeup/                   # Informe final
```

## Capturas

Todas las capturas fueron tomadas de una terminal con los comandos y su salida en crudo.

## Resumen del compromiso

- **Acceso inicial:** `XXXXX:YYYYY` (Hydra; `YYYYY` está en la línea 1384 de rockyou).
- **Hallazgo extra:** `XXXXX` tiene sudo total `(ALL : ALL) ALL`.
- **Vector 1:** `cap_setuid=ep` en `/usr/bin/python3.12` → root.
- **Vector 2:** `env_keep += LD_PRELOAD` + `NOPASSWD: /usr/bin/find` en `/etc/sudoers.d/developer_privesc` → root.
- **Vector 3:** `/usr/local/bin/status_check` SUID root llama `service apache2 status` sin ruta absoluta → PATH hijacking → root.
- **Vector 4:** interfaz `dummy0` `10.10.50.1/24` + servicio interno `http://10.10.50.1:8080` → flag de pivoting.
- **Pivoting desde Kali:** `ssh -D 1080 -N -f XXXXX@192.168.60.132` + `curl --socks5-hostname 127.0.0.1:1080 http://10.10.50.1:8080`.

## Flags

- `CPENT{...}` — root.
- `CPENT{...}` — pivoting.

## Aviso legal

Laboratorio autorizado y controlado. No ejecutes estas técnicas contra sistemas de terceros
sin permiso explícito y por escrito.
