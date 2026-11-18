# LEVIATHAN — Auditoría de seguridad

Writeup público del laboratorio **LEVIATHAN** de Whoami-Labs (`172.17.0.2`).
Dificultad **Hard**: Prototype Pollution, RCE en EJS y escalada de privilegios
mediante un script sudo.

La auditoría se realizó en **caja negra**: sin acceso previo al código, al host
ni al material del laboratorio. El código de la aplicación se leyó únicamente
después del RCE, para confirmar la causa raíz. Las técnicas de detección y la
variante de lectura por HTTP están documentadas en la sección 5 y en el
Anexo A.

> **Versión pública:** las flags están redactadas en el texto y difuminadas en
> las capturas `14`, `20`, `21` y `22` para no revelar la solución del
> laboratorio.

## Documento principal

- [`WRITEUP.md`](WRITEUP.md) — writeup en español con reconocimiento, análisis
  de vulnerabilidades, explotación, escalada de privilegios, evidencias y
  remediación.

## Estructura

```text
.
├── README.md                   # Este índice
├── WRITEUP.md                  # Writeup completo
├── screenshots/                # Capturas de la terminal Kali y del objetivo
└── evidence/                   # Salidas, payloads y notas (flags redactadas)
```

## Resultado

| Flag | Valor |
|---|---|
| Usuario | `Leviathan{REDACTED}` |
| Root | `Leviathan{REDACTED}` |

## Cadena de explotación

1. `POST /api/profile` con `__proto__` contamina `Object.prototype` mediante
   una fusión recursiva insegura; un marcador en `escapeFunction` confirma el
   gadget sin leer el código.
2. La contaminación de `client=true` y `escapeFunction` activa el gadget de
   EJS (CVE-2024-33883) y ejecuta código en el render de `/`.
3. La reverse shell corre como `leviathan`; la flag de usuario está en
   `/home/leviathan/user.txt`. Ya con acceso se leen `server.js` y
   `package.json` para confirmar `merge()` y EJS 3.1.9.
4. `sudo -l` permite `/opt/scripts/backup.sh` sin contraseña; el script hace
   `source` de `/home/leviathan/.backup_config`, controlado por el usuario.
5. Se crea una bash SUID como root y se lee `/root/root.txt`.

## Nota

El laboratorio se dejó limpio tras la auditoría: se eliminaron los artefactos
creados y se restauró el prototipo contaminado del proceso Node. Los detalles
están en la sección 12 del writeup.
