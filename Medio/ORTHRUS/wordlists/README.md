# wordlists/ — Diccionarios usados en ORTHRUS

ORTHRUS es un laboratorio de **Active Directory**. La única lista escrita a mano fue la de
**nombres de usuario** para la enumeración Kerberos. No hubo fuerza bruta de contraseñas: las dos
credenciales se obtuvieron crackeando hashes Kerberos offline con `rockyou.txt`.

---

## `users_corp.txt` — 144 candidatos

Lista de nombres de cuenta para `exploits/krbenum.py` y para el script `krb5-enum-users` de `nmap`.
Se construyó combinando los patrones habituales de un dominio corporativo:

| Bloque | Líneas | Ejemplos |
|---|---|---|
| Cuentas integradas | 1–10 | `administrator`, `admin`, `guest`, `krbtgt`, `test` |
| Nombres anglosajones | 11–41 | `john`, `jane`, `alice`, `michael`, `sarah` |
| Apellidos | 42–51 | `smith`, `johnson`, `garcia`, `martinez` |
| Nombres hispanos | 52–76 | `juan`, `maria`, `carlos`, `laura`, `diego` |
| Temática griega (nombre del lab) | 77–95 | `orthrus`, `cerberus`, `hades`, `zeus`, `medusa` |
| Cuentas de servicio | 96–121 | `svc_backup`, `svc_sql`, `svc_web`, `backup`, `sql` |
| Formatos `nombre.apellido` y `inicial+apellido` | 122–144 | `john.doe`, `jperez`, `mgarcia` |

### Resultado real

De los 144 candidatos, **solo 5 existen**:

```
  [+] administrator                EXISTE (25)
  [+] guest                        EXISTE (18)
  [+] krbtgt                       EXISTE (18)
  [+] svc_backup                   ASREP_SIN_PREAUTH
  [+] svc_sql                      EXISTE (25)

=== 5 existentes de 144 probados ===
```

- `25` = el KDC pide preautenticación (cuenta normal).
- `18` = cuenta deshabilitada o revocada.
- `ASREP_SIN_PREAUTH` = la cuenta **no requiere preautenticación**: su AS-REP se puede crackear
  offline. Es `svc_backup`, la puerta de entrada.

La lista **no se amplió** después: los nombres reales del dominio son cuentas de servicio
(`svc_*`) y las cuentas integradas. Añadir nombres personales no habría cambiado el resultado.

### Reproducir

```bash
python3 exploits/krbenum.py corp.local 172.16.202.130 wordlists/users_corp.txt
```

El enumerador **no prueba contraseñas**: envía un AS-REQ sin preautenticación y lee el código
`KRB-ERROR` de la respuesta. No genera bloqueos ni eventos de logon fallido.

La misma lista alimenta al script nativo de `nmap` (sin código propio):

```bash
nmap -Pn -p 88 --script krb5-enum-users \
  --script-args krb5-enum-users.realm=corp.local,userdb=wordlists/users_corp.txt \
  172.16.202.130
```

Devuelve los mismos tres principales utilizables (`administrator`, `svc_sql`, `svc_backup`) en menos
de un segundo; no lista las cuentas deshabilitadas (`guest`, `krbtgt`). Ver §11 del README.

---

## `rockyou.txt` — lista externa (no incluida)

El crackeo de los hashes AS-REP y TGS se hizo con la lista estándar de Kali:

```
/usr/share/wordlists/rockyou.txt   139 921 507 bytes
```

No se copia al repositorio por tamaño y porque no es material propio. Las dos contraseñas
(`Password123`) aparecen en los primeros cientos de candidatos, así que el crackeo es instantáneo:

```bash
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt loot/asrep_hash.txt
john --format=krb5tgs   --wordlist=/usr/share/wordlists/rockyou.txt loot/tgs_hash.txt
```

---

## Por qué no hay más diccionarios

- **No hubo fuzzing web**: el objetivo no expone HTTP de aplicación (el 5985 es WinRM).
- **No hubo password spraying**: no hizo falta; el AS-REP de `svc_backup` y el TGS de `svc_sql`
  se crackearon offline.
- **No hubo enumeración de recursos SMB con diccionario**: la sesión nula no lista shares y, con
  `svc_backup`, solo aparecen los shares por defecto (`NETLOGON`, `SYSVOL`, `IPC$`).

La lista de usuarios es, por tanto, el único diccionario propio de la auditoría.
