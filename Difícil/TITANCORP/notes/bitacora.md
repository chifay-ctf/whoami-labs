# TITANCORP — Bitácora del análisis

**Objetivo:** `172.16.202.131` — `WIN-CFIU5AU7L2D.corp.local` (DC Windows Server 2019)
**Atacante:** Kali Linux — `172.16.202.129/24`
**Dominio:** `corp.local` — **SID:** `S-1-5-21-2314756761-1692085105-450277737`
**Dificultad:** difícil (★★★★★☆☆☆, 5 pts) — **Categoría:** Active Directory / pivoting & lateral movement
**Fecha:** 26/10/2026
**Bandera:** `CPENT{t1t4n_c0rp_mult1h0p_bl00dh0und_m4st3r_2026}`

> **Nota metodológica:** el laboratorio es una OVA de VMware, no un contenedor. El análisis se hizo
> por red y no se inspeccionó el disco de la VM desde el hipervisor. Las marcas de tiempo de los
> artefactos no son homogéneas (Kali, la VM y los logs usan relojes distintos); el orden de esta
> bitácora se reconstruye por las dependencias reales de cada paso, no por el `mtime` de los ficheros.

---

## 1. Resumen de la sesión

TITANCORP es un dominio con **un único DC** y sin superficieweb, SSH ni RDP accesibles. La única
superficie es Active Directory: DNS, Kerberos, LDAP, SMB y WinRM. La ruta que se ejecutó fue un atajo
sobre el diseño previsto:

```text
sin credenciales
  → AS-REP roasting (3 cuentas) + Kerberoasting (3 cuentas)
  → Password123 en las 6 cuentas
  → svc_sql es miembro de BUILTIN\Administrators
  → WinRM como svc_sql
  → DCSync
  → krbtgt + Administrator + 20 cuentas con el mismo hash
  → lectura de la bandera
```

El fichero de bandera describe otra cadena, la **intencionada**:

```text
d.morales (Helpdesk L1)
  → WriteDACL / GenericAll sobre Data-Analytics-Ops
  → titan_api (Kerberoast / GenericAll)
  → GenericWrite sobre Core-Infrastructure-Admins
  → Administrators
  → DCSync / DC
```

La ruta intencionada se validó **después** del DCSync, usando el hash NT de `d.morales`; su
contraseña en claro no se recuperó. La entrada inicial real no fue `d.morales`, sino las cuentas de
servicio con `Password123`.

---

## 2. Cronología lógica

| Fase | Acción | Resultado |
|---|---|---|
| 1 | `nmap -Pn -sT -p-` y `-sV -sC` | 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389 y RPC alto. 22/80/443/3389 filtrados. |
| 2 | DNS y SMB | `corp.local` → `172.16.202.131`; único DC `WIN-CFIU5AU7L2D`; SMB signing required; SMBv1 off. |
| 3 | LDAP rootDSE | Dominio, functional level 7 y nombre del DC. Subárbol anónimo: `Operations error`. |
| 4 | Domaindump / BloodHound | 28 usuarios, 56 grupos, 1 equipo. Grupos y ACLs relevantes identificados. |
| 5 | AS-REP roasting | 3 cuentas: `auditor_externo`, `c.ramirez`, `svc_backup`. |
| 6 | Cracking AS-REP | Las tres → `Password123`. |
| 7 | Kerberoasting con `svc_sql` | 3 cuentas: `svc_sql`, `svc_oracle`, `titan_api`; las tres → `Password123`. |
| 8 | Acceso SMB/WinRM como `svc_sql` | `Pwn3d!`; miembro de `BUILTIN\Administrators` en el DC. |
| 9 | DCSync | `Administrator`, `krbtgt`, 20 cuentas con el mismo hash NT y hashes únicos. |
| 10 | BloodHound / `dacledit` | Cadena de ACLs `d.morales → Data-Analytics-Ops → titan_api → Core → Administrators`. |
| 11 | Validación de la cadena | Alta/baja controlada de `estudiante` en ambos grupos; cleanup verificado. |
| 12 | Bandera | Lectura de `C:\Users\Administrator\Desktop\FLAG_TITANCORP_DOMAIN_ADMIN.txt` como `titan_api`. |
| 13 | Limpieza | `estudiante` fuera de `Data-Analytics-Ops` y `Core-Infrastructure-Admins`; grupos con sus miembros originales. |

> La secuencia exacta de horas no se usa como prueba. Las evidencias están en `recon/`, `loot/` y
> `shots/captures/`; los comandos y salidas relevantes se citan en el README.

---

## 3. Reconocimiento

### 3.1 Puertos

```text
53/tcp    domain        Simple DNS Plus
88/tcp    kerberos-sec  Microsoft Windows Kerberos
135/tcp   msrpc         Microsoft Windows RPC
139/tcp   netbios-ssn
389/tcp   ldap          AD LDAP (Domain: corp.local)
445/tcp   microsoft-ds  SMB signing enabled and required
464/tcp   kpasswd5
593/tcp   ncacn_http
636/tcp   ldapssl
3268/tcp  globalcatLDAP
3269/tcp  globalcatLDAPssl
5985/tcp  wsman         WinRM
9389/tcp  adws
```

`22`, `80`, `443` y `3389` están filtrados. No hay aplicación web que enumerar. La decisión fue no
perder tiempo con fuerza bruta web/SSH y atacar identidad.

### 3.2 DNS y SMB

- `corp.local` resuelve a `172.16.202.131`.
- `_ldap._tcp.dc._msdcs.corp.local` y `_kerberos._tcp.corp.local` apuntan al mismo DC.
- `smbclient -L` anónimo no lista shares; con `svc_sql` aparecen `ADMIN$`, `C$`, `IPC$`, `NETLOGON`,
  `SYSVOL`.
- SMB signing **enabled and required**; SMBv1 deshabilitado. No se intentó relay.

### 3.3 LDAP y política

El rootDSE es legible sin autenticación, pero el subárbol `DC=corp,DC=local` responde
`Operations error` a una búsqueda anónima. El inventario completo se consolidó con domaindump y
BloodHound una vez obtenida una credencial de servicio.

Datos clave:

- 28 usuarios, 56 grupos, 1 equipo.
- `WIN-CFIU5AU7L2D` es el único DC; no hay otros hosts a los que pivotar.
- `Domain Admins`: `c.duque`, `a.salazar`, `Administrator`.
- `Administrators`: `Core-Infrastructure-Admins`, `Tier1-Admins`, `svc_sql`, `Domain Admins`,
  `Enterprise Admins`, `Administrator`.
- `Core-Infrastructure-Admins`: `s.velez`, `titan_api`.
- `Data-Analytics-Ops`: `titan_api`, `d.morales`.
- `IT-Helpdesk`: `julian.zapata`, `d.morales`.
- Política: mínimo 7, complejidad activa, máximo 42 días, historial 24, **lockout Never**.
- GPO del dominio (`{31B2F340-...}`): `LockoutBadCount = 0`, `MinimumPasswordLength = 7`.

**Decisión:** la política permite password spraying sin bloqueo, pero el hallazgo más grave es la
reutilización masiva de `Password123`; no hace falta spraying.

---

## 4. Kerberos: del anonimato a las credenciales

### 4.1 AS-REP roasting

Sin credenciales, `GetNPUsers` encontró tres cuentas con `UF_DONT_REQUIRE_PREAUTH`:

```text
auditor_externo
c.ramirez
svc_backup
```

Las tres se crackearon con `hashcat -m 18200` y `rockyou.txt`:

```text
Password123
```

### 4.2 Kerberoasting

Con `svc_sql:Password123` se solicitó un TGS para cada SPN:

```text
svc_sql     HTTP/intranet.corp.local, MSSQLSvc/db01.corp.local
svc_oracle  OracleSvc/db-prod.corp.local
titan_api   MSSQLSvc/bi-cluster.corp.local, HTTP/api-bi.corp.local
```

Las tres se crackearon con `hashcat -m 13100`:

```text
Password123
```

### 4.3 Lo que revela la tabla de SPNs

`svc_sql` ya figura como miembro de `CN=Administrators,CN=Builtin,DC=corp,DC=local` y `titan_api`
como miembro de `Core-Infrastructure-Admins`. Es decir, el atajo no necesita la cadena de ACLs: una
cuenta de servicio con contraseña débil ya está en el grupo administrativo del DC.

**Decisión:** usar `svc_sql` para DCSync, no quedarse en la enumeración. `svc_sql` tiene SMB y WinRM
con `Pwn3d!`, y la ACL del dominio concede a `Administrators` `GetChanges` y `GetChangesAll`.

---

## 5. DCSync

```bash
impacket-secretsdump 'corp.local/svc_sql:Password123@172.16.202.131' -just-dc
```

Resultado:

- 29 entradas: usuarios, `krbtgt`, `Guest` y la cuenta de equipo del DC.
- `Administrator` y `krbtgt` comprometidos.
- **20 cuentas comparten el mismo hash NT** `58a478135a93ac3bf058a5ea0e8fdb71`, que corresponde a
  `Password123`.
- `m.torres` tiene un hash único que se crackeó a `Summer2026!`.
- `d.morales` tiene el hash `c5944a4b6fd2e7bd92b44fced7400ee0`; **no se recuperó su contraseña en
  claro**.
- `a.salazar` y `c.duque` (Domain Admins) tienen hashes únicos que no se crackearon.

El volcado no se usó para cambiar contraseñas ni para crear persistencia. Los hashes completos están
en `loot/dcsync-full.txt`; el informe solo muestra prefijos.

---

## 6. Cadena de ACLs (ruta intencionada)

### 6.1 d.morales → Data-Analytics-Ops

ACE relevantes en `Data-Analytics-Ops`:

```text
WriteDACL   <- IT-Helpdesk
FullControl <- d.morales
FullControl <- Domain Admins
WriteOwner + WriteDACL + AllExtendedRights (heredado) <- Administrators
```

`d.morales` es miembro de `IT-Helpdesk` y tiene además `FullControl` directo sobre el grupo. Con
`WriteDACL` puede modificar la DACL y añadir miembros; con `GenericAll` puede hacerlo directamente.

Validación: se añadió `estudiante` al grupo como `d.morales` por WinRM (hash NT), se verificó y se
eliminó. El grupo quedó en `d.morales`, `titan_api`.

### 6.2 Data-Analytics-Ops → titan_api

`titan_api` es miembro de `Data-Analytics-Ops` y es kerberoasteable. La contraseña `Password123` ya
se había recuperado por Kerberoasting. La ruta intencionada lo presenta como paso de pivote; en la
práctica, el atajo ya tenía `titan_api` por roasting.

### 6.3 titan_api → Core-Infrastructure-Admins

ACE relevantes en `Core-Infrastructure-Admins`:

```text
ReadAndExecute + WriteOwner + WriteDACL + AllExtendedRights <- Domain Admins
ReadAndExecute + WriteOwner + WriteDACL + AllExtendedRights <- Enterprise Admins
Modify + WriteOwner + WriteDACL <- Administrators
```

`titan_api` **ya es miembro** de `Core-Infrastructure-Admins`. El grupo está anidado en
`BUILTIN\Administrators`. Por eso `titan_api` ya tiene privilegios administrativos efectivos; el
`GenericWrite` derivado de las ACE de `Administrators` permite además añadir miembros al grupo. Se
validó con `estudiante` y se deshizo.

> Matiz importante: en este laboratorio el paso “GenericWrite sobre Core” no es necesario para que
> `titan_api` sea admin, porque ya pertenece al grupo. Se documenta y se valida porque el fichero de
> bandera lo señala como parte de la cadena diseñada.

### 6.4 Core → Administrators → dominio

`Core-Infrastructure-Admins` es miembro de `BUILTIN\Administrators`. La ACL del dominio concede a
`Administrators`:

```text
GetChanges
GetChangesAll
GetChangesInFilteredSet
DS-Replication-Synchronize
DS-Replication-Manage-Topology
...
```

Eso habilita DCSync. `svc_sql` también es miembro de `Administrators`, por lo que el atajo y la ruta
intencionada convergen en el mismo control: la ACL del dominio sobre `BUILTIN\Administrators`.

---

## 7. Bandera y validación

La OVA **no publica un validador oficial** como los laboratorios Docker de QUANTUM/ARASAKA. No se
inventó uno ni se atribuyó una validación inexistente.

La bandera se leyó directamente del fichero máster del DC:

```text
C:\Users\Administrator\Desktop\FLAG_TITANCORP_DOMAIN_ADMIN.txt
```

```text
CPENT{t1t4n_c0rp_mult1h0p_bl00dh0und_m4st3r_2026}
```

El propio fichero documenta la cadena intencionada de cinco pasos. Esa lista se cita como contexto de
diseño, no como prueba de que la entrada inicial fuera `d.morales`.

---

## 8. Decisiones, callejones sin salida y limitaciones

| Tema | Decisión / resultado |
|---|---|
| Superficie web | 80/443 filtrados; no hay aplicación web. Se descarta enumeración web. |
| SSH/RDP | 22/3389 filtrados; no hay acceso interactivo clásico. |
| LDAP anónimo | RootDSE sí; subárbol no. El inventario se consolidó con domaindump/BloodHound. |
| SMB relay | SMB signing required y SMBv1 off; no se intentó relay. |
| Fuerza bruta | No fue necesaria: roasting + `Password123`; lockout Never lo habría permitido, pero era ruido innecesario. |
| `d.morales` | Su contraseña en claro no se recuperó. Se usó el hash NT de DCSync solo para validar la cadena. |
| `Administrator`/`krbtgt` | Hashes obtenidos, sin crackeo ni uso destructivo. |
| Otros hosts | Solo el DC. La categoría “lateral movement” es entre identidades/grupos, no entre máquinas. |
| Validador | No existe para esta OVA; la evidencia es la lectura del fichero máster. |
| Persistencia | Ninguna. No se crearon cuentas, equipos, tareas, servicios ni claves. |
| Cambios | Solo alta/baja controlada de `estudiante` en dos grupos, con cleanup verificado. |

### 8.1 Diferencias con la ruta “oficial” del fichero de bandera

La cadena que describe la bandera es:

```text
d.morales → WriteDacl/Data-Analytics-Ops → titan_api → GenericWrite/Core → Administrators → DC
```

La cadena que realmente se ejecutó fue:

```text
AS-REP + Kerberoast → Password123 → svc_sql (Administrators) → WinRM → DCSync → DC
```

No son contradictorias: la segunda es un **atajo** que el propio diseño permite por la reutilización
de contraseñas y por `svc_sql` en `Administrators`. La primera se validó después para comprobar que
las ACLs también funcionaban. El informe separa ambas para no atribuir la entrada inicial a una
credencial que no se tenía.

---

## 9. Limpieza

Se utilizó `estudiante` como cuenta de prueba (no privilegiada, ya existente) y se añadió/eliminó de:

- `Data-Analytics-Ops`
- `Core-Infrastructure-Admins`

Comprobación final:

```text
Data-Analytics-Ops:        d.morales, titan_api
Core-Infrastructure-Admins: s.velez, titan_api
```

`estudiante` no queda en ninguno de los dos grupos. No se modificaron contraseñas, atributos de
cuentas, equipos, GPOs, tareas ni servicios. La evidencia está en `loot/chain-dmorales.txt`,
`loot/chain-titanapi.txt` y `loot/cleanup-verification.txt`.

---

## 10. Lecciones

1. **Un servicio con contraseña débil puede ser un Domain Admin.** `svc_sql` estaba en
   `BUILTIN\Administrators`; Kerberoasting fue suficiente.
2. **La reutilización multiplica el impacto.** 20 cuentas con el mismo hash convierten un único
   cracking en un compromiso masivo.
3. **La política de lockout nunca ayuda si la contraseña es `Password123`.** La complejidad mínima
   de 7 caracteres no compensa una contraseña común.
4. **Las ACLs son superficie de ataque.** `WriteDACL`, `GenericAll` y `GenericWrite` sobre grupos
   anidados en `Administrators` permiten escalar sin tocar el DC directamente.
5. **Un solo DC no significa un solo paso.** El pivote es lógico: identidad → grupo → ACL → dominio.
6. **La evidencia manda.** El flag file describe la ruta esperada; el informe demuestra también la
   ruta real y explica la diferencia.
