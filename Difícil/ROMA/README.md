# ROMA — Writeup de Auditoría de Seguridad (CTF)

| Campo | Valor |
|---|---|
| **Laboratorio** | ROMA — *La Ciudad Eterna* |
| **Plataforma** | Whoami-Labs |
| **Dificultad** | Difícil ★★★★★☆☆☆ (5 puntos) |
| **Autor del writeup** | chifay |
| **Fecha** | 15/10/2026 |
| **Objetivo** | `172.17.0.2` (contenedor Docker) |
| **Atacante** | Kali Linux — `172.17.0.1` (red del contenedor) |
| **Hostname del objetivo** | `metasploitable.vm` |
| **Bandera obtenida** | `ROMA{1d0r_us3r_3num_p0rt_kn0ck_d04s_pr1v3sc_f41l2b4n_2026}` |
| **Ruta completa** | Fuerza bruta SSH → `roma3` → clave SSH oculta → `roma1` → clave SSH oculta → `roma2` → **OpenDoas SUID mal configurado** → `root` |
| **Documento** | Writeup completo; los artefactos que respaldan cada conclusión están en el repositorio (ver §14) |

---

## 1. Resumen ejecutivo

Laboratorio de dificultad alta en el que **toda la superficie web y el servicio FTP son señuelos
deliberados**. El único vector de entrada real es **SSH**, protegido por dos capas independientes:

1. **Port knocking** — el puerto 22 está cerrado por `iptables -j DROP` hasta ejecutar la secuencia `7003 → 7005 → 7007` (que *elimina* la regla DROP; la secuencia inversa `7007 → 7005 → 7003` la reinyecta).
2. **Fail2Ban** — 2 fallos de autenticación en menos de 60 s ⇒ ban de 600 s.

Tras forzar el acceso, la escalada se produce encadenando **tres usuarios** (`roma3` → `roma1` → `roma2`),
cada uno custodiando una clave SSH privada partida en dos ficheros ocultos, hasta llegar a un
**binario SUID `doas` mal configurado** que concede root sin contraseña.

| Etapa | Vector | De → A |
|---|---|---|
| 1 | Fuerza bruta SSH (1 intento/min) | — → `roma3` |
| 2 | Clave privada partida oculta en su home | `roma3` → `roma1` |
| 3 | Clave privada partida oculta en `/tmp` | `roma1` → `roma2` |
| 4 | `doas` SUID con `permit nopass` | `roma2` → `root` |

![Cadena de ataque completa](docs/img/11-cadena-completa.png)

---

## 2. Reconocimiento

### 2.1 Puertos

```bash
nmap -Pn -sV -sC -p 21,22,80,7003,7005,7007 172.17.0.2
nmap -Pn -p- --min-rate 3000 172.17.0.2
```

| Puerto | Estado | Servicio | Notas |
|---|---|---|---|
| 21/tcp | open | vsftpd | `500 OOPS: both local and anonymous access disabled!` |
| 22/tcp | open / **filtered** | OpenSSH 8.2p1 Ubuntu-4ubuntu0.13 | Bloqueado salvo knocking activo y sin ban |
| 80/tcp | open | Apache/2.4.41 (Ubuntu) | `index.html` + `status.php` |
| 7003/tcp | open | banner estático | Módulo **R1** → usuario `roma1` |
| 7005/tcp | open | banner estático | Módulo **R2** → usuario `roma2` |
| 7007/tcp | open | banner estático | Módulo **R3** → usuario `roma3` |

Base: **Ubuntu 20.04.6 LTS**. Hostname `metasploitable.vm`.

![Reconocimiento de puertos](docs/img/01-recon-puertos.png)

> **Dato clave:** `22/tcp` figura como **filtered** — el puerto está bloqueado por `iptables`.
> Los puertos 7003/7005/7007 no son servicios interactivos: cada uno se limita a imprimir un
> banner mediante `nc -l`. Aunque su contenido es decorativo, **revela los tres usuarios del sistema**.

### 2.2 FTP — vector cerrado

```
$ nc 172.17.0.2 21
500 OOPS: vsftpd: both local and anonymous access disabled!
```

vsftpd aborta durante la negociación inicial: nunca llega a emitir el banner `220`, por lo que
no se puede enviar ningún comando. Se probó también el **backdoor de vsftpd 2.3.4** (usuario
con acento grave → shell en el puerto 6200): el 6200 permanece cerrado.

### 2.3 Web — señuelo total

| Ruta | Resultado |
|---|---|
| `/` | `index.html` estático, único enlace a `status.php` |
| `/status.php` | Panel de estado de Fail2Ban (**fuga de configuración**) |
| `/.env` | Base64 → `" de todas formas ya aprendiste algo nuevo!!!"` |
| `/R/` y `/roma/R/` | Árbol recursivo de ficheros en base64 (troll) |
| `/roma/R/O/M/A/default/shell/decode.py` | Script del propio autor que genera el árbol |
| `/css/`, `/img/`, `/js/`, `/.ssh/` | Vacíos |

**Concatenando y decodificando** los ficheros de `/R/` (`/R/.R`, `/R/O/.O`, `/R/O/M/.M`, `/R/O/M/A/.A`)
se obtiene el mensaje completo:

> **"Lo siento, por no poder darte pistas sobre el laboratorio, pero de todas formas ya aprendiste algo nuevo!!!"**

El `decode.py` del autor decodifica a ese mismo texto seguido de **`P7003, P7005, P7007`**,
que es la **pista de la secuencia de port knocking**.

`gobuster` (wordlist medium), `nikto`, WebDAV (`PROPFIND` → 405) y el análisis de hosts virtuales
no revelan nada más. No hay LFI en `status.php` (los parámetros no alteran la respuesta) ni
código fuente filtrado.

![El troll de /R/ y la pista real](docs/img/04-senuelo-web.png)

### 2.4 `status.php` — fuga clave de configuración

```
📛 Max Retry   : 2 intentos
⏱️ Find Time   : 60 segundos
🔒 Ban Time    : 600 segundos
```

> "Tu IP puede conectarse libremente al servidor SSH **(después del port knocking)**."

Los bloques de logs fallan con `sudo: a terminal is required to read the password`,
un bug del propio PHP que impide leer `auth.log` / `fail2ban.log` desde la web.

Detalle adicional del código fuente (legible una vez dentro): `status.php` obtiene la IP del
visitante con `$_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR']`, por lo que la IP
baneada es **falsificable** mediante la cabecera `X-Forwarded-For`.

![Configuración de Fail2Ban filtrada](docs/img/05-fail2ban-config.png)

---

## 3. Port knocking — mecanismo de acceso

El puerto 22 está **cerrado por defecto** (`iptables -A INPUT -p tcp --dport 22 -j DROP`).
El laboratorio usa `knockd`, y leyendo `/etc/knockd.conf` (ya dentro del sistema) se ve que
**no hay timeout de ventana**, sino **dos secuencias simétricas**:

```ini
[openSSH]    sequence = 7003,7005,7007   seq_timeout = 15   tcpflags = syn
             command  = /sbin/iptables -D INPUT -p tcp --dport 22 -j DROP

[closeSSH]   sequence = 7007,7005,7003   seq_timeout = 15   tcpflags = syn
             command  = /sbin/iptables -A INPUT -p tcp --dport 22 -j DROP
```

Es decir: la secuencia de apertura **elimina** la regla DROP y el puerto 22 queda accesible
**hasta que se envíe la secuencia inversa**, que la reinyecta.

```bash
# abrir
for p in 7003 7005 7007; do echo >/dev/tcp/172.17.0.2/$p; sleep 0.3; done
ssh roma3@172.17.0.2 ...

# cerrar (opcional)
for p in 7007 7005 7003; do echo >/dev/tcp/172.17.0.2/$p; sleep 0.3; done
```

> **Nota de rigor:** una medición inicial dio la impresión de una ventana de ~12 s. Era una
> medición errónea: el 22 se mantenía abierto mucho más tiempo porque, sin enviar la secuencia
> de cierre, la regla DROP simplemente **no volvía a inyectarse**. La comprobación definitiva
> es leer `knockd.conf`.

![Port knocking: abrir el puerto 22](docs/img/02-port-knocking.png)

![Secuencia de cierre](docs/img/03-knock-cierre.png)

Un escaneo completo inmediatamente después del knocking confirma que **solo se abre el 22**;
no aparece ningún servicio adicional.

---

## 4. Fail2Ban — confirmaciones y ritmo real

- 2 fallos en menos de 60 s ⇒ **ban de 600 s**.
- El ban se aplica a nivel de firewall: `nc -z 22` falla, nmap marca `22/tcp filtered` y SSH
  responde `Connection refused` (REJECT).
- **El knocking NO anula el ban** (verificado experimentalmente): hay que esperar la expiración.
- ⚠️ **Trampa en el panel**: el texto `NO ESTÁS BANEADO` **contiene** la subcadena `ESTÁS BANEADO`.
  Para consultar el estado correctamente hay que filtrar por la clase CSS
  (`class="banned"` frente a `class="safe"`), nunca por el texto.

**Ritmo máximo sostenible: 1 intento cada ~61 s.** Dos fallos separados 61 s caen en ventanas
distintas de `findtime`, por lo que nunca se acumulan 2 y no se dispara el ban. El script usa
`62 s` de espera, más unos 3 s de conexión, lo que deja el intervalo real en torno a 65 s.

---

## 5. Etapa 1 — Fuerza bruta SSH → `roma3`

Los banners de los puertos 7003/7005/7007 y el banner de FTP revelan los tres usuarios del
sistema: **`roma1`**, **`roma2`**, **`roma3`**.

Se construyó una lista de palabras priorizada (*wordlist*) de 477 combinaciones (tema Roma,
vocabulario en español, variantes con año y sufijos, sustituciones *leet* (l33t) y valores
genéricos) y un script que:

1. Espera a que expire el ban consultando `class="banned"` en `status.php`.
2. Hace el knocking `7003/7005/7007`.
3. Prueba **una** credencial.
4. Espera 62 s antes del siguiente intento.

Resultado (tras ~90 intentos, ~1 h 40 min de reloj):

```
[10:35:42] [+] !!! LOGIN OK !!! roma3 / abc123
uid=1002(roma3) gid=1002(roma3) groups=1002(roma3)
```

![Fuerza bruta SSH](docs/img/06-fuerza-bruta.png)

> Contraseña: **`abc123`** — usuario **`roma3`**

---

## 6. Etapa 2 — Clave SSH oculta → `roma1`

Revisando el sistema se localizaron ficheros ocultos en el home de `roma3`
(creados en la fecha de construcción del laboratorio, 3 feb 2026):

| Ruta | Tamaño |
|---|---|
| `/home/roma3/Desktop/.ssh_part1` | 959 B |
| `/home/roma3/Downloads/.ssh_part2` | 852 B |

Ambas son fragmentos de la **misma clave privada OpenSSH** (RSA). Reensamblando el base64:

```python
import base64
lines = [l.strip() for l in open("key_raw.txt") if l.strip()]
body  = "".join(l for l in lines if not l.startswith("-----"))
key   = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + \
        "\n".join((b := base64.b64encode(base64.b64decode(body)).decode())[i:i+70]
                  for i in range(0, len(b), 70)) + \
        "\n-----END OPENSSH PRIVATE KEY-----\n"
```

El comentario de la clave resultante es **`roma1@roma`**: la clave privada de **roma1**
estaba escondida en el home de roma3, partida en dos.

![Clave de roma1 oculta en el home de roma3](docs/img/07-clave-oculta.png)

```bash
ssh -i id_roma3 -o IdentitiesOnly=yes roma1@172.17.0.2
uid=1000(roma1) gid=1000(roma1) groups=1000(roma1)
```

Confirmado con `~/.ssh/authorized_keys` de roma1, que contiene esa misma clave pública.

---

## 7. Etapa 3 — Clave SSH oculta en `/tmp` → `roma2`

En el home de `roma1` había otra pista:

| Ruta | Tamaño |
|---|---|
| `/home/roma1/Desktop/.key_part1` | 959 B |
| `/tmp/.key_part2` | 852 B |

Misma técnica de reensamblado. El comentario de la clave es **`roma2@roma`**:

```bash
ssh -i id_key2 -o IdentitiesOnly=yes roma2@172.17.0.2
uid=1001(roma2) gid=1001(roma2) groups=1001(roma2)
```

![Cadena de pivotes](docs/img/08-pivots.png)

> Nota: `/tmp/.key_part2` queda **expuesto por el bit sticky del directorio** pero es legible
> por cualquiera, lo cual permite recuperarlo desde **cualquier** usuario del sistema.

---

## 8. Etapa 4 — OpenDoas SUID mal configurado → `root`

Como `roma2`, `sudo` exige contraseña, y no hay binarios SUID relevantes ni tareas de cron
útiles. Sin embargo, en `/usr/local/bin` hay herramientas propias del laboratorio:

| Binario | Permisos | Descripción |
|---|---|---|
| `/usr/local/bin/doas` | `-rwsr-xr-x` **SUID root** | OpenDoas (ELF, *not stripped*) |
| `/usr/local/bin/doasedit` | `-rwxr-xr-x` | Editor que usa `doas cp` |
| `/usr/local/bin/vidoas` | `-rwxr-xr-x` | Editor de `doas.conf` |

La configuración de doas es **legible por todos** (`/usr/local/etc/doas.conf`, `-rw-r--r--`):

```
permit nopass keepenv roma2 as root
```

Es decir: **`roma2` puede ejecutar cualquier comando como root sin contraseña.**
Esto convertiría a `doasedit` en un editor de ficheros arbitrario con privilegios
(escribe vía `doas cp`), pero no hace falta: `doas` es directamente utilizable.

![OpenDoas SUID mal configurado](docs/img/09-doas-suid.png)

```bash
$ doas id
uid=0(root) gid=0(root) groups=0(root)

$ doas cat /root/flag.txt
ROMA{1d0r_us3r_3num_p0rt_kn0ck_d04s_pr1v3sc_f41l2b4n_2026}
```

![Root y flag](docs/img/10-flag.png)

### Validación de la bandera

La bandera obtenida se contrastó con el validador del propio laboratorio (`startlab.sh`), que
la compara contra `/root/flag.txt` dentro del contenedor y confirma la consecución del reto:

![Validación de la bandera](docs/img/12-validacion-flag.png)

> `¡Felicitaciones! Has conquistado Roma.` — fecha y hora de validación: **2026-10-15 10:59:18 -0600**,
> IP del laboratorio: `172.17.0.2`.

---

## 9. Cadena de ataque completa

![Cadena de ataque completa](docs/img/11-cadena-completa.png)

En detalle:

```
        knock 7003,7005,7007   ·   1 intento / 62 s
        |
        v
   roma3        abc123     (fuerza bruta SSH)
        |  ~/.ssh_part1 + ~/Downloads/.ssh_part2
        v
   roma1        id_roma3   (clave SSH partida oculta)
        |  ~/Desktop/.key_part1 + /tmp/.key_part2
        v
   roma2        id_key2    (clave SSH partida oculta)
        |  doas.conf: permit nopass keepenv roma2 as root
        v
   ROOT         doas       (OpenDoas SUID root)
        |
        v
   $ doas cat /root/flag.txt
   ROMA{1d0r_us3r_3num_p0rt_kn0ck_d04s_pr1v3sc_f41l2b4n_2026}
```

---

## 10. Vulnerabilidades encontradas

| # | Severidad | Vulnerabilidad | Ubicación |
|---|---|---|---|
| 1 | **Crítica** | Configuración de OpenDoas que concede root sin contraseña a un usuario no privilegiado | `/usr/local/etc/doas.conf` + `/usr/local/bin/doas` (SUID) |
| 2 | **Alta** | Credenciales SSH débiles y adivinables por fuerza bruta | `roma3:abc123` |
| 3 | **Alta** | Claves privadas SSH en texto plano, partidas y ocultas en directorios accesibles a otros usuarios | `/home/roma3/{Desktop,Downloads}/.ssh_part*`, `/home/roma1/Desktop/.key_part1`, `/tmp/.key_part2` |
| 4 | **Alta** | Filtración de la configuración defensiva en un endpoint web público | `/status.php` (maxretry/findtime/bantime) |
| 5 | **Media** | Código fuente del servidor web legible desde el sistema de ficheros | `/var/www/html/status.php` |
| 6 | **Media** | Confianza ciega en `X-Forwarded-For` para el cálculo de la IP baneada | `status.php` |
| 7 | **Media** | Servicios FTP y de banner sin endurecimiento alguno, cuyo texto filtra nombres de usuario | vsftpd `:21`, `:7003/:7005/:7007` |
| 8 | **Baja** | Listado de directorios habilitado en la raíz del sitio | `/R/`, `/css/`, `/img/`, `/js/` |

---

## 11. Recomendaciones

1. **Auditar la configuración de privilegios**: retirar `nopass`, limitar `doas` a comandos
   concretos mediante reglas de ruta y evitar que un binario SUID conceda root a un usuario interactivo.
2. **Nunca almacenar claves privadas en el servidor**: usar un almacén de secretos
   (Vault, SOPS) y rotar cualquier clave que haya pasado por un sistema de ficheros.
3. **Restringir permisos de las claves** a `0600` y evitar fragmentarlas dentro de rutas
   accesibles (en especial `/tmp`, que es legible por todos).
4. **Arreglar el panel `status.php`**: no debe exponer la configuración de Fail2Ban, debe usar
   `REMOTE_ADDR` real o un proxy inverso que fije la cabecera, y no debe tener el código legible
   por los usuarios del sistema.
5. **Reforzar el acceso SSH**: desactivar la autenticación por contraseña (`PasswordAuthentication no`)
   y usar únicamente claves, con `AllowUsers` acotado.
6. **Revisar la política de Fail2Ban** y añadir un límite de intentos más estricto por usuario
   además del límite por IP.
7. **No confundir profundidad con seguridad**: el «troll» del árbol `/R/` es un indicio de que
   la ofuscación del entorno no sustituye a una configuración segura.

---

## 12. Herramientas y scripts utilizados

| Script / herramienta | Función |
|---|---|
| `nmap` | Descubrimiento de puertos y versiones |
| `gobuster`, `nikto`, `curl` | Enumeración web |
| `exploits/crawl.py` | Crawler recursivo con decodificación base64 de `/R/` |
| `exploits/gen_wordlist.py` | Genera la lista de palabras priorizada en formato `usuario:password` |
| `exploits/brute_ssh.sh` | Orquestador: knocking + control de ban + ritmo 1/min |
| `exploits/rsh.sh`, `rsh1.sh`, `rsh2.sh` | Ejecución remota como `roma3` / `roma1` / `roma2` |
| `shots/capture.sh` | Captura las salidas del objetivo que ilustran el writeup |
| `shots/make_images.py` | Renderiza las capturas de `docs/img/` con Chromium headless |

---

## 13. Indicadores de compromiso (IOC)

| Indicador | Valor |
|---|---|
| IP atacante | `172.17.0.1` |
| Usuario comprometido | `roma3` → `roma1` → `roma2` → `root` |
| Credencial SSH válida | `roma3:abc123` |
| Secuencia de knocking | `7003, 7005, 7007` (apertura) · `7007, 7005, 7003` (cierre) |
| Ficheros de clave | `.ssh_part1`, `.ssh_part2`, `.key_part1`, `.key_part2` |
| Bandera | `ROMA{1d0r_us3r_3num_p0rt_kn0ck_d04s_pr1v3sc_f41l2b4n_2026}` |

---

## 14. Estructura del repositorio

Todo lo publicado es **reproducible y auditable**: ninguna conclusión de este documento depende
de la confianza en el autor, cada una tiene su artefacto de respaldo.

```
.
├── README.md                 Este documento (writeup completo)
├── docs/img/                 12 capturas de terminal que ilustran el writeup
├── exploits/                 Scripts de la auditoría
│   ├── brute_ssh.sh          Orquestador del brute force (knock + ritmo 1/min)
│   ├── gen_wordlist.py       Genera la lista de 477 combinaciones priorizadas
│   ├── crawl.py              Crawler recursivo con decodificación base64 de /R/
│   ├── knock_and_ssh.sh      Knock + un único intento SSH
│   └── rsh.sh rsh1.sh rsh2.sh   Ejecución remota como roma3 / roma1 / roma2
├── recon/                    Salidas crudas de reconocimiento
│   ├── nmap_full.txt         Escaneo completo (22/tcp aparece como filtered)
│   ├── nmap_after_knock.txt  El mismo escaneo tras el knocking
│   ├── knock_700[357].txt    Banners de los módulos R1/R2/R3
│   ├── gobuster_*.txt        Enumeración web
│   └── web_status.txt        Panel de Fail2Ban con la config filtrada
├── loot/                     Evidencia del compromiso
│   ├── bruteforce.log        Traza completa del ataque por fuerza bruta
│   ├── flag.txt              Bandera leída
│   ├── decode.py             decode.py del autor (pista del knocking)
│   └── crawl/                Ficheros de /R/ en bruto y decodificados
├── notes/bitacora.md         Bitácora de análisis
├── wordlists/                roma_users.txt (orden de intento)
```

*Auditoría realizada sobre un laboratorio CTF aislado y con autorización explícita para
pruebas ofensivas (whoami-labs.com). Toda la metodología se ejecutó únicamente contra la
red del objetivo, sin acceso al host ni al filesystem del contenedor.*
