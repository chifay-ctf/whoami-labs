# ROMA CTF — Bitácora de análisis

**Objetivo:** 172.17.0.2 (contenedor docker) — **Atacante:** Kali (172.17.0.1 en la red del contenedor)
**Dificultad:** difícil (★★★★★☆☆☆, 5 pts) — **Flag:** `/root/flag.txt`

---

## 1. Reconocimiento

### 1.1 Puertos (nmap -p-)
```
21/tcp    open  ftp     vsftpd  -> "500 OOPS: both local and anonymous access disabled!"
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu-4ubuntu0.13   (filtrado salvo knock + sin ban)
80/tcp    open  http    Apache/2.4.41 (Ubuntu)
7003/tcp  open  (banner estático)  -> MÓDULO R1 / usuario: roma1
7005/tcp  open  (banner estático)  -> MÓDULO R2 / usuario: roma2
7007/tcp  open  (banner estático)  -> MÓDULO R3 / usuario: roma3
```
Hostname del objetivo: `metasploitable.vm`. Base: Ubuntu 20.04.

### 1.2 FTP — vector cerrado
vsftpd rechaza la conexión en el handshake (`500 OOPS`), no llega a enviar `220`, por lo que
no se puede probar ni el backdoor de vsftpd 2.3.4. **Acceso local y anónimo deshabilitados.**

### 1.3 Web —向量 casi completamente señuelo
- `/` → `index.html` estático (enlace a `status.php`).
- `/status.php` → panel de estado de Fail2Ban. **Fuga de configuración:**
  - `Max Retry = 2 intentos`, `Find Time = 60 s`, `Ban Time = 600 s`
  - Confirma que **SSH requiere port knocking** previo.
  - Los bloques de logs fallan (`sudo: a terminal is required...`) → bug del propio PHP.
- `/.env` → base64 → `" de todas formas ya aprendiste algo nuevo!!!"` (troll).
- `/R/` → árbol recursivo de ficheros en base64. Al concatenarlos y decodificarlos:
  > **"Lo siento, por no poder darte pistas sobre el laboratorio, pero de todas formas ya aprendiste algo nuevo!!!"**
- `/roma/R/O/M/A/default/shell/decode.py` → script del propio autor que genera ese árbol.
  Decodifica a: `"...lo siento...\n\nP7003, P7005, P7007"` → **confirma la secuencia de knocking**.
- `/css/`, `/img/`, `/js/`, `/.ssh/` → vacíos. Sin WebDAV. Sin vhosts. Sin LFI en `status.php`.
  (gobuster medium + nikto no.Description(II) reveal nada más.)

### 1.4 Port knocking — hallazgo clave
El puerto 22 está **bloqueado por defecto** (nmap lo reporta `filtered`).
Al ejecutar la secuencia **`7003` → `7005` → `7007`** el puerto 22 se **abre**: `knockd`
ejecuta `iptables -D INPUT -p tcp --dport 22 -j DROP`, es decir, **elimina** la regla DROP.
**No hay ventana temporal**: el puerto permanece abierto hasta que se envíe la secuencia
inversa **`7007` → `7005` → `7003`**, que ejecuta `iptables -A ...` y vuelve a cerrarlo.
`seq_timeout = 15` solo limita el intervalo entre los tres golpes de cada secuencia.

```bash
for p in 7003 7005 7007; do echo >/dev/tcp/172.17.0.2/$p; sleep 0.3; done
ssh roma1@172.17.0.2 ...
```

### 1.5 Fail2Ban — confirmado y efectivo
- 2 fallos de autenticación en <60 s → **ban de 600 s**.
- El ban se aplica por iptables/REJECT: SSH responde `Connection refused` y nmap marca `22/tcp filtered`.
- El **knocking NO anula el ban** (probado): hay que esperar la expiración.
- Sistema de estado: `status.php` marca `class="banned"` vs `class="safe"`.
  ⚠️ Cuidado: el texto "NO ESTÁS BANEADO" **contiene** "ESTÁS BANEADO"; hay que filtrar por la clase CSS.

---

## 2. Vector de ataque elegido

Solo queda **SSH por fuerza bruta**, limitado a **1 intento / 62 s** (para nunca tener 2 fallos
dentro de la ventana de 60 s → evita el ban). Cada intento va precedido del knocking.

Usuarios: `roma1`, `roma2`, `roma3` (revelados por los banners R1/R2/R3 y el banner de FTP).

Scripts: `exploits/brute_ssh.sh`, `exploits/gen_wordlist.py`, `exploits/knock_and_ssh.sh`.

## 3. Escalada tras el acceso

| # | Vector | De → A |
|---|---|---|
| 1 | Fuerza bruta SSH (1 intento / 62 s) | — → `roma3` (`abc123`) |
| 2 | Clave SSH partida en el home de roma3 (`~/.ssh_part1` + `~/Downloads/.ssh_part2`) | `roma3` → `roma1` |
| 3 | Clave SSH partida (`~/Desktop/.key_part1` + `/tmp/.key_part2`) | `roma1` → `roma2` |
| 4 | `doas` SUID + `doas.conf` legible: `permit nopass keepenv roma2 as root` | `roma2` → `root` |

## 4. Progreso

- [x] Recon completo
- [x] Descubrimiento del port knocking (apertura **y** cierre)
- [x] Confirmación de Fail2Ban y cálculo del ritmo máximo
- [x] Credenciales SSH válidas (`roma3:abc123`)
- [x] Escalada `roma3` → `roma1` → `roma2`
- [x] Escalada a root vía OpenDoas mal configurado
- [x] Lectura y validación de `/root/flag.txt`

```
ROMA{1d0r_us3r_3num_p0rt_kn0ck_d04s_pr1v3sc_f41l2b4n_2026}
```
