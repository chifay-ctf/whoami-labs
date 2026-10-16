# wordlists/ — Diccionarios usados en PICAPIEDRA

Todas las listas **creadas a mano durante la auditoría** (no se incluyen las de `rockyou` ni las de
`seclists`, que ya vienen instaladas en Kali). Están aquí para que el writeup sea **reproducible**:
cualquiera puede repetir exactamente los mismos intentos.

---

## Usuarios

### `users_themed.txt` — 26 usuarios

Usuario del portal web derivados del temario del sitio (*Los Picapiedros*) y de la terminología
corporativa en español. Fue la lista base de la fuerza bruta indiscriminada (~40 000 intentos sin
éxito).

```
fred  barney  wilma  betty  pebbles  dino  flintstone  rubble
cantera  picapiedra  yabba  dabba  doo  cantera_admin
admin  root  empleado  empleados  usuario  user  test
gerente  supervisor  fred123  freddy  barneyrubble
```

### `users_priority.txt` — 20 usuarios

Subconjunto priorizado que se usó en las últimas rondas (`brute_multi.py`) tras agotar la lista
completa, para no repetir Effort en combinaciones ya descartadas.

---

## Contraseñas

### `passes_themed.txt` — 70 contraseñas ⭐ (la que resolvió el reto)

Mezcla de las contraseñas más usadas del mundo y del temario del laboratorio: `flintstone`,
`rubble`, `bedrock`, `yabba`, `dabba`, `doo`, `cantera`, `picapiedra`, `roca`, `piedra(s)`,
`dinosaurio`, `prehistorico`, `megalodon`, `huella`…

**Esta lista fue la clave del writeup.** El acierto (`fred` / `yabbadabbadoo`) llegó en una tanda
dirigida posterior, cuando el modelo del atacante sobre la aplicación cambió de «contraseña aleatoria»
a «texto con significado cultural».

### `passes_case.txt` — 30 contraseñas

Variantes con mayúsculas y capitalización sobre el mismo temario (`Bedrock`, `Flintstone`,
`YabbaDabbaDoo`, `CanteraPicapiedra`, `P@ssw0rd`…). Para descartar variación de capitalización antes
de ampliar el diccionario.

### `passes_dates.txt` — 38 contraseñas

Contraseñas con año (`picapiedra2024`, `cantera2026`, `admin2026`…), basadas en que el artefacto del
lab se compiló en 2026 (`Last-Modified: Mon, 09 Feb 2026`) y en el uso habitual del año en claves.

### `known_creds.txt` — 40 pares `usuario:contraseña`

Pares conocidos de entornos de laboratorio (`msfadmin:msfadmin`, `vagrant:vagrant`, `root:toor`…), en
formato `user:pass`. Motivado porque el `nmap` reportaba el hostname como `metasploitable.vm`.
Resultado: todos fallaron, pero cubría el caso «credenciales por defecto de una distro conocida».

---

## Fuzzing

### `web_paths_themed.txt` — 121 rutas

Rutas web en español y con nomenclatura del laboratorio (`nomina.php`, `personal`, `cantera.php`,
`expedientes`, `llaves.php`, `mantenimiento.php`…) para enumerar contenido del *docroot*.
Resultado: ninguna ruta nueva; la web real es mínima (6 ficheros).

### `lfi_filenames.txt` — 52 nombres de fichero

Nombres de fichero comunes para usar la LFI como **oráculo de existencia** (`file_exists()` distingue
«no encontrado» de «encontrado sin permiso»). Se aplicó sobre `/home/*`, `/opt`, `/usr/local/bin`,
`/etc/sudoers.d`, `/var/backups` y `/var/www/html`.

Para el mapeo masivo del filesystem se usó además la wordlist instalada:
`/usr/share/seclists/Discovery/Web-Content/LinuxFileList.txt` (87 018 rutas → 6 490 ficheros
encontrados en el objetivo).

---

## Listas derivadas (no guardadas, se regeneran en un comando)

Estas son subconjuntos de `rockyou.txt` y de las anteriores. No se versionan porque son
megabytes de datos ya presentes en el sistema:

```bash
# top 20 000 y top 30 000 contraseñas de rockyou (usadas en brute_multi.py)
head -20000 /usr/share/wordlists/rockyou.txt > /tmp/rockyou_top20k.txt
head -30000 /usr/share/wordlists/rockyou.txt > /tmp/rock30k.txt

# mezcla temática + rockyou, deduplicada y ordenada (la que llevaba el brute)
cat passes_themed.txt /tmp/rock30k.txt | awk '!seen[$0]++' > pass_final.txt
```

Los ficheros `pairs.txt` / `ftp_pairs.txt` (pares `user|pass`, ~2 M de líneas) tampoco se guardan por
tamaño: se generan al vuelo con `exploits/web_brute.py` y `exploits/brute_multi.py`.

---

## Reproducir la fuerza bruta

```bash
# Login web (la vía que funcionó)
python3 exploits/brute_multi.py \
    wordlists/users_priority.txt wordlists/passes_themed.txt web 80

# SSH + FTP simultáneos (pocos hilos: el sshd satura con MaxStartups)
python3 exploits/brute_multi.py \
    wordlists/users_priority.txt wordlists/passes_themed.txt ssh 4
```

> **Advertencia operativa:** el objetivo limita a ~170 req/s y el `sshd` corta conexiones si se
> supera `MaxStartups`. Lanzar fuerza bruta en paralelo con otros intentos de autenticación produce
> **falsos negativos** (credenciales válidas que «fallan» solo por saturación). Verificar siempre con
> `ssh -vv` antes de descartar una credencial.