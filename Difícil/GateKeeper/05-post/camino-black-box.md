# GATEKEEPER — Camino Black-Box (verificación)

> Documento de respaldo del write-up principal. Resume las preguntas metodológicas
> surgidas durante la auditoría y sus respuestas verificadas.

## 1. ¿Se pueden obtener los 3 usuarios válidos sin acceso al filesystem? — **SÍ**

**Nivel 1 — antes de autenticarse (solo web):**
- `mauricio` está **disclosed** en la lista de 27 usuarios de `/backups/.backup`
  (los otros 26 son decoys, él es real):
  ```
  grep -x mauricio 02-enum/users.txt  →  mauricio
  ```
- **Timing SSH NO es viable** para enumerar: medí 10–15 muestras por usuario y el
  usuario inexistente `zzzznotarealuser9` quedó *dentro* del rango de los válidos
  (median ~3155 ms vs `sysadmin` ~2928 ms, `developer` ~3268 ms). OpenSSH responde de
  forma uniforme → no se distingue válido/inválido por tiempo.

**Nivel 2 — después de autenticarse como `mauricio` (decisivo):**

Con un solo login válido, la enumeración es trivial:

```bash
sshpass -p 143143 ssh -p 33333 mauricio@172.17.0.2 'ls -la /home/'
# developer, mauricio, sysadmin        <-- los 3 usuarios reales
```

`/etc/passwd` (world-readable) y `/home/developer/log.txt` (`-r--r--r--`) confirman los
tres por nombre y uid.

**Conclusión:** los tres usuarios son descubribles sin tocar el filesystem. Solo se
necesita **un** login (`mauricio`, credencial débil) para enumerar los otros dos.

---

## 2. ¿Se puede comprometer el sistema / leer la flag solo black-box? — **SÍ**

La clave privada de `sysadmin` está **dividida en dos** y **ambas partes son
world-readable** dentro del home de `developer`:

```
/home/developer/.ssh_part1              (-r--r--r--)
/home/developer/Desktop/.ssh_part2      (-r--r--r--)
```

```bash
cat /home/developer/.ssh_part1 > dev_key
cat /home/developer/Desktop/.ssh_part2 >> dev_key
ssh-keygen -y -f dev_key            # → "sysadmin@gatekeeper"
ssh -i dev_key -p 33333 sysadmin@172.17.0.2 'id'   # uid=1002(sysadmin)
```

Desde `sysadmin` la escalada es directa (OTP world-readable → `.system_auth` →
`sudo auth_root` → root → flag). Cadena completa en el write-up principal (§8).

---

## 3. Lecciones metodológicas

1. **Los dotfiles se scopan con prefijo `.`** — `/backups/.env` esconde la semilla que
   habilita todo el port-knocking.
2. **Detecta honeypots rápido** — MySQL/PG sin handshake → pasar al siguiente vector.
3. **Credencial débil > brute masivo** — el spray dirigido a usernamesBSCRITA encuentra
   `mauricio:143143`; rockyou online contra SSH es inviable por rate-limit.
4. **Analiza permisos, no solo contenidos** — el `-rw-r--r--` de `/tmp/.current_otp`
   *es* la vulnerabilidad.
5. **La autorización debe validarse contra el actor real** — `auth_root` confía en un
   marker de `/tmp` en vez de revalidar el OTP por sí mismo.

---

*Verificaciones realizadas directamente contra `172.17.0.2` con el lab en curso, usando
solo red + credenciales derivadas. Script de knock: `scripts/knock.sh`.*
