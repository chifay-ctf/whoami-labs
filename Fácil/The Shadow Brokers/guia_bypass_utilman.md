# Bypass de login Windows 7 — Método Utilman (Startup Repair)

> **Laboratorio:** The Shadow Brokers (Whoami-Labs)
> **Objetivo:** obtener `cmd.exe` como `SYSTEM` en la pantalla de login, desactivar el firewall y permitir la explotación remota por SMB.
>
> **Nota de publicación:** documento de apoyo de la auditoría. El bypass se usó únicamente para deshabilitar el firewall y habilitar SMB; **no se reseteó la contraseña de `student`**. La contraseña original se recuperó después mediante `hashdump` y cracking. La VM se dejó con `utilman.exe` reemplazado por `cmd.exe` por decisión del usuario; el binario original permanece en `C:\Windows\System32\Utilman_backup.exe`.

## 1. Forzar Windows Error Recovery

1. En VMware, apagar la VM de golpe mientras arranca Windows (**VM → Power → Power Off**).
2. Encenderla de nuevo.
3. Debe aparecer **Windows Error Recovery** con:
   - *Launch Startup Repair (recommended)*
   - *Start Windows Normally*
4. Elegir **Launch Startup Repair**.
   - Si no aparece, repetir el apagado forzado 2–3 veces durante el arranque.

## 2. Abrir Notepad desde Startup Repair

1. Esperar el diálogo de **Startup Repair**.
2. Pulsar **Cancel**.
3. En la ventana de error, pulsar **View problem details**.
4. Bajar hasta el final y hacer clic en el último enlace (abre un **Bloc de notas** con el log).

## 3. Reemplazar `utilman.exe` por `cmd.exe`

1. En Notepad: **File → Open** (`Ctrl+O`).
2. Ir a la unidad de Windows. Normalmente `C:\Windows\System32`; en algunos equipos es `D:\Windows\System32`.
3. Cambiar **Files of type** a **All Files**.
4. Renombrar `utilman.exe` → `Utilman_bk.exe`.
5. Copiar `cmd.exe` (clic derecho → Copy).
6. Pegar en la misma carpeta (clic derecho → Paste).
7. Renombrar la copia `cmd - Copy.exe` → `utilman.exe`.
8. Cerrar Notepad y todas las ventanas de recuperación. Elegir **Restart**.

## 4. Abrir CMD como SYSTEM en el login

1. En la pantalla de login, pulsar el icono de **Ease of Access** (abajo a la izquierda) o **Windows + U** (en macOS: **Command + U**).
2. Debe abrirse una consola `C:\Windows\system32>` como **SYSTEM**.

## 5. Desactivar el firewall

En esa consola ejecutar:

```cmd
netsh advfirewall set allprofiles state off
```

Esto abre 135/139/445 para poder explotar MS17-010 desde Kali. En esta auditoría **no** se ejecutó `net user student ...`; la contraseña se recuperó por otras vías.

## 6. Revertir el cambio (si se decide restaurar)

En una consola elevada de Windows:

```cmd
copy C:\Windows\System32\Utilman_backup.exe C:\Windows\System32\utilman.exe
```

O renombrar `utilman.exe` (la copia de `cmd.exe`) y dejar `Utilman_bk.exe` como `utilman.exe`.

## Notas

- Si `utilman.exe` no se puede renombrar, se puede usar `sethc.exe` y pulsar **Shift 5 veces** en el login.
- Si el enlace de Notepad no aparece, en **System Recovery Options** elegir **Command Prompt** y hacer la copia directamente:

  ```cmd
  copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
  ```

- El firewall también se puede desactivar luego desde el escritorio:

  ```cmd
  netsh advfirewall set allprofiles state off
  ```

- **Estado final de esta auditoría:** el firewall sigue deshabilitado y `utilman.exe` sigue siendo `cmd.exe`; no se restauró la configuración. Ver la nota de cierre del informe (sección 8.1).
