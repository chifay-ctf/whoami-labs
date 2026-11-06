#!/usr/bin/env bash
# capture_terminal.sh <nombre> <comando> [timeout_segundos]
# Ejecuta el comando en la sesión tmux "shadow", espera el prompt y guarda:
#   - evidence/<nombre>.txt   (contenido visible de la terminal)
#   - screenshots/<nombre>.png (captura real de la ventana qterminal)
set -u

NAME="${1:?nombre requerido}"
CMD="${2:?comando requerido}"
TIMEOUT="${3:-180}"
BASE="/home/kali/Downloads/Labs/Facil/The Shadow Brokers/NEW"
SES="shadow"
WID="79691783"

mkdir -p "$BASE/evidence" "$BASE/screenshots"

# Limpiar la pantalla y ejecutar el comando.
tmux send-keys -t "$SES" C-c 2>/dev/null || true
sleep 0.3
tmux send-keys -t "$SES" "clear" Enter
sleep 0.5
tmux send-keys -t "$SES" "$CMD" Enter

# Esperar a que vuelva el prompt (o agotar el timeout).
for _ in $(seq 1 "$TIMEOUT"); do
  LAST=$(tmux capture-pane -t "$SES" -p 2>/dev/null | tail -n 1)
  case "$LAST" in
    *"chfay@kali:~/The Shadow Brokers"*) break ;;
  esac
  sleep 1
done

tmux capture-pane -t "$SES" -p -S -2000 > "$BASE/evidence/${NAME}.txt"

# Traer la ventana al frente y capturarla con su marco.
xdotool windowactivate "$WID" 2>/dev/null || true
sleep 0.5
FRAME=$(xwininfo -id "$WID" -tree 2>/dev/null | awk '/Parent window id/{print $4}')
if [ -n "${FRAME:-}" ]; then
  import -window "$FRAME" "$BASE/screenshots/${NAME}.png"
else
  import -window "$WID" "$BASE/screenshots/${NAME}.png"
fi

echo "[+] $NAME -> screenshots/${NAME}.png"
