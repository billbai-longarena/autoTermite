#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_LOG="$ROOT_DIR/termite_daemon.stdout.log"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing command: $1"
    exit 1
  fi
}

is_daemon_running() {
  pgrep -f "termite_daemon.py" >/dev/null 2>&1
}

supports_tkinter() {
  local py="$1"
  "$py" -c '
import sys
try:
    import _tkinter
except Exception:
    raise SystemExit(1)

# macOS 15 + Apple/Xcode Python (Tk 8.5) is known to crash in TkpInit.
tk_version = tuple(int(x) for x in _tkinter.TK_VERSION.split(".")[:2])
if tk_version < (8, 6):
    raise SystemExit(2)

if "/Applications/Xcode.app/" in sys.executable:
    raise SystemExit(3)
' >/dev/null 2>&1
}

resolve_gui_python() {
  local candidates=()
  local candidate

  if [ -n "${TERMITE_GUI_PYTHON:-}" ]; then
    candidates=("$TERMITE_GUI_PYTHON")
  else
    # Prefer macOS framework/system Python for Tk stability.
    candidates=(
      "/opt/homebrew/bin/python3.13"
      "/opt/homebrew/bin/python3.12"
      "/opt/homebrew/bin/python3.11"
      "/opt/homebrew/bin/python3"
      "/usr/local/bin/python3.13"
      "/usr/local/bin/python3.12"
      "/usr/local/bin/python3.11"
      "/usr/local/bin/python3"
      "/Users/bingbingbai/opt/anaconda3/envs/pytorch/bin/python3"
      "python3"
      "/usr/bin/python3"
    )
  fi

  for candidate in "${candidates[@]}"; do
    if [ -x "$candidate" ] || command -v "$candidate" >/dev/null 2>&1; then
      if supports_tkinter "$candidate"; then
        echo "$candidate"
        return 0
      fi
    fi
  done

  return 1
}

start_daemon() {
  if is_daemon_running; then
    echo "[daemon] already running"
    return
  fi

  echo "[daemon] requesting sudo permission..."
  sudo -v

  echo "[daemon] starting in background..."
  sudo -b env \
    ROOT_DIR="$ROOT_DIR" \
    DAEMON_LOG="$DAEMON_LOG" \
    PYTHONUNBUFFERED=1 \
    sh -c 'cd "$ROOT_DIR" && exec python3 termite_daemon.py >>"$DAEMON_LOG" 2>&1'

  sleep 1
  if is_daemon_running; then
    echo "[daemon] started, log: $DAEMON_LOG"
  else
    echo "[daemon] failed to start"
    exit 1
  fi
}

start_gui() {
  echo "[gui] starting..."
  cd "$ROOT_DIR"

  GUI_PYTHON="$(resolve_gui_python || true)"
  if [ -z "$GUI_PYTHON" ]; then
    echo "[gui] failed: no usable python with tkinter (Tk 8.6+) support found."
    echo "[gui] set TERMITE_GUI_PYTHON=/path/to/python3 and retry."
    exit 1
  fi

  echo "[gui] using python: $GUI_PYTHON"
  exec "$GUI_PYTHON" termite_control_gui.py
}

main() {
  require_cmd python3
  require_cmd pgrep
  require_cmd sudo

  start_daemon
  start_gui
}

main "$@"
