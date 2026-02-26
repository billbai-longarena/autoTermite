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
  
  # Use Homebrew Python 3 if available, otherwise fallback to system python3
  if [ -x "/opt/homebrew/bin/python3.13" ]; then
    GUI_PYTHON="/opt/homebrew/bin/python3.13"
  elif [ -x "/opt/homebrew/bin/python3" ]; then
    GUI_PYTHON="/opt/homebrew/bin/python3"
  elif [ -x "/usr/local/bin/python3.13" ]; then
    GUI_PYTHON="/usr/local/bin/python3.13"
  elif [ -x "/usr/local/bin/python3" ]; then
    GUI_PYTHON="/usr/local/bin/python3"
  else
    GUI_PYTHON="python3"
  fi
  
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
