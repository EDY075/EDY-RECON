#!/usr/bin/env bash
# Launcher portatil do EDY RECON para Linux/Kali.
set -eu
umask 077

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"

if [ ! -x "$VENV_PYTHON" ]; then
    echo "[X] Ambiente virtual .venv nao encontrado." >&2
    echo "    Execute ./kali_pos_install.sh para criar o ambiente isolado." >&2
    exit 1
fi

cd -- "$SCRIPT_DIR"
exec "$VENV_PYTHON" -B "$SCRIPT_DIR/edyrecon.py" "$@"
