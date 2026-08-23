#!/usr/bin/env bash
# Pos-instalacao portatil para uma copia do EDY RECON no Kali.
set -eu
umask 077

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ENABLE_CRON="false"
case "${1:-}" in
    "") ;;
    --enable-weekly-update) ENABLE_CRON="true" ;;
    -h|--help)
        echo "Uso: ./kali_pos_install.sh [--enable-weekly-update]"
        exit 0
        ;;
    *) echo "[X] Opcao desconhecida: $1" >&2; exit 2 ;;
esac

cd -- "$SCRIPT_DIR"
command -v python3 >/dev/null 2>&1 || { echo "[X] python3 ausente." >&2; exit 1; }
python3 -m venv --help >/dev/null 2>&1 || { echo "[X] python3-venv ausente." >&2; exit 1; }

echo "[1/5] Estrutura e permissoes..."
mkdir -p reports sessions logs
chmod 700 reports sessions logs
find reports sessions logs -type f -exec chmod 600 {} +
chmod 755 EDYRECON.sh edyrecon.py kali_install.sh kali_pos_install.sh sync_to_kali.sh
if [ -f data/config.json ]; then chmod 600 data/config.json; fi
printf '%s\n' 'EDYRECON_MANAGED_V1' > .edyrecon-managed
chmod 600 .edyrecon-managed

echo "[2/5] Ambiente Python isolado..."
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python -m pip check

echo "[3/5] Launcher versionado..."
test -x "$SCRIPT_DIR/EDYRECON.sh"

echo "[4/5] Atalho da area de trabalho..."
DESKTOP_DIR="${XDG_DESKTOP_DIR:-$HOME/Desktop}"
if command -v xdg-user-dir >/dev/null 2>&1; then
    detected="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
    if [ -n "$detected" ]; then DESKTOP_DIR="$detected"; fi
fi
mkdir -p "$DESKTOP_DIR"
DESKTOP_FILE="$DESKTOP_DIR/EDY RECON.desktop"
cat > "$DESKTOP_FILE" <<DESK
[Desktop Entry]
Version=1.0
Type=Application
Name=EDY RECON
Comment=Ferramenta de OSINT e testes autorizados
Exec="$SCRIPT_DIR/EDYRECON.sh"
Path=$SCRIPT_DIR
Icon=utilities-terminal
Terminal=true
Categories=Utility;Security;
StartupNotify=false
DESK
chmod 755 "$DESKTOP_FILE"
if command -v gio >/dev/null 2>&1; then
    gio set "$DESKTOP_FILE" metadata::trusted true 2>/dev/null || true
fi

echo "[5/5] Atualizacao semanal..."
if [ "$ENABLE_CRON" = "true" ]; then
    command -v crontab >/dev/null 2>&1 || { echo "[X] crontab ausente." >&2; exit 1; }
    ( crontab -l 2>/dev/null | grep -v "atualizar_wordlists.py" || true; \
      echo "0 3 * * 1 '$SCRIPT_DIR/.venv/bin/python' '$SCRIPT_DIR/atualizar_wordlists.py' >> '$SCRIPT_DIR/logs/atualizar.log' 2>&1" ) | crontab -
    echo "    Cron semanal instalado por solicitacao explicita."
else
    echo "    Cron nao instalado. Use --enable-weekly-update para habilitar conscientemente."
fi

echo "[OK] Pos-instalacao concluida. Execute ./EDYRECON.sh"
