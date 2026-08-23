#!/usr/bin/env bash
# Instalador/atualizador seguro do EDY RECON para Kali Linux.
set -eu
umask 077

DEST_INPUT="${1:-/opt/EDYRECON}"
SRC="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ "$(id -u)" != "0" ]; then
    echo "[X] Execute com sudo: sudo bash $0 [destino]" >&2
    exit 1
fi
case "$DEST_INPUT" in /*) ;; *) echo "[X] O destino deve ser absoluto." >&2; exit 1 ;; esac
case "$DEST_INPUT" in
    /|/home|/opt|/usr|/var|/root|*/../*|*/./*) echo "[X] Destino amplo ou nao canonico recusado." >&2; exit 1 ;;
esac
case "$DEST_INPUT" in *[!A-Za-z0-9_./-]*) echo "[X] Destino contem caracteres inseguros." >&2; exit 1 ;; esac
if [[ ! "$DEST_INPUT" =~ ^/opt/EDYRECON$ ]] && \
   [[ ! "$DEST_INPUT" =~ ^/home/[A-Za-z0-9_.-]+(/Desktop)?/EDYRECON$ ]]; then
    echo "[X] O destino deve ser uma pasta EDYRECON permitida." >&2
    exit 1
fi

mkdir -p -- "$DEST_INPUT"
DEST="$(realpath -m -- "$DEST_INPUT")"
if [ "$DEST" = "$SRC" ]; then
    echo "[X] Origem e destino sao iguais; use kali_pos_install.sh nessa copia." >&2
    exit 1
fi

echo "[*] Verificando dependencias legitimas do sistema..."
missing=""
command -v python3 >/dev/null 2>&1 || missing="$missing python3"
if command -v python3 >/dev/null 2>&1; then
    python3 -m venv --help >/dev/null 2>&1 || missing="$missing python3-venv"
fi
command -v rsync >/dev/null 2>&1 || missing="$missing rsync"
if [ -n "$missing" ]; then
    echo "[X] Dependencias ausentes:$missing" >&2
    echo "    Instale-as pelo gerenciador oficial do Kali e execute novamente." >&2
    exit 1
fi

echo "[*] Copiando codigo e recursos sem excluir dados existentes..."
BACKUP_DIR="$DEST/archive/install-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p -- "$BACKUP_DIR"
rsync -a --backup --backup-dir="$BACKUP_DIR" \
    --exclude '.git/' --exclude '.venv/' --exclude '__pycache__/' \
    --exclude 'archive/' \
    --exclude 'reports/' --exclude 'sessions/' --exclude 'logs/' \
    --exclude 'data/config.json' --exclude 'kali_target.conf' \
    "$SRC/" "$DEST/"

printf '%s\n' 'EDYRECON_MANAGED_V1' > "$DEST/.edyrecon-managed"
chmod 600 "$DEST/.edyrecon-managed"

echo "[*] Criando ambiente Python isolado..."
python3 -m venv "$DEST/.venv"
"$DEST/.venv/bin/python" -m pip install -r "$DEST/requirements.txt"
"$DEST/.venv/bin/python" -m pip check

echo "[*] Aplicando permissoes conservadoras..."
chmod 755 "$DEST/EDYRECON.sh" "$DEST/edyrecon.py" "$DEST/kali_install.sh" \
    "$DEST/kali_pos_install.sh" "$DEST/sync_to_kali.sh"
mkdir -p "$DEST/reports" "$DEST/sessions" "$DEST/logs"
chmod 700 "$DEST/reports" "$DEST/sessions" "$DEST/logs"
find "$DEST/reports" "$DEST/sessions" "$DEST/logs" -type f -exec chmod 600 {} +
if [ -f "$DEST/data/config.json" ]; then chmod 600 "$DEST/data/config.json"; fi

echo "[*] Criando comando /usr/local/bin/edyrecon..."
ln -sfn "$DEST/EDYRECON.sh" /usr/local/bin/edyrecon

echo "[OK] Instalacao concluida em $DEST. Execute: edyrecon"
