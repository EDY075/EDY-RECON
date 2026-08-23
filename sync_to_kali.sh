#!/usr/bin/env bash
# Sincronizacao segura do EDY RECON para uma instalacao Kali gerenciada.
set -eu
umask 077

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
CONF="$SCRIPT_DIR/kali_target.conf"
MODE="dry-run"
MARKER=".edyrecon-managed"

usage() {
    cat <<'USAGE'
Uso: bash sync_to_kali.sh [--apply]

Sem --apply, executa apenas rsync --dry-run e nao altera o destino.
Com --apply, exige destino validado e o marker .edyrecon-managed criado pelo
kali_install.sh. Configuracao, sessoes e relatorios nunca sao enviados.
USAGE
}

case "${1:-}" in
    "") ;;
    --apply) MODE="apply" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[X] Opcao desconhecida: $1" >&2; usage >&2; exit 2 ;;
esac

if [ ! -f "$CONF" ]; then
    echo "[X] Copie kali_target.conf.example para kali_target.conf e edite." >&2
    exit 1
fi

KALI_USER="root"
KALI_HOST=""
KALI_PATH="/opt/EDYRECON"
KALI_PORT="22"

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

# Parser deliberadamente restrito: nao usa source, eval ou expansao de shell.
while IFS= read -r line || [ -n "$line" ]; do
    line="$(trim "$line")"
    case "$line" in ""|'#'*) continue ;; esac
    case "$line" in
        *=*) key="$(trim "${line%%=*}")"; value="$(trim "${line#*=}")" ;;
        *) echo "[X] Linha invalida em kali_target.conf." >&2; exit 1 ;;
    esac
    case "$value" in
        \"*\") value="${value#\"}"; value="${value%\"}" ;;
        \'*\') value="${value#\'}"; value="${value%\'}" ;;
    esac
    case "$value" in *['$`;&|<>']*) echo "[X] Valor inseguro em kali_target.conf." >&2; exit 1 ;; esac
    case "$key" in
        KALI_USER) KALI_USER="$value" ;;
        KALI_HOST) KALI_HOST="$value" ;;
        KALI_PATH) KALI_PATH="$value" ;;
        KALI_PORT) KALI_PORT="$value" ;;
        *) echo "[X] Chave nao permitida em kali_target.conf: $key" >&2; exit 1 ;;
    esac
done < "$CONF"

case "$KALI_USER" in ""|*[!A-Za-z0-9_.-]*) echo "[X] KALI_USER invalido." >&2; exit 1 ;; esac
case "$KALI_HOST" in ""|*[!A-Za-z0-9_.-]*) echo "[X] KALI_HOST invalido." >&2; exit 1 ;; esac
case "$KALI_PORT" in ""|*[!0-9]*) echo "[X] KALI_PORT invalido." >&2; exit 1 ;; esac
if [ "$KALI_PORT" -lt 1 ] || [ "$KALI_PORT" -gt 65535 ]; then
    echo "[X] KALI_PORT fora da faixa 1..65535." >&2
    exit 1
fi
case "$KALI_PATH" in *[!A-Za-z0-9_./-]*) echo "[X] KALI_PATH contem caracteres inseguros." >&2; exit 1 ;; esac
if [[ ! "$KALI_PATH" =~ ^/opt/EDYRECON$ ]] && \
   [[ ! "$KALI_PATH" =~ ^/home/[A-Za-z0-9_.-]+(/Desktop)?/EDYRECON$ ]]; then
    echo "[X] KALI_PATH deve apontar para uma pasta EDYRECON permitida." >&2
    exit 1
fi
case "$KALI_PATH" in *'/../'*|*'/./'*|*'//'*) echo "[X] KALI_PATH nao canonico." >&2; exit 1 ;; esac

if ! command -v rsync >/dev/null 2>&1; then
    echo "[X] rsync local e obrigatorio; scp nao oferece dry-run seguro." >&2
    exit 1
fi

REMOTE="${KALI_USER}@${KALI_HOST}"
SSH=(ssh -p "$KALI_PORT" -o BatchMode=yes -o ConnectTimeout=8 -- "$REMOTE")
TARGET="${REMOTE}:${KALI_PATH}/"

echo "[*] Validando destino gerenciado em $KALI_HOST (porta $KALI_PORT)..."
if ! "${SSH[@]}" "test -d '$KALI_PATH' && test -f '$KALI_PATH/$MARKER' && grep -qx 'EDYRECON_MANAGED_V1' '$KALI_PATH/$MARKER'"; then
    echo "[X] Destino sem marker valido. Execute kali_install.sh no Kali primeiro." >&2
    exit 1
fi
if ! "${SSH[@]}" "command -v rsync >/dev/null 2>&1"; then
    echo "[X] rsync nao esta disponivel no destino." >&2
    exit 1
fi

RSYNC_ARGS=(
    -avz --itemize-changes
    --exclude '.git/' --exclude '.venv/' --exclude '__pycache__/'
    --exclude 'archive/'
    --exclude 'reports/' --exclude 'sessions/' --exclude 'logs/'
    --exclude 'data/config.json' --exclude 'kali_target.conf'
)

if [ "$MODE" = "dry-run" ]; then
    echo "[*] DRY-RUN: nenhuma alteracao remota sera feita."
    rsync "${RSYNC_ARGS[@]}" --dry-run -e "ssh -p $KALI_PORT" "$SCRIPT_DIR/" "$TARGET"
    echo "[OK] Previa concluida. Revise-a e use --apply somente se estiver correta."
    exit 0
fi

echo "[*] Aplicando sincronizacao validada; dados locais serao preservados."
BACKUP_DIR="archive/sync-$(date -u +%Y%m%dT%H%M%SZ)"
rsync "${RSYNC_ARGS[@]}" --backup --backup-dir="$BACKUP_DIR" --delete-delay \
    -e "ssh -p $KALI_PORT" "$SCRIPT_DIR/" "$TARGET"

"${SSH[@]}" "umask 077; chmod 755 '$KALI_PATH/EDYRECON.sh' '$KALI_PATH/edyrecon.py' '$KALI_PATH/kali_install.sh' '$KALI_PATH/kali_pos_install.sh' '$KALI_PATH/sync_to_kali.sh'; mkdir -p '$KALI_PATH/reports' '$KALI_PATH/sessions' '$KALI_PATH/logs'; chmod 700 '$KALI_PATH/reports' '$KALI_PATH/sessions' '$KALI_PATH/logs'; find '$KALI_PATH/reports' '$KALI_PATH/sessions' '$KALI_PATH/logs' -type f -exec chmod 600 {} +"

echo "[OK] Sincronizacao aplicada. Arquivos substituidos/removidos foram movidos para $BACKUP_DIR."
