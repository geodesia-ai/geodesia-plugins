#!/bin/sh
# Installa il guard senza passare dai plugin, per gli host dove `/plugin` non c'e'.
#
# Fa tre cose: copia l'hook e l'avviatore, copia la skill, e FONDE la configurazione degli hook nel
# settings.json esistente. Fonde, non sovrascrive: i permessi e gli hook gia' presenti restano, e una
# copia di sicurezza viene messa da parte prima di toccare qualsiasi cosa.
#
#   sh install.sh                     installa in OGNI host che trova sulla macchina
#   sh install.sh --host cursor       ne installa uno solo
#   sh install.sh --dry-run           dice cosa farebbe, senza scrivere niente
#   sh install.sh --uninstall         toglie le voci del guard e lascia intatto il resto
#
# Host: claude, codex, cursor, gemini, windsurf, copilot.
#
set -eu

QUI=$(cd "$(dirname "$0")" && pwd)
AZIONE="install"
SOLO=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)   AZIONE="dry-run" ;;
        --uninstall) AZIONE="uninstall" ;;
        --host)      shift; SOLO="${1:-}" ;;
        --host=*)    SOLO="${1#--host=}" ;;
        -h|--help)   sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "argomento sconosciuto: $1" >&2; exit 2 ;;
    esac
    shift
done

PY=""
for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
    echo "Serve Python 3.8 o piu' recente. Non ne ho trovato nessuno sul PATH." >&2
    exit 1
fi

echo "python: $($PY --version 2>&1)"
echo "azione: $AZIONE${SOLO:+  (solo $SOLO)}"
echo

"$PY" "$QUI/install.py" "$AZIONE" "$QUI" "$SOLO"
