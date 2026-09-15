#!/bin/sh
# Installa il guard senza passare dai plugin, per gli host dove `/plugin` non c'e'.
#
# Fa tre cose: copia l'hook e l'avviatore, copia la skill, e FONDE la configurazione degli hook nel
# settings.json esistente. Fonde, non sovrascrive: i permessi e gli hook gia' presenti restano, e una
# copia di sicurezza viene messa da parte prima di toccare qualsiasi cosa.
#
#   sh install.sh                 installa per l'utente corrente (~/.claude)
#   sh install.sh --dry-run       dice cosa farebbe, senza scrivere niente
#   sh install.sh --uninstall     toglie gli hook dal settings.json e rimuove i file
#
set -eu

QUI=$(cd "$(dirname "$0")" && pwd)
DEST="${G1_DEST:-$HOME/.claude}"
AZIONE="install"

for arg in "$@"; do
    case "$arg" in
        --dry-run)   AZIONE="dry-run" ;;
        --uninstall) AZIONE="uninstall" ;;
        *) echo "argomento sconosciuto: $arg" >&2; exit 2 ;;
    esac
done

PY=""
for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
    echo "Serve Python 3.8 o piu' recente. Non ne ho trovato nessuno sul PATH." >&2
    exit 1
fi

echo "destinazione: $DEST"
echo "python:       $($PY --version 2>&1)"
echo "azione:       $AZIONE"
echo

"$PY" "$QUI/install.py" "$AZIONE" "$QUI" "$DEST"
