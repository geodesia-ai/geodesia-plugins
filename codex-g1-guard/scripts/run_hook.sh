#!/bin/sh
# Trova un interprete Python e gli passa l'hook. Esiste per un motivo solo: NESSUN nome di comando
# copre i tre sistemi.
#
#   python3  ->  Linux si', macOS si', Windows NO
#   python   ->  Windows si', macOS si', Linux NO su Debian e Ubuntu puliti, dove e' un pacchetto a parte
#
# Claude Code non ha un campo per-piattaforma nei suoi hook, quindi la scelta va fatta a tempo di
# esecuzione. E' lo stesso rimedio del plugin ufficiale `security-guidance`; il plugin ufficiale
# `hookify` non ce l'ha, e infatti ha il difetto aperto #85 proprio su Windows.
#
# FALLISCE APERTO, come tutto il resto del guard. Se non c'e' nessun interprete si esce a 0 in
# silenzio: l'agente continua a lavorare senza protezione. Un guard che rompe la sessione quando
# manca una dipendenza viene disinstallato, e allora non protegge niente. Il costo di questa scelta
# e' che l'assenza e' silenziosa: chi installa deve VERIFICARE, non dare per scontato.

# `${0%/*}` invece di `dirname`: e' espansione della shell, non un binario esterno. Con un PATH
# ridotto `dirname` non c'e', e l'avviatore scriverebbe un errore su stderr proprio nel caso in cui
# deve tacere. Se `$0` non contiene una barra, la cartella e' quella corrente.
case "$0" in
    */*) QUI="${0%/*}" ;;
    *)   QUI="." ;;
esac
HOOK="$QUI/g1_guard.py"

[ -f "$HOOK" ] || exit 0

for INTERPRETE in python3 python py; do
    if command -v "$INTERPRETE" >/dev/null 2>&1; then
        if [ "$INTERPRETE" = "py" ]; then
            exec "$INTERPRETE" -3 "$HOOK"        # il launcher di Windows vuole la versione
        fi
        exec "$INTERPRETE" "$HOOK"
    fi
done

exit 0
