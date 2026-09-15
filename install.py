"""Fonde il guard nel settings.json di un host, senza distruggere quello che c'e'.

La regola che conta e' una sola: FONDERE. Un installatore che sovrascrive `hooks` cancella gli hook
di qualcun altro, e uno che sovrascrive il file cancella i permessi accumulati in mesi. Qui si
aggiungono solo le voci del guard, riconoscibili perche' puntano al nostro avviatore, e si toglie
esattamente quelle in disinstallazione.

Nessuna dipendenza: solo libreria standard, come l'hook.
"""
import json, os, pathlib, shutil, sys, time

AZIONE, SORGENTE, DEST = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
PLUGIN = SORGENTE / "g1-guard"
COMANDO = 'sh "$HOME/.claude/hooks/run_hook.sh" || true'

AGGANCI = [
    ("UserPromptSubmit", None, "G-1: scanning the prompt"),
    ("PostToolUse", "WebFetch|WebSearch|Read|Bash|Glob|Grep|NotebookRead|mcp__.*",
     "G-1: scanning what was read"),
    ("PreToolUse", "Bash|Write|Edit|NotebookEdit|WebFetch|SendUserFile|mcp__.*",
     "G-1: verifying the call"),
    # `Stop` NON si installa. Misurato: quattro relazioni di lavoro su quattro superano la soglia di
    # `answer_safety` perche' DESCRIVONO attacchi. Chi lo vuole lo aggiunge a mano; il README spiega.
]
AMBIENTE = {
    "GEODESIA_G1_URL": "https://demo.geodesia.ai/mcp",
    "G1_HOOK_TIMEOUT": "12",
    "G1_DENY_ON": "all",
}

secco = AZIONE == "dry-run"
passi = []


def fai(descrizione, funzione):
    passi.append(descrizione)
    print(("[simulato] " if secco else "[fatto]    ") + descrizione)
    if not secco:
        funzione()


def voce(matcher, messaggio):
    v = {"hooks": [{"type": "command", "command": COMANDO, "timeout": 20,
                    "statusMessage": messaggio}]}
    if matcher:
        v["matcher"] = matcher
    return v


def nostra(v):
    return any(h.get("command") == COMANDO for h in v.get("hooks", []))


def carica_settings(p):
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except ValueError:
        print(f"\nERRORE: {p} non e' JSON valido. Non lo tocco.", file=sys.stderr)
        sys.exit(1)


def main():
    settings = DEST / "settings.json"
    hooks_dir = DEST / "hooks"
    skill_dir = DEST / "skills/geodesia-g1"

    if AZIONE == "uninstall":
        d = carica_settings(settings)
        tolti = 0
        for evento in list(d.get("hooks", {})):
            resto = [v for v in d["hooks"][evento] if not nostra(v)]
            tolti += len(d["hooks"][evento]) - len(resto)
            if resto:
                d["hooks"][evento] = resto
            else:
                del d["hooks"][evento]
        if not d.get("hooks"):
            d.pop("hooks", None)
        for k in AMBIENTE:
            d.get("env", {}).pop(k, None)
        if d.get("env") == {}:
            d.pop("env", None)
        backup = settings.with_name(f"settings.json.bak-g1-{time.strftime('%Y%m%d-%H%M%S')}")
        fai(f"copia di sicurezza in {backup.name}", lambda: shutil.copy2(settings, backup))
        fai(f"tolte {tolti} voci di hook da settings.json",
            lambda: settings.write_text(json.dumps(d, indent=2) + "\n"))
        for p in (hooks_dir / "g1_guard.py", hooks_dir / "run_hook.sh"):
            if p.exists():
                fai(f"rimosso {p}", lambda p=p: p.unlink())
        if skill_dir.exists():
            fai(f"rimossa la skill {skill_dir}", lambda: shutil.rmtree(skill_dir))
        print("\nDisinstallato. Riavvia l'agente: gli hook si leggono all'avvio.")
        return

    # ── copia dei file ────────────────────────────────────────────────────────────────────────
    fai(f"creo {hooks_dir}", lambda: hooks_dir.mkdir(parents=True, exist_ok=True))
    for nome in ("g1_guard.py", "run_hook.sh"):
        src = PLUGIN / "scripts" / nome
        if not src.exists():
            print(f"ERRORE: manca {src}", file=sys.stderr)
            sys.exit(1)
        fai(f"copio {nome} in {hooks_dir}",
            lambda s=src, n=nome: (shutil.copy2(s, hooks_dir / n),
                                   os.chmod(hooks_dir / n, 0o755)))
    src_skill = PLUGIN / "skills/geodesia-g1/SKILL.md"
    if src_skill.exists():
        fai(f"copio la skill in {skill_dir}",
            lambda: (skill_dir.mkdir(parents=True, exist_ok=True),
                     shutil.copy2(src_skill, skill_dir / "SKILL.md")))

    # ── fusione nel settings.json ─────────────────────────────────────────────────────────────
    d = carica_settings(settings)
    if settings.exists():
        backup = settings.with_name(f"settings.json.bak-g1-{time.strftime('%Y%m%d-%H%M%S')}")
        fai(f"copia di sicurezza in {backup.name}", lambda: shutil.copy2(settings, backup))

    hooks = d.setdefault("hooks", {})
    aggiunti = gia = 0
    for evento, matcher, messaggio in AGGANCI:
        elenco = hooks.setdefault(evento, [])
        if any(nostra(v) for v in elenco):
            gia += 1
            continue
        elenco.append(voce(matcher, messaggio))
        aggiunti += 1

    env = d.setdefault("env", {})
    for k, v in AMBIENTE.items():
        env.setdefault(k, v)          # setdefault: non si sovrascrive una scelta gia' fatta
    env.setdefault("G1_ALLOWED_DOMAINS", "")

    fai(f"fondo {aggiunti} agganci in settings.json ({gia} gia' presenti, "
        f"{sum(len(v) for v in hooks.values()) - aggiunti} voci altrui conservate)",
        lambda: settings.write_text(json.dumps(d, indent=2) + "\n"))

    print("\nInstallato." if not secco else "\nNiente e' stato scritto.")
    print("\nDue cose da fare adesso:")
    print("  1. RIAVVIA l'agente. Gli hook si leggono all'avvio: una sessione aperta non li ha.")
    print("  2. Metti i TUOI domini in G1_ALLOWED_DOMAINS dentro il blocco env di settings.json.")
    print("     Senza, ogni destinazione risulta nuova e dopo la prima lettura esterna il guard")
    print("     nega tutte le uscite.")
    print("\nPer verificare che sia vivo, e non solo installato:")
    print(f"  printf '%s' '{{\"hook_event_name\":\"PostToolUse\",\"session_id\":\"t\",")
    print("   \"tool_name\":\"Bash\",\"tool_input\":{},\"tool_response\":\"118 tests passed.\"}' \\")
    print(f"    | sh {hooks_dir}/run_hook.sh    # deve tacere e uscire 0")


main()
