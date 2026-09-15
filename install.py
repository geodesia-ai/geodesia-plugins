"""Installa il guard in ogni host presente, fondendo invece di sovrascrivere.

La regola che conta e' una sola: FONDERE. Un installatore che sovrascrive il blocco degli hook
cancella quelli di un altro fornitore, e uno che riscrive il file cancella i permessi accumulati in
mesi. Qui si aggiungono solo le voci del guard, riconoscibili perche' contengono `run_hook.sh`, e la
disinstallazione toglie esattamente quelle.

Ogni host ha il suo percorso, i suoi nomi di evento e la sua forma di diniego. I nomi degli eventi
sono presi dalla documentazione di ciascuno; l'hook li riconduce a tre famiglie e risponde nel
dialetto giusto, che gli viene detto con `G1_HOST`. Cursor, Copilot e Windsurf non mandano il nome
dell'evento nel payload, quindi glielo si passa come argomento.

Nessuna dipendenza: solo libreria standard, come l'hook.
"""
import json, os, pathlib, shutil, sys, time

AZIONE, SORGENTE = sys.argv[1], pathlib.Path(sys.argv[2])
SOLO_HOST = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else ""
PLUGIN = SORGENTE / "g1-guard"
CASA = pathlib.Path.home()
# I file del guard stanno in UN posto solo, anche quando gli host sono sei: un secondo esemplare
# diverge al primo aggiornamento, ed e' il difetto che questo progetto ha gia' pagato altrove.
HOOKS = CASA / ".geodesia-g1"
FIRMA = "run_hook.sh"                      # come si riconosce una voce nostra, per toglierla dopo

AMBIENTE = {
    "GEODESIA_G1_URL": "https://demo.geodesia.ai/mcp",
    "G1_HOOK_TIMEOUT": "12",
    "G1_DENY_ON": "all",
    "G1_ALLOWED_DOMAINS": "",
}

# host -> (cartella che ne prova la presenza, file di configurazione, eventi (prompt, letto, azione))
# `Stop` non si installa da nessuna parte: quattro relazioni di lavoro su quattro lo fanno scattare
# perche' DESCRIVONO attacchi. Chi lo vuole lo aggiunge a mano; il README spiega con i numeri.
HOST = {
    "claude":   (".claude",          ".claude/settings.json",
                 ("UserPromptSubmit", "PostToolUse", "PreToolUse")),
    "codex":    (".codex",           ".codex/hooks.json",
                 ("UserPromptSubmit", "PostToolUse", "PreToolUse")),
    "cursor":   (".cursor",          ".cursor/hooks.json",
                 ("beforeSubmitPrompt", "postToolUse", "beforeShellExecution")),
    "gemini":   (".gemini",          ".gemini/settings.json",
                 ("UserPromptSubmit", "AfterTool", "BeforeTool")),
    "windsurf": (".codeium/windsurf", ".codeium/windsurf/hooks.json",
                 ("pre_user_prompt", "post_mcp_tool_use", "pre_run_command")),
    "copilot":  (".copilot",         ".copilot/hooks/geodesia-g1.json",
                 ("userPromptSubmitted", "postToolUse", "preToolUse")),
}

secco = AZIONE == "dry-run"


def dire(fatto, descrizione):
    print(("  [simulato] " if secco else "  [fatto]    ") + descrizione)
    if not secco:
        fatto()


def comando(host, evento):
    """L'invocazione. `G1_HOST` sceglie il dialetto, l'argomento dice quale evento e'."""
    return f'G1_HOST={host} sh "{HOOKS}/run_hook.sh" {evento}'


def nostra(testo):
    return FIRMA in json.dumps(testo)


def carica(p):
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text() or "{}")
    except ValueError:
        print(f"  ATTENZIONE: {p} non e' JSON valido. Lo salto invece di rovinarlo.", file=sys.stderr)
        return None


def salva(p, d):
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        b = p.with_name(p.name + f".bak-g1-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(p, b)
        print(f"  [fatto]    copia di sicurezza: {b.name}")
    p.write_text(json.dumps(d, indent=2) + "\n")


def voci_hook(host, evento, forma):
    """Ogni host vuole una forma diversa per la stessa cosa."""
    c = comando(host, evento)
    if forma == "claude":       # anche codex: stessa struttura annidata
        return {"hooks": [{"type": "command", "command": c, "timeout": 20,
                           "statusMessage": "Geodesia G-1"}]}
    if forma == "cursor":       # piatta, e `version: 1` a livello di file o gli hook tacciono
        return {"command": c, "timeout": 30}
    if forma == "gemini":
        return {"hooks": [{"name": "geodesia-g1", "type": "command", "command": c,
                           "timeout": 20000}]}
    return {"command": c, "timeout": 20}            # windsurf, copilot


def forma_di(host):
    return {"claude": "claude", "codex": "claude", "gemini": "gemini",
            "cursor": "cursor"}.get(host, "piatta")


def installa_host(host):
    prova, conf, eventi = HOST[host]
    if not (CASA / prova).is_dir():
        return None
    p = CASA / conf
    d = carica(p)
    if d is None:
        return False
    print(f"\n{host}  ->  {p}")
    forma = forma_di(host)
    hooks = d.setdefault("hooks", {})
    if host == "cursor":
        d.setdefault("version", 1)                  # senza, su Cursor 3.x tacciono tutti
    aggiunti = gia = altrui = 0
    for evento in eventi:
        elenco = hooks.setdefault(evento, [])
        if any(nostra(v) for v in elenco):
            gia += 1
            continue
        altrui += len(elenco)
        elenco.append(voci_hook(host, evento, forma))
        aggiunti += 1
    if host == "gemini":
        d.setdefault("mcpServers", {}).setdefault(
            "geodesia-g1", {"httpUrl": AMBIENTE["GEODESIA_G1_URL"]})
    env = d.setdefault("env", {}) if host in ("claude",) else None
    if env is not None:
        for k, v in AMBIENTE.items():
            env.setdefault(k, v)                    # setdefault: non si sovrascrive una scelta fatta
    dire(lambda: salva(p, d),
         f"{aggiunti} agganci aggiunti, {gia} gia' presenti, {altrui} voci altrui conservate")
    return True


def disinstalla_host(host):
    prova, conf, eventi = HOST[host]
    p = CASA / conf
    if not p.exists():
        return None
    d = carica(p)
    if d is None or "hooks" not in d:
        return None
    tolti = 0
    for evento in list(d["hooks"]):
        if not isinstance(d["hooks"][evento], list):
            continue
        resto = [v for v in d["hooks"][evento] if not nostra(v)]
        tolti += len(d["hooks"][evento]) - len(resto)
        if resto:
            d["hooks"][evento] = resto
        else:
            del d["hooks"][evento]
    if not tolti:
        return None
    if not d["hooks"]:
        d.pop("hooks")
    for k in AMBIENTE:
        if isinstance(d.get("env"), dict):
            d["env"].pop(k, None)
    if d.get("env") == {}:
        d.pop("env")
    print(f"\n{host}  ->  {p}")
    dire(lambda: salva(p, d), f"tolte {tolti} voci del guard, il resto del file intatto")
    return True


def main():
    scelti = [SOLO_HOST] if SOLO_HOST else list(HOST)
    if SOLO_HOST and SOLO_HOST not in HOST:
        print(f"host sconosciuto: {SOLO_HOST}. Conosco: {', '.join(HOST)}", file=sys.stderr)
        return 2

    if AZIONE == "uninstall":
        fatti = [h for h in scelti if disinstalla_host(h)]
        if not secco:
            for n in ("g1_guard.py", "run_hook.sh"):
                if (HOOKS / n).exists():
                    (HOOKS / n).unlink()
            if HOOKS.exists() and not any(HOOKS.iterdir()):
                HOOKS.rmdir()
        print(f"\nTolto da: {', '.join(fatti) if fatti else 'nessun host'}.")
        print("Riavvia gli agenti: gli hook si leggono all'avvio.")
        return 0

    # ── i file, in un posto solo ──────────────────────────────────────────────────────────────
    print(f"file del guard  ->  {HOOKS}")
    dire(lambda: HOOKS.mkdir(parents=True, exist_ok=True), f"creo {HOOKS}")
    for nome in ("g1_guard.py", "run_hook.sh"):
        src = PLUGIN / "scripts" / nome
        if not src.exists():
            print(f"ERRORE: manca {src}", file=sys.stderr)
            return 1
        dire(lambda s=src, n=nome: (shutil.copy2(s, HOOKS / n), os.chmod(HOOKS / n, 0o755)),
             f"copio {nome}")
    skill = PLUGIN / "skills/geodesia-g1/SKILL.md"
    if skill.exists() and (CASA / ".claude").is_dir():
        dest = CASA / ".claude/skills/geodesia-g1"
        dire(lambda: (dest.mkdir(parents=True, exist_ok=True),
                      shutil.copy2(skill, dest / "SKILL.md")), "copio la skill per Claude Code")

    trovati = []
    for host in scelti:
        esito = installa_host(host)
        if esito:
            trovati.append(host)
        elif esito is None and SOLO_HOST:
            print(f"\n{host}: non lo vedo installato ({CASA / HOST[host][0]} non esiste).")

    print()
    if not trovati:
        print("Nessun host trovato. Usa --host <nome> per forzarne uno:")
        print(f"  {', '.join(HOST)}")
        return 1
    print(f"Installato per: {', '.join(trovati)}")
    print("\nDue cose adesso:")
    print("  1. RIAVVIA gli agenti. Gli hook si leggono all'avvio.")
    print("  2. Metti i TUOI domini in G1_ALLOWED_DOMAINS, altrimenti ogni destinazione risulta")
    print("     nuova e dopo la prima lettura esterna il guard nega tutte le uscite.")
    print("\nPer verificare che sia VIVO, non solo installato:")
    print(f"  echo '{{\"tool_name\":\"Bash\",\"tool_input\":{{}},\"session_id\":\"t\",")
    print('   "tool_response":"118 tests passed."}\' \\')
    print(f"    | sh {HOOKS}/run_hook.sh PostToolUse     # deve tacere e uscire 0")
    return 0


sys.exit(main())
