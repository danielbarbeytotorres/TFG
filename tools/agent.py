#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import sys
import json
import errno
import textwrap
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
import glob
import concurrent.futures

# --- IMPORTACIÓN DE RICH PARA UI PROFESIONAL ---
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
except ImportError:
    sys.stderr.write("Error: Falta la librería 'rich'. Instálala con: pip install rich\n")
    sys.exit(1)

# Inicializamos consola global
console = Console()

try:
    from openai import OpenAI
except Exception:
    console.print("[bold red]Error:[/bold red] Instala el SDK oficial de OpenAI en tu venv:")
    console.print("  python -m pip install 'openai>=1.0.0'")
    sys.exit(1)

# === Config + Prompt ===
MODEL = os.getenv("AGENT_MODEL", "gpt-5-mini")
OUT_DIR = os.getenv("AGENT_OUT_DIR", os.path.abspath("./out_scripts"))

SYSTEM_PROMPT = textwrap.dedent("""\
Eres un generador de scripts de ciberseguridad DEFENSIVA para Metasploitable 2 (Ubuntu 8.04, SysV init).
Recibirás un JSON con campos: name, host, port, solution, solution_type.

REGLAS PRINCIPALES:
- Implementa EXACTAMENTE la acción indicada en "solution" si es automatizable sin interacción humana.
- Si "solution" exige pasos interactivos (por ejemplo `vncpasswd`, `passwd`, asistentes que piden input), NO esperes entrada ni inventes contraseñas.
  - En su lugar:
    1) Aísla el servicio inseguro de forma no interactiva y reversible (pararlo si NO es sshd, ligarlo a 127.0.0.1 con sed, o bloquear SOLO su puerto concreto con iptables).
    2) Añade una línea a `/tmp/mitigation_todo.log` con `date +%F_%T` explicando la acción manual pendiente.
    3) Termina con `exit 0` igualmente.
- No hagas detección de conectividad compleja ni cadenas `/dev/tcp → curl → nc → telnet`.

ACCESO REMOTO (OBLIGATORIO):
- NUNCA parar, matar, deshabilitar ni quitar del arranque el servicio SSH/sshd. Prohibido `killall sshd`, `/etc/init.d/ssh stop`, `update-rc.d -f ssh remove`, o editar `sshd_config` para bloquear el acceso remoto.
- NUNCA dejes iptables de forma que impida nuevas conexiones SSH entrantes (tcp/22). Antes de añadir reglas DROP generales, el script DEBE garantizar una excepción ACCEPT para SSH:
  iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || \
  iptables -I INPUT -p tcp --dport 22 -j ACCEPT
- Prohibido aplicar reglas tipo "bloquear TODO el tráfico TCP entrante excepto loopback" si eso rompería el acceso SSH.
  Si la mitigación pide "bloquear todo", NO cambies el firewall global: escribe esa acción como pendiente en `/tmp/mitigation_todo.log` y termina con `exit 0`.

FIREWALL:
- Puedes usar `iptables` para bloquear puertos inseguros específicos (telnet, rlogin, VNC sin auth, etc.), siempre comprobando idempotencia con `iptables -C ...` antes de `iptables -I ...`.
- Mantén siempre SSH accesible desde la máquina de administración.

ESTILO DEL SCRIPT:
- Salida: SOLO un único bloque de código tipo ```bash ...``` sin texto ni explicación fuera.
- Empieza siempre con:
  #!/bin/bash
  set -euo pipefail
- Haz copia de seguridad antes de editar configs: `<archivo>.bak.$(date +%F_%H%M%S)`.
- Haz cambios idempotentes (usa `grep`, `sed`, `iptables -C` antes de tocar).
- Usa SOLO estos comandos: `/etc/init.d/<svc>`, `invoke-rc.d`, `update-rc.d`, `netstat`, `ps`, `pidof`, `kill`, `sed`, `grep`, `cp`, `mv`, `chmod`, `cat`, `tee`, `date`, `awk`, `iptables`.
- PROHIBIDOS: `systemctl`, `journalctl`, `ss`, `nft`, `firewall-cmd`, `apt-get install`, `python`, `service`, `read`, `vncpasswd`, `passwd`.
- Máximo ~40 líneas útiles.

COMPORTAMIENTO AL FINAL:
- Si aplicas mitigación automática con éxito, termina con `exit 0`.
- Si no puedes aplicar todo porque requiere intervención manual o porque rompería SSH/firewall global, registra lo pendiente en `/tmp/mitigation_todo.log` y termina igualmente con `exit 0`.
""")

# === Helpers ===
CODE_BLOCK_RE = re.compile(r"```(?:bash|sh)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
SHEBANG_RE = re.compile(r"^\s*#!")

def now_ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def minimal_payload(vuln_json: Dict[str, Any]) -> Dict[str, Any]:
    v = vuln_json.get("result", {}) or {}
    return {
        "name": v.get("name") or vuln_json.get("name"),
        "host": v.get("host") or vuln_json.get("host"),
        "port": v.get("port") or vuln_json.get("port"),
        "solution": v.get("solution") or vuln_json.get("solution"),
        "solution_type": v.get("solution_type") or vuln_json.get("solution_type"),
    }

def slugify(text: Optional[str]) -> str:
    if not text:
        return "script"
    s = re.sub(r"[^\w\-]+", "_", text.strip().lower())
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "script"

def ensure_dir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

def extract_script_from_text(text: str) -> str:
    if not text:
        return ""
    m = CODE_BLOCK_RE.search(text)
    if m:
        return m.group(1).strip()
    if SHEBANG_RE.search(text) or "set -euo pipefail" in text:
        return text.strip()
    return ""

def write_script(content: str, vuln_name: Optional[str], out_dir: str = OUT_DIR) -> str:
    ts_date = datetime.now().strftime("%Y-%m-%d")
    ts_time = datetime.now().strftime("%H%M%S")
    base_dir = os.path.join(out_dir, ts_date)
    ensure_dir(base_dir)
    fname = f"{ts_time}_{slugify(vuln_name)}.sh"
    out_path = os.path.join(base_dir, fname)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        text = content if SHEBANG_RE.search(content) else "#!/usr/bin/env bash\nset -euo pipefail\n" + content
        f.write(text.rstrip() + "\n")
    os.chmod(out_path, 0o755)
    return out_path

# === LLM ===
def call_llm_chatstyle(vuln_minimal: Dict[str, Any]) -> (str, float):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY no definida.")
    client = OpenAI(api_key=api_key)

    user_prompt = "JSON de vulnerabilidad:\n" + json.dumps(vuln_minimal, ensure_ascii=False, indent=2)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    start = time.time()
    resp = client.chat.completions.create(model=MODEL, messages=messages)
    duration = time.time() - start

    raw_output = resp.choices[0].message.content
    script = extract_script_from_text(raw_output)

    if not script:
        raise RuntimeError("El modelo no devolvió un bloque de script válido.")

    return script, duration

# --------------------
# Worker Function
# --------------------
def process_file_task(path: str, out_dir: str, progress, task_id) -> Dict[str, Any]:
    result = {"file": path, "ok": False, "out": None, "error": None, "duration": 0}

    fname = os.path.basename(path)
    # Acortar nombre si es muy largo para que no rompa la tabla visualmente
    fname_display = (fname[:35] + '..') if len(fname) > 35 else fname

    try:
        # 1. Leer JSON
        progress.update(task_id, description=f"[blue]Leyendo {fname_display}[/blue]")
        vuln = read_json(path)
        minimal = minimal_payload(vuln)

        # 2. Llamar a IA
        progress.update(task_id, advance=20, description=f"[yellow]Generando script {fname_display}[/yellow]")

        script, duration = call_llm_chatstyle(minimal)
        result["duration"] = duration

        # 3. Guardar Script
        progress.update(task_id, advance=60, description=f"[cyan]Guardando {fname_display}[/cyan]")
        out_path = write_script(script, minimal.get("name"), out_dir=out_dir)

        # 4. Finalizar
        result["ok"] = True
        result["out"] = out_path

        progress.update(task_id, completed=100, description=f"[green]✔ {fname_display}[/green]")

    except Exception as e:
        result["error"] = str(e)
        progress.update(task_id, completed=100, description=f"[red]✘ Error: {str(e)[:20]}...[/red]")

    return result

# --------------------
# Helpers batch
# --------------------
def gather_json_files(path: str) -> List[str]:
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        pattern = os.path.join(path, "*.json")
        return sorted(glob.glob(pattern))
    raise FileNotFoundError(f"Ruta no encontrada: {path}")

# --------------------
# Main
# --------------------
def main(argv):
    if len(argv) < 2:
        console.print("[bold red]Uso:[/bold red] python3 agent.py /ruta/json [/ruta/salida] [--workers N]")
        return 2

    input_path = argv[1]
    out_dir = OUT_DIR

    if len(argv) >= 3 and not argv[2].startswith("--"):
        out_dir = argv[2]

    if "--out" in argv:
        try:
            out_dir = argv[argv.index("--out") + 1]
        except: pass

    workers = int(os.getenv("AGENT_WORKERS", "5"))
    if "--workers" in argv:
        try:
            workers = int(argv[argv.index("--workers") + 1])
        except: pass

    try:
        files = gather_json_files(input_path)
    except Exception as e:
        console.print(f"[bold red]Error al buscar archivos:[/bold red] {e}")
        return 1

    if not files:
        console.print("[bold yellow]No se encontraron archivos .json para procesar.[/bold yellow]")
        return 0

    console.print(Panel.fit(
        f"Target: [u]{input_path}[/u]\n"
        f"Salida: [u]{out_dir}[/u]\n"
        f"Model:  [bold blue]{MODEL}[/bold blue]\n" 
        f"Workers: [bold]{workers}[/bold]",
        border_style="blue",
        title="[bold cyan]AGENT.PY[/bold cyan]"
    ))

    start_all = time.time()
    results = []

    progress_columns = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    ]

    with Progress(*progress_columns, console=console) as progress:
        task_map = {}
        futures_map = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            for f in files:
                fname = os.path.basename(f)
                t_id = progress.add_task(f"[dim]Esperando: {fname}[/dim]", total=100, start=False)
                future = executor.submit(process_file_task, f, out_dir, progress, t_id)
                futures_map[future] = f
                progress.start_task(t_id)

            for future in concurrent.futures.as_completed(futures_map):
                res = future.result()
                results.append(res)

    duration_all = time.time() - start_all

    # Tabla Resumen
    oks = sum(1 for r in results if r['ok'])
    fails = sum(1 for r in results if not r['ok'])

    table = Table(title="Resumen de Ejecución", box=box.ROUNDED)
    table.add_column("Archivo JSON", style="cyan")
    table.add_column("Estado", justify="center")
    table.add_column("Tiempo", justify="right")
    table.add_column("Salida / Error", style="dim")

    for res in results:
        fname = os.path.basename(res['file'])
        fname_short = (fname[:40] + '..') if len(fname) > 40 else fname

        if res['ok']:
            status = "[bold green1]OK[/bold green1]"
            detail = os.path.basename(res['out']) if res['out'] else "Generado"
            time_str = f"{res['duration']:.1f}s"
        else:
            status = "[bold red]FAIL[/bold red]"
            detail = res['error']
            time_str = "-"

        table.add_row(fname_short, status, time_str, detail)

    console.print("\n")
    console.print(table)

    summary_color = "green" if fails == 0 else "red"
    console.print(Panel(
        f"Procesados: {len(files)} | [green]Éxitos: {oks}[/green] | [red]Fallos: {fails}[/red]\n"
        f"Tiempo total en generar scripts de seguridad: {duration_all:.1f}s",
        style=f"bold {summary_color}",
        expand=False
    ))

    return 1 if fails > 0 else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
