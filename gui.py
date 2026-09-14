# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
QA Automation Agent — desktop control center.

A local tkinter GUI on top of the existing CLI. Nothing new is executed
here: the GUI only composes the same `main.py` commands a power user would
type, streams their output into a console pane, and opens the generated
reports. All the agent's safety rules (scope guard, budgets, redaction,
escalation) apply unchanged because the CLI applies them.

Launch:  QA_Agent.bat  (Windows)  |  .venv/Scripts/python gui.py
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, font, messagebox, ttk

ROOT = Path(__file__).resolve().parent
MAIN_PY = ROOT / "main.py"
REPORTS = ROOT / "reports"

BG = "#12151c"
BG_CARD = "#1a1f2b"
BG_INPUT = "#20273a"
FG = "#e8ecf4"
FG_DIM = "#8a94a8"
ACCENT = "#4da3ff"
OK = "#3ecf8e"
WARN = "#f5b04d"
ERR = "#ff6b6b"
BORDER = "#2a3247"

PROFILES = {
    "safe": "Prudente — pocas páginas, rápido, primer contacto",
    "standard": "Equilibrado — el predeterminado (25 páginas, 100 requests)",
    "deep": "Profundo — más páginas, profundidad 4, 30 min",
    "ci": "Pipelines — headless, gate de registro, sin umbral de cobertura",
}
ACTIONS = {
    "run": "Ciclo autónomo completo (ejecuta pruebas reales)",
    "plan": "Planifica sin ejecutar (requisitos, riesgos, tests propuestos)",
    "discover": "Solo descubrimiento — lee el proyecto, no toca nada",
}
COMMANDS = ("run", "plan", "discover")


# ---------------------------------------------------------------------------
# Command builders — pure functions, unit-tested
# ---------------------------------------------------------------------------


def build_command(
    action: str,
    target: str,
    profile: str,
    *,
    url: str | None = None,
    browser: str | None = None,
    headed: bool = False,
    output_dir: str | None = None,
    min_coverage: float | None = None,
    max_pages: int | None = None,
    max_requests: int | None = None,
    dry_run: bool = False,
    allow_external: bool = False,
    python_exe: str | None = None,
) -> list[str]:
    """Compose the CLI argv for a GUI action. Mirrors main.py's flags.

    `python_exe=None` (the runtime default) resolves through
    `agent_invocation()` — the exe re-invokes itself when frozen, or
    `<python> main.py` from a source checkout. Tests pass an explicit
    `python_exe` for deterministic argv.
    """
    if action not in COMMANDS:
        raise ValueError(f"unknown action {action!r}")
    cmd = agent_invocation() if python_exe is None else [python_exe, str(MAIN_PY)]
    cmd += [action, target, "--profile", profile]
    if url:
        cmd += ["--url", url]
    if browser and browser != "chromium":
        cmd += ["--browser", browser]
    if headed:
        cmd += ["--headed"]
    if output_dir:
        cmd += ["--output", output_dir]
    if min_coverage is not None:
        cmd += ["--min-coverage", str(min_coverage)]
    if max_pages:
        cmd += ["--max-pages", str(int(max_pages))]
    if max_requests:
        cmd += ["--max-requests", str(int(max_requests))]
    if dry_run:
        cmd += ["--dry-run"]
    if allow_external:
        cmd += ["--allow-external"]
    return cmd


def reports_dir_for(output_dir: str | None) -> Path:
    """Resolve where the reports of a run land (same rule as main.py)."""
    if output_dir:
        path = Path(output_dir)
        return path if path.is_absolute() else ROOT / path
    return REPORTS


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def summarize_findings(findings: list[dict] | None) -> dict[str, int]:
    """Count findings by severity. Malformed entries are skipped defensively:
    a partially-written report must never crash the results panel."""
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def latest_report_data(base: Path) -> dict | None:
    """Parse the most recent valid audit_report.json under `base`, or None.
    Newest-first with fallback: a corrupt newest report (e.g. an interrupted
    run) never blanks the panel when an older valid one exists."""
    try:
        candidates = sorted(
            (p for p in Path(base).glob("**/audit_report.json") if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for candidate in candidates:
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                continue  # corrupt artifact — try the next run directory
        return None
    except Exception:  # noqa: BLE001 — results panel is best-effort by design
        return None


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------


class TextRedirector:
    """Queue-based stdout bridge: worker thread -> Tk event loop."""

    def __init__(self, widget: tk.Text, line_queue: queue.Queue[str]) -> None:
        self._widget = widget
        self._queue = line_queue

    def write(self, text: str) -> None:
        for line in text.splitlines():
            self._queue.put(line)
        if text.endswith("\n") is False and text.strip():
            pass  # partial line: flushed on the next write

    def flush(self) -> None:  # file-like API
        return None

    def drain(self) -> None:
        """Move queued lines into the widget (called from the UI thread)."""
        self._widget.configure(state="normal")
        try:
            while True:
                line = self._queue.get_nowait()
                self._widget.insert("end", line + "\n")
                self._widget.see("end")
        except queue.Empty:
            pass
        finally:
            self._widget.configure(state="disabled")


class QAGui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("QA Automation Agent — Panel de Control")
        self.geometry("1080x740")
        self.minsize(920, 620)
        self.configure(bg=BG)

        self._proc: subprocess.Popen | None = None
        self._queue: queue.Queue[str] = queue.Queue()
        self._redirector = TextRedirector(None, self._queue)  # widget wired later

        base = font.nametofont("TkDefaultFont")
        base.configure(family="Segoe UI", size=10)
        self.option_add("*Font", base)

        self._build_styles()
        self._build_layout()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(80, self._poll_queue)

    # ------------------------------------------------------------------
    def _build_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=FG, fieldbackground=BG_INPUT)
        style.configure("Card.TFrame", background=BG_CARD)
        style.configure("Bg.TFrame", background=BG)
        style.configure("TLabel", background=BG_CARD, foreground=FG)
        style.configure("Dim.TLabel", background=BG_CARD, foreground=FG_DIM, font=("Segoe UI", 9))
        style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG, bordercolor=BORDER)
        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#0b1220",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 7),
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#6cb4ff"), ("disabled", "#33415c")],
            foreground=[("disabled", "#7c8db0")],
        )
        style.configure(
            "Stop.TButton",
            background=ERR,
            foreground="#1c0d0d",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 7),
        )
        style.map("Stop.TButton", background=[("active", "#ff8c8c"), ("disabled", "#5a3030")])
        style.configure("Card.TLabelframe", background=BG_CARD, bordercolor=BORDER, relief="solid")
        style.configure("Card.TLabelframe.Label", background=BG_CARD, foreground=ACCENT, font=("Segoe UI", 10, "bold"))
        style.configure("TCombobox", fieldbackground=BG_INPUT, background=BG_INPUT, foreground=FG)
        style.configure("TCheckbutton", background=BG_CARD, foreground=FG)
        style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=BG_INPUT, bordercolor=BG_CARD)

    # ------------------------------------------------------------------
    def _build_layout(self) -> None:
        header = tk.Frame(self, bg=BG, height=64)
        header.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(
            header,
            text="🛡  QA Automation Agent",
            font=("Segoe UI", 17, "bold"),
            bg=BG,
            fg=FG,
        ).pack(side="left")
        tk.Label(
            header,
            text="  auditoría local y autónoma — nada sale de tu máquina",
            font=("Segoe UI", 10),
            bg=BG,
            fg=FG_DIM,
        ).pack(side="left", pady=(6, 0))
        tk.Button(
            header,
            text="Abrir informes  ↗",
            command=self._open_reports,
            bg=BG_CARD,
            fg=ACCENT,
            activebackground=BG_INPUT,
            activeforeground=ACCENT,
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
        ).pack(side="right")

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        body.columnconfigure(0, weight=0)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # ---- left: configuration card ----
        left = ttk.Frame(body, style="Card.TFrame", padding=16)
        left.grid(row=0, column=0, sticky="nsw", padx=(0, 12))

        ttk.Label(left, text="Qué quieres hacer").pack(anchor="w")
        self.action_var = tk.StringVar(value="run")
        action_box = ttk.Frame(left, style="Card.TFrame")
        action_box.pack(fill="x", pady=(4, 10))
        for i, (value, label) in enumerate(
            [
                ("run", "▶  Ejecutar auditoría"),
                ("plan", "📋  Solo plan"),
                ("discover", "🔍  Solo descubrir"),
            ]
        ):
            ttk.Radiobutton(
                action_box,
                text=label,
                value=value,
                variable=self.action_var,
                command=self._sync_hint,
            ).grid(row=0, column=i, sticky="w", padx=(0, 10))

        ttk.Label(left, text="Objetivo").pack(anchor="w")
        target_box = ttk.Frame(left, style="Card.TFrame")
        target_box.pack(fill="x", pady=(4, 2))
        self.target_var = tk.StringVar(value="samples/demo_site")
        ttk.Entry(target_box, textvariable=self.target_var, width=34).pack(side="left", fill="x", expand=True)
        ttk.Button(target_box, text="…", width=3, command=self._pick_target).pack(side="left", padx=(6, 0))
        ttk.Label(
            left,
            text="carpeta de proyecto o URL (http://…)",
            style="Dim.TLabel",
        ).pack(anchor="w", pady=(0, 10))

        ttk.Label(left, text="Perfil de seguridad").pack(anchor="w")
        self.profile_var = tk.StringVar(value="standard")
        self.profile_hint = tk.StringVar(value=PROFILES["standard"])
        profile_box = ttk.Frame(left, style="Card.TFrame")
        profile_box.pack(fill="x", pady=(4, 2))
        combo = ttk.Combobox(
            profile_box,
            textvariable=self.profile_var,
            values=list(PROFILES),
            state="readonly",
            width=14,
        )
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", lambda _e: self._sync_hint())
        ttk.Label(left, textvariable=self.profile_hint, style="Dim.TLabel").pack(anchor="w", pady=(0, 10))

        ttk.Label(left, text="Opciones").pack(anchor="w")
        opts = ttk.Frame(left, style="Card.TFrame")
        opts.pack(fill="x", pady=(4, 8))
        self.headed_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Mostrar navegador", variable=self.headed_var).grid(row=0, column=0, sticky="w")
        self.dry_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Dry-run (no ejecuta)", variable=self.dry_var).grid(row=1, column=0, sticky="w")
        self.external_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Permitir dominios externos", variable=self.external_var).grid(row=2, column=0, sticky="w")

        limits = ttk.Frame(left, style="Card.TFrame")
        limits.pack(fill="x", pady=(0, 12))
        ttk.Label(limits, text="Máx. páginas").grid(row=0, column=0, sticky="w", pady=(6, 0))
        self.pages_var = tk.StringVar(value="")
        ttk.Entry(limits, textvariable=self.pages_var, width=8).grid(row=0, column=1, padx=(8, 16), pady=(6, 0))
        ttk.Label(limits, text="Máx. requests").grid(row=0, column=2, sticky="w", pady=(6, 0))
        self.requests_var = tk.StringVar(value="")
        ttk.Entry(limits, textvariable=self.requests_var, width=8).grid(row=0, column=3, padx=(8, 0), pady=(6, 0))

        self.run_btn = ttk.Button(left, text="▶  Iniciar auditoría", style="Accent.TButton", command=self._start)
        self.run_btn.pack(fill="x", pady=(4, 6))
        self.stop_btn = ttk.Button(left, text="■  Detener", style="Stop.TButton", command=self._stop, state="disabled")
        self.stop_btn.pack(fill="x")

        # ---- results panel: findings by severity of the latest run ----
        results = ttk.LabelFrame(left, text=" Últimos resultados ", style="Card.TLabelframe", padding=10)
        results.pack(fill="x", pady=(16, 0))
        sev_colors = {"critical": ERR, "high": "#ff9f43", "medium": WARN, "low": ACCENT, "info": FG_DIM}
        self.severity_vars: dict[str, tk.StringVar] = {}
        for i, sev in enumerate(SEVERITY_ORDER):
            row, col = divmod(i, 2)
            col_base = col * 3
            tk.Label(
                results, text="●", fg=sev_colors[sev], bg=BG_CARD, font=("Segoe UI", 10, "bold")
            ).grid(row=row, column=col_base, sticky="w", padx=(0, 4), pady=2)
            var = tk.StringVar(value="0")
            self.severity_vars[sev] = var
            tk.Label(
                results, textvariable=var, fg=FG, bg=BG_CARD,
                font=("Segoe UI", 10, "bold"), width=3, anchor="e",
            ).grid(row=row, column=col_base + 1, sticky="w", padx=(0, 4))
            tk.Label(results, text=sev.capitalize(), fg=FG_DIM, bg=BG_CARD).grid(
                row=row, column=col_base + 2, sticky="w"
            )
        self.gate_var = tk.StringVar(value="gate: —   ·   total: 0")
        tk.Label(
            results, textvariable=self.gate_var, fg=FG_DIM, bg=BG_CARD, font=("Segoe UI", 9)
        ).grid(row=3, column=0, columnspan=6, sticky="w", pady=(8, 0))

        # ---- right: console + progress ----
        right = ttk.Frame(body, style="Card.TFrame", padding=12)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        console_header = ttk.Frame(right, style="Card.TFrame")
        console_header.grid(row=0, column=0, sticky="ew")
        self.status_var = tk.StringVar(value="Listo.")
        ttk.Label(console_header, textvariable=self.status_var).pack(side="left")
        ttk.Label(console_header, text="salida en vivo", style="Dim.TLabel").pack(side="right")

        console = tk.Text(
            right,
            bg=BG_INPUT,
            fg=FG,
            insertbackground=FG,
            relief="flat",
            padx=10,
            pady=8,
            height=20,
            font=("Consolas", 9),
            state="disabled",
        )
        console.grid(row=1, column=0, sticky="nsew", pady=(8, 8))
        console.tag_configure("err", foreground=ERR)
        console.tag_configure("warn", foreground=WARN)
        console.tag_configure("ok", foreground=OK)
        console.tag_configure("dim", foreground=FG_DIM)
        self.console = console
        self._redirector._widget = console

        scrollbar = ttk.Scrollbar(right, command=console.yview)
        console.configure(yscrollcommand=scrollbar.set)
        # grid the scrollbar into the console's cell: place inside right
        scrollbar.grid(row=1, column=1, sticky="ns")

        self.progress = ttk.Progressbar(right, mode="indeterminate", style="Horizontal.TProgressbar")
        self.progress.grid(row=2, column=0, sticky="ew")

        footer = ttk.Frame(right, style="Card.TFrame")
        footer.grid(row=3, column=0, sticky="ew")
        self.open_report_btn = ttk.Button(
            footer, text="Abrir último informe HTML", command=self._open_latest_report
        )
        self.open_report_btn.pack(side="left")
        ttk.Label(footer, text="los informes se guardan en /reports", style="Dim.TLabel").pack(side="right")

        self._sync_hint()
        self._append("Bienvenido. Configura el objetivo a la izquierda y presiona “Iniciar auditoría”.\n", "dim")
        # Show the results of a previous run, if any, from the very start.
        self.set_results(latest_report_data(reports_dir_for(self._output_dir())))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _sync_hint(self) -> None:
        self.profile_hint.set(PROFILES.get(self.profile_var.get(), ""))
        self.status_var.set(ACTIONS.get(self.action_var.get(), ""))

    def _append(self, text: str, tag: str | None = None) -> None:
        self.console.configure(state="normal")
        self.console.insert("end", text, (tag,) if tag else ())
        self.console.see("end")
        self.console.configure(state="disabled")

    def _pick_target(self) -> None:
        chosen = filedialog.askdirectory(parent=self, title="Selecciona la carpeta del proyecto")
        if chosen:
            self.target_var.set(chosen)

    def _open_reports(self) -> None:
        reports_dir_for(self._output_dir()).mkdir(parents=True, exist_ok=True)
        webbrowser.open(reports_dir_for(self._output_dir()).as_uri())

    def _output_dir(self) -> str | None:
        return None  # default reports/; kept as a hook for future expansion

    def set_results(self, data: dict | None) -> None:
        """Populate the results panel from an audit_report.json payload."""
        counts = summarize_findings((data or {}).get("findings"))
        for sev, var in self.severity_vars.items():
            var.set(str(counts.get(sev, 0)))
        gate = (data or {}).get("quality_gate") or {}
        run_id = (data or {}).get("run_id", "")
        self.gate_var.set(
            f"gate: {gate.get('status') or '—'}   ·   total: {sum(counts.values())}"
            + (f"   ·   {run_id}" if run_id else "")
        )

    def _open_latest_report(self) -> None:
        base = reports_dir_for(self._output_dir())
        candidates = sorted(
            (p for p in base.glob("**/audit_report.html") if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            messagebox.showinfo("Sin informes aún", "Aún no hay informes. Ejecuta una auditoría primero.")
            return
        webbrowser.open(candidates[0].as_uri())

    # ------------------------------------------------------------------
    # Run / stop
    # ------------------------------------------------------------------
    def _start(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            messagebox.showwarning("En ejecución", "Ya hay una auditoría corriendo.")
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Falta el objetivo", "Escribe una carpeta o URL para auditar.")
            return
        if self.action_var.get() in ("run", "plan") and "\x00" in target:
            messagebox.showerror("Objetivo inválido", "El objetivo contiene caracteres inválidos.")
            return
        try:
            pages = int(self.pages_var.get()) if self.pages_var.get().strip() else None
            requests = int(self.requests_var.get()) if self.requests_var.get().strip() else None
        except ValueError:
            messagebox.showerror("Límites inválidos", "Páginas y requests deben ser números enteros.")
            return

        cmd = build_command(
            self.action_var.get(),
            target,
            self.profile_var.get(),
            headed=self.headed_var.get(),
            max_pages=pages,
            max_requests=requests,
            dry_run=self.dry_var.get(),
            allow_external=self.external_var.get(),
            python_exe=None,
        )
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
        self._append(" ".join(cmd) + "\n\n", "dim")
        self.status_var.set("Ejecutando…")
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.start(12)
        threading.Thread(target=self._worker, args=(cmd,), daemon=True).start()

    def _worker(self, cmd: list[str]) -> None:
        try:
            proc = subprocess.Popen(
        cmd,
        cwd=str(agent_cwd()),
        stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
        except Exception as exc:  # noqa: BLE001 — surfaced in the console, never a silent crash
            self._queue.put(f"[gui] no se pudo iniciar el proceso: {exc}")
            self._queue.put("__DONE__ 1")
            return
        self._proc = proc
        assert proc.stdout is not None
        for line in proc.stdout:
            self._queue.put(line.rstrip("\n"))
        code = proc.wait()
        self._queue.put(f"__DONE__ {code}")

    def _poll_queue(self) -> None:
        self._redirector.drain()
        try:
            while True:
                line = self._queue.get_nowait()
                if line.startswith("__DONE__"):
                    self._finish(int(line.split(maxsplit=1)[1]))
                else:
                    tag = None
                    lowered = line.lower()
                    if "error" in lowered or "traceback" in lowered or "crash" in lowered:
                        tag = "err"
                    elif "warning" in lowered or "interrupted" in lowered:
                        tag = "warn"
                    elif "quality gate: pass" in lowered or "run complete" in lowered:
                        tag = "ok"
                    self._append(line + "\n", tag)
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    def _finish(self, code: int) -> None:
        self.progress.stop()
        self.run_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self._proc = None
        # Refresh the results panel from the newest report on disk (best-effort:
        # an interrupted run may not have produced one).
        self.set_results(latest_report_data(reports_dir_for(self._output_dir())))
        if code == 0:
            self.status_var.set("Terminado — revisa el informe (botón abajo a la derecha).")
            self._append("\n✔ Auditoría completada con éxito.\n", "ok")
            if messagebox.askyesno("Informe listo", "La auditoría terminó. ¿Abrir el informe HTML?"):
                self._open_latest_report()
        elif code == 130:
            self.status_var.set("Interrumpido por el usuario.")
            self._append("\n■ Ejecución interrumpida (el manifiesto lo registra).\n", "warn")
        else:
            self.status_var.set(f"Terminó con código {code} — mira la consola.")
            self._append(f"\n✖ El proceso terminó con código {code}.\n", "err")

    def _stop(self) -> None:
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            self._append("\n[gui] deteniendo…\n", "warn")

    def _on_close(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            if not messagebox.askyesno(
                "Auditoría en curso", "Hay una auditoría ejecutándose. ¿Detenerla y salir?"
            ):
                return
            self._stop()
        self.destroy()


FROZEN = bool(getattr(sys, "frozen", False))


def agent_cwd() -> Path:
    """Where runs execute and where `reports/` is created.

    Frozen: the folder containing the .exe (portable — reports travel with
    the binary). Source: the project root. The GUI keeps the user inside
    that root: relative targets like `samples/demo_site` resolve against it,
    and the agent writes its reports under the same `reports/` the GUI reads.
    """
    if FROZEN:
        return Path(sys.executable).resolve().parent
    return ROOT


def agent_invocation() -> list[str]:
    """The argv prefix that runs the agent CLI.

    Frozen: the exe re-invokes ITSELF with the subcommand as argv (the GUI
    exe and the CLI entry point are the same binary — sys.argv[0] carries
    the user's exact path, spaces included).
    Source: `<python> main.py ...`.
    """
    if FROZEN:
        return [sys.argv[0]]
    return [sys.executable, str(MAIN_PY)]


SUBCOMMANDS = {"run", "plan", "discover", "report", "validate", "install-browsers"}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    # The windowed exe doubles as the headless runner: when the GUI re-invokes
    # itself (agent_invocation) the child must EXECUTE the subcommand, not open
    # a second window. Imported lazily so plain GUI launches stay fast.
    if args and args[0] in SUBCOMMANDS:
        from main import main as agent_main

        return agent_main(args)
    if not FROZEN and not MAIN_PY.exists():
        print(f"no se encontró {MAIN_PY}", file=sys.stderr)
        return 2
    try:
        import tkinter  # noqa: F401 — explicit guard for the launcher
    except ImportError:
        print("tkinter no está disponible en este Python", file=sys.stderr)
        return 2
    QAGui().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
