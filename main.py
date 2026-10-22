#!/usr/bin/env python3
"""websec_core.py - TUI Ultra-Compacta estilo btop / hollywood.
Alta densidad de datos, telemetría continua de red, sparklines de actividad y streaming hacker.
"""

import os
import sys
import json
import time
import random
import threading
from datetime import datetime
from pathlib import Path
from typing import Set, List, Dict, Any, Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import Static, Input, Button, Label
try:
    from textual.widgets import RichLog as TextLog
except ImportError:
    from textual.widgets import TextLog

from textual.screen import Screen
from textual.reactive import reactive
from rich.markup import escape

from browser_client import fetch, set_browser_mode
from level_handlers import recon
from level_handlers import level0, level1, level2, level3, void, recon
from credential_scanner import scan_text
from privacy_guard import evaluate_privacy, PrivacyStatus

PROJECT_DIR = Path(__file__).parent.resolve()
WHITELIST_PATH = PROJECT_DIR / "allowed_targets.txt"

SPARK_CHARS = " ▂▃▄▅▆▇█"

def load_whitelist() -> Set[str]:
    if WHITELIST_PATH.exists():
        return {line.strip() for line in WHITELIST_PATH.read_text().splitlines() if line.strip()}
    return set()

def save_whitelist(domains: Set[str]):
    WHITELIST_PATH.write_text("\n".join(sorted(domains)))


# -----------------------------------------------------------------------------
# Micro Widgets de Alta Densidad
# -----------------------------------------------------------------------------

class MicroShieldWidget(Static):
    """Panel btop-style: Shield y Privacidad en tiempo real."""

    def on_mount(self) -> None:
        self.update_content(None)
        self.poll_privacy()
        self.set_interval(5.0, self.poll_privacy)

    def poll_privacy(self) -> None:
        def _bg():
            try:
                st = evaluate_privacy()
                self.app.call_from_thread(self.update_content, st)
            except Exception:
                pass
        threading.Thread(target=_bg, daemon=True).start()

    def update_content(self, s: Optional[PrivacyStatus]) -> None:
        if not s:
            self.update("[dim]Escaneando interfaces...[/]")
            return

        score_col = "green" if s.score >= 80 else "yellow" if s.score >= 50 else "red"
        vpn_txt = "[bold green]TUNNEL ON[/]" if s.vpn_active else "[bold red]NO TUNNEL[/]"
        dns_txt = "[green]10.2.0.1[/]" if s.dns_secure else f"[bold red]LEAK {s.dns_server[:10]}[/]"
        ipv6_txt = "[green]BLOCKED[/]" if s.ipv6_blocked else "[bold red]EXPOSED[/]"
        mac_txt = "[green]SPOOFED[/]" if s.mac_spoofed else "[red]FACTORY[/]"

        txt = (
            f" [bold {score_col}]PRIV-SCORE: {s.score}%[/] [dim]({s.threat_level[:9]})[/]\n"
            f" [dim]VPN:[/]  {vpn_txt} [dim]{s.vpn_interface}[/]\n"
            f" [dim]DNS:[/]  {dns_txt}\n"
            f" [dim]IPV6:[/] {ipv6_txt}\n"
            f" [dim]MAC:[/]  {mac_txt}\n"
            f" [dim]WAN:[/]  [white]{s.public_ip}[/]\n"
            f" [dim]ISP:[/]  [yellow]{s.isp_org[:14]}[/]\n"
            f" [dim]LOC:[/]  [cyan]{s.city[:10]}, {s.country[:3]}[/]"
        )
        self.update(txt)


class MicroTelemetryWidget(Static):
    """Panel de Telemetría btop con micro-gráficos sparkline."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.net_history = [random.randint(0, 3) for _ in range(22)]
        self.req_history = [random.randint(0, 2) for _ in range(22)]
        self.bytes_sent = 1024
        self.requests_count = 0

    def on_mount(self) -> None:
        self.set_interval(1.0, self.tick)

    def tick(self) -> None:
        # Generar micro-actividad
        delta_net = random.randint(0, 7) if self.app.is_auditing else random.randint(0, 2)
        delta_req = random.randint(1, 7) if self.app.is_auditing else 0
        
        self.net_history.pop(0)
        self.net_history.append(delta_net)
        self.req_history.pop(0)
        self.req_history.append(delta_req)

        self.bytes_sent += delta_net * 128
        self.requests_count += delta_req

        net_spark = "".join(SPARK_CHARS[v] for v in self.net_history)
        req_spark = "".join(SPARK_CHARS[v] for v in self.req_history)

        state_tag = "[bold green]LIVE PUMP[/]" if self.app.is_auditing else "[dim]IDLE[/]"

        txt = (
            f" [dim]STATE:[/] {state_tag}\n"
            f" [dim]NET-IO:[/] [cyan]{net_spark}[/]\n"
            f" [dim]FLOW:[/]   {self.bytes_sent // 1024} KB [dim]sent[/]\n"
            f" [dim]AUD-IO:[/] [magenta]{req_spark}[/]\n"
            f" [dim]HITS:[/]   {self.requests_count} reqs\n"
            f" [dim]CPU-T:[/]  {random.randint(41, 46)}°C [dim]clk 2.8G[/]\n"
            f" [dim]MEM:[/]    {random.randint(22, 28)}% [dim]heap 12M[/]"
        )
        self.update(txt)


class MicroTargetWidget(Static):
    """Panel de Targets y Vault btop-style."""

    def refresh_data(self, targets: Set[str], token_count: int, last_hit: str = ""):
        lines = []
        for t in sorted(targets)[:4]:
            lines.append(f" [cyan]›[/] [white]{t[:20]}[/]")
        if len(targets) > 4:
            lines.append(f" [dim]+{len(targets) - 4} more targets[/]")
        elif not targets:
            lines.append(" [dim](No targets)[/]")

        target_block = "\n".join(lines)
        token_txt = f"[bold yellow]{token_count} TOKENS[/]" if token_count else "[dim]0 tokens[/]"
        hit_txt = f"[green]{last_hit[:20]}[/]" if last_hit else "[dim]clean memory[/]"

        txt = (
            f" [bold white]TARGETS ({len(targets)}):[/]\n"
            f"{target_block}\n\n"
            f" [bold white]CREDS VAULT:[/] {token_txt}\n"
            f" [dim]LAST:[/] {hit_txt}"
        )
        self.update(txt)


class MicroControlWidget(Static):
    """Panel de Control btop-style: muestra modo y nivel activos."""

    def refresh_display(self, mode: str, level: str, browser: bool = False):
        level_names = {
            "0": "0·Passive",
            "1": "1·Active",
            "2": "2·Fuzzing",
            "3": "3·Destruct",
            "void": "void()·Chaos",
        }
        lvl_str = level_names.get(level, level)
        lvl_color = "red" if level in ["3", "void"] else "yellow" if level == "2" else "cyan"
        browser_txt = "[magenta]BROWSER ON[/]" if browser else "[dim]browser off[/]"
        txt = (
            f" [dim]MODE:[/]  [bold white]{mode}[/]\n"
            f" [dim]LEVEL:[/] [bold {lvl_color}]{lvl_str}[/]\n"
            f" [dim]BROWSER:[/] {browser_txt}\n"
            f" [dim]SAFETY:[/] [green]GUARD ON[/]\n"
            f" [dim]WHITELIST:[/] [white]ENFORCED[/]\n\n"
            f" [dim]Keys:[/] [bold cyan][M][/]ode [bold cyan][L][/]evel"
            f"       [bold green][SPACE][/] START"
        )
        self.update(txt)
        level_names = {
            "0": "0·Passive",
            "1": "1·Active",
            "2": "2·Fuzzing",
            "3": "3·Destruct",
            "void": "void()·Chaos"
        }
        lvl_str = level_names.get(level, level)
        lvl_color = "red" if level in ["3", "void"] else "yellow" if level == "2" else "cyan"

        txt = (
            f" [dim]MODE:[/]  [bold white]{mode}[/]\n"
            f" [dim]LEVEL:[/] [bold {lvl_color}]{lvl_str}[/]\n"
            f" [dim]SAFETY:[/] [green]GUARD ON[/]\n"
            f" [dim]WHITELIST:[/] [white]ENFORCED[/]\n\n"
            f" [dim]Keys:[/] [bold cyan][M][/]ode [bold cyan][L][/]evel\n"
            f"       [bold green][SPACE][/] START"
        )
        self.update(txt)


# -----------------------------------------------------------------------------
# Aplicación TUI Nano/btop
# -----------------------------------------------------------------------------

class WebSecApp(App):
    CSS_PATH = "websec.css"
    BINDINGS = [
        ("space", "start_audit", "Start"),
        ("m", "toggle_mode", "Mode"),
        ("l", "cycle_level", "Level"),
        ("t", "edit_whitelist", "Targets"),
        ("p", "refresh_privacy", "Shield"),
        ("e", "export", "Export"),
        ("c", "clear_log", "Clear"),
        ("b", "toggle_browser", "Browser"),
        ("q", "quit", "Quit"),
    ]
    CSS_PATH = "websec.css"
    BINDINGS = [
        ("space", "start_audit", "Start"),
        ("m", "toggle_mode", "Mode"),
        ("l", "cycle_level", "Level"),
        ("t", "edit_whitelist", "Targets"),
        ("p", "refresh_privacy", "Shield"),
        ("e", "export", "Export"),
        ("c", "clear_log", "Clear"),
        ("q", "quit", "Quit"),
        # Recon shortcuts
        ("s", "action_scan_ports", "Port Scan"),
        ("f", "action_fingerprint", "Fingerprint"),
        ("g", "action_subdomains", "Sub‑domains"),
        ("h", "action_toggle_stealth", "Stealth/Ghost"),
    ]

    def __init__(self):
        super().__init__()
        self.mode = "WebSec"
        self.level = "0"
        self.targets: Set[str] = load_whitelist()
        self.results: List[Dict[str, Any]] = []
        self.total_tokens_found = 0
        self.last_token_snippet = ""
        self.use_browser = False  # Flag to route requests via Playwright
        # Recon feature flags
        self.recon_flags = {
            "scan_ports": False,
            "fingerprint": False,
            "subdomains": False,
            "stealth": False,
        }


        self.shield_widget = MicroShieldWidget(id="shield-content")
        self.telemetry_widget = MicroTelemetryWidget(id="telemetry-content")
        self.target_widget = MicroTargetWidget(id="targets-content")
        self.control_widget = MicroControlWidget(id="controls-content")
        self.log_widget: TextLog = TextLog(highlight=True)

    def compose(self) -> ComposeResult:
        # Micro Header tipo btop / htop
        with Horizontal(id="micro-header-bar"):
            yield Static("⚡ WEB-SEC // CYBER-DECK [NANO]", id="brand-title")
            yield Static("UTC: 00:00 | HOST: linux-box | MEM: 4.2G", id="header-stats")

        # Grid Ultra-Compacto
        with Grid(id="micro-grid"):
            # Box 1: Shield / Privacidad
            with Vertical(id="box-shield", classes="nano-box"):
                yield Static("■ 1. PRIVACY SHIELD", classes="nano-header")
                yield self.shield_widget

            # Box 2: Telemetría / Hollywood sparklines
            with Vertical(id="box-telemetry", classes="nano-box"):
                yield Static("■ 2. NETWORK TELEMETRY", classes="nano-header")
                yield self.telemetry_widget

            # Box 3: Controles / Motor
            with Vertical(id="box-controls", classes="nano-box"):
                yield Static("■ 3. AUDIT ENGINE", classes="nano-header")
                yield self.control_widget

            # Box 4 (Ancho): Live Stream Matrix / Hacker logs
            with Vertical(id="box-stream", classes="nano-box"):
                yield Static("■ LIVE OPS STREAM (hollywood)", classes="nano-header")
                yield self.log_widget

            # Box 5: Targets & Vault
            with Vertical(id="box-targets", classes="nano-box"):
                yield Static("■ 4. TARGETS & VAULT", classes="nano-header")
                yield self.target_widget

        # Micro Footer de Teclas Rápidas tipo btop
        with Horizontal(id="micro-footer-bar"):
            yield Static(" [SPACE] ", classes="key-badge")
            yield Static("Start", classes="key-desc")
            yield Static(" [M] ", classes="key-badge")
            yield Static("Mode", classes="key-desc")
            yield Static(" [L] ", classes="key-badge")
            yield Static("Level", classes="key-desc")
            yield Static(" [T] ", classes="key-badge")
            yield Static("Targets", classes="key-desc")
            yield Static(" [P] ", classes="key-badge")
            yield Static("Shield", classes="key-desc")
            yield Static(" [E] ", classes="key-badge")
            yield Static("Export", classes="key-desc")
            yield Static(" [C] ", classes="key-badge")
            yield Static("Clear", classes="key-desc")
            yield Static(" [Q] ", classes="key-badge")
            yield Static("Quit", classes="key-desc")

    def on_mount(self) -> None:
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser)
        self.target_widget.refresh_data(self.targets, self.total_tokens_found, self.last_token_snippet)
        self.set_interval(1.0, self.update_top_bar)
        
        # Hollywood style init logs
        self.log_widget.write("[bold cyan]>>> KERNEL INITIALIZED: AUDIT ENGINE READY[/]")
        self.log_widget.write("[dim]Subsystems: net_mon=UP, bento_bus=OK, cert_scanner=ARMED[/]")
        self.log_widget.write("[dim]Press [SPACE] to launch mission against whitelisted scope.[/]")

    def update_top_bar(self) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        self.query_one("#header-stats", Static).update(f"LOCAL: {now} | SCOPE: {len(self.targets)} hosts | BUS: READY")

    def action_toggle_mode(self) -> None:
        self.mode = "WebScrap" if self.mode == "WebSec" else "WebSec"
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser)
        self.log_widget.write(f"[dim]» Mode switched to:[/] [bold cyan]{self.mode}[/]")

    # ---------- Recon shortcut actions ----------
    def action_scan_ports(self) -> None:
        """Toggle port scan flag and start audit if not already running."""
        self.recon_flags["scan_ports"] = not self.recon_flags["scan_ports"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser)
        self.log_widget.write(f"[dim]» Port Scan flag set to:[/] {self.recon_flags['scan_ports']}" )
        if not self.is_auditing:
            self.action_start_audit()

    def action_fingerprint(self) -> None:
        """Toggle fingerprint flag and start audit if idle."""
        self.recon_flags["fingerprint"] = not self.recon_flags["fingerprint"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser)
        self.log_widget.write(f"[dim]» Fingerprint flag set to:[/] {self.recon_flags['fingerprint']}")
        if not self.is_auditing:
            self.action_start_audit()

    def action_subdomains(self) -> None:
        """Toggle sub‑domains enumeration flag and start audit if idle."""
        self.recon_flags["subdomains"] = not self.recon_flags["subdomains"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser)
        self.log_widget.write(f"[dim]» Sub‑domains flag set to:[/] {self.recon_flags['subdomains']}")
        if not self.is_auditing:
            self.action_start_audit()

    def action_toggle_stealth(self) -> None:
        """Toggle stealth/ghost mode for all recon actions."""
        self.recon_flags["stealth"] = not self.recon_flags["stealth"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser)
        self.log_widget.write(f"[dim]» Stealth mode set to:[/] {self.recon_flags['stealth']}")
        # No immediate audit start; stealth only affects subsequent runs.

    def action_cycle_level(self) -> None:
        levels = ["0", "1", "2", "3", "void"]
        idx = (levels.index(self.level) + 1) % len(levels)
        self.level = levels[idx]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser)
        risk = "[red]HIGH RISK[/]" if self.level in ["3", "void"] else "[green]SAFE[/]"
        self.log_widget.write(f"[dim]» Level cycled to:[/] [bold yellow]Level {self.level}[/] ({risk})")

    def action_clear_log(self) -> None:
        self.log_widget.clear()

    def action_refresh_privacy(self) -> None:
        self.shield_widget.poll_privacy()
        self.log_widget.write("[dim]» Shield probe dispatched.[/]")

    def action_edit_whitelist(self) -> None:
        self.push_screen(WhitelistScreen(self.targets))

    def action_start_audit(self) -> None:
        if self.is_auditing:
            self.log_widget.write("[yellow]⚠️ Auditoría en curso, espera que finalice el ciclo.[/]")
            return

        if not self.targets:
            self.log_widget.write("[bold red]❌ Sin objetivos definidos. Presiona [T] para agregar.[/]")
            return

        if self.level in {"3", "void"}:
            self.confirm_destructive()
        else:
            threading.Thread(target=self._run_audit_pipeline, daemon=True).start()

    def confirm_destructive(self):
        def _callback(answer: bool):
            if answer:
                if self.level == "void":
                    self.confirm_void()
                else:
                    threading.Thread(target=self._run_audit_pipeline, daemon=True).start()
            else:
                self.log_widget.write("[yellow]⚠️ Misión destructiva cancelada.[/]")
        
        self.push_screen(ConfirmScreen(
            title="CONFIRMAR ATAQUE",
            message=f"Nivel {self.level} activo. Mutará datos remotos.\n¿Autorizar?",
            callback=_callback,
        ))

    def confirm_void(self):
        def _final_cb(txt: str):
            if txt.strip().upper() == "CONFIRM":
                threading.Thread(target=self._run_audit_pipeline, daemon=True).start()
            else:
                self.log_widget.write("[bold red]❌ Token erróneo. Abortando void().[/]")

        self.push_screen(InputScreen(
            title="OVERRIDE void()",
            prompt="Escribe 'CONFIRM' para disparar el caos:",
            callback=_final_cb
        ))

    def log_scanner_hook(self, message: str):
        self.log_widget.write(message)
        hits = scan_text(message)
        if hits:
            for c_type, items in hits.items():
                self.total_tokens_found += len(items)
                self.last_token_snippet = f"[{c_type}] {items[0][:12]}"
                self.log_widget.write(f"[bold red]⚡ TOKEN LEAK:[/] {c_type} -> {escape(items[0][:20])}...")
            self.target_widget.refresh_data(self.targets, self.total_tokens_found, self.last_token_snippet)

    def _run_audit_pipeline(self):
        self.is_auditing = True
        self.app.call_from_thread(self.log_widget.write, f"[bold magenta]▶ DISPATCH MISSION [{self.mode} // LVL {self.level}][/]")
        
        handler_map = {
            "0": level0.run,
            "1": level1.run,
            "2": level2.run,
            "3": level3.run,
            "void": void.run,
            "recon": recon.run,
        }
        handler = handler_map.get(self.level)
        if not handler:
            self.use_browser = False  # Flag to route requests via Playwright
            return
        handler = handler_map.get(self.level)
        if not handler:
            self.use_browser = False  # Flag to route requests via Playwright

            return

        class InterceptLogger:
            def __init__(self, outer):
                self.outer = outer
            def write(self, msg):
                self.outer.app.call_from_thread(self.outer.log_scanner_hook, msg)

        custom_logger = InterceptLogger(self)

        for target in list(self.targets):
            self.app.call_from_thread(self.log_widget.write, f"[cyan]› Probing host:[/] [white]{target}[/]")
            try:
                result = handler(target, self.mode, custom_logger)
                self.results.append({"timestamp": time.time(), "target": target, "result": result})
            except Exception as exc:
                self.app.call_from_thread(self.log_widget.write, f"[bold red]! Error on {target}:[/] {exc}")

        self.app.call_from_thread(self.log_widget.write, f"[bold green]✔ Misión concluida contra {len(self.targets)} hosts.[/]")
        self.use_browser = False  # Flag to route requests via Playwright


    def action_export(self):
        if not self.results:
            self.log_widget.write("[yellow]! Sin resultados para volcar.[/]")
            return
        out_path = PROJECT_DIR / "outputs"
        out_path.mkdir(exist_ok=True)
        out_file = out_path / f"audit_{int(time.time())}.json"
        out_file.write_text(json.dumps(self.results, indent=2))
        self.log_widget.write(f"[bold green]✔ Exportado ->[/] {out_file.name}")


# -----------------------------------------------------------------------------
# Modales Compactos
# -----------------------------------------------------------------------------

class ConfirmScreen(Screen):
    BINDINGS = [("y", "yes", "Yes"), ("n", "no", "No"), ("escape", "no", "Cancel")]
    def __init__(self, title: str, message: str, callback):
        super().__init__()
        self.dialog_title = title
        self.message = message
        self.callback = callback

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog-box"):
            yield Static(f"⚠️ {self.dialog_title}", id="dialog-header")
            yield Label(self.message, id="dialog-body")
            with Horizontal(id="dialog-buttons"):
                yield Button("SÍ", id="yes", variant="error")
                yield Button("NO", id="no", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.callback(event.button.id == "yes")
        self.app.pop_screen()

    def action_yes(self):
        self.callback(True)
        self.app.pop_screen()

    def action_no(self):
        self.callback(False)
        self.app.pop_screen()


class InputScreen(Screen):
    def __init__(self, title: str, prompt: str, callback):
        super().__init__()
        self.dialog_title = title
        self.prompt = prompt
        self.callback = callback

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog-box"):
            yield Static(f"⚡ {self.dialog_title}", id="dialog-header")
            yield Label(self.prompt, id="dialog-body")
            yield Input(placeholder="CONFIRM", id="dialog-input")
            with Horizontal(id="dialog-buttons"):
                yield Button("OK", id="submit", variant="error")
                yield Button("CANCEL", id="cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            txt = self.query_one(Input).value
            self.callback(txt)
        self.app.pop_screen()


class WhitelistScreen(Screen):
    def __init__(self, current: Set[str]):
        super().__init__()
        self.current = set(current)

    def compose(self) -> ComposeResult:
        with Vertical(id="whitelist-dialog"):
            yield Static("🎯 TARGET SCOPE (WHITELIST)", id="dialog-header")
            yield Label("Hosts separados por espacio o línea:")
            txt = " ".join(sorted(self.current))
            yield Input(value=txt, id="whitelist-input")
            with Horizontal(id="dialog-buttons"):
                yield Button("GUARDAR", id="save", variant="success")
                yield Button("SALIR", id="cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            txt = self.query_one(Input).value
            new_set = {line.strip() for line in txt.split() if line.strip()}
            save_whitelist(new_set)
            self.app.targets = new_set
            self.app.target_widget.refresh_data(self.app.targets, self.app.total_tokens_found, self.app.last_token_snippet)
            self.app.log_widget.write(f"[dim]» Scope ajustado a {len(new_set)} hosts.[/]")
        self.app.pop_screen()


if __name__ == "__main__":
    WebSecApp().run()
