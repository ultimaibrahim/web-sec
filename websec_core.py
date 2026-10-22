#!/usr/bin/env python3
"""websec_core.py - Arquitectura Bento Grid Cyber-Deck para WebSec & Scraping.
Integra monitoreo en vivo de privacidad, escaneo de credenciales y auditoría de seguridad.
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Set, List, Dict, Any, Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import Header, Footer, Button, Select, Static, Input, Label
try:
    from textual.widgets import RichLog as TextLog
except ImportError:
    from textual.widgets import TextLog

from textual.screen import Screen
from textual.reactive import reactive
from rich.markup import escape
from rich.text import Text

# Módulos del proyecto
from level_handlers import level0, level1, level2, level3, void
from credential_scanner import scan_text
from privacy_guard import evaluate_privacy, PrivacyStatus

PROJECT_DIR = Path(__file__).parent.resolve()
WHITELIST_PATH = PROJECT_DIR / "allowed_targets.txt"

def load_whitelist() -> Set[str]:
    if WHITELIST_PATH.exists():
        return {line.strip() for line in WHITELIST_PATH.read_text().splitlines() if line.strip()}
    return set()

def save_whitelist(domains: Set[str]):
    WHITELIST_PATH.write_text("\n".join(sorted(domains)))


# -----------------------------------------------------------------------------
# Componentes TUI (Bento Modules)
# -----------------------------------------------------------------------------

class PrivacyMonitorWidget(Static):
    """Panel Bento: Monitor continuo de Privacidad y Evasión en tiempo real."""
    
    status_text = reactive("Iniciando auditoría de red...")

    def on_mount(self) -> None:
        self.update_stats()
        self.set_interval(6.0, self.update_stats)

    def update_stats(self) -> None:
        def _fetch():
            try:
                status = evaluate_privacy()
                self.app.call_from_thread(self._render_status, status)
            except Exception as e:
                self.app.call_from_thread(self._render_error, str(e))

        threading.Thread(target=_fetch, daemon=True).start()

    def _render_error(self, err: str):
        self.update(f"[bold red]❌ Error de sondeo:[/bold red] {err}")

    def _render_status(self, s: PrivacyStatus):
        score_color = "green" if s.score >= 80 else "yellow" if s.score >= 50 else "red"
        vpn_badge = "[bold green]● CONNECTED[/]" if s.vpn_active else "[bold red]○ DISCONNECTED[/]"
        dns_badge = "[bold green]SECURE (10.2.0.1)[/]" if s.dns_secure else f"[bold red]LEAK ({s.dns_server})[/]"
        ipv6_badge = "[bold green]BLOCKED (SAFE)[/]" if s.ipv6_blocked else "[bold red]LEAKING[/]"
        mac_badge = "[bold green]SPOOFED[/]" if s.mac_spoofed else "[bold red]FACTORY UNMASKED[/]"

        loc = f"{s.city}, {s.country}" if s.country else "Desconocida"
        isp = s.isp_org[:28] + "..." if len(s.isp_org) > 28 else s.isp_org

        content = f"""[bold cyan]─── 🛡️ COVERT SHIELD / PRIVACY ───[/]
[bold {score_color}]PRIVACY SCORE: {s.score}/100[/] [{score_color}][{s.threat_level}][/]

[dim]VPN TUNNEL:[/]    {vpn_badge} [dim]({s.vpn_interface})[/]
[dim]DNS ROUTE:[/]     {dns_badge}
[dim]IPV6 LEAK:[/]     {ipv6_badge}
[dim]MAC IDENTITY:[/] {mac_badge} [dim]{s.current_mac}[/]
[dim]PUBLIC WAN:[/]    [bold white]{s.public_ip}[/]
[dim]ISP / ORG:[/]     [yellow]{isp}[/]
[dim]LOCATION:[/]      [cyan]{loc}[/]
"""
        self.update(content)


class TargetVaultWidget(Static):
    """Panel Bento: Whitelist de Objetivos y Credential Scanner Hits."""
    
    def update_content(self, targets: Set[str], hits_count: int, last_hit: str = ""):
        target_lines = "\n".join([f"  [cyan]›[/] [white]{t}[/]" for t in sorted(targets)]) if targets else "  [dim](Sin objetivos definidos)[/]"
        
        hit_preview = f"[bold green]Último Hallazgo:[/] {last_hit}" if last_hit else "[dim]No hay tokens filtrados aún[/]"

        body = f"""[bold cyan]─── 🎯 TARGET MATRIX ───[/]
[bold white]Whitelisted Targets ({len(targets)}):[/]
{target_lines}

[bold cyan]─── 🔑 CREDENTIAL VAULT ───[/]
[bold yellow]Detecciones Totales:[/] [bold white]{hits_count}[/]
{hit_preview}
"""
        self.update(body)


# -----------------------------------------------------------------------------
# Aplicación Principal
# -----------------------------------------------------------------------------

class WebSecApp(App):
    CSS_PATH = "websec.css"
    BINDINGS = [
        ("s", "start_audit", "Start Audit"),
        ("w", "edit_whitelist", "Edit Targets"),
        ("p", "refresh_privacy", "Refresh Shield"),
        ("e", "export", "Export JSON"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.mode = "WebSec"
        self.level = "0"
        self.targets: Set[str] = load_whitelist()
        self.results: List[Dict[str, Any]] = []
        self.total_tokens_found = 0
        self.last_token_snippet = ""
        
        self.log_widget: TextLog = TextLog(highlight=True)
        self.privacy_widget = PrivacyMonitorWidget(id="bento-privacy")
        self.vault_widget = TargetVaultWidget(id="bento-vault")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        # Grid Principal Bento
        with Grid(id="main-bento-grid"):
            # Columna Lateral Izquierda (Shield de Privacidad)
            with Vertical(id="left-column"):
                yield self.privacy_widget
                with Container(id="audit-config-card"):
                    yield Static("[bold cyan]─── ⚙️ AUDIT ENGINE ───[/]")
                    yield Select(
                        options=[("Modo: WebSec (Auditoría)", "WebSec"), ("Modo: WebScrap (Extracción)", "WebScrap")],
                        prompt="Seleccionar Modo",
                        value=self.mode,
                        id="mode_select",
                    )
                    yield Select(
                        options=[
                            ("0 · Reconocimiento Pasivo", "0"),
                            ("1 · Auditoría Activa Leve", "1"),
                            ("2 · Fuzzing Controlado", "2"),
                            ("3 · Prueba Destructiva (Lab)", "3"),
                            ("void() · Caos Masivo (Lab)", "void"),
                        ],
                        prompt="Seleccionar Nivel",
                        value=self.level,
                        id="level_select",
                    )
                    with Horizontal(id="action-buttons-row"):
                        yield Button("▶ INICIAR", id="start_btn", variant="success")
                        yield Button("🎯 OBJETIVOS", id="edit_whitelist_btn", variant="primary")

            # Columna Central (Live Operations & Matrix Stream)
            with Vertical(id="center-column"):
                yield Static("[bold cyan]─── 📟 LIVE OPERATIONS STREAM ───[/]", id="stream-header")
                yield self.log_widget

            # Columna Derecha (Target Radar & Vault)
            with Vertical(id="right-column"):
                yield self.vault_widget

        yield Footer()

    def on_mount(self) -> None:
        self.title = "WEB-SEC // CYBER-DECK v2.4"
        self.sub_title = "COVERT SECURITY & EXTRACTION PLATFORM"
        self.log_widget.write(f"[bold green]▶ Sistema inicializado a las {datetime.now().strftime('%H:%M:%S')}[/]")
        self.log_widget.write("[dim]Presiona [S] para Iniciar, [W] para Targets, [P] para Shield, [Q] para Salir.[/]")
        self.refresh_vault_ui()

    def refresh_vault_ui(self):
        self.vault_widget.update_content(
            self.targets,
            self.total_tokens_found,
            self.last_token_snippet
        )

    def action_refresh_privacy(self):
        self.log_widget.write("[cyan]ℹ Actualizando telemetría de privacidad y evasión...[/]")
        self.privacy_widget.update_stats()

    def action_edit_whitelist(self):
        self.push_screen(WhitelistScreen(self.targets))

    def action_start_audit(self):
        self.start_audit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "edit_whitelist_btn":
            self.push_screen(WhitelistScreen(self.targets))
        elif event.button.id == "start_btn":
            self.start_audit()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "mode_select":
            self.mode = event.value
            self.log_widget.write(f"[yellow]⚙ Modo cambiado a:[/] [bold white]{self.mode}[/]")
        elif event.select.id == "level_select":
            self.level = event.value
            risk_color = "red" if self.level in ["3", "void"] else "cyan"
            self.log_widget.write(f"[yellow]⚙ Nivel de auditoría ajustado a:[/] [{risk_color}]Nivel {self.level}[/]")

    def log_scanner_hook(self, message: str):
        """Intercepta logs para escanear credenciales en vivo en cada salida."""
        self.log_widget.write(message)
        hits = scan_text(message)
        if hits:
            for c_type, items in hits.items():
                self.total_tokens_found += len(items)
                self.last_token_snippet = f"[{c_type}] {items[0][:16]}..."
                self.log_widget.write(f"[bold red]🔥 ALERTA CREDENCIAL:[/] {c_type} detectado: {escape(items[0][:24])}...")
            self.refresh_vault_ui()

    def start_audit(self):
        if not self.targets:
            self.log_widget.write("[bold red]❌ La lista de objetivos está vacía. Presiona 'OBJETIVOS' para agregar.[/]")
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
                self.log_widget.write("[yellow]⚠️ Operación destructiva cancelada por el operador.[/]")
        
        self.push_screen(ConfirmScreen(
            title="ACCION DE ALTO RIESGO",
            message=f"Has seleccionado Nivel {self.level}. Esta fase realiza mutaciones agresivas en el destino.\n¿Deseas continuar?",
            callback=_callback,
        ))

    def confirm_void(self):
        def _final_cb(txt: str):
            if txt.strip().upper() == "CONFIRM":
                threading.Thread(target=self._run_audit_pipeline, daemon=True).start()
            else:
                self.log_widget.write("[bold red]❌ Token de confirmación incorrecto. Abortando void().[/]")

        self.push_screen(InputScreen(
            title="CONFIRMACIÓN CRÍTICA void()",
            prompt="Escribe 'CONFIRM' para autorizar el ataque destructivo:",
            callback=_final_cb
        ))

    def _run_audit_pipeline(self):
        self.app.call_from_thread(self.log_widget.write, f"\n[bold magenta]══════ INICIANDO MISIÓN [{self.mode} // NIVEL {self.level}] ══════[/]")
        
        handler_map = {
            "0": level0.run,
            "1": level1.run,
            "2": level2.run,
            "3": level3.run,
            "void": void.run,
        }
        handler = handler_map.get(self.level)
        if not handler:
            self.app.call_from_thread(self.log_widget.write, f"[red]Sin controlador para el nivel {self.level}[/]")
            return

        # Adaptador para el logger de handlers
        class InterceptLogger:
            def __init__(self, outer):
                self.outer = outer
            def write(self, msg):
                self.outer.app.call_from_thread(self.outer.log_scanner_hook, msg)

        custom_logger = InterceptLogger(self)

        for target in list(self.targets):
            self.app.call_from_thread(self.log_widget.write, f"[bold cyan]🔍 Conectando con objetivo:[/] [white underline]{target}[/]")
            try:
                result = handler(target, self.mode, custom_logger)
                self.results.append({"timestamp": time.time(), "target": target, "result": result})
            except Exception as exc:
                self.app.call_from_thread(self.log_widget.write, f"[bold red]❌ Error ejecutando en {target}:[/] {exc}")

        self.app.call_from_thread(self.log_widget.write, f"[bold green]✔ Ciclo completado contra {len(self.targets)} objetivo(s).[/]\n")

    def action_export(self):
        if not self.results:
            self.log_widget.write("[yellow]No hay resultados registrados para exportar.[/]")
            return
        out_path = PROJECT_DIR / "outputs"
        out_path.mkdir(exist_ok=True)
        out_file = out_path / f"audit_{int(time.time())}.json"
        out_file.write_text(json.dumps(self.results, indent=2))
        self.log_widget.write(f"[bold green]✔ Resultados exportados a:[/] [white]{out_file}[/]")


# -----------------------------------------------------------------------------
# Modales y Subpantallas
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
            yield Static(f"[bold red]⚠️ {self.dialog_title}[/]", id="dialog-header")
            yield Label(self.message, id="dialog-body")
            with Horizontal(id="dialog-buttons"):
                yield Button("CONFIRMAR", id="yes", variant="error")
                yield Button("CANCELAR", id="no", variant="default")

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
            yield Static(f"[bold magenta]⚡ {self.dialog_title}[/]", id="dialog-header")
            yield Label(self.prompt, id="dialog-body")
            yield Input(placeholder="Escribe CONFIRM...", id="dialog-input")
            with Horizontal(id="dialog-buttons"):
                yield Button("AUTORIZAR", id="submit", variant="error")
                yield Button("CANCELAR", id="cancel", variant="default")

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
            yield Static("[bold cyan]🎯 CONFIGURAR OBJETIVOS PERMITIDOS (WHITELIST)[/]", id="dialog-header")
            yield Label("Ingresa un dominio o IP por línea (ej: demo.testfire.net o 127.0.0.1):")
            txt = "\n".join(sorted(self.current))
            yield Input(value=txt, id="whitelist-input")
            with Horizontal(id="dialog-buttons"):
                yield Button("GUARDAR CAMBIOS", id="save", variant="success")
                yield Button("DESCARTAR", id="cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            txt = self.query_one(Input).value
            new_set = {line.strip() for line in txt.split() if line.strip()}
            save_whitelist(new_set)
            self.app.targets = new_set
            self.app.refresh_vault_ui()
            self.app.log_widget.write(f"[bold green]✔ Whitelist actualizada:[/] {len(new_set)} objetivos en memoria.")
        self.app.pop_screen()


if __name__ == "__main__":
    WebSecApp().run()
