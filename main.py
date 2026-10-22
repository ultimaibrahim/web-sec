#!/usr/bin/env python3
"""websec_core.py - TUI Ultra-Compacta estilo btop / hollywood.
Alta densidad de datos, telemetría continua de red, sparklines de actividad y streaming hacker.
Diseño Crystal & Squircle, arquitectura por capas, cero código destructivo accidental.
"""

import json
import os
import random
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.containers import Container, Grid, Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Static

try:
    from textual.widgets import RichLog as TextLog
except ImportError:
    from textual.widgets import TextLog

from browser_client import fetch, set_browser_mode
from credential_scanner import scan_text
from level_handlers import level0, level1, level2, level3, recon, void, void_plus
from privacy_guard import PrivacyStatus, evaluate_privacy
import storage_vault

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
# Micro Widgets de Alta Densidad (Crystal & Squircle Architecture)
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
        delta_net = random.randint(0, 7) if getattr(self.app, "is_auditing", False) else random.randint(0, 2)
        delta_req = random.randint(1, 7) if getattr(self.app, "is_auditing", False) else 0

        self.net_history.pop(0)
        self.net_history.append(delta_net)
        self.req_history.pop(0)
        self.req_history.append(delta_req)

        self.bytes_sent += delta_net * 128
        self.requests_count += delta_req

        net_spark = "".join(SPARK_CHARS[v] for v in self.net_history)
        req_spark = "".join(SPARK_CHARS[v] for v in self.req_history)

        state_tag = "[bold green]LIVE PUMP[/]" if getattr(self.app, "is_auditing", False) else "[dim]IDLE[/]"

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
    """Panel de Control btop-style: muestra modo, nivel y banderas de Recon."""

    def refresh_display(
        self,
        mode: str,
        level: str,
        browser: bool = False,
        recon_flags: Optional[Dict[str, bool]] = None,
    ):
        level_names = {
            "0": "0·Passive",
            "1": "1·Active",
            "2": "2·Fuzzing",
            "3": "3·Destruct",
            "recon": "Recon·Intel",
            "void": "void()·Chaos",
            "void_plus": "void+·Extreme",
        }
        lvl_str = level_names.get(level, level)
        lvl_color = "red" if level in ["3", "void", "void_plus"] else "yellow" if level == "2" else "cyan"
        browser_txt = "[magenta]BROWSER ON[/]" if browser else "[dim]browser off[/]"

        # Format RECON indicators
        flags = recon_flags or {}
        p_tag = "[bold green]p[/]" if flags.get("scan_ports") else "[dim]p[/]"
        m_tag = "[bold green]m[/]" if flags.get("subdomains") else "[dim]m[/]"
        d_tag = "[bold green]d[/]" if flags.get("deep_crawl") else "[dim]d[/]"
        F_tag = "[bold green]F[/]" if flags.get("fingerprint") else "[dim]F[/]"
        D_tag = "[bold green]D[/]" if flags.get("dump_db") else "[dim]D[/]"
        s_tag = "[bold green]s[/]" if flags.get("stealth") else "[dim]s[/]"
        P_tag = "[bold green]P[/]" if flags.get("proxy_tor") else "[dim]P[/]"
        v_tag = "[bold green]v[/]" if flags.get("vault_store", True) else "[dim]v[/]"
        r_tag = "[bold green]r[/]" if flags.get("export_report") else "[dim]r[/]"

        flag_line = f" [dim]FLAGS:[/] {p_tag} {m_tag} {d_tag} {F_tag} {D_tag} {s_tag} {P_tag} {v_tag} {r_tag}"
        recon_status = "[bold cyan]RECON[/] [bold green]ARMED[/]" if level == "recon" or any(flags.values()) else "[dim]RECON: OFF[/]"

        txt = (
            f" [dim]MODE:[/]    [bold white]{mode}[/]\n"
            f" [dim]LEVEL:[/]   [bold {lvl_color}]{lvl_str}[/]\n"
            f" [dim]BROWSER:[/] {browser_txt}\n"
            f" [dim]STATUS:[/]  {recon_status}\n"
            f"{flag_line}\n\n"
            f" [dim]Keys:[/] [cyan][M][/]ode [cyan][L][/]evel [cyan][p,d,g,f,D,h,x,r][/]\n"
            f"       [bold green][SPACE][/] START AUDIT"
        )
        self.content = txt
        self.update(txt)


class FlipProgressBarWidget(Static):
    """Animated FLIP Progress Bar with Crystal & Squircle styling.
    Renders micro-pulse transitions (180ms FLIP physics) and stage telemetry.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.progress: float = 0.0
        self.stage_text: str = "STANDBY // READY"
        self._flip_frame: int = 0
        self._chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.content = ""

    def on_mount(self) -> None:
        self.set_interval(0.2, self._tick_animation)
        self._render_bar()

    def _is_auditing(self) -> bool:
        try:
            return bool(getattr(self.app, "is_auditing", False))
        except Exception:
            return False

    def _tick_animation(self) -> None:
        if self._is_auditing():
            self._flip_frame = (self._flip_frame + 1) % len(self._chars)
            self._render_bar()

    def set_progress(self, percent: float, stage: str = "") -> None:
        self.progress = max(0.0, min(100.0, float(percent)))
        if stage:
            self.stage_text = stage
        self._render_bar()

    def reset(self) -> None:
        self.progress = 0.0
        self.stage_text = "STANDBY // READY"
        self._render_bar()

    def _render_bar(self) -> None:
        bar_len = 28
        filled = int((self.progress / 100.0) * bar_len)
        bar_fill = "█" * filled
        bar_empty = "░" * (bar_len - filled)

        is_running = self._is_auditing()
        spinner = self._chars[self._flip_frame] if is_running else "●"
        spin_color = "cyan" if is_running else "green"
        pct_color = "bold green" if self.progress >= 100 else "bold cyan" if self.progress > 0 else "dim"

        txt = (
            f" [{spin_color}]{spinner}[/] [{pct_color}]{bar_fill}[/][dim]{bar_empty}[/] "
            f"[{pct_color}]{int(self.progress):3d}%[/]  "
            f"[dim]STAGE:[/] [bold white]{self.stage_text[:30]}[/]"
        )
        self.content = txt
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
        ("p", "action_scan_ports", "Ports"),
        ("d", "action_deep_crawl", "Crawl"),
        ("g", "action_subdomains", "Subdomains"),
        ("f", "action_fingerprint", "Fingerprint"),
        ("D", "action_dump_db", "DumpDB"),
        ("v", "action_toggle_vault", "VaultDB"),
        ("r", "action_export_report", "Report"),
        ("h", "action_toggle_stealth", "Stealth"),
        ("x", "action_toggle_proxy", "Tor/Proxy"),
        ("b", "toggle_browser", "Browser"),
        ("e", "export", "Export JSON"),
        ("c", "clear_log", "Clear"),
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
        self.use_browser = False
        self.is_auditing = False

        # Recon feature flags (p, m, d, F, D, v, r, s, P)
        self.recon_flags = {
            "scan_ports": False,
            "subdomains": False,
            "deep_crawl": False,
            "fingerprint": False,
            "dump_db": False,
            "vault_store": True,
            "export_report": False,
            "stealth": False,
            "proxy_tor": False,
        }

        self.shield_widget = MicroShieldWidget(id="shield-content")
        self.telemetry_widget = MicroTelemetryWidget(id="telemetry-content")
        self.target_widget = MicroTargetWidget(id="targets-content")
        self.control_widget = MicroControlWidget(id="controls-content")
        self.progress_bar = FlipProgressBarWidget(id="progress-bar")
        self.log_widget: TextLog = TextLog(highlight=True)

    def compose(self) -> ComposeResult:
        with Horizontal(id="micro-header-bar"):
            yield Static("⚡ WEB-SEC // CYBER-DECK [NANO]", id="brand-title")
            yield Static("UTC: 00:00 | HOST: linux-box | MEM: 4.2G", id="header-stats")

        with Grid(id="micro-grid"):
            # Box 1: Shield / Privacidad
            with Vertical(id="box-shield", classes="nano-box"):
                yield Static("■ 1. PRIVACY SHIELD", classes="nano-header")
                yield self.shield_widget

            # Box 2: Telemetría / Sparklines
            with Vertical(id="box-telemetry", classes="nano-box"):
                yield Static("■ 2. NETWORK TELEMETRY", classes="nano-header")
                yield self.telemetry_widget

            # Box 3: Controles / Motor
            with Vertical(id="box-controls", classes="nano-box"):
                yield Static("■ 3. AUDIT ENGINE", classes="nano-header")
                yield self.control_widget

            # Box 4 (Ancho): Live Stream Matrix + FLIP Progress Bar
            with Vertical(id="box-stream", classes="nano-box"):
                yield Static("■ LIVE OPS STREAM (hollywood)", classes="nano-header")
                yield self.progress_bar
                yield self.log_widget

            # Box 5: Targets & Vault
            with Vertical(id="box-targets", classes="nano-box"):
                yield Static("■ 4. TARGETS & VAULT", classes="nano-header")
                yield self.target_widget

        # Micro Footer de Teclas Rápidas
        with Horizontal(id="micro-footer-bar"):
            yield Static(" [SPACE] ", classes="key-badge")
            yield Static("Start", classes="key-desc")
            yield Static(" [M] ", classes="key-badge")
            yield Static("Mode", classes="key-desc")
            yield Static(" [L] ", classes="key-badge")
            yield Static("Level", classes="key-desc")
            yield Static(" [P,D,G,F] ", classes="key-badge")
            yield Static("ReconFlags", classes="key-desc")
            yield Static(" [R] ", classes="key-badge")
            yield Static("Report", classes="key-desc")
            yield Static(" [T] ", classes="key-badge")
            yield Static("Targets", classes="key-desc")
            yield Static(" [Q] ", classes="key-badge")
            yield Static("Quit", classes="key-desc")

    def on_mount(self) -> None:
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.target_widget.refresh_data(self.targets, self.total_tokens_found, self.last_token_snippet)
        self.set_interval(1.0, self.update_top_bar)

        self.log_widget.write("[bold cyan]>>> KERNEL INITIALIZED: AUDIT ENGINE READY[/]")
        self.log_widget.write("[dim]Subsystems: net_mon=UP, bento_bus=OK, cert_scanner=ARMED, recon_engine=ONLINE[/]")
        self.log_widget.write("[dim]Press [SPACE] to launch mission against whitelisted scope.[/]")

    def update_top_bar(self) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        self.query_one("#header-stats", Static).update(f"LOCAL: {now} | SCOPE: {len(self.targets)} hosts | BUS: READY")

    def action_toggle_mode(self) -> None:
        self.mode = "WebScrap" if self.mode == "WebSec" else "WebSec"
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.log_widget.write(f"[dim]» Mode switched to:[/] [bold cyan]{self.mode}[/]")

    def action_toggle_browser(self) -> None:
        self.use_browser = not self.use_browser
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        st = "[bold magenta]ENABLED[/]" if self.use_browser else "[dim]DISABLED[/]"
        self.log_widget.write(f"[dim]» Browser routing (Playwright):[/] {st}")

    # ---------- Recon feature flags toggles ----------
    def action_scan_ports(self) -> None:
        self.recon_flags["scan_ports"] = not self.recon_flags["scan_ports"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.log_widget.write(f"[dim]» Port Scan flag [p]:[/] {self.recon_flags['scan_ports']}")

    def action_deep_crawl(self) -> None:
        self.recon_flags["deep_crawl"] = not self.recon_flags["deep_crawl"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.log_widget.write(f"[dim]» Deep Crawl flag [d]:[/] {self.recon_flags['deep_crawl']}")

    def action_subdomains(self) -> None:
        self.recon_flags["subdomains"] = not self.recon_flags["subdomains"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.log_widget.write(f"[dim]» Subdomains flag [m]:[/] {self.recon_flags['subdomains']}")

    def action_fingerprint(self) -> None:
        self.recon_flags["fingerprint"] = not self.recon_flags["fingerprint"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.log_widget.write(f"[dim]» Fingerprint flag [F]:[/] {self.recon_flags['fingerprint']}")

    def action_dump_db(self) -> None:
        self.recon_flags["dump_db"] = not self.recon_flags["dump_db"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.log_widget.write(f"[dim]» DB Dump flag [D]:[/] {self.recon_flags['dump_db']}")

    def action_toggle_vault(self) -> None:
        self.recon_flags["vault_store"] = not self.recon_flags["vault_store"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.log_widget.write(f"[dim]» SQLite Vault store flag [v]:[/] {self.recon_flags['vault_store']}")

    def action_export_report(self) -> None:
        self.recon_flags["export_report"] = not self.recon_flags["export_report"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.log_widget.write(f"[dim]» Multi-format Report flag [r]:[/] {self.recon_flags['export_report']}")

    def action_toggle_stealth(self) -> None:
        self.recon_flags["stealth"] = not self.recon_flags["stealth"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.log_widget.write(f"[dim]» Stealth / Ghost mode flag [s]:[/] {self.recon_flags['stealth']}")

    def action_toggle_proxy(self) -> None:
        self.recon_flags["proxy_tor"] = not self.recon_flags["proxy_tor"]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        self.log_widget.write(f"[dim]» Tor/SOCKS5 Auto-Route flag [P]:[/] {self.recon_flags['proxy_tor']}")

    def action_cycle_level(self) -> None:
        levels = ["0", "1", "2", "3", "recon", "void", "void_plus"]
        idx = (levels.index(self.level) + 1) % len(levels)
        self.level = levels[idx]
        self.control_widget.refresh_display(self.mode, self.level, self.use_browser, self.recon_flags)
        risk = "[red]HIGH RISK[/]" if self.level in ["3", "void", "void_plus"] else "[green]SAFE[/]"
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

        if self.level in {"3", "void", "void_plus"}:
            self.confirm_destructive()
        else:
            threading.Thread(target=self._run_audit_pipeline, daemon=True).start()

    def confirm_destructive(self):
        def _callback(answer: bool):
            if answer:
                if self.level == "void":
                    self.confirm_void()
                elif self.level == "void_plus":
                    self.confirm_void_plus()
                else:
                    threading.Thread(target=self._run_audit_pipeline, daemon=True).start()
            else:
                self.log_widget.write("[yellow]⚠️ Misión destructiva cancelada por el operador.[/]")

        self.push_screen(ConfirmScreen(
            title=f"CONFIRMAR ACCIÓN [{self.level.upper()}]",
            message=f"Nivel {self.level} activo. Mutará datos remotos.\n¿Autorizar ejecución?",
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
            callback=_final_cb,
        ))

    def confirm_void_plus(self):
        def _final_cb(txt: str):
            if txt.strip().upper() == "DESTROY-SCOPE-CONFIRM":
                threading.Thread(target=self._run_audit_pipeline, daemon=True).start()
            else:
                self.log_widget.write("[bold red]❌ Token erróneo. Abortando void_plus().[/]")

        self.push_screen(InputScreen(
            title="DOUBLE OVERRIDE void_plus()",
            prompt="Escribe 'DESTROY-SCOPE-CONFIRM' para autorizar el caos extremo:",
            callback=_final_cb,
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
        self.app.call_from_thread(self.progress_bar.set_progress, 0.0, f"STARTING {self.level.upper()}")
        self.app.call_from_thread(self.log_widget.write, f"[bold magenta]▶ DISPATCH MISSION [{self.mode} // LVL {self.level}][/]")

        handler_map = {
            "0": level0.run,
            "1": level1.run,
            "2": level2.run,
            "3": level3.run,
            "recon": recon.run,
            "void": void.run,
            "void_plus": void_plus.run,
        }

        handler = handler_map.get(self.level, level0.run)

        class InterceptLogger:
            def __init__(self, outer):
                self.outer = outer
                self.app = outer

            def write(self, msg):
                self.outer.app.call_from_thread(self.outer.log_scanner_hook, msg)

        custom_logger = InterceptLogger(self)

        try:
            total = len(self.targets)
            for idx, target in enumerate(list(self.targets), start=1):
                self.app.call_from_thread(self.log_widget.write, f"[cyan]› Probing host [{idx}/{total}]:[/] [white]{target}[/]")
                base_pct = (idx - 1) / total * 100.0
                self.app.call_from_thread(self.progress_bar.set_progress, base_pct, f"AUDITING {target[:15]}")
                try:
                    result = handler(target, self.mode, custom_logger, use_browser=self.use_browser, stealth=self.recon_flags.get("stealth", False))
                    self.results.append({"timestamp": time.time(), "target": target, "result": result})
                except Exception as exc:
                    self.app.call_from_thread(self.log_widget.write, f"[bold red]! Error on {target}:[/] {exc}")

            self.app.call_from_thread(self.log_widget.write, f"[bold green]✔ Misión concluida contra {len(self.targets)} hosts.[/]")
            self.app.call_from_thread(self.progress_bar.set_progress, 100.0, "MISSION COMPLETE")
        finally:
            self.is_auditing = False

    def action_export(self):
        if not self.results:
            self.log_widget.write("[yellow]! Sin resultados para volcar.[/]")
            return
        out_path = PROJECT_DIR / "outputs"
        out_path.mkdir(exist_ok=True)
        out_file = out_path / f"audit_{int(time.time())}.json"
        out_file.write_text(json.dumps(self.results, indent=2, default=str), encoding="utf-8")
        self.log_widget.write(f"[bold green]✔ Exportado ->[/] {out_file.name}")


# -----------------------------------------------------------------------------
# Modales Compactos (Crystal & Squircle Design System)
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
        else:
            self.callback("")
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
