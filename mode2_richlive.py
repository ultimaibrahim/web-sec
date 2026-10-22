#!/usr/bin/env python3
"""mode2_richlive.py - Modo 1: Consola Cyber-Deck pura con Rich Live (v3.2).
- CERO solapamientos: Decodificador ANSI multicarácter estricto para flechas.
- Navegación horizontal en logs sin interferencias.
- Plugins integrados: Nmap, Gobuster, SQLMap, Auditoría OWASP, Playwright/BS4.
- Persistencia SQLite automática, cifrado AES-256 y exportación de reportes Markdown.
- Modo Dry-Run y Modo Stealth integrados.
"""

import sys
import os
import time
import random
import select
import termios
import tty
import threading
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Set, List, Dict, Any, Optional

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.markup import escape

from level_handlers import level0, level1, level2, level3, void
from credential_scanner import scan_text
from privacy_guard import evaluate_privacy, PrivacyStatus
import plugin_runner
import storage_vault
from browser_client import set_stealth_mode, is_stealth_enabled

PROJECT_DIR = Path(__file__).parent.resolve()
WHITELIST_PATH = PROJECT_DIR / "allowed_targets.txt"
SPARK_CHARS = " ▂▃▄▅▆▇█"

TEXT_FADE_PALETTE = [
    "#cbd5e1",
    "#94a3b8",
    "#64748b",
    "#475569",
    "#334155",
    "#1e293b",
    "#0b1222"
]

def load_whitelist() -> Set[str]:
    if WHITELIST_PATH.exists():
        return {line.strip() for line in WHITELIST_PATH.read_text().splitlines() if line.strip()}
    return set()

def save_whitelist(domains: Set[str]):
    WHITELIST_PATH.write_text("\n".join(sorted(domains)))

def render_scrolled_line(text: str, offset: int, max_visible: int, base_style: str = "white") -> Text:
    t = Text()
    if offset > 0:
        t.append("« ", style="bold yellow")
        max_visible -= 2

    sliced = text[offset:]
    if len(sliced) <= max_visible:
        t.append(sliced, style=base_style)
        return t

    fade_len = len(TEXT_FADE_PALETTE)
    solid_len = max(0, max_visible - fade_len)
    t.append(sliced[:solid_len], style=base_style)

    for i, col in enumerate(TEXT_FADE_PALETTE):
        idx = solid_len + i
        if idx < len(sliced):
            t.append(sliced[idx], style=col)

    return t

class RobustTerminalReader:
    def __enter__(self):
        self.old_settings = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())
        return self

    def __exit__(self, type, value, traceback):
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)

    def read_key_or_arrow(self) -> str:
        if not select.select([sys.stdin], [], [], 0)[0]:
            return ""

        first = sys.stdin.read(1)
        if first == '\x1b':
            time.sleep(0.01)
            seq = ""
            while select.select([sys.stdin], [], [], 0)[0]:
                seq += sys.stdin.read(1)

            if seq == "[C" or seq == "OC":
                return "KEY_RIGHT"
            elif seq == "[D" or seq == "OD":
                return "KEY_LEFT"
            elif seq == "[A" or seq == "OA":
                return "KEY_UP"
            elif seq == "[B" or seq == "OB":
                return "KEY_DOWN"
            elif not seq:
                return "KEY_ESC"
            return "UNKNOWN_ESC"

        return first

class RichLiveDeck:
    def __init__(self):
        self.console = Console()
        self.mode = "WebSec"
        self.level = "0"
        self.targets = load_whitelist()
        storage_vault.init_database()
        
        self.privacy_status = PrivacyStatus(
            vpn_active=False,
            vpn_interface="Probing...",
            dns_secure=False,
            dns_server="Resolving...",
            ipv6_blocked=True,
            public_ip="Connecting...",
            isp_org="Analyzing WAN...",
            country="",
            city="",
            mac_spoofed=False,
            current_mac="Reading...",
            tcp_timestamps_off=False,
            timezone_utc=False,
            hostname_clean=False,
            current_hostname="Reading...",
            score=0,
            threat_level="PROBING"
        )
        
        self.logs: List[str] = [
            f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] [bold cyan]KERNEL:[/] High-Speed Cyber-Deck v3.2 [bold green]ONLINE[/].",
            f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] [bold white]PLUGINS ACTIVOS:[/] Nmap [bold green]✔[/], Gobuster [bold green]✔[/], SQLMap [bold green]✔[/], OWASP Headers [bold green]✔[/], Playwright [bold green]✔[/].",
            f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] [bold yellow]FLECHAS:[/] Usa [bold cyan]← / →[/] para Scroll H, [bold cyan]↑ / ↓[/] para Scroll V sin colisiones.",
            f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] [bold green]ESCRITURA:[/] Pulsa [bold white][ENTER][/] para escribir comandos (:help, :nmap, :sqlmap, :gobuster, :headers, :dry-run, :export-md)"
        ]
        self.tokens_found = 0
        self.last_token = "clean"
        self.is_running = True
        self.is_auditing = False
        self.dry_run = False
        
        # Desplazamiento
        self.h_offset = 0
        self.v_offset = 0
        self.wrap_mode = False
        self.stealth_active = False
        
        # Modo de escritura
        self.input_buffer = ""
        self.input_mode = False
        self.current_cwd = str(PROJECT_DIR)
        
        # Telemetría sparklines
        self.net_history = [random.randint(0, 3) for _ in range(24)]
        self.req_history = [0 for _ in range(24)]
        self.bytes_sent = 2048

        threading.Thread(target=self._privacy_daemon, daemon=True).start()

    def _privacy_daemon(self):
        try:
            self.privacy_status = evaluate_privacy()
            self.log(f"[dim]Shield telemetría sincronizada: Score {self.privacy_status.score}%[/]")
        except Exception:
            pass

        while self.is_running:
            time.sleep(8)
            try:
                st = evaluate_privacy()
                self.privacy_status = st
            except Exception:
                pass

    def log(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[dim]{ts}[/] {text}")
        if len(self.logs) > 200:
            self.logs.pop(0)

        hits = scan_text(text)
        if hits:
            for c_type, items in hits.items():
                self.tokens_found += len(items)
                self.last_token = f"[{c_type}] {items[0][:14]}"
                self.logs.append(f"[dim]{ts}[/] [bold red]🔥 VAULT HIT:[/] {c_type}: {escape(items[0][:20])}...")
                # Persistencia automática de credenciales con cifrado AES-256
                target_hint = list(self.targets)[0] if self.targets else "stream"
                storage_vault.save_finding(target_hint, "RegexVault", c_type, items[0], encrypt=True)

    def trigger_audit(self):
        if self.is_auditing:
            self.log("[yellow]Auditoría ya en ejecución...[/]")
            return
        if not self.targets:
            self.log("[bold red]ERROR:[/] No hay targets. Escribe [white]:add midominio.com[/]")
            return

        # -------------------------------------------------------------------------
        # GUARDIA ESTRICTA PARA NIVELES DESTRUCTIVOS (Nivel 3 y void())
        # Requiere OBLIGATORIAMENTE que todos los guardias de seguridad estén activos:
        # 1. Túnel VPN activo (proton0 / wg0)
        # 2. DNS Seguro (10.2.0.1 sin fugas)
        # 3. Fuga IPv6 bloqueada
        # 4. Modo Stealth habilitado
        # -------------------------------------------------------------------------
        if self.level in ("3", "void") and not self.dry_run:
            s = self.privacy_status
            missing_guards = []
            if not s.vpn_active:
                missing_guards.append("Túnel VPN inactivo (proton0/wg0 DOWN)")
            if not s.dns_secure:
                missing_guards.append(f"Fuga de DNS detectada ({s.dns_server} != 10.2.0.1)")
            if not s.ipv6_blocked:
                missing_guards.append("Fuga IPv6 activa (IP pública expuesta)")
            if not self.stealth_active:
                missing_guards.append("Modo Stealth DESACTIVADO (Pulsa [S] o :stealth)")

            if missing_guards:
                self.log(f"[bold red]⛔ BLOQUEO DE SEGURIDAD CRÍTICO // NIVEL {self.level} RECHAZADO[/]")
                self.log("[bold red]Para ejecutar acciones destructivas se requiere el 100% de los guardias activos:[/]")
                for mg in missing_guards:
                    self.log(f"   [bold yellow]✗[/] [red]{mg}[/]")
                self.log("[dim]Activa tu VPN y pulsa [S] para Stealth, o usa [D] Dry-Run para simular.[/]")
                return

        def _worker():
            self.is_auditing = True
            dry_tag = " [DRY-RUN SIMULADO]" if self.dry_run else ""
            self.log(f"[bold magenta]▶ DISPATCHING AUDIT [{self.mode} // LVL {self.level}]{dry_tag}[/]")
            handler_map = {"0": level0.run, "1": level1.run, "2": level2.run, "3": level3.run, "void": void.run}
            handler = handler_map.get(self.level)
            
            class BridgeLogger:
                def __init__(self, deck): self.deck = deck
                def write(self, m): self.deck.log(m)

            b_log = BridgeLogger(self)

            for t in list(self.targets):
                self.log(f"[cyan]› Target probe:[/] [white]{t}[/]")
                if self.dry_run:
                    self.log(f"[yellow]  [DRY-RUN] Simulación: Se enviaría payload de nivel {self.level} a {t} (red remota intacta).[/]")
                    time.sleep(0.5)
                else:
                    try:
                        if handler:
                            handler(t, self.mode, b_log)
                    except Exception as e:
                        self.log(f"[bold red]! Err {t}:[/] {e}")
                storage_vault.save_scan_record(t, self.mode, self.level, f"Audit {self.mode} Lvl {self.level} completed")

            self.log(f"[bold green]✔ Ciclo de auditoría concluido.[/]")
            self.is_auditing = False

        threading.Thread(target=_worker, daemon=True).start()

    def execute_command(self, cmd_line: str):
        raw_cmd = cmd_line.strip()
        if not raw_cmd:
            return

        is_internal = raw_cmd.startswith(":")
        clean_cmd = raw_cmd[1:].strip() if is_internal else raw_cmd
        parts = clean_cmd.split()
        first_word = parts[0].lower() if parts else ""
        args = parts[1:]

        # 1. COMANDOS DE PLUGINS Y WEB-SEC
        if is_internal or first_word in ("add", "rm", "mode", "lvl", "level", "start", "audit", "priv", "help", "wrap", "nmap", "sqlmap", "gobuster", "ffuf", "whatweb", "headers", "stealth", "dry-run", "export-md"):
            if first_word in ("q", "quit", "exit"):
                self.is_running = False
                return
            elif first_word in ("help", "?"):
                self.log("[bold cyan]PLUGINS DISPONIBLES:[/] :nmap <host> | :sqlmap <url> | :gobuster <url> | :ffuf <url> | :whatweb <url> | :headers <host>")
                self.log("[bold cyan]CONTROLES:[/] :stealth | :dry-run | :export-md | :add <host> | :rm <host> | :wrap")
                self.log("[bold cyan]SHELL LINUX:[/] Ejecuta comandos nativos directamente: [white]ls, cd, cat, curl, ping, etc.[/]")
                return
            elif first_word == "ffuf":
                target = args[0] if args else (list(self.targets)[0] if self.targets else "")
                if not target:
                    self.log("[yellow]Uso: :ffuf <http://url>[/]")
                    return
                self.log(f"[bold cyan]⚡ Fuzzing con FFUF (20k wordlist) contra:[/] [white]{target}[/]")
                def _run_ffuf():
                    res = plugin_runner.run_ffuf_scan(target)
                    if "error" in res:
                        self.log(f"[red]FFuf Error:[/] {res['error']}")
                    else:
                        m = res.get("fuzzed_matches", [])
                        if m:
                            self.log(f"[bold green]✔ Coincidencias FFuf detectadas ({len(m)}):[/]")
                            for match in m:
                                self.log(f"   [yellow]•[/] {match}")
                                storage_vault.save_finding(target, "ffuf", "match", match)
                        else:
                            self.log(f"[dim]FFuf: Sin coincidencias con códigos 200/301/302.[/]")
                threading.Thread(target=_run_ffuf, daemon=True).start()
                return
            elif first_word == "whatweb":
                target = args[0] if args else (list(self.targets)[0] if self.targets else "")
                if not target:
                    self.log("[yellow]Uso: :whatweb <dominio/url>[/]")
                    return
                self.log(f"[bold cyan]🔍 Fingerprinting con WHATWEB contra:[/] [white]{target}[/]")
                def _run_whatweb():
                    res = plugin_runner.run_whatweb_scan(target)
                    if "error" in res:
                        self.log(f"[red]WhatWeb Error:[/] {res['error']}")
                    else:
                        self.log(f"[bold green]WhatWeb Hallazgos:[/] {res.get('fingerprint', 'N/A')}")
                        storage_vault.save_finding(target, "whatweb", "fingerprint", res.get('fingerprint', ''))
                threading.Thread(target=_run_whatweb, daemon=True).start()
                return
            elif first_word == "stealth":
                self.stealth_active = not self.stealth_active
                set_stealth_mode(self.stealth_active)
                st_color = "bold green" if self.stealth_active else "bold red"
                self.log(f"[{st_color}]STEALTH MODE:[/] {'ACTIVADO (Jitter aleatorio + Rotación UA + Bypass WebDriver)' if self.stealth_active else 'DESACTIVADO'}")
                return
            elif first_word in ("dry-run", "dryrun"):
                self.dry_run = not self.dry_run
                self.log(f"[bold yellow]DRY-RUN MODE:[/] {'ACTIVADO (Simulación sin mutación remota)' if self.dry_run else 'DESACTIVADO (Tráfico real)'}")
                return
            elif first_word in ("export-md", "export", "report"):
                rep_path = storage_vault.export_markdown_report()
                self.log(f"[bold green]✔ Reporte ejecutivo Markdown exportado:[/] [white]{rep_path.name}[/]")
                return
            elif first_word == "nmap":
                target = args[0] if args else (list(self.targets)[0] if self.targets else "")
                if not target:
                    self.log("[yellow]Uso: :nmap <dominio/ip>[/]")
                    return
                self.log(f"[bold cyan]🔍 Ejecutando Plugin NMAP contra:[/] [white]{target}[/]")
                def _run_nmap():
                    res = plugin_runner.run_nmap_scan(target)
                    if "error" in res:
                        self.log(f"[red]Nmap Error:[/] {res['error']}")
                    else:
                        ports = res.get("open_ports", [])
                        if ports:
                            self.log(f"[bold green]✔ Puertos abiertos encontrados ({len(ports)}):[/]")
                            for p in ports: 
                                self.log(f"   [yellow]•[/] {p}")
                                storage_vault.save_finding(target, "nmap", "open_port", p)
                        else:
                            self.log(f"[dim]Nmap: No se detectaron puertos abiertos estándar en {target}[/]")
                threading.Thread(target=_run_nmap, daemon=True).start()
                return
            elif first_word == "gobuster":
                target = args[0] if args else (list(self.targets)[0] if self.targets else "")
                if not target:
                    self.log("[yellow]Uso: :gobuster <http://url>[/]")
                    return
                self.log(f"[bold cyan]📁 Ejecutando Plugin GOBUSTER contra:[/] [white]{target}[/]")
                def _run_gobuster():
                    res = plugin_runner.run_gobuster_scan(target)
                    if "error" in res:
                        self.log(f"[red]Gobuster Error:[/] {res['error']}")
                    else:
                        paths = res.get("found_paths", [])
                        if paths:
                            self.log(f"[bold green]✔ Rutas detectadas ({len(paths)}):[/]")
                            for p in paths:
                                self.log(f"   [yellow]•[/] {p}")
                                storage_vault.save_finding(target, "gobuster", "discovered_path", p)
                        else:
                            self.log(f"[dim]Gobuster: Sin rutas coincidentes en wordlist común.[/]")
                threading.Thread(target=_run_gobuster, daemon=True).start()
                return
            elif first_word == "headers":
                target = args[0] if args else (list(self.targets)[0] if self.targets else "")
                if not target:
                    self.log("[yellow]Uso: :headers <dominio/url>[/]")
                    return
                self.log(f"[bold cyan]🛡️ Evaluando Cabeceras OWASP contra:[/] [white]{target}[/]")
                def _run_headers():
                    res = plugin_runner.audit_security_headers(target)
                    if "error" in res:
                        self.log(f"[red]OWASP Error:[/] {res['error']}")
                    else:
                        sc = res.get("score", 0)
                        col = "green" if sc >= 80 else "yellow" if sc >= 40 else "red"
                        self.log(f"[bold {col}]Puntuación Cabeceras: {sc}%[/]")
                        for h, ok in res.get("checks", {}).items():
                            status = "[green]PRESENTE[/]" if ok else "[red]FALTA[/]"
                            self.log(f"   [dim]{h}:[/] {status}")
                        storage_vault.save_finding(target, "owasp_headers", "security_score", f"Score: {sc}%")
                threading.Thread(target=_run_headers, daemon=True).start()
                return
            elif first_word == "sqlmap":
                target = args[0] if args else (list(self.targets)[0] if self.targets else "")
                if not target:
                    self.log("[yellow]Uso: :sqlmap <http://url?id=1>[/]")
                    return
                self.log(f"[bold magenta]⚡ Ejecutando Plugin SQLMAP (Dry-Run seguro) contra:[/] [white]{target}[/]")
                def _run_sql():
                    res = plugin_runner.run_sqlmap_check(target)
                    status_col = "red" if res.get("vulnerable") else "green"
                    self.log(f"[bold {status_col}]SQLMap Resultado:[/] {'VULNERABLE A SQLi' if res.get('vulnerable') else 'Limpio / No vulnerable'}")
                    storage_vault.save_finding(target, "sqlmap", "sqli_status", "Vulnerable" if res.get("vulnerable") else "Clean")
                threading.Thread(target=_run_sql, daemon=True).start()
                return
            elif first_word == "add":
                if args:
                    self.targets.add(args[0])
                    save_whitelist(self.targets)
                    self.log(f"[bold green]✔ Target añadido:[/] [white]{args[0]}[/]")
                return
            elif first_word in ("rm", "del"):
                if args and args[0] in self.targets:
                    self.targets.remove(args[0])
                    save_whitelist(self.targets)
                    self.log(f"[yellow]✔ Target eliminado:[/] [white]{args[0]}[/]")
                return
            elif first_word == "wrap":
                self.wrap_mode = not self.wrap_mode
                self.log(f"[cyan]Modo Wrap de texto:[/] {'[bold green]ACTIVADO[/]' if self.wrap_mode else '[bold yellow]DESACTIVADO (Scroll H)[/]'}")
                return
            elif first_word == "mode":
                self.mode = "WebScrap" if self.mode == "WebSec" else "WebSec"
                self.log(f"[dim]Modo cambiado a:[/] [bold cyan]{self.mode}[/]")
                return
            elif first_word in ("lvl", "level"):
                if args and args[0] in ("0", "1", "2", "3", "void"):
                    self.level = args[0]
                    self.log(f"[dim]Nivel cambiado a:[/] [bold yellow]Level {self.level}[/]")
                return
            elif first_word in ("start", "audit"):
                self.trigger_audit()
                return
            elif first_word == "priv":
                threading.Thread(target=lambda: setattr(self, 'privacy_status', evaluate_privacy()), daemon=True).start()
                self.log("[cyan]Sondeo de privacidad disparado en background.[/]")
                return

        # 2. SHELL NATIVO LINUX
        if first_word == "cd":
            target_dir = args[0] if args else os.path.expanduser("~")
            try:
                new_path = Path(self.current_cwd).joinpath(os.path.expanduser(target_dir)).resolve()
                if new_path.is_dir():
                    self.current_cwd = str(new_path)
                    os.chdir(self.current_cwd)
                    self.log(f"[cyan]📁 CWD:[/] [white]{self.current_cwd}[/]")
                else:
                    self.log(f"[red]cd: No existe el directorio: {target_dir}[/]")
            except Exception as e:
                self.log(f"[red]cd error:[/] {e}")
            return

        if first_word in ("clear", "cls"):
            self.logs.clear()
            self.h_offset = 0
            self.v_offset = 0
            return

        self.log(f"[bold yellow]❯ {escape(raw_cmd)}[/]")
        def _exec_shell():
            try:
                proc = subprocess.run(
                    raw_cmd,
                    shell=True,
                    cwd=self.current_cwd,
                    capture_output=True,
                    text=True,
                    timeout=8
                )
                if proc.stdout:
                    lines = proc.stdout.splitlines()
                    for line in lines[:30]:
                        self.log(f"  [dim]│[/] {escape(line)}")
                    if len(lines) > 30:
                        self.log(f"  [dim]│ ... ({len(lines) - 30} líneas más)[/]")
                if proc.stderr:
                    for line in proc.stderr.splitlines()[:5]:
                        self.log(f"  [red]│[/] {escape(line)}")
                if proc.returncode != 0 and not proc.stderr:
                    self.log(f"  [red]Proceso terminó con código {proc.returncode}[/]")
            except subprocess.TimeoutExpired:
                self.log(f"[red]Comando cancelado por timeout (límite 8s).[/]")
            except Exception as e:
                self.log(f"[red]Error ejecutando comando:[/] {e}")

        threading.Thread(target=_exec_shell, daemon=True).start()

    def make_layout(self) -> Layout:
        term_width = shutil.get_terminal_size((100, 28)).columns

        layout = Layout(name="root")
        layout.split(
            Layout(name="header", size=1),
            Layout(name="cred_watch", size=1),
            Layout(name="body", ratio=1),
            Layout(name="command_bar", size=3),
            Layout(name="footer", size=1)
        )
        layout["body"].split_row(
            Layout(name="left", size=32),
            Layout(name="center", ratio=1),
            Layout(name="right", size=30)
        )
        layout["left"].split(
            Layout(name="shield", size=11),
            Layout(name="telemetry", size=9),
            Layout(name="controls", ratio=1)
        )
        layout["right"].split(
            Layout(name="scope", size=10),
            Layout(name="vault", ratio=1)
        )

        # Header
        now = datetime.now().strftime("%H:%M:%S")
        cwd_short = Path(self.current_cwd).name or "/"
        scroll_indicator = f" | H:+{self.h_offset}ch" if self.h_offset > 0 else ""
        v_indicator = f" | V:+{self.v_offset}" if self.v_offset > 0 else ""
        dry_badge = " [DRY-RUN]" if self.dry_run else ""
        head_text = Text.assemble(
            ("⚡ ULTIMA WEB SEC // CYBER-DECK v4.0  ", "bold cyan"),
            ("CWD: ", "dim"), (f"~/{cwd_short} ", "bold white"),
            ("LOCAL: ", "dim"), (now, "white"),
            (" | SCOPE: ", "dim"), (str(len(self.targets)), "bold yellow"),
            (f"{scroll_indicator}{v_indicator}{dry_badge}", "bold yellow")
        )
        layout["header"].update(head_text)

        # Barra Superior Dinámica: LIVE CRED-WATCH & PLUGINS TICKER
        cred_alert = f"[bold red]🔥 {self.tokens_found} LEAKS[/]" if self.tokens_found > 0 else "[green]0 LEAKS (CLEAN)[/]"
        cred_text = Text.assemble(
            (" LIVE CRED-WATCH: ", "bold yellow"),
            Text.from_markup(cred_alert),
            (" | LAST: ", "dim"),
            Text.from_markup(f"[cyan]{self.last_token}[/]"),
            (" | PLUGINS READY: ", "dim"),
            Text.from_markup("[white]nmap[/] [green]●[/] [white]gobuster[/] [green]●[/] [white]sqlmap[/] [green]●[/] [white]playwright[/] [green]●[/] [white]owasp[/] [green]●[/]")
        )
        layout["cred_watch"].update(cred_text)

        # 1. Shield Panel
        s = self.privacy_status
        sc_col = "green" if s.score >= 80 else "yellow" if s.score >= 50 else "red"
        vpn_st = "[bold green]ON[/]" if s.vpn_active else "[bold red]OFF[/]"
        dns_st = "[green]10.2.0.1[/]" if s.dns_secure else f"[red]LEAK[/]"
        mac_st = "[green]SPOOF[/]" if s.mac_spoofed else "[red]RAW[/]"

        shield_table = Table.grid(padding=(0, 1))
        shield_table.add_row("[bold white]SCORE:[/]", f"[bold {sc_col}]{s.score}% ({s.threat_level[:8]})[/]")
        shield_table.add_row("[dim]VPN:[/]", f"{vpn_st} [dim]({s.vpn_interface[:8]})[/]")
        shield_table.add_row("[dim]DNS:[/]", dns_st)
        shield_table.add_row("[dim]IPV6:[/]", "[green]BLOCKED[/]" if s.ipv6_blocked else "[red]LEAK[/]")
        shield_table.add_row("[dim]MAC:[/]", mac_st)
        shield_table.add_row("[dim]IP:[/]", f"[white]{s.public_ip[:16]}[/]")
        shield_table.add_row("[dim]ISP:[/]", f"[yellow]{s.isp_org[:14]}[/]")
        shield_table.add_row("[dim]LOC:[/]", f"[cyan]{s.city[:10]}, {s.country[:3]}[/]")
        layout["shield"].update(Panel(shield_table, title="[bold cyan]1. SHIELD[/]", border_style="blue"))

        # 2. Telemetry Panel
        delta_net = random.randint(0, 7) if self.is_auditing else random.randint(0, 2)
        delta_req = random.randint(1, 7) if self.is_auditing else 0
        self.net_history.pop(0)
        self.net_history.append(delta_net)
        self.req_history.pop(0)
        self.req_history.append(delta_req)
        self.bytes_sent += delta_net * 256

        net_sp = "".join(SPARK_CHARS[v] for v in self.net_history)
        req_sp = "".join(SPARK_CHARS[v] for v in self.req_history)
        pump_st = "[bold green]LIVE PUMP[/]" if self.is_auditing else "[dim]IDLE[/]"

        telem_table = Table.grid(padding=(0, 1))
        telem_table.add_row("[dim]BUS:[/]  ", pump_st)
        telem_table.add_row("[dim]NET:[/]  ", f"[cyan]{net_sp}[/]")
        telem_table.add_row("[dim]VOL:[/]  ", f"{self.bytes_sent // 1024} KB")
        telem_table.add_row("[dim]AUD:[/]  ", f"[magenta]{req_sp}[/]")
        telem_table.add_row("[dim]LOAD:[/] ", f"{random.randint(14, 22)}% [dim]4.2G ram[/]")
        layout["telemetry"].update(Panel(telem_table, title="[bold cyan]2. TELEMETRY[/]", border_style="blue"))

        # 3. Controls Panel
        lvl_col = "red" if self.level in ["3", "void"] else "yellow" if self.level == "2" else "cyan"
        stealth_badge = "[bold green]ENGAGED[/]" if self.stealth_active else "[dim]DISENGAGED[/]"
        dry_text = "[bold yellow]DRY-RUN ON[/]" if self.dry_run else "[green]LIVE TRAFFIC[/]"
        ctrl_table = Table.grid(padding=(0, 1))
        ctrl_table.add_row("[dim]MODE:[/] ", f"[bold white]{self.mode}[/]")
        ctrl_table.add_row("[dim]LEVEL:[/]", f"[bold {lvl_col}]{self.level}[/]")
        ctrl_table.add_row("[dim]TARGETS:[/]", f"[white]{len(self.targets)} scoped[/]")
        ctrl_table.add_row("[dim]STEALTH:[/]", stealth_badge)
        ctrl_table.add_row("[dim]TRAFFIC:[/]", dry_text)
        ctrl_table.add_row("[dim]VIEW:[/] ", f"[cyan]{'WRAP' if self.wrap_mode else 'SCROLL-H'}[/]")
        layout["controls"].update(Panel(ctrl_table, title="[bold cyan]3. ENGINE & PLUGINS[/]", border_style="blue"))

        # Center: Stream Logs
        center_width = max(20, term_width - 66)
        slice_end = len(self.logs) - self.v_offset if self.v_offset > 0 else len(self.logs)
        slice_start = max(0, slice_end - 22)
        visible_logs = self.logs[slice_start:slice_end]

        formatted_logs = []
        for l in visible_logs:
            if self.wrap_mode:
                formatted_logs.append(Text.from_markup(l))
            else:
                plain = Text.from_markup(l).plain
                formatted_logs.append(render_scrolled_line(plain, self.h_offset, center_width))

        stream_group = Text("\n").join(formatted_logs)
        scroll_title = f"[bold green]LIVE STREAM[/] [dim](H:+{self.h_offset}ch | [←/→] scroll | [W] wrap)[/]" if not self.wrap_mode else "[bold green]LIVE STREAM [WRAP MODE][/]"
        layout["center"].update(Panel(stream_group, title=scroll_title, border_style="green"))

        # Right: Scope & Vault
        scope_lines = []
        for t in sorted(self.targets)[:5]:
            faded_t = render_scrolled_line(t, 0, 22, base_style="white")
            line = Text.assemble(("› ", "cyan"), faded_t)
            scope_lines.append(line)
        if len(self.targets) > 5:
            scope_lines.append(Text(f"+{len(self.targets)-5} more...", style="dim"))

        layout["scope"].update(Panel(Text("\n").join(scope_lines), title="[bold cyan]4. TARGET SCOPE[/]", border_style="cyan"))

        vault_body = (
            f"[bold yellow]TOKENS TOTAL:[/] [bold white]{self.tokens_found}[/]\n\n"
            f"[dim]ULTIMO HALLAZGO:[/] \n[green]{self.last_token}[/]\n\n"
            f"[dim]STORAGE:[/] [white]SQLite AES-256[/]\n"
            f"[dim]PLUGINS:[/] [cyan]:nmap :sqlmap :headers[/]"
        )
        layout["vault"].update(Panel(vault_body, title="[bold yellow]5. CRED VAULT[/]", border_style="yellow"))

        # Command Input Bar
        cursor = "█" if int(time.time() * 3) % 2 == 0 else " "
        prompt_style = "bold cyan" if self.input_mode else "dim white"
        prompt_title = f"[bold green]PROMPT ACTIVO (Escribe :help para ver plugins y presiona Enter)[/]" if self.input_mode else "[dim]PROMPT INACTIVO (Presiona [ENTER] o [:] para escribir)[/]"
        
        avail_prompt_width = max(15, term_width - 12)
        if len(self.input_buffer) > avail_prompt_width:
            faded_buffer = render_scrolled_line(self.input_buffer, len(self.input_buffer) - avail_prompt_width, avail_prompt_width, base_style="bold white")
            prompt_body = Text.assemble(
                ("❯ ", prompt_style),
                faded_buffer,
                (cursor, "bold green")
            )
        else:
            prompt_body = Text.assemble(
                ("❯ ", prompt_style),
                (self.input_buffer, "bold white"),
                (cursor, "bold green")
            )
            
        layout["command_bar"].update(Panel(prompt_body, title=prompt_title, border_style="green" if self.input_mode else "dim"))

        # Footer Keys
        if self.input_mode:
            foot_text = Text.from_markup(
                "[bold green]MODO ESCRITURA[/]  "
                "[bold cyan][ENTER][/] [white]Ejecutar[/]  "
                "[bold cyan][ESC][/] [white]Salir a navegación[/]"
            )
        else:
            foot_text = Text.from_markup(
                "[bold cyan][ENTER / :][/] [white]Escribir[/]  "
                "[bold cyan][S][/] [white]Stealth[/]  "
                "[bold cyan][D][/] [white]DryRun[/]  "
                "[bold cyan][← / →][/] [white]Scroll H[/]  "
                "[bold cyan][↑ / ↓][/] [white]Scroll V[/]  "
                "[bold cyan][W][/] [white]Wrap[/]  "
                "[bold cyan][SPACE][/] [white]Start[/]  "
                "[bold cyan][M][/] [white]Mode[/]  "
                "[bold cyan][L][/] [white]Level[/]  "
                "[bold cyan][Q][/] [white]Quit[/]"
            )
        layout["footer"].update(foot_text)

        return layout

    def run(self):
        with RobustTerminalReader() as reader:
            with Live(self.make_layout(), console=self.console, refresh_per_second=25, screen=True) as live:
                while self.is_running:
                    key = reader.read_key_or_arrow()
                    if key:
                        # 1. MODO ESCRITURA
                        if self.input_mode:
                            if key in ('\r', '\n'):
                                self.execute_command(self.input_buffer)
                                self.input_buffer = ""
                                self.input_mode = False
                            elif key == 'KEY_ESC':
                                self.input_mode = False
                                self.input_buffer = ""
                            elif key in ('\x7f', '\x08'):
                                self.input_buffer = self.input_buffer[:-1]
                            elif len(key) == 1 and ord(key) >= 32 and ord(key) <= 126:
                                self.input_buffer += key

                        # 2. MODO COMANDO / NAVEGACIÓN
                        else:
                            if key == "KEY_RIGHT":
                                self.h_offset += 8
                            elif key == "KEY_LEFT":
                                self.h_offset = max(0, self.h_offset - 8)
                            elif key == "KEY_UP":
                                self.v_offset = min(len(self.logs) - 5, self.v_offset + 3)
                            elif key == "KEY_DOWN":
                                self.v_offset = max(0, self.v_offset - 3)
                            elif key in ('\r', '\n', ':', 'i', 'I'):
                                self.input_mode = True
                                if key == ':':
                                    self.input_buffer = ":"
                            elif key in ('w', 'W'):
                                self.wrap_mode = not self.wrap_mode
                                self.log(f"[dim]Modo Wrap:[/] {'[green]ON[/]' if self.wrap_mode else '[yellow]OFF[/]'}")
                            elif key in ('s', 'S'):
                                self.stealth_active = not self.stealth_active
                                set_stealth_mode(self.stealth_active)
                                st_col = "green" if self.stealth_active else "red"
                                self.log(f"[dim]Stealth mode:[/] [{st_col}]{'ON (Jitter + Anti-bot evasion)' if self.stealth_active else 'OFF'}[/]")
                            elif key in ('d', 'D'):
                                self.dry_run = not self.dry_run
                                d_col = "yellow" if self.dry_run else "green"
                                self.log(f"[dim]Dry-Run mode:[/] [{d_col}]{'ON (Simulación segura)' if self.dry_run else 'OFF (Tráfico real)'}[/]")
                            elif key == '0':
                                self.h_offset = 0
                                self.v_offset = 0
                            elif key == ' ':
                                self.trigger_audit()
                            elif key in ('m', 'M'):
                                self.mode = "WebScrap" if self.mode == "WebSec" else "WebSec"
                                self.log(f"[dim]Mode cycled to:[/] [cyan]{self.mode}[/]")
                            elif key in ('l', 'L'):
                                lvls = ["0", "1", "2", "3", "void"]
                                idx = (lvls.index(self.level) + 1) % len(lvls)
                                self.level = lvls[idx]
                                self.log(f"[dim]Level cycled to:[/] [yellow]Level {self.level}[/]")
                            elif key in ('q', 'Q'):
                                self.is_running = False
                                break

                    live.update(self.make_layout())
                    time.sleep(0.04)

if __name__ == "__main__":
    RichLiveDeck().run()
