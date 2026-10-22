#!/usr/bin/env python3
"""mode3_blueteam.py – Ultima Web Sec // Blue Team Active Defense Cyber-Deck.
TUI dedicada para Operaciones de Defensa Activa, Honeytokens, Tarpit & Shadow-Ban.
Diseñada con estética Bento Grid, alertas en vivo y efectos de sonido en tiempo real.
"""

import os
import sys
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live

from blue_team_shield import (
    THREAT_REGISTRY,
    DECOY_PATHS,
    HONEY_CREDENTIALS,
    ActiveDefenseShieldServer,
)
from sound_effects import play_alert_detected, play_shield_on, play_burn_sequence

console = Console()

class BlueTeamDeck:
    def __init__(self, port: int = 8999):
        self.port = port
        self.server = ActiveDefenseShieldServer(port=self.port)
        self.running = True
        self.logs: List[str] = []
        self.last_hit_count = 0

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[dim]{ts}[/] {msg}")
        if len(self.logs) > 80:
            self.logs.pop(0)

    def start_server(self):
        self.server.start()
        play_shield_on()
        self.log(f"[bold cyan]🛡️ ACTIVE DEFENSE CORE ARMED ON PORT {self.port}[/]")
        self.log(f"[dim]› Monitoreando {len(DECOY_PATHS)} honeypots y trampas de sesión...[/]")

    def build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3),
        )
        layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=3),
        )
        layout["left"].split_column(
            Layout(name="status", size=10),
            Layout(name="hostiles", ratio=1),
        )
        layout["right"].split_column(
            Layout(name="decoy_stats", size=8),
            Layout(name="live_stream", ratio=1),
        )

        # 1. Header
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        head = Text.assemble(
            ("🚨 ULTIMA WEB SEC // ", "bold red"),
            ("BLUE TEAM SOC & ACTIVE COUNTER-MEASURES  ", "bold white"),
            (f"[SYS_TIME: {now}]", "dim cyan"),
        )
        layout["header"].update(Panel(head, border_style="red"))

        # 2. Status & Telemetry
        summary = THREAT_REGISTRY.get_summary()
        stat_table = Table.grid(padding=(0, 1))
        stat_table.add_column(style="dim")
        stat_table.add_column()
        stat_table.add_row("DEFENSE ENGINE:", "[bold green]ONLINE (TARPIT / SHADOW-BAN)[/]")
        stat_table.add_row("DECOY HONEYPOTS:", f"[bold yellow]{len(DECOY_PATHS)} Armados[/]")
        stat_table.add_row("HOSTILE ENTITIES:", f"[bold red]{summary['total_hostiles']} Detectadas[/]")
        stat_table.add_row("DECOY TRAP HITS:", f"[bold magenta]{summary['total_decoy_hits']} Disparados[/]")
        stat_table.add_row("SHIELD PORT:", f"[bold cyan]{self.port}/TCP[/]")
        layout["status"].update(Panel(stat_table, title="[bold cyan]■ 1. DEFENSE TELEMETRY[/]", border_style="cyan"))

        # 3. Hostiles Registry
        hostile_table = Table(expand=True, box=None)
        hostile_table.add_column("IP Hostil", style="bold red")
        hostile_table.add_column("Hits", style="yellow", justify="center")
        hostile_table.add_column("Estado", style="magenta")
        hostile_table.add_column("Causa", style="dim")

        if not summary["hostiles"]:
            hostile_table.add_row("[dim]Sin amenazas detectadas[/]", "-", "[green]SEGURO[/]", "-")
        else:
            for ip, data in list(summary["hostiles"].items())[-8:]:
                reasons = ", ".join(data.get("reasons", []))
                hostile_table.add_row(ip, str(data.get("hits", 1)), "[bold red]SHADOW-BANNED[/]", reasons[:25])
        layout["hostiles"].update(Panel(hostile_table, title="[bold red]■ 2. HOSTILE ENTITIES BAN-LIST[/]", border_style="red"))

        # 4. Decoy Stats
        decoy_text = Text()
        decoy_text.append("Rutas Trampa Activas:\n", style="bold yellow")
        for p in list(DECOY_PATHS)[:6]:
            decoy_text.append(f" › {p}  ", style="dim white")
        decoy_text.append("\nCanarios en Tránsito: AWS_KEY, JWT_SIGNATURE, DB_DUMP", style="dim cyan")
        layout["decoy_stats"].update(Panel(decoy_text, title="[bold yellow]■ 3. HONEYTOKEN CANARIES[/]", border_style="yellow"))

        # 5. Live Stream
        stream_text = Text.from_markup("\n".join(self.logs[-14:]))
        layout["live_stream"].update(Panel(stream_text, title="[bold green]■ 4. INCIDENT RESPONSE STREAM[/]", border_style="green"))

        # 6. Footer
        foot = Text.assemble(
            (" CONTROLES: ", "bold yellow"),
            ("[Ctrl+C] ", "bold white"), ("Apagar Daemon | ", "dim"),
            ("[B] ", "bold white"), ("Disparar Purga Burn | ", "dim"),
            ("[T] ", "bold white"), ("Probar Tarpit Mock", "dim"),
        )
        layout["footer"].update(Panel(foot, border_style="dim"))

        return layout

    def run(self):
        self.start_server()
        with Live(self.build_layout(), refresh_per_second=4, console=console, screen=True) as live:
            try:
                while self.running:
                    # Checar si hubo nuevos hits de atacantes
                    summary = THREAT_REGISTRY.get_summary()
                    current_hits = summary["total_decoy_hits"]
                    if current_hits > self.last_hit_count:
                        diff = current_hits - self.last_hit_count
                        self.last_hit_count = current_hits
                        # Sonido de alarma al detectar intruso
                        play_alert_detected()
                        recent = summary["recent_hits"][-1]
                        self.log(f"[bold red]⚠️ INTRUSO DETECTADO: {recent['ip']} tocó honeypot {recent['path']}![/]")
                        self.log(f"[bold magenta]⚡ CONTRAMEDIDA ACTIVADA: Shadow-ban aplicado a {recent['ip']} (Tarpit 120s)[/]")

                    live.update(self.build_layout())
                    time.sleep(0.25)
            except KeyboardInterrupt:
                self.server.stop()
                console.print("\n[yellow]Blue Team Deck apagado limpiamente.[/]")

if __name__ == "__main__":
    BlueTeamDeck().run()
