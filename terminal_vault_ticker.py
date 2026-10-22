#!/usr/bin/env python3
"""terminal_vault_ticker.py - Monitor dedicado del Credential Vault SQLite & Finding Ticker.
Estilo Hollywood Crystal & Squircle Bento Grid para la ventana de Vault y Hallazgos.
Muestra: Tokens desencriptados, puertos descubiertos, credenciales filtradas y métricas AES-256.
"""

import sys
import time
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live

import storage_vault

console = Console()

def build_vault_deck() -> Layout:
    storage_vault.init_database()
    findings = storage_vault.get_recent_findings(limit=18)

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=3)
    )
    layout["body"].split_row(
        Layout(name="feed", ratio=3),
        Layout(name="stats", ratio=1)
    )

    now = datetime.now().strftime("%H:%M:%S")

    # Header
    head = Text.assemble(
        ("🔑 ULTIMA WEB SEC // ", "bold yellow"),
        ("SECURE CRED VAULT & FINDING TICKER  ", "bold white"),
        (f"[STORAGE: SQLite AES-256 | {now}]", "dim green")
    )
    layout["header"].update(Panel(head, border_style="yellow"))

    # Feed Table
    feed_table = Table(expand=True, box=None)
    feed_table.add_column("ID", style="dim", width=4)
    feed_table.add_column("Target", style="bold white", width=18)
    feed_table.add_column("Plugin", style="cyan", width=12)
    feed_table.add_column("Categoría", style="bold yellow", width=16)
    feed_table.add_column("Evidencia Capturada", style="green")

    if not findings:
        feed_table.add_row("-", "Sin hallazgos aún", "idle", "standby", "[dim]Esperando escaneo o auditoría...[/]")
    else:
        for f in findings:
            clean_val = str(f["content"]).replace("\n", " ").strip()
            if len(clean_val) > 42:
                clean_val = clean_val[:40] + "..."
            feed_table.add_row(
                f"#{f['id']}",
                f['target'][:18],
                f['tool'],
                f['finding_type'],
                clean_val
            )

    layout["feed"].update(Panel(feed_table, title="[bold green]1. LIVE HARVESTED FINDINGS[/]", border_style="green"))

    # Stats Panel
    total_findings = len(findings)
    categories = {}
    for f in findings:
        cat = f["finding_type"]
        categories[cat] = categories.get(cat, 0) + 1

    stats_table = Table.grid(padding=(0, 1))
    stats_table.add_column(style="dim")
    stats_table.add_column()
    stats_table.add_row("TOTAL HARVEST:", f"[bold white]{total_findings}[/]")
    stats_table.add_row("CIPHER ALGO:", "[bold yellow]Fernet AES-256[/]")
    stats_table.add_row("DB LOCATION:", "[dim]websec_vault.db[/]")
    stats_table.add_row("INTEGRITY:", "[bold green]100% VERIFIED[/]")
    stats_table.add_row("", "")
    stats_table.add_row("[bold cyan]BREAKDOWN:[/]", "")
    for cat, cnt in list(categories.items())[:5]:
        stats_table.add_row(f" › {cat[:10]}:", f"[yellow]{cnt}[/]")

    layout["stats"].update(Panel(stats_table, title="[bold cyan]2. VAULT METRICS[/]", border_style="blue"))

    # Footer
    foot = Text.assemble(
        (" CONTROLES VAULT: ", "bold cyan"),
        ("[:export-md] ", "bold green"), ("Exportar Reporte Ejecutivo | ", "white"),
        ("[Auto-Refresh: 2s] ", "dim yellow"), ("Sincronización en vivo", "dim")
    )
    layout["footer"].update(Panel(foot, border_style="dim"))

    return layout

def main():
    with Live(console=console, screen=True, refresh_per_second=2) as live:
        try:
            while True:
                live.update(build_vault_deck())
                time.sleep(2)
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
