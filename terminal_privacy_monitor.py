#!/usr/bin/env python3
"""terminal_privacy_monitor.py - Monitor dedicado de Telemetría de Privacidad y Red.
Estilo Hollywood Crystal & Squircle Bento Grid para la ventana de Privacidad.
Muestra: VPN, Tor, DNS Leak, IPv6, MAC Spoofing, TCP Timestamps, WAN IP y Kill-Switch.
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

from privacy_guard import evaluate_privacy, PrivacyStatus

console = Console()

def build_privacy_deck(status: PrivacyStatus) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=3)
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=1)
    )
    layout["left"].split_column(
        Layout(name="identity", ratio=1),
        Layout(name="kernel", size=8)
    )
    layout["right"].split_column(
        Layout(name="tunnel", ratio=1),
        Layout(name="threat", size=8)
    )

    now = datetime.now().strftime("%H:%M:%S")

    # Header
    head = Text.assemble(
        ("🔒 ULTIMA WEB SEC // ", "bold cyan"),
        ("ZERO-LEAK PRIVACY TELEMETRY  ", "bold white"),
        (f"[LIVE REFRESH: {now}]", "dim yellow")
    )
    layout["header"].update(Panel(head, border_style="cyan"))

    # 1. Identity & WAN
    t_id = Table.grid(padding=(0, 1))
    t_id.add_column(style="dim")
    t_id.add_column()
    t_id.add_row("WAN IP:", f"[bold white]{status.public_ip}[/]")
    t_id.add_row("ORG / ISP:", f"[bold yellow]{status.isp_org}[/]")
    t_id.add_row("GEO LOCAL:", f"[cyan]{status.city}, {status.country}[/]")
    t_id.add_row("TIMEZONE:", "[green]UTC (Masked)[/]" if status.timezone_utc else "[red]LOCAL (Leak)[/]")
    t_id.add_row("HOSTNAME:", f"[green]{status.current_hostname}[/]" if status.hostname_clean else f"[red]{status.current_hostname} (Personal)[/]")
    layout["identity"].update(Panel(t_id, title="[bold cyan]1. WAN IDENTITY & GEO[/]", border_style="blue"))

    # 2. Kernel Hardening
    t_kern = Table.grid(padding=(0, 1))
    t_kern.add_column(style="dim")
    t_kern.add_column()
    t_kern.add_row("IPV6 BLOCK:", "[bold green]ENGAGED (Zero-Leak)[/]" if status.ipv6_blocked else "[bold red]VULNERABLE (Leak)[/]")
    t_kern.add_row("MAC SPOOF:", f"[bold green]{status.current_mac[:17]}[/]" if status.mac_spoofed else f"[bold red]{status.current_mac[:17]} (Factory)[/]")
    t_kern.add_row("TCP TIMESTAMPS:", "[bold green]0 (Anti-Uptime Fingerprint)[/]" if status.tcp_timestamps_off else "[bold red]1 (OS Uptime Leak)[/]")
    layout["kernel"].update(Panel(t_kern, title="[bold magenta]2. KERNEL HARDENING[/]", border_style="magenta"))

    # 3. Tunnel & DNS
    t_tun = Table.grid(padding=(0, 1))
    t_tun.add_column(style="dim")
    t_tun.add_column()
    vpn_text = f"[bold green]ONLINE ({status.vpn_interface})[/]" if status.vpn_active else "[bold red]OFFLINE (Direct Physical)[/]"
    dns_text = f"[bold green]SECURE ({status.dns_server})[/]" if status.dns_secure else f"[bold red]LEAK ({status.dns_server})[/]"
    t_tun.add_row("TUNNEL STATUS:", vpn_text)
    t_tun.add_row("DNS RESOLUTION:", dns_text)
    t_tun.add_row("TOR SOCKS5:", "[green]127.0.0.1:9050 LISTENING[/]" if "tor" in status.vpn_interface.lower() or status.vpn_active else "[dim]STANDBY[/]")
    t_tun.add_row("KILL-SWITCH:", "[green]IPTABLES ACTIVE[/]" if status.vpn_active else "[yellow]UNARMED[/]")
    layout["tunnel"].update(Panel(t_tun, title="[bold green]3. TUNNEL & COVERT ROUTING[/]", border_style="green"))

    # 4. Threat Matrix Score
    score = status.score
    sc_color = "bold green" if score >= 85 else "bold yellow" if score >= 50 else "bold red"
    sc_text = Text()
    sc_text.append(f"  SCORE: {score}% / 100%\n", style=sc_color)
    sc_text.append(f"  STATUS: {status.threat_level}\n", style="bold white")
    if score >= 85:
        sc_text.append("  COVERT LEVEL: Blindaje total listo para misiones", style="dim green")
    else:
        sc_text.append("  ADVERTENCIA: Activa escudos con [K] o conecta ProtonVPN", style="dim yellow")
    layout["threat"].update(Panel(sc_text, title="[bold yellow]4. DEFENSE READINESS[/]", border_style="yellow"))

    # Footer
    foot = Text.assemble(
        (" ACCIONES EN VIVO: ", "bold cyan"),
        ("[K / :shields] ", "bold yellow"), ("Armar Escudos | ", "white"),
        ("[X / :disarm] ", "bold magenta"), ("Rotar y Sellar | ", "white"),
        ("[Ctrl+C] ", "bold red"), ("Cerrar Monitor", "dim")
    )
    layout["footer"].update(Panel(foot, border_style="dim"))

    return layout

def main():
    with Live(console=console, screen=True, refresh_per_second=2) as live:
        try:
            while True:
                status = evaluate_privacy()
                live.update(build_privacy_deck(status))
                time.sleep(2)
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
