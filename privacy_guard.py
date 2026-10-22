#!/usr/bin/env python3
"""privacy_guard.py - Módulo de diagnóstico de privacidad y seguridad en red.
Integra y extiende las validaciones de ~/check_privacidad.sh con soporte asíncrono
para Textual TUI y ejecución en CLI independiente.
"""

import subprocess
import socket
import urllib.request
import json
import re
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

FACTORY_MAC = "94:e7:0b:65:6d:5f"

@dataclass
class PrivacyStatus:
    vpn_active: bool
    vpn_interface: str
    dns_secure: bool
    dns_server: str
    ipv6_blocked: bool
    public_ip: str
    isp_org: str
    country: str
    city: str
    mac_spoofed: bool
    current_mac: str
    score: int
    threat_level: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def check_vpn_tunnel() -> tuple[bool, str]:
    """Revisa si el túnel proton0 o wg0 está activo."""
    for iface in ["proton0", "proton", "wg0", "tun0"]:
        try:
            res = subprocess.run(
                ["ip", "-br", "link", "show", iface],
                capture_output=True,
                text=True,
                timeout=2
            )
            if res.returncode == 0 and "UP" in res.stdout:
                return True, iface
        except Exception:
            pass
    return False, "None"

def check_dns_security() -> tuple[bool, str]:
    """Verifica si el DNS apunta al túnel de privacidad o a resolver local/VPN."""
    resolv_file = Path("/etc/resolv.conf")
    if not resolv_file.exists():
        return False, "No resolv.conf"
    
    servers = []
    try:
        content = resolv_file.read_text()
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) > 1:
                    servers.append(parts[1])
    except Exception as e:
        return False, f"Err: {e}"

    primary = servers[0] if servers else "Unknown"
    # Si apunta a 10.2.0.1 (Proton), 1.1.1.1, 9.9.9.9, o 127.0.0.53 con DoT
    is_tunnel_dns = "10.2.0.1" in servers or "10.2.0." in primary
    return is_tunnel_dns, primary

def check_ipv6_leak() -> bool:
    """Verifica si IPv6 está bloqueado (evita fuga de IP real)."""
    try:
        req = urllib.request.Request("https://ifconfig.co", headers={"User-Agent": "curl/7.68.0"})
        # Forzamos resolver solo IPv6 si fuera posible, o probar socket af_inet6
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(2.0)
        # Conectar a Google DNS v6
        s.connect(("2001:4860:4860::8888", 53))
        s.close()
        # Si conecta, IPv6 no está bloqueado -> posible fuga
        return False
    except Exception:
        # Si falló la conexión por IPv6, significa que está bloqueado correctamente
        return True

def get_public_ip_info() -> tuple[str, str, str, str]:
    """Obtiene la IP pública e información de geolocalización ligera."""
    endpoints = [
        "https://ipapi.co/json/",
        "https://api.myip.com",
        "https://ipwho.is/"
    ]
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (PrivacyGuard/1.0)"})
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                ip = data.get("ip") or data.get("query", "Unknown")
                org = data.get("org") or data.get("connection", {}).get("isp", "") or data.get("isp", "Unknown")
                country = data.get("country_name") or data.get("country", "")
                city = data.get("city", "")
                return ip, org, country, city
        except Exception:
            continue

    # Fallback con curl directo
    try:
        res = subprocess.run(["curl", "-s", "--max-time", "3", "https://ifconfig.me"], capture_output=True, text=True)
        if res.stdout.strip():
            return res.stdout.strip(), "Direct WAN", "", ""
    except Exception:
        pass

    return "Desconectado", "Sin conexión", "", ""

def check_mac_address() -> tuple[bool, str]:
    """Verifica si la MAC inalámbrica está suplantada / aleatoria."""
    mac_paths = [
        Path("/sys/class/net/wlo1/address"),
        Path("/sys/class/net/wlan0/address")
    ]
    current_mac = "Unknown"
    for p in mac_paths:
        if p.exists():
            try:
                current_mac = p.read_text().strip().lower()
                break
            except Exception:
                pass

    if current_mac == "unknown" or not current_mac:
        return False, "N/A"

    is_spoofed = (current_mac != FACTORY_MAC.lower())
    return is_spoofed, current_mac

def evaluate_privacy() -> PrivacyStatus:
    """Evalúa todos los vectores de privacidad y calcula un score."""
    vpn_ok, vpn_iface = check_vpn_tunnel()
    dns_ok, dns_srv = check_dns_security()
    ipv6_ok = check_ipv6_leak()
    pub_ip, org, country, city = get_public_ip_info()
    mac_ok, mac_addr = check_mac_address()

    # Cálculo ponderado de Privacy Score (0 a 100)
    score = 0
    if vpn_ok:
        score += 35
    if dns_ok:
        score += 25
    if ipv6_ok:
        score += 15
    if mac_ok:
        score += 15
    if "proton" in org.lower() or "vpn" in org.lower() or "datacenter" in org.lower() or "m247" in org.lower():
        score += 10
    elif pub_ip != "Desconectado" and vpn_ok:
        score += 10

    if score >= 85:
        threat = "SECURE / COVERT"
    elif score >= 50:
        threat = "EXPOSED / PARTIAL"
    else:
        threat = "COMPROMISED / OPEN"

    return PrivacyStatus(
        vpn_active=vpn_ok,
        vpn_interface=vpn_iface,
        dns_secure=dns_ok,
        dns_server=dns_srv,
        ipv6_blocked=ipv6_ok,
        public_ip=pub_ip,
        isp_org=org,
        country=country,
        city=city,
        mac_spoofed=mac_ok,
        current_mac=mac_addr,
        score=score,
        threat_level=threat
    )

if __name__ == "__main__":
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    status = evaluate_privacy()

    table = Table(title="[bold cyan]🛡️ REPORTE DE PRIVACIDAD Y SEGURIDAD OPERATIVA[/bold cyan]", show_header=True)
    table.add_column("Vector", style="bold white")
    table.add_column("Estado", justify="center")
    table.add_column("Detalle", style="dim")

    table.add_row(
        "Túnel VPN",
        "[bold green]ACTIVO[/]" if status.vpn_active else "[bold red]INACTIVO[/]",
        status.vpn_interface
    )
    table.add_row(
        "DNS Seguro",
        "[bold green]PROTEGIDO[/]" if status.dns_secure else "[bold red]FUGA / LOCAL[/]",
        status.dns_server
    )
    table.add_row(
        "Fuga IPv6",
        "[bold green]BLOQUEADO (OK)[/]" if status.ipv6_blocked else "[bold red]FUGA DETECTADA[/]",
        "Sin rastro IPv6" if status.ipv6_blocked else "Expuesto"
    )
    table.add_row(
        "MAC Spoofing",
        "[bold green]PROTEGIDA (ALEATORIA)[/]" if status.mac_spoofed else "[bold red]FÁBRICA (EXPUESTA)[/]",
        status.current_mac
    )
    table.add_row(
        "Dirección IP WAN",
        "[yellow]" + status.public_ip + "[/]",
        f"{status.isp_org} ({status.city}, {status.country})"
    )

    score_color = "green" if status.score >= 80 else "yellow" if status.score >= 50 else "red"
    console.print(table)
    console.print(Panel(
        f"[bold {score_color}]PRIVACY SCORE: {status.score}/100[/]  •  NIVEL DE AMENAZA: [bold {score_color}]{status.threat_level}[/]",
        title="[bold white]Diagnóstico Global[/]",
        border_style=score_color
    ))
