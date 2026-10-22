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
    tcp_timestamps_off: bool
    timezone_utc: bool
    hostname_clean: bool
    current_hostname: str
    score: int
    threat_level: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def check_vpn_tunnel() -> tuple[bool, str]:
    """Revisa si el túnel proton0, wg0 o Tor SOCKS5 está activo."""
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

    # Verificación secundaria: Demonio Tor en 127.0.0.1:9050
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.6)
        res = s.connect_ex(("127.0.0.1", 9050))
        s.close()
        if res == 0:
            return True, "tor:9050"
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
    # Si apunta a 10.2.0.1 (Proton), 1.1.1.1, 9.9.9.9, 127.0.0.1 (Tor DNS/dnscrypt) o 127.0.0.53 con DoT
    is_tunnel_dns = "10.2.0.1" in servers or "10.2.0." in primary or "1.1.1.1" in servers or "9.9.9.9" in servers
    
    # Si Tor SOCKS está activo en 9050, el motor web/recon de la suite resuelve remotamente por SOCKS5 (sin DNS leak en host)
    if not is_tunnel_dns:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", 9050)) == 0:
                    return True, "Tor SOCKS-DNS"
        except Exception:
            pass

    return is_tunnel_dns, primary

def check_ipv6_leak() -> bool:
    """Verifica si IPv6 está bloqueado (evita fuga de IP real)."""
    try:
        req = urllib.request.Request("https://ifconfig.co", headers={"User-Agent": "curl/7.68.0"})
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            # Conectar a Google DNS v6
            s.connect(("2001:4860:4860::8888", 53))
            # Si conecta, IPv6 no está bloqueado -> posible fuga
            return False
        finally:
            s.close()
    except Exception:
        # Si falló la conexión por IPv6, significa que está bloqueado correctamente
        return True

def get_public_ip_info() -> tuple[str, str, str, str]:
    """Obtiene la IP pública e información de geolocalización ligera.
    Si Tor está activo y no hay VPN a nivel de interfaz de red del sistema,
    resuelve la IP de salida de la red Tor para reportar la identidad anónima de la sesión.
    """
    # Si Tor SOCKS está activo y no hay interfaz VPN física levantada, reportar la IP de salida Tor
    vpn_active, vpn_iface = check_vpn_tunnel()
    if vpn_active and vpn_iface.startswith("tor:"):
        try:
            res = subprocess.run(
                ["curl", "-s", "--socks5", "127.0.0.1:9050", "--max-time", "4", "https://check.torproject.org/api/ip"],
                capture_output=True,
                text=True
            )
            if res.returncode == 0 and res.stdout.strip():
                tdata = json.loads(res.stdout)
                tor_ip = tdata.get("IP", "")
                if tor_ip:
                    return tor_ip, "Tor Exit Node", "Tor Onion Network", "Anonymous"
        except Exception:
            pass

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

def check_tcp_timestamps() -> bool:
    """Verifica si TCP timestamps están apagados (evita OS fingerprinting por uptime)."""
    ts_path = Path("/proc/sys/net/ipv4/tcp_timestamps")
    if ts_path.exists():
        try:
            return ts_path.read_text().strip() == "0"
        except Exception:
            pass
    return False

def check_timezone_utc() -> bool:
    """Verifica si la zona horaria del sistema está en UTC (evita geolocalización por timezone)."""
    try:
        res = subprocess.run(["timedatectl"], capture_output=True, text=True, timeout=2)
        if "Time zone: UTC" in res.stdout or "Universal" in res.stdout:
            return True
        # Alternativa leyendo /etc/timezone
        tz_file = Path("/etc/timezone")
        if tz_file.exists() and "etc/utc" in tz_file.read_text().lower():
            return True
    except Exception:
        pass
    import time
    return time.tzname[0].upper() == "UTC"

def check_hostname_privacy() -> tuple[bool, str]:
    """Verifica si el hostname es genérico y no delata el usuario o modelo de máquina."""
    host = socket.gethostname().lower()
    # Si contiene nombres personales, marcas o identificadores
    leaks = ["ibrahim", "ultima", "laptop", "desktop", "macbook", "thinkpad"]
    is_leaking = any(w in host for w in leaks)
    return (not is_leaking), host

def evaluate_privacy() -> PrivacyStatus:
    """Evalúa todos los vectores de privacidad y calcula un score."""
    vpn_ok, vpn_iface = check_vpn_tunnel()
    dns_ok, dns_srv = check_dns_security()
    ipv6_ok = check_ipv6_leak()
    pub_ip, org, country, city = get_public_ip_info()
    mac_ok, mac_addr = check_mac_address()
    tcp_ts_ok = check_tcp_timestamps()
    tz_ok = check_timezone_utc()
    host_ok, host_name = check_hostname_privacy()

    # Cálculo ponderado de Privacy Score (0 a 100)
    score = 0
    if vpn_ok:
        score += 30
    if dns_ok:
        score += 20
    if ipv6_ok:
        score += 10
    if mac_ok:
        score += 10
    if tcp_ts_ok:
        score += 10
    if tz_ok:
        score += 10
    if host_ok:
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
        tcp_timestamps_off=tcp_ts_ok,
        timezone_utc=tz_ok,
        hostname_clean=host_ok,
        current_hostname=host_name,
        score=score,
        threat_level=threat
    )

def enforce_shield_lock(level: str) -> tuple[bool, str]:
    """Valida si los escudos permiten la ejecución del nivel solicitado.
    Para niveles agresivos (Level 3, void, void_plus), exige túnel VPN o interfaz aislada.
    """
    lvl = str(level).strip().lower()
    high_risk_levels = ["3", "level3", "void", "void()", "void_plus", "void_plus()"]
    
    if lvl not in high_risk_levels:
        return True, "Nivel de bajo impacto autorizado."

    status = evaluate_privacy()
    
    # Comprobar si hay túnel activo (VPN, Wireguard, Proton o Tor SOCKS5 local)
    has_tor_socks = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        res = s.connect_ex(("127.0.0.1", 9050))
        if res == 0:
            has_tor_socks = True
        s.close()
    except Exception:
        pass

    if not status.vpn_active and not has_tor_socks:
        msg = (
            f"[CRITICAL ABORT] SHIELD LOCK ENFORCED:\n"
            f"El nivel '{level}' genera tráfico anómalo, mutación destructiva y/o fuzzing masivo.\n"
            f"Se detectó conexión directa en interfaz física sin túnel de anonimato.\n"
            f"• VPN: INACTIVA\n"
            f"• Tor (9050): INACTIVO\n"
            f"• IP Pública Expuesta: {status.public_ip} ({status.isp_org})\n\n"
            f"ACCIÓN REQUERIDA:\n"
            f"1. Levante un túnel VPN (Proton/Wireguard) o inicie el demonio Tor.\n"
            f"2. Se recomienda ejecutar esta suite dentro de una VM aislada (Tails OS / Parrot OS).\n"
            f"3. Para transferir evidencias y volcados, utilice canales cifrados P2P como 'Magic-Wormhole'."
        )
        return False, msg

    return True, f"Escudos verificados para {level}. Túnel activo: {status.vpn_interface if status.vpn_active else 'Tor SOCKS5 (9050)'}"

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
        "TCP Timestamps (OS Uptime)",
        "[bold green]APAGADO (OK)[/]" if status.tcp_timestamps_off else "[bold red]ACTIVO (FUGA UPTIME)[/]",
        "Anti-p0f fingerprinting" if status.tcp_timestamps_off else "sysctl net.ipv4.tcp_timestamps=1"
    )
    table.add_row(
        "Zona Horaria (Timezone)",
        "[bold green]UTC (NEUTRAL)[/]" if status.timezone_utc else "[bold red]LOCAL (FUGA GEO)[/]",
        "UTC" if status.timezone_utc else "Zona local expuesta"
    )
    table.add_row(
        "Hostname Limpio",
        "[bold green]GENÉRICO (OK)[/]" if status.hostname_clean else "[bold red]PERSONAL (EXPUESTO)[/]",
        status.current_hostname
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
