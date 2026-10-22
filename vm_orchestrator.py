#!/usr/bin/env python3
"""vm_orchestrator.py - Gestor de Laboratorio y Máquinas Virtuales de Alta Seguridad.
Estándar Crystal & Squircle Bento Grid para gestión de:
1. 🛡️ Parrot OS Security (Estación Ofensiva Persistente con web-sec)
2. 🧅 Tails OS (Escudo Amnésico Volátil en RAM)
3. 🏛️ Debian Minimal Vault (Bóveda Cifrada Air-Gapped sin internet)
"""

import sys
import os
import subprocess
import shutil
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

console = Console()

VM_DIR = Path("/home/ultimau/vms")
ISOS_DIR = VM_DIR / "isos"
DISKS_DIR = VM_DIR / "disks"

ISOS = {
    "debian": {
        "name": "Debian Minimal Netinst (Air-Gapped Vault)",
        "file": ISOS_DIR / "debian-netinst.iso",
        "url": "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.7.0-amd64-netinst.iso",
        "disk": DISKS_DIR / "vault_debian.qcow2",
        "disk_size": "20G",
        "desc": "Bóveda cifrada LUKS desconectada de la red (-net none)."
    },
    "tails": {
        "name": "Tails OS (Amnesic Incognito Live)",
        "file": ISOS_DIR / "tails.iso",
        "url": "https://download.tails.net/tails/stable/tails-amd64-7.15/tails-amd64-7.15.iso",
        "disk": None,
        "desc": "100% en RAM vía Tor forzoso. Cero huella en disco."
    },
    "parrot": {
        "name": "Parrot OS Security Edition",
        "file": ISOS_DIR / "parrot-security.iso",
        "url": "https://deb.parrot.sh/parrot/iso/6.2/Parrot-security-6.2_amd64.iso",
        "disk": DISKS_DIR / "parrot_security.qcow2",
        "disk_size": "35G",
        "desc": "Estación de ataque y scraping persistente con herramientas completas."
    }
}

def check_dirs():
    ISOS_DIR.mkdir(parents=True, exist_ok=True)
    DISKS_DIR.mkdir(parents=True, exist_ok=True)

def show_menu():
    console.clear()
    head = Text.assemble(
        ("⚡ ULTIMA WEB SEC // ", "bold cyan"),
        ("HARDENED VIRTUALIZATION MATRIX (QEMU/KVM)  ", "bold white"),
        ("[AIR-GAPPED & COVERT]", "bold yellow")
    )
    console.print(Panel(head, border_style="cyan"))

    table = Table(title="[bold green]MÁQUINAS VIRTUALES Y BÓVEDAS DISPONIBLES[/]", border_style="blue", expand=True)
    table.add_column("ID", style="bold yellow", width=4)
    table.add_column("Sistema Operativo", style="bold white", width=26)
    table.add_column("Rol en la Arquitectura", style="cyan", width=28)
    table.add_column("Estado ISO / Disco", style="green")

    for k, info in ISOS.items():
        iso_status = "[bold green]LISTA (Descargada)[/]" if info["file"].exists() else "[dim red]No descargada[/]"
        disk_status = ""
        if info["disk"]:
            disk_status = " | Disco: [bold green]Creado[/]" if info["disk"].exists() else " | Disco: [yellow]Pendiente[/]"
        table.add_row(
            k,
            info["name"],
            info["desc"][:26] + "...",
            f"ISO: {iso_status}{disk_status}"
        )

    console.print(table)

    actions = Text()
    actions.append("\nACCIONES DISPONIBLES:\n", style="bold yellow")
    actions.append("  [1] Descargar ISO seleccionada (Descarga segura y resume)\n", style="white")
    actions.append("  [2] Iniciar Parrot OS Security (Estación de Scraping y Web-Sec)\n", style="white")
    actions.append("  [3] Iniciar Tails OS en RAM (Amnésico con Tor forzado)\n", style="white")
    actions.append("  [4] Iniciar Debian Minimal Vault (Bóveda Air-Gapped sin internet)\n", style="white")
    actions.append("  [5] Crear / Resetear disco virtual (.qcow2)\n", style="white")
    actions.append("  [q] Salir\n", style="dim")
    console.print(Panel(actions, title="[bold yellow]PANEL DE CONTROL[/]", border_style="yellow"))

def download_iso(key: str):
    info = ISOS.get(key)
    if not info:
        console.print("[red]ID inválido.[/]")
        return
    dest = info["file"]
    if dest.exists():
        console.print(f"[yellow]La ISO ya existe en:[/] {dest}")
        ans = Prompt.ask("¿Deseas descargarla nuevamente?", choices=["s", "n"], default="n")
        if ans == "n":
            return

    console.print(f"[bold cyan]Iniciando descarga de {info['name']}...[/]")
    console.print(f"[dim]URL:[/] {info['url']}")
    console.print(f"[dim]Destino:[/] {dest}\n")

    cmd = ["curl", "-L", "-C", "-", "--progress-bar", "-o", str(dest), info["url"]]
    try:
        subprocess.run(cmd, check=True)
        console.print(f"[bold green]✔ ISO descargada exitosamente en:[/] {dest}")
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]! Error en la descarga:[/] {e}")

def ensure_disk(key: str) -> Path:
    info = ISOS[key]
    disk = info["disk"]
    if not disk.exists():
        console.print(f"[yellow]Creando disco dinámico qcow2 de {info['disk_size']} para {info['name']}...[/]")
        subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk), info["disk_size"]], check=True)
        console.print(f"[green]✔ Disco creado:[/] {disk}")
    return disk

def launch_parrot():
    info = ISOS["parrot"]
    disk = info["disk"]
    if not disk.exists():
        console.print("[red]El disco virtual parrot_security.qcow2 no fue encontrado en /home/ultimau/vms/disks/[/]")
        return
    console.print(f"[bold green]⚡ Lanzando Parrot Security en QEMU/KVM con UEFI (OVMF)...[/]")
    
    # Soporte UEFI obligatorio para discos GPT modernos de Parrot OS
    ovmf_bios = "/usr/share/ovmf/OVMF.fd"
    cmd = [
        "qemu-system-x86_64",
        "-enable-kvm",
        "-cpu", "host",
        "-smp", "4",
        "-m", "6G"
    ]
    if Path(ovmf_bios).exists():
        cmd.extend(["-bios", ovmf_bios])

    cmd.extend([
        "-drive", f"file={disk},if=virtio,format=qcow2",
        "-vga", "virtio",
        "-display", "gtk,gl=on",
        "-device", "virtio-serial-pci",
        "-chardev", "qemu-vdagent,id=vdagent,name=vdagent,clipboard=on",
        "-device", "virtserialport,chardev=vdagent,name=com.redhat.spice.0",
        "-net", "nic,model=virtio",
        "-net", "user,dns=1.1.1.1",
        "-usb",
        "-device", "usb-tablet"
    ])
    subprocess.Popen(cmd)
    console.print("[green]✔ Parrot Security iniciado con soporte UEFI (OVMF) y aceleración KVM.[/]")

def launch_tails():
    info = ISOS["tails"]
    if not info["file"].exists():
        console.print("[red]Primero descarga la ISO de Tails OS (Opción 1).[/]")
        return
    console.print(f"[bold green]🧅 Lanzando Tails OS Amnésico 100% en RAM...[/]")
    cmd = [
        "qemu-system-x86_64",
        "-enable-kvm",
        "-cpu", "host",
        "-smp", "4",
        "-m", "4G",
        "-cdrom", str(info["file"]),
        "-boot", "d",
        "-vga", "virtio",
        "-display", "gtk,gl=on",
        "-net", "nic,model=virtio",
        "-net", "user,dns=1.1.1.1",
        "-usb",
        "-device", "usb-tablet"
    ]
    subprocess.Popen(cmd)
    console.print("[green]✔ Tails OS iniciado en RAM. Todo rastro desaparecerá al cerrar.[/]")

def launch_vault():
    info = ISOS["debian"]
    disk = info["disk"]
    if not disk.exists():
        console.print("[red]El disco virtual vault_debian.qcow2 no existe.[/]")
        return
    console.print(f"[bold cyan]🏛️ Lanzando Bóveda Debian Minimal AIR-GAPPED (Usuario: debian / Clave: toor)...[/]")
    cmd = [
        "qemu-system-x86_64",
        "-enable-kvm",
        "-cpu", "host",
        "-smp", "2",
        "-m", "2G",
        "-drive", f"file={disk},if=virtio,format=qcow2",
        "-vga", "virtio",
        "-display", "gtk",
        "-net", "none",
        "-usb",
        "-device", "usb-tablet"
    ]
    subprocess.Popen(cmd)
    console.print("[green]✔ Bóveda iniciada (100% aislada de red). Credenciales: debian / toor (o root / toor).[/]")

def main():
    check_dirs()
    while True:
        show_menu()
        choice = Prompt.ask("\nSelecciona una opción", default="1")
        if choice == "1":
            os_choice = Prompt.ask("¿Cuál ISO descargar?", choices=["debian", "tails", "parrot"], default="debian")
            download_iso(os_choice)
            Prompt.ask("\nPresiona [ENTER] para continuar...")
        elif choice == "2":
            launch_parrot()
            Prompt.ask("\nPresiona [ENTER] para continuar...")
        elif choice == "3":
            launch_tails()
            Prompt.ask("\nPresiona [ENTER] para continuar...")
        elif choice == "4":
            launch_vault()
            Prompt.ask("\nPresiona [ENTER] para continuar...")
        elif choice == "5":
            disk_choice = Prompt.ask("¿Qué disco inicializar?", choices=["debian", "parrot"], default="debian")
            ensure_disk(disk_choice)
            Prompt.ask("\nPresiona [ENTER] para continuar...")
        elif choice in ("q", "Q", "exit"):
            console.print("[yellow]Saliendo de la Matriz de Virtualización.[/]")
            break

if __name__ == "__main__":
    main()
