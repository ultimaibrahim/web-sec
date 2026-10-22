#!/usr/bin/env python3
"""counter_intel.py - Sistema de Contra-Vigilancia, Kill-Switch y Protocolo 'Dead Drop' (Burn Sequence).
Maneja detección de honeytokens, rotación de emergencia de identidad y evacuación cifrada de evidencias.
"""

import os
import shutil
import subprocess
import socket
import tempfile
from pathlib import Path
from datetime import datetime
from sound_effects import play_alert_detected, play_burn_sequence

def emergency_kill_switch():
    """Corta inmediatamente toda la conectividad de red para evitar triangulación."""
    play_burn_sequence()
    # 1. Tumbar interfaces de red activas
    for iface in ["wlo1", "wlan0", "eth0", "tun0", "proton0", "wg0"]:
        try:
            subprocess.run(["sudo", "ip", "link", "set", iface, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)
        except Exception:
            pass

    # 2. Bloquear todo el tráfico saliente por iptables (Null-route)
    try:
        subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)
    except Exception:
        pass

def rotate_identity_and_disappear() -> dict:
    """Cambia MAC, hostname, y limpia cachés de sesión volátiles para reaparecer como nueva entidad."""
    actions = []
    
    # 1. Rotar MAC
    wifi_iface = None
    try:
        res = subprocess.run(["ip", "-br", "link"], capture_output=True, text=True, timeout=2)
        for line in res.stdout.splitlines():
            if any(k in line for k in ["wl", "wlo", "wlan"]):
                wifi_iface = line.split()[0]
                break
        if wifi_iface and shutil.which("macchanger"):
            subprocess.run(["sudo", "macchanger", "-r", wifi_iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            actions.append(f"MAC aleatorizada en {wifi_iface}")
    except Exception:
        pass

    # 2. Rotar Hostname
    new_host = f"node-{os.urandom(2).hex()}"
    try:
        subprocess.run(["sudo", "hostname", new_host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)
        actions.append(f"Hostname rotado a {new_host}")
    except Exception:
        pass

    # 3. Limpiar buffers temporales y memoria de sesión
    for p in Path("/tmp").glob("websec_*"):
        try:
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            actions.append("Caché efímera /tmp purgada")
        except Exception:
            pass

    return {"status": "disappeared", "actions": actions}

def secure_dead_drop_evac(vault_db_path: str = "websec_vault.db") -> dict:
    """Protocolo 'Dead Drop': Cifra la base de datos de auditoría con clave en memoria efímera,
    destruye el archivo original del disco (shredding) y prepara el paquete para extracción P2P segura.
    """
    src_db = Path(vault_db_path)
    if not src_db.exists():
        return {"error": "No hay base de datos de auditoría que evacuar."}

    # 1. Empaquetar y cifrar en memoria con contraseña efímera
    import secrets
    from cryptography.fernet import Fernet
    import base64
    import hashlib

    passphrase = secrets.token_urlsafe(16)
    key = base64.urlsafe_b64encode(hashlib.sha256(passphrase.encode()).digest())
    fernet = Fernet(key)

    raw_data = src_db.read_bytes()
    encrypted_blob = fernet.encrypt(raw_data)

    dead_drop_file = Path(tempfile.gettempdir()) / f"deaddrop_{datetime.now().strftime('%H%M%S')}.pkg"
    dead_drop_file.write_bytes(encrypted_blob)

    # 2. Shredding (Sobrescritura segura del archivo original antes de borrarlo)
    try:
        if shutil.which("shred"):
            subprocess.run(["shred", "-u", "-z", "-n", "3", str(src_db)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        else:
            # Sobrescritura manual en Python
            length = len(raw_data)
            src_db.write_bytes(os.urandom(length))
            src_db.unlink()
    except Exception:
        if src_db.exists():
            src_db.unlink()

    return {
        "status": "evacuated",
        "dead_drop_package": str(dead_drop_file),
        "decryption_key": passphrase,
        "instructions": "Transfiera este archivo por Magic-Wormhole antes de apagar la VM."
    }
