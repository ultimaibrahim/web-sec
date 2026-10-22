#!/usr/bin/env python3
"""blue_team_shield.py – Active Defense, Tarpitting, Honeypots & Threat Counter-Measures.
Módulo de Contramedidas Defensivas y Guerra Asimétrica para Ultima Web Sec:
- A. Tarpitting (Slow HTTP defense / drenaje de sockets)
- B. Honeytokens & Decoy Endpoints (Cebo, detección y perfilado)
- C. Poisoned Payloads (Gzip Bombs controladas para herramientas agresivas)
- D. Blackholing & Banning Asimétrico (Shadow-ban)
"""

import gzip
import io
import json
import logging
import re
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_LOG = logging.getLogger("blue_team")

# ---------------------------------------------------------------------------
# Estado Dinámico de Amenazas (Threat State)
# ---------------------------------------------------------------------------

class ThreatRegistry:
    """Registro en memoria de atacantes detectados y su nivel de hostilidad."""

    def __init__(self):
        self._lock = threading.Lock()
        self.hostile_ips: Dict[str, Dict[str, Any]] = {}
        self.decoy_hits: List[Dict[str, Any]] = []

    def record_hit(self, ip: str, path: str, user_agent: str, reason: str = "decoy_access"):
        with self._lock:
            now = time.time()
            if ip not in self.hostile_ips:
                self.hostile_ips[ip] = {
                    "first_seen": now,
                    "last_seen": now,
                    "hits": 1,
                    "reasons": [reason],
                    "status": "shadow_banned",
                    "user_agent": user_agent,
                }
            else:
                self.hostile_ips[ip]["hits"] += 1
                self.hostile_ips[ip]["last_seen"] = now
                if reason not in self.hostile_ips[ip]["reasons"]:
                    self.hostile_ips[ip]["reasons"].append(reason)

            self.decoy_hits.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "path": path,
                "reason": reason,
                "ua": user_agent,
            })

    def is_hostile(self, ip: str) -> bool:
        with self._lock:
            return ip in self.hostile_ips

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_hostiles": len(self.hostile_ips),
                "total_decoy_hits": len(self.decoy_hits),
                "hostiles": dict(self.hostile_ips),
                "recent_hits": list(self.decoy_hits[-20:]),
            }


THREAT_REGISTRY = ThreatRegistry()


# ---------------------------------------------------------------------------
# B. Honeytokens & Decoy Endpoints
# ---------------------------------------------------------------------------

# Lista de señuelos atractivos para atacantes automáticos
DECOY_PATHS: Set[str] = {
    "/api/v1/internal_auth",
    "/api/v1/superadmin/token",
    "/backup/admin.sql.gz",
    "/server-status",
    "/actuator/env",
    "/.aws/credentials",
    "/config/database.yml",
    "/phpmyadmin/index.php",
    "/wp-login.php",
}

# Credenciales trampa de alta convicción (Canarios)
HONEY_CREDENTIALS = {
    "AWS_KEY": "AKIAIOSFODNN7EXAMPLETRAP",
    "BEARER_CANARY": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.decoy_trap_signature_active_defense",
    "ADMIN_HASH": "$2a$12$e7r9QhXg5mZ2o3T4K9pWv.trapTokenIbrahimGarcíaDecoy",
}


def is_decoy_path(path: str) -> bool:
    """Valida si la ruta solicitada corresponde a un cebo de contra-inteligencia."""
    clean_path = path.split("?")[0].rstrip("/") or "/"
    return clean_path in DECOY_PATHS or any(clean_path.endswith(d) for d in DECOY_PATHS)


def generate_decoy_response(path: str) -> Dict[str, Any]:
    """Genera respuestas señuelo con tokens canario para rastrear al atacante si los reutiliza."""
    if "admin.sql" in path or "backup" in path:
        return {
            "status": 200,
            "headers": {"Content-Type": "application/x-gzip", "Server": "nginx/1.18.0"},
            "body": b"-- Decoy SQL Dump\n-- CANARY: TRAP_SQL_TOKEN_58921\nCREATE TABLE admin (user VARCHAR(50), pass VARCHAR(255));\n",
        }
    elif "credentials" in path or "env" in path:
        return {
            "status": 200,
            "headers": {"Content-Type": "text/plain", "Server": "Apache/2.4.41"},
            "body": f"[default]\naws_access_key_id = {HONEY_CREDENTIALS['AWS_KEY']}\naws_secret_access_key = trap_secret_99812_trigger_alarm\n".encode(),
        }
    else:
        return {
            "status": 200,
            "headers": {"Content-Type": "application/json", "Server": "Cloudflare"},
            "body": json.dumps({
                "status": "authenticated",
                "role": "system_maintenance",
                "token": HONEY_CREDENTIALS["BEARER_CANARY"],
                "notice": "Internal endpoint for emergency session restore",
            }).encode(),
        }


# ---------------------------------------------------------------------------
# C. Poisoned Payloads (Gzip Decompression Bomb de Contramedida)
# ---------------------------------------------------------------------------

def generate_poisoned_gzip(expansion_mb: int = 100) -> bytes:
    """Genera una carga gzip ultra-comprimida (ej. ~100 KB en tránsito que expande a 100 MB).

    Provoca el colapso de escáneres automáticos que intentan parsear o deserializar
    cuerpos en memoria sin cuota estricta (FFuf, Burp Intruder, scanners en Node/Python).
    """
    buf = io.BytesIO()
    # Escribir ceros altamente compresibles
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as gz:
        chunk = b"0" * (1024 * 1024)  # 1 MB
        for _ in range(expansion_mb):
            gz.write(chunk)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# A. Tarpitting (Slow HTTP Socket Drain)
# ---------------------------------------------------------------------------

def handle_tarpit_client(client_socket: socket.socket, max_duration: int = 120):
    """Mantiene la conexión del atacante abierta indefinidamente enviando datos a cuentagotas.

    Drena sus threads y sockets sin consumir recursos del servidor.
    """
    try:
        # Enviar cabecera chunked
        client_socket.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Server: Ultima-Defensive-Core\r\n"
            b"\r\n"
        )
        start = time.time()
        # Enviar 1 byte cada 10 segundos
        while time.time() - start < max_duration:
            client_socket.sendall(b"1\r\nX\r\n")
            time.sleep(10)
        # Cierre limpio
        client_socket.sendall(b"0\r\n\r\n")
    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# D. Blackholing & Banning Asimétrico (Shadow-Ban)
# ---------------------------------------------------------------------------

def apply_shadow_ban(ip: str, client_socket: socket.socket, mode: str = "tarpit"):
    """Aplica acción de contención asimétrica contra la IP hostil:

    - tarpit: Drena sockets del atacante por 120s.
    - poison: Devuelve bomba gzip para congelar su escáner.
    - silent_drop: Cierra conexión sin responder FIN/RST inmediato o devuelve 200 vacío.
    """
    if mode == "tarpit":
        t = threading.Thread(target=handle_tarpit_client, args=(client_socket, 120), daemon=True)
        t.start()
    elif mode == "poison":
        try:
            payload = generate_poisoned_gzip(expansion_mb=50)
            raw_header = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Encoding: gzip\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n\r\n"
            )
            client_socket.sendall(raw_header.encode("utf-8") + payload)
        except Exception:
            pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
    else:  # silent 200 empty
        try:
            client_socket.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
        except Exception:
            pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Servidor Defensivo de Ejemplo / Micro-Shield Daemon
# ---------------------------------------------------------------------------

class ActiveDefenseShieldServer:
    """Micro-servidor defensivo para interceptar sondas de red y ejecutar contraataque."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8999):
        self.host = host
        self.port = port
        self.running = False
        self._server_sock: Optional[socket.socket] = None

    def start(self):
        self.running = True
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(128)
        _LOG.info("Active Defense Shield Server escuchando en %s:%d", self.host, self.port)

        def _accept_loop():
            while self.running:
                try:
                    conn, addr = self._server_sock.accept()
                    client_ip = addr[0]
                    # Procesar petición en thread efímero
                    threading.Thread(target=self._handle_request, args=(conn, client_ip), daemon=True).start()
                except Exception:
                    break

        threading.Thread(target=_accept_loop, daemon=True).start()

    def _handle_request(self, conn: socket.socket, client_ip: str):
        try:
            conn.settimeout(5.0)
            data = conn.recv(4096).decode("utf-8", errors="ignore")
            if not data:
                conn.close()
                return

            first_line = data.splitlines()[0] if data.splitlines() else ""
            parts = first_line.split()
            method = parts[0] if len(parts) > 0 else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            # Extraer User-Agent
            ua = "Unknown"
            ua_match = re.search(r"User-Agent:\s*([^\r\n]+)", data, re.IGNORECASE)
            if ua_match:
                ua = ua_match.group(1).strip()

            # 1. Comprobar si la IP ya es hostil -> Aplicar Shadow-ban o Tarpit
            if THREAT_REGISTRY.is_hostile(client_ip):
                THREAT_REGISTRY.record_hit(client_ip, path, ua, reason="repeat_hostile_probe")
                apply_shadow_ban(client_ip, conn, mode="tarpit")
                return

            # 2. Comprobar si tocó un Honeypot / Decoy
            if is_decoy_path(path):
                THREAT_REGISTRY.record_hit(client_ip, path, ua, reason="decoy_trap_triggered")
                # Servir cebo con token canario
                decoy = generate_decoy_response(path)
                resp = (
                    f"HTTP/1.1 {decoy['status']} OK\r\n"
                    f"Content-Length: {len(decoy['body'])}\r\n"
                )
                for k, v in decoy["headers"].items():
                    resp += f"{k}: {v}\r\n"
                resp += "\r\n"
                conn.sendall(resp.encode() + decoy["body"])
                conn.close()
                return

            # 3. Tráfico aparentemente normal
            body = b'{"status": "active", "shield": "Ultima Web Sec 4.0"}\n'
            hdr = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            )
            conn.sendall(hdr.encode("utf-8") + body)
            conn.close()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    print("Iniciando micro-shield activo en puerto 8999...")
    shield = ActiveDefenseShieldServer(port=8999)
    shield.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shield.stop()
        print("\nShield apagado.")
