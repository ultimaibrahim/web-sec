#!/usr/bin/env python3
"""storage_vault.py - Módulo de persistencia SQLite, cifrado AES-256 y reportes Markdown."""

import sqlite3
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from cryptography.fernet import Fernet

DB_PATH = Path(__file__).parent / "websec_vault.db"
KEY_FILE = Path(__file__).parent / ".vault.key"

def _get_or_create_key() -> bytes:
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes().strip()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    KEY_FILE.chmod(0o600)
    return key

def encrypt_data(plaintext: str) -> str:
    key = _get_or_create_key()
    f = Fernet(key)
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")

def decrypt_data(ciphertext: str) -> str:
    key = _get_or_create_key()
    f = Fernet(key)
    return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")

def init_database():
    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    target TEXT,
                    tool TEXT,
                    finding_type TEXT,
                    content TEXT,
                    is_encrypted INTEGER DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    target TEXT,
                    mode TEXT,
                    level TEXT,
                    summary TEXT
                )
            """)
    finally:
        conn.close()

def save_finding(target: str, tool: str, finding_type: str, content: str, encrypt: bool = False):
    init_database()
    saved_content = encrypt_data(content) if encrypt else content
    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO findings (timestamp, target, tool, finding_type, content, is_encrypted) VALUES (?, ?, ?, ?, ?, ?)",
                (time.time(), target, tool, finding_type, saved_content, 1 if encrypt else 0)
            )
    finally:
        conn.close()

def save_scan_record(target: str, mode: str, level: str, summary: str):
    init_database()
    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scan_history (timestamp, target, mode, level, summary) VALUES (?, ?, ?, ?, ?)",
                (time.time(), target, mode, level, summary)
            )
    finally:
        conn.close()

def save_recon_results(target: str, data: Dict[str, Any], encrypt: bool = False):
    """Persist structured Recon intelligence findings to SQLite & Encrypted Vault."""
    init_database()
    # 1. Save extracted credentials / leaks
    for cred in data.get("creds", []):
        save_finding(target, tool="recon_crawler", finding_type="credential_leak", content=str(cred), encrypt=True)

    # 2. Save open ports
    ports = data.get("ports", {})
    open_ports = [p for p, s in ports.items() if s == "open"]
    if open_ports:
        save_finding(target, tool="recon_portscan", finding_type="open_ports", content=f"Open: {open_ports}", encrypt=False)

    # 3. Save subdomains
    subs = data.get("subdomains", [])
    if subs:
        sub_names = [s.get("host", str(s)) if isinstance(s, dict) else str(s) for s in subs]
        save_finding(target, tool="recon_subdomains", finding_type="subdomains", content=json.dumps(sub_names), encrypt=False)

    # 4. Save tech stack
    techs = data.get("technologies", [])
    if techs:
        save_finding(target, tool="recon_fingerprint", finding_type="technologies", content=json.dumps(techs), encrypt=False)

    # 5. Save summary record
    summary = f"Recon audit: {len(open_ports)} open ports, {len(subs)} subdomains, {len(data.get('endpoints', []))} endpoints, {len(data.get('creds', []))} leaks"
    save_scan_record(target, mode=data.get("mode", "Recon"), level="recon", summary=summary)


def get_recent_findings(limit: int = 15) -> List[Dict[str, Any]]:
    init_database()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        results = []
        for r in rows:
            content = decrypt_data(r["content"]) if r["is_encrypted"] else r["content"]
            results.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "target": r["target"],
                "tool": r["tool"],
                "finding_type": r["finding_type"],
                "content": content
            })
        return results
    finally:
        conn.close()

def export_markdown_report(output_dir: Optional[Path] = None) -> Path:
    init_database()
    if output_dir is None:
        output_dir = Path(__file__).parent / "outputs"
    output_dir.mkdir(exist_ok=True)
    report_file = output_dir / f"audit_report_{int(time.time())}.md"

    findings = get_recent_findings(50)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        scans = conn.cursor().execute("SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT 20").fetchall()
    finally:
        conn.close()

    lines = [
        "# 🛡️ Web-Sec Executive Security & Reconnaissance Report",
        f"**Fecha de generación:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total de hallazgos archivados:** {len(findings)}",
        "",
        "## 1. Historial Reciente de Misiones",
        "| Fecha | Objetivo | Modo | Nivel | Resumen |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ]
    for s in scans:
        date_str = time.strftime('%H:%M:%S', time.localtime(s["timestamp"]))
        lines.append(f"| {date_str} | `{s['target']}` | {s['mode']} | {s['level']} | {s['summary']} |")

    lines.extend([
        "",
        "## 2. Hallazgos y Credenciales Extraídas",
        "| ID | Herramienta | Tipo | Objetivo | Detalle |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ])
    for f in findings:
        detail = f["content"].replace("\n", " ")[:60]
        lines.append(f"| #{f['id']} | {f['tool']} | `{f['finding_type']}` | `{f['target']}` | {detail}... |")

    report_file.write_text("\n".join(lines), encoding="utf-8")
    return report_file
