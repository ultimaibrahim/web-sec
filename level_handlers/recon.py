# level_handlers/recon.py
"""Recon – Non‑destructive front.
Implements endpoint enumeration, credential extraction, and optional
database download. All actions are read‑only (GET/HEAD) and respect the
whitelist and stealth options.
"""

import asyncio
from typing import Dict, Any, List

import requests
from browser_client import fetch

from credential_scanner import scan_text

from .helpers import (
    enumerate_endpoints,
    extract_credentials_from_response,
    download_database,
    stealth_headers,
    rate_limited_fetch,
    scan_ports,
    enumerate_subdomains,
    fingerprint_target,
    shodan_lookup,
    export_html_report,
)


def run(
    target: str,
    mode: str,
    logger,  # TextLog widget
    use_browser: bool = False,
    stealth: bool = False,
) -> Dict[str, Any]:
    """Execute Recon actions.
    Returns a dict with discovered endpoints, extracted credentials and
    optional DB download path.
    """
    logger.write(f"[cyan]Recon – Enumerando endpoints en {target}[/]")
    # 1️⃣ Enumerate common endpoints (rate‑limited)
    endpoints = enumerate_endpoints(target, use_browser=use_browser, stealth=stealth)
    discovered: List[str] = []
    creds: List[str] = []
    for url, resp in endpoints.items():
        if resp and getattr(resp, "status_code", None) == 200:
            discovered.append(url)
            # Scan response text for credentials
            text = getattr(resp, "text", "")
            # Use generic scanner for tokens + our extra regexes
            scanned = scan_text(text)
            for _, items in scanned.items():
                creds.extend(items)
            # Extra regex extraction
            creds.extend(extract_credentials_from_response(text))
    # Store credentials in vault
    if creds:
        vault = getattr(logger.app, "vault", None)
        if vault is not None:
            key = f"{target}_recon_{len(vault.all())}"
            vault.set(key, creds)
            logger.write(f"[yellow]Credenciales encontradas guardadas en vault bajo `{key}`[/]")
    # 2️⃣ Optional DB download (prompt via logger? here we auto‑download if endpoint exists)
    db_path: Any = None
    db_endpoint = "/dump"
    if f"{target.rstrip('/')}{db_endpoint}" in endpoints:
        logger.write(f"[magenta]Intentando descargar base de datos desde {db_endpoint}[/]")
        db_path = download_database(target, db_endpoint, use_browser=use_browser, stealth=stealth)
        if db_path:
            logger.write(f"[green]Base de datos guardada en {db_path}[/]")
    result = {
        "mode": "recon",
        "target": target,
        "endpoints": discovered,
        "creds": creds,
        "db_path": str(db_path) if db_path else None,
    }
    return result
