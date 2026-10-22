# level_handlers/level3.py
"""Level 3 – Destructive (opt‑in) with advanced features.
Implements multi‑vector async payloads, sub‑domain discovery, credential storage,
rollback, stealth mode and optional ghost mode.
"""
import asyncio
import random
from typing import Dict, Any

import requests
from browser_client import fetch
try:
    from textual.widgets import RichLog as TextLog
except ImportError:
    from textual.widgets import TextLog

from credential_scanner import scan_text
from .helpers import (
    async_bulk_requests,
    ws_flood,
    upload_bomb,
    temp_token_generator,
    rollback_action,
    stealth_headers,
    ddos_light,
)

def run(
    target: str,
    mode: str,
    logger: TextLog,
    use_browser: bool = False,
    stealth: bool = False,
) -> Dict[str, Any]:
    """Execute Level 3 actions.
    Parameters:
        target – base URL.
        mode – current mode (WebSec / WebScrap).
        logger – TextLog widget.
        use_browser – route requests through Playwright `fetch`.
        stealth – add randomised headers to evade WAFs.
    Returns a dict summarising actions.
    """
    logger.write(f"[red]Level 3 – Ejecutando acciones destructivas en {target}[/]")
    results: Dict[str, Any] = {}

    headers = stealth_headers() if stealth else {}

    # -----------------------------------------------------------------
    # 1️⃣ Multi‑vector async payloads (POST, PUT, PATCH)
    # -----------------------------------------------------------------
    payloads = [
        ("POST", f"{target.rstrip('/')}/api/create", {"json": {"name": "test_multi", "value": random.randint(0, 1000)}}),
        ("PUT", f"{target.rstrip('/')}/api/update", {"json": {"id": 1, "value": random.randint(0, 1000)}}),
        ("PATCH", f"{target.rstrip('/')}/api/patch", {"json": {"id": 1, "flag": True}}),
    ]
    # Add headers to each request dict
    for p in payloads:
        p[2]["headers"] = headers
    try:
        async_resps = asyncio.run(async_bulk_requests(payloads))
        for idx, resp in enumerate(async_resps):
            if isinstance(resp, Exception):
                logger.write(f"[red]Vector {idx} error: {resp}")
                results[f"vector_{idx}"] = str(resp)
            else:
                logger.write(f"[green]Vector {idx} status: {resp.status_code}")
                results[f"vector_{idx}"] = resp.status_code
    except Exception as e:
        logger.write(f"[red]Async bulk error: {e}")

    # -----------------------------------------------------------------
    # 2️⃣ Sub‑domain / API discovery (simple list of common paths)
    # -----------------------------------------------------------------
    common_paths = ["/admin", "/debug", "/swagger.json", "/api/docs"]
    for p in common_paths:
        url = f"{target.rstrip('/')}{p}"
        try:
            resp = fetch("GET", url, headers=headers, timeout=8) if use_browser else requests.get(url, headers=headers, timeout=8)
            if resp.status_code == 200:
                logger.write(f"[yellow]Endpoint discovered: {url}")
                results[f"discover_{p}"] = "200"
        except Exception:
            pass

    # -----------------------------------------------------------------
    # 3️⃣ Credential persistence (scan INSERT/DELETE responses)
    # -----------------------------------------------------------------
    # For demo we reuse the INSERT URL from earlier payloads
    insert_url = f"{target.rstrip('/')}/api/create"
    try:
        resp = fetch("POST", insert_url, json={"name": "cred_scan", "value": 0}, headers=headers, timeout=8) if use_browser else requests.post(insert_url, json={"name": "cred_scan", "value": 0}, headers=headers, timeout=8)
        creds = scan_text(resp.text)
        if creds:
            # Store in vault via app reference (available as logger.app)
            vault_key = f"{target}_creds_{len(logger.app.vault.all())}"
            logger.app.vault.set(vault_key, creds)
            logger.write(f"[yellow]Credencial guardada en vault como `{vault_key}`")
            results["creds"] = creds
    except Exception as e:
        logger.write(f"[red]Cred scan error: {e}")

    # -----------------------------------------------------------------
    # 4️⃣ Optional DDoS light test (20 GETs to /ping)
    # -----------------------------------------------------------------
    ddos_res = ddos_light(target, endpoint="/ping", use_browser=use_browser, stealth=stealth)
    avg_latency = sum(r[1] for r in ddos_res) / len(ddos_res)
    logger.write(f"[magenta]DDoS Light avg latency: {avg_latency:.2f}s ({len(ddos_res)} hits)")
    results["ddos_avg_latency"] = avg_latency

    # -----------------------------------------------------------------
    # 5️⃣ Optional rollback (if INSERT succeeded)
    # -----------------------------------------------------------------
    if results.get("vector_0") and isinstance(results["vector_0"], int) and 200 <= results["vector_0"] < 300:
        # Assume vector_0 was the INSERT, rollback with DELETE
        rb = rollback_action("POST", insert_url, use_browser=use_browser, stealth=stealth)
        logger.write(f"[green]Rollback response: {getattr(rb, 'status_code', rb)}")
        results["rollback"] = getattr(rb, "status_code", str(rb))

    # -----------------------------------------------------------------
    # 6️⃣ Optional WebSocket flood (demo, 10 connections)
    # -----------------------------------------------------------------
    ws_url = f"{target.rstrip('/')}/ws"
    ws_res = asyncio.run(ws_flood(ws_url, connections=10, interval_ms=250))
    success = sum(1 for _, code, _ in ws_res if code == 101)
    logger.write(f"[cyan]WebSocket flood: {success}/{len(ws_res)} successful upgrades")
    results["ws_success"] = success

    # -----------------------------------------------------------------
    # 7️⃣ Optional Upload bomb (20 files)
    # -----------------------------------------------------------------
    ub_res = upload_bomb(target, count=20, use_browser=use_browser, stealth=stealth)
    ub_success = sum(1 for _, code in ub_res if code and 200 <= code < 300)
    logger.write(f"[cyan]Upload bomb: {ub_success}/{len(ub_res)} uploads succeeded")
    results["upload_success"] = ub_success

    return {"level": 3, "target": target, "actions": results}
