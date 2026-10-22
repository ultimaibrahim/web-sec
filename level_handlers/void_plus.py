# level_handlers/void_plus.py
"""void_plus() – Ultra-High Intensity Destructive & Chaos Suite.
Requires explicit DOUBLE confirmation (Modal confirmation + Token override).
Features:
- Multi-vector concurrent mutation bursts (POST, PUT, PATCH, DELETE)
- Dynamic upload bombs with binary payload variations
- WebSocket connection stress testing
- Automated inverse rollback tracking to restore modified endpoints
- Deep leak scanning across all mutation responses
- Full audit persistence in encrypted vault & SQLite DB
"""
import asyncio
import base64
import random
import string
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from browser_client import fetch
from credential_scanner import scan_text
import storage_vault
from .discover import discover_routes

from .helpers import (
    async_bulk_requests,
    ddos_light,
    rollback_action,
    stealth_headers,
    upload_bomb,
    ws_flood,
    run_amass,
    run_nmap,
    launch_metasploit,
    start_ligolo_tunnel,
    # Red‑Team tool wrappers
    run_findomain,
    run_dnsx,
    run_httpx,
    run_naabu,
    run_nuclei,
    run_nikto,
    run_zap,
    run_sqlmap,
    run_mimikatz,
    run_lazagne,
    run_responder,
    run_crackmapexec,
    run_sharphound,
    run_rubeus,
    run_linpeas,
    run_winpeas,
    run_scoutsuite,
    run_prowler,
    run_kube_hunter,
    run_trufflehog,
    run_wfuzz,
    run_dirsearch,
    run_atomic_red_team,
    run_mitre_navigator,
)
    async_bulk_requests,
    ddos_light,
    rollback_action,
    stealth_headers,
    upload_bomb,
    ws_flood,
    run_amass,
    run_nmap,
    launch_metasploit,
    start_ligolo_tunnel,
)

WHITELIST_PATH = Path(__file__).resolve().parent.parent / "allowed_targets.txt"


def _is_whitelisted(target: str) -> bool:
    if not WHITELIST_PATH.exists():
        return False
    allowed = {line.strip().lower() for line in WHITELIST_PATH.read_text().splitlines() if line.strip()}
    clean = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip().lower()
    return clean in allowed or any(clean.endswith("." + a) for a in allowed)


def run(
    target: str,
    mode: str,
    logger: Any,
    use_browser: bool = False,
    stealth: bool = False,
    double_confirmed: bool = False,
    **kwargs,
) -> Dict[str, Any]:
    """Execute void_plus destructive sequence with double confirmation enforcement."""
    # Enforce strict scope whitelist
    if not _is_whitelisted(target):
        logger.write(f"[bold red]❌ VOID+ ABORTED: Target {target} is NOT in allowed_targets.txt![/]")
        return {"level": "void_plus", "target": target, "status": "ABORTED_NOT_WHITELISTED"}

    # Enforce mandatory double confirmation
    if not double_confirmed:
        logger.write(f"[bold red]❌ VOID+ ABORTED: Target {target} missing required double confirmation![/]")
        return {"level": "void_plus", "target": target, "status": "ABORTED_UNCONFIRMED"}

    logger.write(f"[bold red]☣️ VOID_PLUS() INITIATED: MASSIVE CHAOS SEQUENCE DISPATCHED ON {target}[/]")
    summary: Dict[str, Any] = {
        "level": "void_plus",
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vectors": {},
        "rollbacks": {},
        "creds_found": [],
    }

    headers = stealth_headers() if stealth else {}
    base_url = target.rstrip("/")

    # Dynamic Route & Endpoint Convergence Discovery
    logger.write("[cyan]› Dynamic Convergence: Crawling frontend & JS bundles for active endpoints...[/]")
    discovered_pool = {}
    try:
        discovered_pool = discover_routes(target)
        if discovered_pool:
            logger.write(f"[bold green]  ✓ Discovered {len(discovered_pool)} dynamic endpoints from JS bundles[/]")
            for r, tags in list(discovered_pool.items())[:5]:
                logger.write(f"[dim]    › {r} [{', '.join(tags)}][/]")
        else:
            logger.write("[dim]  (Dynamic discovery yielded 0 client-side endpoints, falling back to heuristic paths)[/]")
    except Exception as d_err:
        logger.write(f"[dim]  (Dynamic discovery bypassed: {d_err})[/]")

    # Resolve dynamic endpoints or fallback to standard routes
    upload_candidates = [r for r, tags in discovered_pool.items() if "upload" in tags]
    target_upload_path = upload_candidates[0] if upload_candidates else "/upload"

    create_candidates = [r for r, tags in discovered_pool.items() if "create" in tags]
    target_bulk_create = create_candidates[0] if create_candidates else "/api/bulk_create"

    update_candidates = [r for r, tags in discovered_pool.items() if "update" in tags]
    target_config = update_candidates[0] if update_candidates else "/api/config"

    delete_candidates = [r for r, tags in discovered_pool.items() if "delete" in tags]
    target_bulk_delete = delete_candidates[0] if delete_candidates else "/api/bulk_delete"

    # 1. High-Concurrency Multi-Vector Mutations (POST, PUT, PATCH, DELETE)
    logger.write(f"[magenta]› Vector 1: Multi-vector concurrent mutation bursts on dynamic routes...[/]")
    bulk_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    payloads = [
        ("POST", f"{base_url}{target_bulk_create}", {"json": [{"id": f"void_{bulk_id}_{i}", "chaos": True} for i in range(100)], "headers": headers}),
        ("PUT", f"{base_url}{target_config}", {"json": {"environment": "chaos_test", "timestamp": time.time()}, "headers": headers}),
        ("PATCH", f"{base_url}/api/settings", {"json": {"debug_override": True}, "headers": headers}),
        ("DELETE", f"{base_url}{target_bulk_delete}", {"headers": headers}),
    ]

    def _run_coroutine(coro):
        try:
            return asyncio.run(coro)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

    try:
        burst_resps = _run_coroutine(async_bulk_requests(payloads))
        for idx, resp in enumerate(burst_resps):
            if isinstance(resp, Exception):
                logger.write(f"[dim]  Vector {idx} err: {resp}[/]")
                summary["vectors"][f"burst_{idx}"] = str(resp)
            else:
                code = getattr(resp, "status_code", None)
                logger.write(f"[green]  Vector {idx} status: {code}[/]")
                summary["vectors"][f"burst_{idx}"] = code

                # Scan response for leaks
                body = getattr(resp, "text", "")
                hits = scan_text(body)
                for _, items in hits.items():
                    summary["creds_found"].extend(items)
    except Exception as exc:
        logger.write(f"[red]! Burst error: {exc}[/]")

    # 2. Upload Bomb Stress Test (30 dynamic files)
    logger.write(f"[magenta]› Vector 2: Upload bomb stress testing on {target_upload_path} (multi-payload)...[/]")
    try:
        ub_res = upload_bomb(target, upload_path=target_upload_path, count=30, use_browser=use_browser, stealth=stealth)
        ub_success = sum(1 for _, code in ub_res if code and 200 <= code < 300)
        logger.write(f"[cyan]  Upload bomb: {ub_success}/{len(ub_res)} responses received[/]")
        summary["vectors"]["upload_bomb"] = {"total": len(ub_res), "successful": ub_success}
    except Exception as exc:
        logger.write(f"[red]! Upload bomb error: {exc}[/]")

    # 3. WebSocket Upgrade Flood
    logger.write("[magenta]› Vector 3: Simulated WebSocket connection stress...[/]")
    try:
        ws_res = _run_coroutine(ws_flood(f"{base_url}/ws", connections=15, interval_ms=150))
        ws_upgrades = sum(1 for _, code, _ in ws_res if code == 101)
        logger.write(f"[cyan]  WebSocket stress: {ws_upgrades}/{len(ws_res)} upgrades[/]")
        summary["vectors"]["ws_flood"] = {"total": len(ws_res), "upgrades": ws_upgrades}
    except Exception as exc:
        logger.write(f"[red]! WebSocket stress error: {exc}[/]")

    # 4. Latency Under Pressure
    logger.write("[magenta]› Vector 4: Latency degradation test (20 rapid probes)...[/]")
    try:
        ddos_res = ddos_light(target, endpoint="/ping", count=20, use_browser=use_browser, stealth=stealth)
        avg_lat = sum(r[1] for r in ddos_res) / len(ddos_res) if ddos_res else 0.0
        logger.write(f"[cyan]  Mean latency: {avg_lat:.3f}s across {len(ddos_res)} probes[/]")
        summary["vectors"]["ddos_latency"] = avg_lat
    except Exception as exc:
        logger.write(f"[red]! Latency probe error: {exc}[/]")

    # 5. Automated Rollback Phase
    logger.write("[yellow]› Vector 5: Attempting safety rollbacks for modified resources...[/]")
    try:
        rb_res = rollback_action("POST", f"{base_url}/api/bulk_create", use_browser=use_browser, stealth=stealth)
        rb_code = getattr(rb_res, "status_code", str(rb_res))
        logger.write(f"[green]  Rollback bulk_create: status {rb_code}[/]")
        summary["rollbacks"]["bulk_create"] = rb_code
        # ---------------------------------------------------------------------------
        # Extended Red‑Team tool integrations (ext_ flags)
        # ---------------------------------------------------------------------------
        ext_tool_map = {
            "ext_findomain": run_findomain,
            "ext_dnsx": run_dnsx,
            "ext_httpx": run_httpx,
            "ext_naabu": run_naabu,
            "ext_nuclei": run_nuclei,
            "ext_nikto": run_nikto,
            "ext_zap": run_zap,
            "ext_sqlmap": run_sqlmap,
            "ext_mimikatz": run_mimikatz,
            "ext_lazagne": run_lazagne,
            "ext_responder": run_responder,
            "ext_cme": run_crackmapexec,
            "ext_sharphound": run_sharphound,
            "ext_rubeus": run_rubeus,
            "ext_linpeas": run_linpeas,
            "ext_winpeas": run_winpeas,
            "ext_scoutsuite": run_scoutsuite,
            "ext_prowler": run_prowler,
            "ext_kubehunter": run_kube_hunter,
            "ext_trufflehog": run_trufflehog,
            "ext_wfuzz": run_wfuzz,
            "ext_dirsearch": run_dirsearch,
            "ext_atomic": run_atomic_red_team,
            "ext_navigator": run_mitre_navigator,
        }
        for flag, func in ext_tool_map.items():
            if kwargs.get(flag):
                try:
                    # Simple heuristics to pass appropriate arguments
                    if flag in ["ext_findomain", "ext_dnsx", "ext_naabu", "ext_nuclei", "ext_kubehunter"]:
                        result = func(target)
                    elif flag in ["ext_httpx", "ext_sqlmap", "ext_zap", "ext_wfuzz", "ext_dirsearch"]:
                        result = func(target)
                    elif flag in ["ext_mimikatz", "ext_lazagne", "ext_responder", "ext_sharphound", "ext_rubeus", "ext_scoutsuite", "ext_prowler", "ext_navigator"]:
                        result = func()
                    elif flag == "ext_cme":
                        module = kwargs.get("cme_module", "smb")
                        extra = kwargs.get("cme_extra", [])
                        result = func(module, target, *extra)
                    elif flag == "ext_linpeas":
                        path = kwargs.get("linpeas_path", "/tmp/linpeas.sh")
                        result = func(path)
                    elif flag == "ext_winpeas":
                        path = kwargs.get("winpeas_path", "/tmp/winpeas.exe")
                        result = func(path)
                    elif flag == "ext_scoutsuite":
                        profile = kwargs.get("scout_profile", "")
                        result = func(profile)
                    elif flag == "ext_prowler":
                        provider = kwargs.get("prowler_provider", "aws")
                        result = func(provider)
                    elif flag == "ext_trufflehog":
                        repo = kwargs.get("trufflehog_repo", ".")
                        result = func(repo)
                    elif flag == "ext_wfuzz":
                        wordlist = kwargs.get("wfuzz_wordlist", "")
                        result = func(target, wordlist)
                    elif flag == "ext_dirsearch":
                        wordlist = kwargs.get("dirsearch_wordlist", "")
                        result = func(target, wordlist)
                    elif flag == "ext_atomic":
                        technique = kwargs.get("atomic_id", "")
                        result = func(technique)
                    else:
                        result = {"error": "Unsupported flag"}
                    summary["vectors"][flag] = result.get("returncode", result.get("error", "unknown"))
                    logger.write(f"[cyan]  Ext tool {flag} executed, result: {summary["vectors"][flag]}")
                except Exception as e:
                    summary["vectors"][flag] = str(e)
                    logger.write(f"[red]! Ext tool {flag} error: {e}")
    except Exception as exc:
        logger.write(f"[dim]  Rollback bulk_create: {exc}[/]")

    # 6. Final Leak Scanning & SQLite Archival
    summary["creds_found"] = sorted(list(set(summary["creds_found"])))
    if summary["creds_found"]:
        logger.write(f"[bold red]⚡ CRITICAL: {len(summary['creds_found'])} credentials leaked during chaos![/]")
        for c in summary["creds_found"]:
            storage_vault.save_finding(target, tool="void_plus", finding_type="chaos_leak", content=str(c), encrypt=True)

    storage_vault.save_scan_record(
        target,
        mode=mode,
        level="void_plus",
        summary=f"VOID+ chaos completed. Vectors: {list(summary['vectors'].keys())}, Leaks: {len(summary['creds_found'])}"
    )

    logger.write("[bold green]✔ VOID_PLUS() execution cycle finalized.[/]")
    return summary
