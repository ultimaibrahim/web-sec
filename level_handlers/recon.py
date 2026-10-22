# level_handlers/recon.py
"""Recon – Comprehensive Non‑Destructive Intelligence Front.
Implements:
- Flag p: Asynchronous TCP port scanning (scan_ports)
- Flag m: Aggressive mass subdomain enumeration (mass_subdomains)
- Flag d: Deep recursive endpoint and form crawl (deep_crawl)
- Flag F: Wappalyzer-grade technology fingerprinting (advanced_fingerprint)
- Flag D: Safe database dump inspection (download_database)
- Flag v: Persistence to SQLite DB & AES-256 encrypted vault (storage_vault)
- Flag r: Multi-format reporting (HTML & pure-Python PDF)
- Flag s: Anti-WAF stealth & ghost jitter timing
- Flag P: Auto-Tor / SOCKS5 proxy routing
"""
import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from browser_client import fetch
from credential_scanner import scan_text
import storage_vault

from .helpers import (
    advanced_fingerprint,
    deep_crawl,
    download_database,
    enumerate_endpoints,
    export_html_report,
    export_pdf_report,
    extract_credentials_from_response,
    fingerprint_target,
    load_recon_config,
    mass_subdomains,
    proxy_headers,
    rate_limited_fetch,
    scan_ports,
    stealth_headers,
)


def run(
    target: str,
    mode: str,
    logger: Any,
    use_browser: bool = False,
    stealth: bool = False,
    flags: Optional[Dict[str, bool]] = None,
) -> Dict[str, Any]:
    """Execute Recon intelligence actions based on flags.
    Parameters:
        target: Target URL or IP
        mode: WebSec / WebScrap
        logger: TextLog or InterceptLogger
        use_browser: Route requests through Playwright fetch
        stealth: Apply jitter delays & randomized evasion headers
        flags: Feature flags dict (p, m, d, F, D, v, r, s, P)
    """
    app = getattr(logger, "app", None) or getattr(logger, "outer", None)
    progress_bar = getattr(logger, "progress_bar", None)
    if not progress_bar and app:
        progress_bar = getattr(app, "progress_bar", None)

    def _update_progress(pct: float, stage: str):
        if progress_bar:
            try:
                if app and hasattr(app, "call_from_thread") and callable(getattr(app, "call_from_thread")):
                    app.call_from_thread(progress_bar.set_progress, pct, stage)
                else:
                    progress_bar.set_progress(pct, stage)
            except Exception:
                pass

    # Resolve active flags
    app_flags = getattr(app, "recon_flags", {}) if app else {}
    active_flags = dict(app_flags)
    if flags:
        active_flags.update(flags)

    # Allow single letter flags or full names
    flag_p = active_flags.get("p", active_flags.get("scan_ports", False))
    flag_m = active_flags.get("m", active_flags.get("subdomains", active_flags.get("mass_subdomains", False)))
    flag_d = active_flags.get("d", active_flags.get("deep_crawl", False))
    flag_F = active_flags.get("F", active_flags.get("fingerprint", active_flags.get("advanced_fingerprint", False)))
    flag_D = active_flags.get("D", active_flags.get("dump_db", active_flags.get("download_db", False)))
    flag_v = active_flags.get("v", active_flags.get("vault_store", True))  # Default on for vault persistence
    flag_r = active_flags.get("r", active_flags.get("export_report", False))
    flag_s = active_flags.get("s", active_flags.get("stealth", stealth))
    flag_P = active_flags.get("P", active_flags.get("proxy_tor", False))

    clean_target = target if target.startswith("http") else f"https://{target}"
    logger.write(f"[bold cyan]🔍 RECON INTELLIGENCE DISPATCHED ON:[/] [white]{clean_target}[/]")
    logger.write(f"[dim]Flags: p={flag_p} m={flag_m} d={flag_d} F={flag_F} D={flag_D} v={flag_v} r={flag_r} s={flag_s} P={flag_P}[/]")

    _update_progress(5.0, "RECON INITIALIZING")

    # 0. Proxy / Tor Setup
    proxy_info = proxy_headers(stealth=flag_s, auto_tor=flag_P)
    if proxy_info.get("auto_triggered") or proxy_info.get("tor_active"):
        logger.write(f"[magenta]🛡️ Evasion Shield:[/] {proxy_info['reason']}")

    results: Dict[str, Any] = {
        "mode": "recon",
        "target": clean_target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "flags": active_flags,
        "endpoints": [],
        "creds": [],
        "technologies": [],
        "ports": {},
        "subdomains": [],
        "db_path": None,
        "tor_active": proxy_info.get("tor_active", False),
    }

    # 1. Basic Common Endpoints Baseline
    _update_progress(15.0, "PROBING BASELINE ENDPOINTS")
    logger.write("[dim]› Probing common API & security endpoints...[/]")
    endpoints_map = enumerate_endpoints(clean_target, use_browser=use_browser, stealth=flag_s)
    for url, resp in endpoints_map.items():
        if resp and getattr(resp, "status_code", None) == 200:
            results["endpoints"].append(url)
            text = getattr(resp, "text", "")
            scanned = scan_text(text)
            for _, items in scanned.items():
                results["creds"].extend(items)
            results["creds"].extend(extract_credentials_from_response(text))

    def _run_coroutine(coro):
        try:
            return asyncio.run(coro)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

    # 2. Flag 'p': Port Scanning
    if flag_p:
        _update_progress(30.0, "SCANNING TCP PORTS")
        logger.write("[cyan]› Probing active TCP ports (async)...[/]")
        try:
            ports = _run_coroutine(scan_ports(clean_target, stealth=flag_s))
            results["ports"] = ports
            open_p = [p for p, s in ports.items() if s == "open"]
            logger.write(f"[green]✔ Port scan complete: {len(open_p)} open ports found {open_p[:8]}[/]")
        except Exception as e:
            logger.write(f"[red]! Port scan error: {e}[/]")

    # 3. Flag 'm': Mass Subdomains Enumeration
    if flag_m:
        _update_progress(45.0, "ENUMERATING SUBDOMAINS")
        logger.write("[cyan]› Executing aggressive mass subdomain enumeration (OSINT + DNS)...[/]")
        try:
            sub_res = _run_coroutine(mass_subdomains(clean_target, stealth=flag_s))
            results["subdomains"] = sub_res.get("subdomains", [])
            logger.write(f"[green]✔ Subdomains found: {len(results['subdomains'])} live hosts ({', '.join(sub_res.get('sources', []))})[/]")
        except Exception as e:
            logger.write(f"[red]! Subdomain enumeration error: {e}[/]")

    # 4. Flag 'F': Advanced Technology Fingerprint (Wappalyzer clone)
    if flag_F:
        _update_progress(60.0, "FINGERPRINTING TECH STACK")
        logger.write("[cyan]› Fingerprinting tech stack (Wappalyzer pure-Python engine)...[/]")
        try:
            fp_res = advanced_fingerprint(clean_target, use_browser=use_browser, stealth=flag_s)
            results["technologies"] = fp_res.get("technologies", [])
            results["fingerprint"] = {
                "server": fp_res.get("server", ""),
                "powered_by": fp_res.get("powered_by", ""),
                "title": fp_res.get("title", ""),
            }
            tech_names = [t["name"] for t in results["technologies"]]
            logger.write(f"[green]✔ Tech detected:[/] [bold white]{', '.join(tech_names) or 'Standard Stack'}[/]")
        except Exception as e:
            logger.write(f"[red]! Fingerprinting error: {e}[/]")

    # 5. Flag 'd': Deep Crawl & Leak Extraction
    if flag_d:
        _update_progress(75.0, "DEEP RECURSIVE CRAWLING")
        logger.write("[cyan]› Deep recursive crawl on target (endpoints, forms, secrets)...[/]")
        try:
            crawl_res = deep_crawl(clean_target, max_depth=2, max_pages=20, use_browser=use_browser, stealth=flag_s, logger=logger)
            for ep in crawl_res.get("endpoints", []):
                if ep not in results["endpoints"]:
                    results["endpoints"].append(ep)
            for c in crawl_res.get("creds", []):
                if c not in results["creds"]:
                    results["creds"].append(c)
            results["forms"] = crawl_res.get("forms", [])
            logger.write(f"[green]✔ Deep crawl complete: {len(crawl_res.get('endpoints', []))} URLs, {len(crawl_res.get('forms', []))} forms[/]")
        except Exception as e:
            logger.write(f"[red]! Deep crawl error: {e}[/]")

    # 6. Flag 'D': Database Dump Download
    if flag_D:
        _update_progress(85.0, "PROBING DATABASE DUMPS")
        logger.write("[magenta]› Probing database dumps (/dump, /backup)...[/]")
        db_path = download_database(clean_target, "/dump", use_browser=use_browser, stealth=flag_s)
        if db_path:
            results["db_path"] = str(db_path)
            logger.write(f"[green]✔ Database snapshot captured -> {db_path.name}[/]")

    # Deduplicate creds
    results["creds"] = sorted(list(set(results["creds"])))
    if results["creds"]:
        logger.write(f"[bold red]⚡ CRITICAL: {len(results['creds'])} credentials / tokens identified![/]")

    # 7. Flag 'v': Store in SQLite Database & Encrypted Vault
    if flag_v:
        _update_progress(92.0, "ARCHIVING FINDINGS TO VAULT")
        try:
            storage_vault.save_recon_results(clean_target, results, encrypt=True)
            logger.write("[yellow]✔ Findings cataloged in SQLite Database (websec_vault.db)[/]")
        except Exception as e:
            logger.write(f"[red]! SQLite storage error: {e}[/]")

    # 8. Flag 'r': Generate HTML and PDF Reports
    if flag_r:
        _update_progress(96.0, "GENERATING EXECUTIVE REPORTS")
        logger.write("[cyan]› Exporting executive HTML and PDF reports...[/]")
        out_dir = Path("outputs")
        out_dir.mkdir(exist_ok=True)
        ts_slug = int(time.time())
        safe_slug = clean_target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")

        html_out = out_dir / f"recon_{safe_slug}_{ts_slug}.html"
        pdf_out = out_dir / f"recon_{safe_slug}_{ts_slug}.pdf"

        try:
            export_html_report(results, html_out)
            export_pdf_report(results, pdf_out)
            results["reports"] = {"html": str(html_out), "pdf": str(pdf_out)}
            logger.write(f"[bold green]✔ Reports generated:[/] {html_out.name} & {pdf_out.name}")
        except Exception as e:
            logger.write(f"[red]! Report export error: {e}[/]")

    _update_progress(100.0, "RECON MISSION COMPLETE")
    logger.write(f"[bold green]✔ Recon cycle concluded for {clean_target}[/]")
    return results
