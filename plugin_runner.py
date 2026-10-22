#!/usr/bin/env python3
"""plugin_runner.py - Motor de ejecución no destructivo para herramientas de seguridad.
Orquesta Nmap, FFuf, Gobuster, SQLMap y Auditoría pasiva de cabeceras OWASP.
"""

import subprocess
import shutil
import json
import re
import urllib.request
import ssl
from pathlib import Path
from typing import Dict, Any, List

def run_nmap_scan(target: str, ports: str = "F") -> Dict[str, Any]:
    """Ejecuta escaneo rápido de puertos con nmap en formato seguro."""
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return {"error": "nmap no instalado en el sistema"}

    target_clean = re.sub(r"[^a-zA-Z0-9.-]", "", target.replace("https://", "").replace("http://", "").split("/")[0])
    cmd = [nmap_bin, "-T4", f"-{ports}", "--open", target_clean]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        open_ports = []
        for line in res.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
        return {
            "tool": "nmap",
            "target": target_clean,
            "open_ports": open_ports,
            "raw": res.stdout[:500]
        }
    except Exception as e:
        return {"tool": "nmap", "error": str(e)}

def run_gobuster_scan(target: str, wordlist: str = "") -> Dict[str, Any]:
    """Ejecuta enumeración de rutas web con gobuster de forma no invasiva usando wordlist local garantizada."""
    gobuster_bin = shutil.which("gobuster")
    if not gobuster_bin:
        return {"error": "gobuster no instalado"}

    url = target if target.startswith("http") else f"https://{target}"
    
    # Prioridad: wordlist de 20k / full del proyecto garantizada
    wl_20k = Path(__file__).parent / "wordlists" / "routes_20k.txt"
    local_wl = Path(__file__).parent / "wordlists" / "routes_common.txt"
    if not wordlist or not Path(wordlist).exists():
        if wl_20k.exists():
            wordlist = str(wl_20k)
        elif local_wl.exists():
            wordlist = str(local_wl)
        else:
            return {"error": "No se encontró wordlist para el escaneo."}

    cmd = [gobuster_bin, "dir", "-u", url, "-w", wordlist, "-q", "-t", "10", "--timeout", "4s", "-k"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        found_paths = [re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', l).strip() for l in res.stdout.splitlines() if "(Status:" in l]
        return {
            "tool": "gobuster",
            "target": url,
            "found_paths": [p for p in found_paths if p][:20]
        }
    except Exception as e:
        return {"tool": "gobuster", "error": str(e)}

def run_ffuf_scan(target: str, wordlist: str = "") -> Dict[str, Any]:
    """Ejecuta fuzzing web ultrarrápido con ffuf."""
    ffuf_bin = shutil.which("ffuf")
    if not ffuf_bin:
        return {"error": "ffuf no instalado"}

    base_url = target if target.startswith("http") else f"https://{target}"
    url = f"{base_url.rstrip('/')}/FUZZ"

    wl_20k = Path(__file__).parent / "wordlists" / "routes_20k.txt"
    local_wl = Path(__file__).parent / "wordlists" / "routes_common.txt"
    if not wordlist or not Path(wordlist).exists():
        if wl_20k.exists():
            wordlist = str(wl_20k)
        elif local_wl.exists():
            wordlist = str(local_wl)
        else:
            return {"error": "No se encontró wordlist para ffuf."}

    cmd = [ffuf_bin, "-u", url, "-w", wordlist, "-mc", "200,204,301,302,307,401,403", "-s", "-t", "25", "-timeout", "4"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        found = [l.strip() for l in res.stdout.splitlines() if l.strip()]
        return {
            "tool": "ffuf",
            "target": base_url,
            "fuzzed_matches": found[:20]
        }
    except Exception as e:
        return {"tool": "ffuf", "error": str(e)}

def run_whatweb_scan(target: str) -> Dict[str, Any]:
    """Identifica tecnologías, CMS, servidores y librerías web con WhatWeb."""
    whatweb_bin = shutil.which("whatweb")
    if not whatweb_bin:
        return {"error": "whatweb no instalado"}

    url = target if target.startswith("http") else f"https://{target}"
    cmd = [whatweb_bin, "-a", "1", "--color=never", url]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return {
            "tool": "whatweb",
            "target": url,
            "fingerprint": res.stdout.strip()[:400]
        }
    except Exception as e:
        return {"tool": "whatweb", "error": str(e)}

def run_sqlmap_check(target: str) -> Dict[str, Any]:
    """Verificación no destructiva (--batch --banner) con sqlmap."""
    sqlmap_bin = shutil.which("sqlmap")
    if not sqlmap_bin:
        return {"error": "sqlmap no instalado"}

    url = target if target.startswith("http") else f"http://{target}"
    cmd = [sqlmap_bin, "-u", url, "--batch", "--banner", "--risk=1", "--level=1", "--flush-session"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        is_vuln = "is vulnerable" in res.stdout.lower() or "sql injection" in res.stdout.lower()
        return {
            "tool": "sqlmap",
            "target": url,
            "vulnerable": is_vuln,
            "summary": res.stdout[-400:] if res.stdout else "Sin salida"
        }
    except Exception as e:
        return {"tool": "sqlmap", "error": str(e)}

def audit_security_headers(target: str) -> Dict[str, Any]:
    """Auditoría pasiva de cabeceras HTTP de seguridad (OWASP Baseline)."""
    url = target if target.startswith("http") else f"https://{target}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (SecurityAuditor/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            
            checks = {
                "strict-transport-security (HSTS)": "strict-transport-security" in headers,
                "content-security-policy (CSP)": "content-security-policy" in headers,
                "x-frame-options (Anti-Clickjacking)": "x-frame-options" in headers,
                "x-content-type-options": "x-content-type-options" in headers,
                "referrer-policy": "referrer-policy" in headers
            }
            score = int((sum(1 for v in checks.values() if v) / len(checks)) * 100)
            return {
                "tool": "owasp_headers",
                "target": url,
                "score": score,
                "checks": checks,
                "missing": [k for k, v in checks.items() if not v]
            }
    except Exception as e:
        return {"tool": "owasp_headers", "error": str(e)}

def audit_critical_leaks(target: str) -> Dict[str, Any]:
    """Prueba especializada y directa contra exposiciones críticas: .git, .env, backups y sourcemaps."""
    url = target if target.startswith("http") else f"https://{target}"
    base_url = url.rstrip("/")
    
    probes = [
        {"path": "/.git/config", "indicator": "[core]", "risk": "CRITICAL", "desc": "Git Repository Config Exposed"},
        {"path": "/.git/HEAD", "indicator": "ref: refs/", "risk": "CRITICAL", "desc": "Git HEAD Exposed"},
        {"path": "/.env", "indicator": "=", "risk": "CRITICAL", "desc": "Environment Variables File Exposed"},
        {"path": "/.env.local", "indicator": "=", "risk": "CRITICAL", "desc": "Local Env Exposed"},
        {"path": "/.env.production", "indicator": "=", "risk": "CRITICAL", "desc": "Production Env Exposed"},
        {"path": "/app.js.map", "indicator": "mappings", "risk": "HIGH", "desc": "JavaScript Source Map Exposed"},
        {"path": "/bundle.js.map", "indicator": "mappings", "risk": "HIGH", "desc": "Bundle Source Map Exposed"},
        {"path": "/robots.txt", "indicator": "", "risk": "INFO", "desc": "Robots Policy"},
        {"path": "/sitemap.xml", "indicator": "<?xml", "risk": "INFO", "desc": "XML Sitemap"}
    ]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    findings = []
    for p in probes:
        target_path = base_url + p["path"]
        try:
            req = urllib.request.Request(target_path, headers={"User-Agent": "Mozilla/5.0 (SecurityCheck/1.0)"})
            with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
                if r.status == 200:
                    ct = r.headers.get("Content-Type", "").lower()
                    # Descartar si el servidor devuelve HTML genérico SPA para rutas 404
                    if "text/html" in ct and not p["path"].endswith(".html"):
                        body = r.read(300).decode("utf-8", errors="ignore").lower()
                        if "<!doctype html" in body or "<html" in body:
                            continue
                    
                    body_sample = r.read(200).decode("utf-8", errors="ignore")
                    if not p["indicator"] or p["indicator"].lower() in body_sample.lower():
                        findings.append({
                            "path": p["path"],
                            "risk": p["risk"],
                            "description": p["desc"],
                            "content_type": ct,
                            "snippet": body_sample[:100]
                        })
        except Exception:
            pass

    return {
        "tool": "critical_leaks",
        "target": base_url,
        "vulnerabilities_found": len(findings),
        "details": findings
    }

def discover_subdomains(domain: str) -> Dict[str, Any]:
    """Descubrimiento híbrido de subdominios (OSINT Passive Certificate Transparency + HackerTarget + DNS Probing)."""
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    discovered = set()
    sources = []

    # 1. Passive OSINT: HackerTarget HostSearch
    try:
        req = urllib.request.Request(
            f"https://api.hackertarget.com/hostsearch/?q={clean_domain}",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            lines = r.read().decode("utf-8", errors="ignore").strip().split("\n")
            for line in lines:
                if "," in line:
                    host = line.split(",")[0].strip().lower()
                    if host.endswith(clean_domain):
                        discovered.add(host)
            sources.append("HackerTarget")
    except Exception:
        pass

    # 2. Passive OSINT: crt.sh (Certificate Transparency)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            f"https://crt.sh/?q=%25.{clean_domain}&output=json",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.endswith(clean_domain) and "*" not in name:
                        discovered.add(name)
            sources.append("crt.sh")
    except Exception:
        pass

    # 3. Active DNS Verification + Common Dictionary fallback
    import socket
    common_prefixes = ["www", "api", "app", "dev", "test", "staging", "admin", "portal", "cdn", "docs", "beta", "demo", "auth", "mail", "status"]
    for prefix in common_prefixes:
        discovered.add(f"{prefix}.{clean_domain}")

    live_hosts = []
    for host in sorted(list(discovered)):
        try:
            ip = socket.gethostbyname(host)
            live_hosts.append({"subdomain": host, "ip": ip, "live": True})
        except Exception:
            pass

    return {
        "tool": "subdomain_discovery",
        "domain": clean_domain,
        "sources": sources,
        "total_live": len(live_hosts),
        "subdomains": live_hosts
    }

