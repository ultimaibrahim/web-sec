# level_handlers/helpers.py
"""Utility helpers for Level 3, void(), void_plus and Recon front.
All functions are lightweight and provide robust pure-Python fallbacks
along with optional integration for external OSINT and security binaries.
"""
import asyncio
import base64
import json
import os
import random
import re
import shutil
import socket
import ssl
import string
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

# External tool wrappers

def run_amass(target: str, flags: dict) -> dict:
    """
    Execute Amass enumeration if available.
    Returns a dict with stdout, stderr, and returncode or error information.
    """
    bin_path = shutil.which("amass")
    if not bin_path:
        return {"error": "Amass binary not found in PATH"}
    args = [bin_path, "enum", "-d", target]
    if flags.get("ext_amass_brute"):
        args.append("-brute")
    # Additional flags can be extended here
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}


def run_nmap(target: str, flags: dict) -> dict:
    """
    Run Nmap scan with optional aggressive flags.
    Returns XML output and scan metadata.
    """
    bin_path = shutil.which("nmap")
    if not bin_path:
        return {"error": "Nmap binary not found in PATH"}
    args = [bin_path, "-oX", "-", target]
    if flags.get("ext_nmap_stealth"):
        args.extend(["-sS", "-T3"])
    if flags.get("ext_nmap_full"):
        args.append("-A")
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        return {"raw_xml": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}


def launch_metasploit(resource: str, target: str) -> dict:
    """Launch Metasploit console with a one‑liner command (destructive)."""
    bin_path = shutil.which("msfconsole")
    if not bin_path:
        return {"error": "Metasploit console not found"}
    commands = f"use exploit/multi/handler; set PAYLOAD {resource}; set LHOST {target}; run"
    args = [bin_path, "-q", "-x", commands]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

# Red‑Team tool wrappers (external binaries)

def run_findomain(domain: str) -> dict:
    """Run Findomain to enumerate subdomains. Returns stdout string or error."""
    bin_path = shutil.which("findomain")
    if not bin_path:
        return {"error": "findomain not found"}
    args = [bin_path, "-t", domain]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_dnsx(domain: str) -> dict:
    """Run DNSX for DNS resolution/enumeration."""
    bin_path = shutil.which("dnsx")
    if not bin_path:
        return {"error": "dnsx not found"}
    args = [bin_path, "-d", domain]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_httpx(url: str) -> dict:
    """Run httpx for HTTP probing. Returns JSON output if -json flag is used."""
    bin_path = shutil.which("httpx")
    if not bin_path:
        return {"error": "httpx not found"}
    args = [bin_path, "-u", url, "-json"]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_naabu(target: str) -> dict:
    """Run naabu port scanner against a target host or CIDR."""
    bin_path = shutil.which("naabu")
    if not bin_path:
        return {"error": "naabu not found"}
    args = [bin_path, "-host", target]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_nuclei(target: str, templates: str = "") -> dict:
    """Run Nuclei against target with optional template directory."""
    bin_path = shutil.which("nuclei")
    if not bin_path:
        return {"error": "nuclei not found"}
    args = [bin_path, "-target", target]
    if templates:
        args.extend(["-t", templates])
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_nikto(host: str) -> dict:
    """Run Nikto web scanner on a host."""
    bin_path = shutil.which("nikto")
    if not bin_path:
        return {"error": "nikto not found"}
    args = [bin_path, "-h", host]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_zap(host: str) -> dict:
    """Run OWASP ZAP in headless mode against a host."""
    bin_path = shutil.which("zaproxy") or shutil.which("zap")
    if not bin_path:
        return {"error": "ZAP binary not found"}
    args = [bin_path, "-daemon", "-host", host]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_sqlmap(url: str) -> dict:
    """Run sqlmap against a URL to detect SQL injection."""
    bin_path = shutil.which("sqlmap")
    if not bin_path:
        return {"error": "sqlmap not found"}
    args = [bin_path, "-u", url, "--batch", "--output-dir=./sqlmap_output"]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

# Windows/Linux post‑exploitation tools (may require manual install)

def run_mimikatz(arguments: str = "") -> dict:
    """Execute mimikatz if binary is present. Arguments can be passed as a string."""
    bin_path = shutil.which("mimikatz")
    if not bin_path:
        return {"error": "mimikatz not found"}
    args = [bin_path]
    if arguments:
        args.extend(arguments.split())
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_lazagne(arguments: str = "") -> dict:
    """Run LaZagne to dump credentials. Requires python package or binary."""
    bin_path = shutil.which("lazagne")
    if not bin_path:
        return {"error": "lazagne not found"}
    args = [bin_path]
    if arguments:
        args.extend(arguments.split())
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_responder(arguments: str = "") -> dict:
    """Run Responder for LLMNR/NBT‑NS poisoning."""
    bin_path = shutil.which("Responder")
    if not bin_path:
        return {"error": "Responder not found"}
    args = [bin_path]
    if arguments:
        args.extend(arguments.split())
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_crackmapexec(module: str, target: str, *extra) -> dict:
    """Run CrackMapExec with provided module and target."""
    bin_path = shutil.which("cme") or shutil.which("crackmapexec")
    if not bin_path:
        return {"error": "CrackMapExec not found"}
    args = [bin_path, module, target] + list(extra)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_sharphound(arguments: str = "") -> dict:
    """Execute SharpHound (BloodHound collector)."""
    bin_path = shutil.which("sharphound")
    if not bin_path:
        return {"error": "sharphound not found"}
    args = [bin_path]
    if arguments:
        args.extend(arguments.split())
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_rubeus(arguments: str = "") -> dict:
    """Execute Rubeus (Kerberos abuse)."""
    bin_path = shutil.which("rubeus")
    if not bin_path:
        return {"error": "rubeus not found"}
    args = [bin_path]
    if arguments:
        args.extend(arguments.split())
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_linpeas(path: str = "/tmp/linpeas.sh") -> dict:
    """Execute LinPEAS script. Path may be a local file or URL downloaded earlier."""
    if not os.path.isfile(path):
        return {"error": f"LinPEAS script not found at {path}"}
    args = ["bash", path]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_winpeas(path: str = "/tmp/winpeas.exe") -> dict:
    """Execute WinPEAS (Windows privilege enumeration)."""
    if not os.path.isfile(path):
        return {"error": f"WinPEAS binary not found at {path}"}
    args = [path]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_scoutsuite(profile: str = "") -> dict:
    """Run ScoutSuite cloud security auditor. Profile optional (aws, azure, gcp)."""
    bin_path = shutil.which("scout")
    if not bin_path:
        return {"error": "ScoutSuite not found"}
    args = [bin_path]
    if profile:
        args.append(profile)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_prowler(provider: str = "aws") -> dict:
    """Run Prowler for AWS/Azure/GCP compliance checks."""
    bin_path = shutil.which("prowler")
    if not bin_path:
        return {"error": "prowler not found"}
    args = [bin_path, "-p", provider]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_kube_hunter(target: str) -> dict:
    """Run kube‑hunter against a Kubernetes API endpoint."""
    bin_path = shutil.which("kube-hunter")
    if not bin_path:
        return {"error": "kube‑hunter not found"}
    args = [bin_path, "--remote", target]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_trufflehog(repo_path: str) -> dict:
    """Run TruffleHog to scan a repository for secrets."""
    bin_path = shutil.which("trufflehog")
    if not bin_path:
        return {"error": "trufflehog not found"}
    args = [bin_path, "filesystem", "--directory", repo_path]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_wfuzz(url: str, wordlist: str) -> dict:
    """Run wfuzz for web fuzzing against a URL using a wordlist."""
    bin_path = shutil.which("wfuzz")
    if not bin_path:
        return {"error": "wfuzz not found"}
    args = [bin_path, "-c", "-w", wordlist, "--hc", "404", url]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_dirsearch(url: str, wordlist: str) -> dict:
    """Run dirsearch for directory enumeration."""
    bin_path = shutil.which("dirsearch")
    if not bin_path:
        return {"error": "dirsearch not found"}
    args = [bin_path, "-u", url, "-w", wordlist]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_atomic_red_team(technique_id: str) -> dict:
    """Execute an Atomic Red Team test by technique ID (requires atomic-red-team repo)."""
    bin_path = shutil.which("invoke-atomic")
    if not bin_path:
        return {"error": "invoke-atomic not found"}
    args = [bin_path, "-t", technique_id]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

def run_mitre_navigator(scenarios_path: str) -> dict:
    """Launch MITRE ATT&CK Navigator with given JSON layers file."""
    bin_path = shutil.which("navigator")
    if not bin_path:
        return {"error": "MITRE Navigator not found"}
    args = [bin_path, "-l", scenarios_path]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}

# End of Red‑Team wrappers

    """
    Launch Metasploit console with a one‑liner command.
    This is a destructive action; callers should confirm twice before invoking.
    """
    bin_path = shutil.which("msfconsole")
    if not bin_path:
        return {"error": "Metasploit console not found"}
    commands = f"use exploit/multi/handler; set PAYLOAD {resource}; set LHOST {target}; run"
    args = [bin_path, "-q", "-x", commands]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"error": str(e)}


def start_ligolo_tunnel(host: str, port: int, remote: str) -> dict:
    """
    Start Ligolo‑NG tunnel. Assumes binary at /usr/local/bin/ligolo-ng or in PATH.
    """
    bin_path = shutil.which("ligolo-ng") or "/usr/local/bin/ligolo-ng"
    if not os.path.isfile(bin_path):
        return {"error": "Ligolo‑NG binary not found"}
    args = [bin_path, "client", "-target", f"{host}:{port}", "-remote", remote]
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {"process": proc}
    except Exception as e:
        return {"error": str(e)}


import requests
import yaml
from bs4 import BeautifulSoup
import urllib3
try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

from browser_client import fetch
from credential_scanner import scan_text
from privacy_guard import evaluate_privacy

# ---------------------------------------------------------------------------
# Recon helper functions & Configuration
# ---------------------------------------------------------------------------

_RECON_CFG_PATH = Path.home() / ".config" / "websec" / "recon.yaml"


def _ensure_cfg_file() -> dict:
    """Load recon config, creating defaults if missing.
    Returns the config dict.
    """
    default_cfg = {
        "stealth": False,
        "ghost_delay_ms": [100, 500],
        "shodan_api_key": "",
        "censys_api_id": "",
        "censys_api_secret": "",
        "securitytrails_api_key": "",
        "port_scan_range": [1, 1024],
        "subdomain_wordlist": str(Path.home() / ".config" / "websec" / "wordlists" / "subdomains.txt"),
        "tor_socks_port": 9050,
        "auto_tor": True,
    }
    cfg_dir = _RECON_CFG_PATH.parent
    cfg_dir.mkdir(parents=True, exist_ok=True)
    if not _RECON_CFG_PATH.exists():
        _RECON_CFG_PATH.write_text(yaml.safe_dump(default_cfg))
        try:
            _RECON_CFG_PATH.chmod(0o600)
        except Exception:
            pass
        return default_cfg
    try:
        cfg = yaml.safe_load(_RECON_CFG_PATH.read_text()) or {}
    except Exception:
        cfg = {}
    for k, v in default_cfg.items():
        cfg.setdefault(k, v)
    return cfg


def load_recon_config() -> dict:
    """Public API to load the recon configuration."""
    return _ensure_cfg_file()


def save_recon_config(cfg: dict) -> None:
    """Write the provided config dict back to the yaml file."""
    _RECON_CFG_PATH.write_text(yaml.safe_dump(cfg))
    try:
        _RECON_CFG_PATH.chmod(0o600)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Rate Limiting & Concurrency
# ---------------------------------------------------------------------------

_rate_semaphore = asyncio.Semaphore(10)


def rate_limited_fetch(
    method: str,
    url: str,
    *,
    delay_range: Optional[Tuple[int, int]] = None,
    **kwargs,
) -> Any:
    """Wrap ``fetch`` with a semaphore and optional random delay."""
    if delay_range:
        lo, hi = delay_range
        time.sleep(random.uniform(lo, hi) / 1000.0)
    async def _wrapper():
        async with _rate_semaphore:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, lambda: fetch(method, url, **kwargs))

    try:
        return asyncio.run(_wrapper())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_wrapper())
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# Stealth & Evasion Headers
# ---------------------------------------------------------------------------

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]

_REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://news.ycombinator.com/",
    "https://github.com/",
]


def stealth_headers() -> Dict[str, str]:
    """Return a randomised set of headers to evade simple WAF signatures."""
    ip_spoof = f"{random.randint(11, 190)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return {
        "User-Agent": random.choice(_USER_AGENTS),
        "Referer": random.choice(_REFERERS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
        "X-Forwarded-For": ip_spoof,
        "X-Real-IP": ip_spoof,
        "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Linux"',
        "DNT": "1",
    }


# ---------------------------------------------------------------------------
# Proxy & Tor Automatic Activation (Item 1 & 2)
# ---------------------------------------------------------------------------

def is_tor_available(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """Check if Tor SOCKS5 proxy service is actively listening."""
    try:
        with socket.create_connection((host, port), timeout=0.8):
            return True
    except Exception:
        return False


def proxy_headers(
    stealth: bool = False,
    auto_tor: bool = False,
    check_privacy: bool = True,
) -> Dict[str, Any]:
    """Smart proxy and evasion manager.
    Detects if anonymization is necessary (score leaks or threat level)
    and automatically enables Tor/SOCKS5 if present on the system.
    """
    cfg = load_recon_config()
    tor_port = cfg.get("tor_socks_port", 9050)
    tor_active = is_tor_available("127.0.0.1", tor_port) or is_tor_available("127.0.0.1", 9150)
    if is_tor_available("127.0.0.1", 9150):
        tor_port = 9150

    auto_triggered = False
    reason = "Manual / Standard Mode"

    # Detect necessity automatically
    if check_privacy:
        try:
            status = evaluate_privacy()
            if status.score < 60 or not status.dns_secure or not status.vpn_active:
                auto_triggered = True
                reason = f"Auto-Activated: Privacy Score={status.score}%, Threat={status.threat_level}"
        except Exception:
            pass

    proxies: Dict[str, str] = {}
    should_route_proxy = auto_tor or auto_triggered or stealth

    if should_route_proxy and tor_active:
        proxies = {
            "http": f"socks5h://127.0.0.1:{tor_port}",
            "https": f"socks5h://127.0.0.1:{tor_port}",
        }
        reason += f" -> Routed via SOCKS5 Tor (127.0.0.1:{tor_port})"
    elif os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY"):
        proxies = {
            "http": os.environ.get("HTTP_PROXY", ""),
            "https": os.environ.get("HTTPS_PROXY", ""),
        }
        reason += " -> Routed via System Environment Proxy"

    headers = stealth_headers() if (stealth or auto_triggered) else {"User-Agent": "Mozilla/5.0 (DefensiveWebSec/2.5)"}

    return {
        "proxies": proxies,
        "headers": headers,
        "tor_active": tor_active,
        "auto_triggered": auto_triggered,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Port Scanning & Subdomain Enumeration
# ---------------------------------------------------------------------------

async def scan_ports(
    target: str,
    ports: Optional[List[int]] = None,
    *,
    use_browser: bool = False,
    stealth: bool = False,
) -> Dict[int, str]:
    """Asynchronously attempt TCP connections to a list of ports."""
    cfg = load_recon_config()
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    if ports is None:
        # Default top fast ports
        ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3000, 3306, 5432, 6379, 8000, 8080, 8443, 8888]

    results: Dict[int, str] = {}
    semaphore = asyncio.Semaphore(25)

    async def _probe(port: int):
        async with semaphore:
            try:
                conn = asyncio.open_connection(clean_target, port)
                _, writer = await asyncio.wait_for(conn, timeout=1.2)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                results[port] = "open"
            except Exception:
                results[port] = "closed"

            if stealth:
                lo, hi = cfg.get("ghost_delay_ms", [100, 500])
                await asyncio.sleep(random.uniform(lo, hi) / 1000.0)

    await asyncio.gather(*[_probe(p) for p in ports])
    return results


async def enumerate_subdomains(
    base: str,
    wordlist_path: Optional[str] = None,
    *,
    use_browser: bool = False,
    stealth: bool = False,
) -> List[str]:
    """Legacy wrapper for subdomain discovery."""
    res = await mass_subdomains(base, wordlist_path=wordlist_path, stealth=stealth)
    return [sub["host"] if isinstance(sub, dict) else sub for sub in res.get("subdomains", [])]


# ---------------------------------------------------------------------------
# Mass Subdomains Aggressive Helper
# ---------------------------------------------------------------------------

_COMMON_SUBDOMAIN_PREFIXES = [
    "www", "api", "app", "dev", "test", "staging", "admin", "portal", "cdn",
    "docs", "beta", "demo", "auth", "mail", "status", "grafana", "corp",
    "sso", "idp", "vault", "db", "intranet", "billing", "support", "shop",
    "store", "ws", "backend", "frontend", "proxy", "relay", "direct", "chat",
    "k8s", "vpn", "remote", "git", "gitlab", "jenkins", "login", "monitor",
    "ns1", "ns2", "smtp", "secure", "static", "assets", "download", "media"
]


async def mass_subdomains(
    base: str,
    wordlist_path: Optional[str] = None,
    stealth: bool = False,
    timeout: float = 1.0,
) -> Dict[str, Any]:
    """Enhanced, aggressive subdomain discovery engine.
    Combines:
    1. Passive Certificate Transparency (crt.sh)
    2. Passive OSINT (HackerTarget)
    3. External installed tools (subfinder, assetfinder, amass) if present
    4. Async parallel DNS brute force with built-in or custom wordlist
    """
    clean_domain = base.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip().lower()
    candidates: Set[str] = set()
    sources_used: List[str] = []

    # 1. Passive crt.sh query
    try:
        def _fetch_crt():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"https://crt.sh/?q=%25.{clean_domain}&output=json",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            with urllib.request.urlopen(req, timeout=7, context=ctx) as r:
                return json.loads(r.read().decode("utf-8", errors="ignore"))

        loop = asyncio.get_running_loop()
        crt_data = await loop.run_in_executor(None, _fetch_crt)
        for item in crt_data:
            val = item.get("name_value", "")
            for name in val.split("\n"):
                clean_name = name.strip().lower()
                if clean_name.endswith(clean_domain) and "*" not in clean_name:
                    candidates.add(clean_name)
        sources_used.append("crt.sh")
    except Exception:
        pass

    # 2. Passive HackerTarget
    try:
        def _fetch_ht():
            req = urllib.request.Request(
                f"https://api.hackertarget.com/hostsearch/?q={clean_domain}",
                headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.read().decode("utf-8", errors="ignore")

        loop = asyncio.get_running_loop()
        ht_data = await loop.run_in_executor(None, _fetch_ht)
        for line in ht_data.splitlines():
            if "," in line:
                host = line.split(",")[0].strip().lower()
                if host.endswith(clean_domain):
                    candidates.add(host)
        sources_used.append("HackerTarget")
    except Exception:
        pass

    # 3. External CLI tools if installed in PATH
    for tool_name, cmd_args in [
        ("subfinder", ["subfinder", "-d", clean_domain, "-silent"]),
        ("assetfinder", ["assetfinder", "--subs-only", clean_domain]),
    ]:
        bin_path = shutil.which(tool_name)
        if bin_path:
            try:
                def _run_tool(args):
                    p = subprocess.run(args, capture_output=True, text=True, timeout=8)
                    return p.stdout.splitlines()

                lines = await asyncio.get_running_loop().run_in_executor(None, _run_tool, cmd_args)
                for line in lines:
                    h = line.strip().lower()
                    if h.endswith(clean_domain):
                        candidates.add(h)
                sources_used.append(tool_name)
            except Exception:
                pass

    # 4. Dictionary prefixes
    prefixes = list(_COMMON_SUBDOMAIN_PREFIXES)
    if wordlist_path and Path(wordlist_path).exists():
        try:
            extra = [w.strip() for w in Path(wordlist_path).read_text().splitlines() if w.strip()]
            prefixes.extend(extra[:200])
        except Exception:
            pass
    for p in prefixes:
        candidates.add(f"{p}.{clean_domain}")

    # 5. Async DNS verification with concurrency limit
    resolved_hosts: List[Dict[str, str]] = []
    dns_semaphore = asyncio.Semaphore(30)
    cfg = load_recon_config()

    async def _resolve_dns(fqdn: str):
        async with dns_semaphore:
            try:
                loop = asyncio.get_running_loop()
                addr_info = await asyncio.wait_for(loop.getaddrinfo(fqdn, None), timeout=timeout)
                if addr_info:
                    ip = addr_info[0][4][0]
                    resolved_hosts.append({"host": fqdn, "ip": ip, "status": "resolved"})
            except Exception:
                pass
            if stealth:
                lo, hi = cfg.get("ghost_delay_ms", [100, 500])
                await asyncio.sleep(random.uniform(lo, hi) / 1000.0)

    tasks = [_resolve_dns(h) for h in sorted(candidates)]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Sort resolved subdomains
    resolved_hosts.sort(key=lambda x: x["host"])

    return {
        "domain": clean_domain,
        "total_live": len(resolved_hosts),
        "subdomains": resolved_hosts,
        "sources": sources_used or ["Internal DNS Engine"],
    }


# ---------------------------------------------------------------------------
# Deep Crawl Aggressive Helper
# ---------------------------------------------------------------------------

def deep_crawl(
    target: str,
    max_depth: int = 2,
    max_pages: int = 25,
    use_browser: bool = False,
    stealth: bool = False,
    logger: Any = None,
) -> Dict[str, Any]:
    """Aggressive recursive web crawler for the target scope.
    Extracts internal endpoints, form inputs, scripts, query parameters,
    and inspects responses for sensitive token leaks.
    """
    clean_target = target if target.startswith("http") else f"https://{target}"
    parsed_base = urllib.parse.urlparse(clean_target)
    base_netloc = parsed_base.netloc.lower()

    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(clean_target, 0)]
    queued: Set[str] = {clean_target.split("#")[0].rstrip("/")}
    endpoints: Set[str] = set()
    forms_catalog: List[Dict[str, Any]] = []
    scripts_catalog: Set[str] = set()
    creds_found: List[str] = []

    p_info = proxy_headers(stealth=stealth)
    headers = p_info["headers"]
    proxies = p_info["proxies"]

    while queue and len(visited) < max_pages:
        current_url, depth = queue.pop(0)
        norm_url = current_url.split("#")[0].rstrip("/")
        if norm_url in visited:
            continue
        visited.add(norm_url)

        if logger and hasattr(logger, "write"):
            logger.write(f"[dim]  [crawl d={depth}]:[/] {norm_url}")

        try:
            if use_browser:
                resp = fetch("GET", current_url, headers=headers, timeout=8)
                body = getattr(resp, "text", "")
                status = getattr(resp, "status_code", 0)
            else:
                resp = requests.get(current_url, headers=headers, proxies=proxies, timeout=8, verify=False)
                body = resp.text
                status = resp.status_code

            if status >= 400:
                continue

            endpoints.add(current_url)

            # Leak detection
            token_hits = scan_text(body)
            for _, hit_list in token_hits.items():
                creds_found.extend(hit_list)
            creds_found.extend(extract_credentials_from_response(body))

            if depth >= max_depth:
                continue

            # Parse HTML for links, scripts, and forms
            soup = BeautifulSoup(body, "html.parser")

            # Extract Links
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                joined = urllib.parse.urljoin(current_url, href)
                parsed_j = urllib.parse.urlparse(joined)

                if parsed_j.scheme in ["http", "https"] and (parsed_j.netloc.lower() == base_netloc or parsed_j.netloc.lower().endswith("." + base_netloc)):
                    norm_j = joined.split("#")[0].rstrip("/")
                    if norm_j not in visited and norm_j not in queued:
                        queued.add(norm_j)
                        queue.append((joined, depth + 1))
                        endpoints.add(joined)

            # Extract Forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                inputs = [inp.get("name") for inp in form.find_all(["input", "select", "textarea"]) if inp.get("name")]
                full_action = urllib.parse.urljoin(current_url, action)
                forms_catalog.append({
                    "page": current_url,
                    "action": full_action,
                    "method": method,
                    "inputs": inputs,
                })
                endpoints.add(full_action)

            # Extract Scripts
            for script in soup.find_all("script", src=True):
                src = script["src"].strip()
                scripts_catalog.add(urllib.parse.urljoin(current_url, src))

        except Exception:
            pass

        if stealth:
            cfg = load_recon_config()
            lo, hi = cfg.get("ghost_delay_ms", [100, 500])
            time.sleep(random.uniform(lo, hi) / 1000.0)

    return {
        "target": clean_target,
        "pages_crawled": len(visited),
        "endpoints": sorted(list(endpoints)),
        "forms": forms_catalog,
        "scripts": sorted(list(scripts_catalog)),
        "creds": list(set(creds_found)),
    }


# ---------------------------------------------------------------------------
# Advanced Fingerprint (Open-Source Wappalyzer Clone)
# ---------------------------------------------------------------------------

_TECH_SIGNATURES = [
    # CMS
    {"name": "WordPress", "category": "CMS", "html": [r"/wp-content/", r"/wp-includes/"], "headers": {"X-Powered-By": r"WordPress"}, "cookies": [r"wordpress_", r"wp-settings-"]},
    {"name": "Drupal", "category": "CMS", "html": [r"Drupal\.settings", r"/sites/default/files"], "headers": {"X-Generator": r"Drupal"}},
    {"name": "Joomla", "category": "CMS", "html": [r"/media/system/js/", r"content=\"Joomla!"], "headers": {"X-Content-Encoded-By": r"Joomla"}},
    {"name": "Ghost", "category": "CMS", "html": [r"ghost-portal", r"content=\"Ghost"], "headers": {"X-Powered-By": r"Ghost"}},
    {"name": "Shopify", "category": "E-Commerce", "html": [r"cdn\.shopify\.com", r"Shopify\.shop"], "headers": {"X-ShopId": r".+"}},
    # Frameworks
    {"name": "React", "category": "JavaScript Framework", "html": [r"data-reactroot", r"react\.production\.min\.js", r"_next/static", r"__NEXT_DATA__"]},
    {"name": "Next.js", "category": "Web Framework", "html": [r"_next/static", r"__NEXT_DATA__"], "headers": {"X-Powered-By": r"Next\.js"}},
    {"name": "Vue.js", "category": "JavaScript Framework", "html": [r"data-v-[a-zA-Z0-9]+", r"vue\.global\.prod\.js", r"_nuxt/"]},
    {"name": "Nuxt.js", "category": "Web Framework", "html": [r"_nuxt/", r"__NUXT__"]},
    {"name": "Angular", "category": "JavaScript Framework", "html": [r"ng-version", r"ng-app", r"<app-root"]},
    {"name": "Svelte", "category": "JavaScript Framework", "html": [r"svelte-[a-zA-Z0-9]+"]},
    {"name": "Tailwind CSS", "category": "UI Framework", "html": [r"cdn\.tailwindcss\.com", r"tailwindcss"]},
    {"name": "Bootstrap", "category": "UI Framework", "html": [r"bootstrap(?:\.bundle)?(?:\.min)?\.js", r"bootstrap(?:\.min)?\.css"]},
    {"name": "HTMX", "category": "JavaScript Library", "html": [r"htmx\.org", r"hx-get", r"hx-post"]},
    {"name": "Alpine.js", "category": "JavaScript Framework", "html": [r"alpinejs", r"x-data="]},
    {"name": "jQuery", "category": "JavaScript Library", "html": [r"jquery(?:\.min)?\.js", r"jQuery v[0-9\.]+"]},
    # Backend & Servers
    {"name": "Laravel", "category": "Backend Framework", "cookies": [r"laravel_session", r"XSRF-TOKEN"], "headers": {"Set-Cookie": r"laravel_session"}},
    {"name": "Django", "category": "Backend Framework", "cookies": [r"csrftoken", r"sessionid"], "html": [r"csrfmiddlewaretoken"]},
    {"name": "Flask", "category": "Backend Framework", "headers": {"Server": r"Werkzeug"}, "cookies": [r"session="]},
    {"name": "Express.js", "category": "Backend Framework", "headers": {"X-Powered-By": r"Express"}, "cookies": [r"connect\.sid"]},
    {"name": "ASP.NET", "category": "Backend Framework", "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".+"}, "cookies": [r"ASP\.NET_SessionId", r"ASPSESSIONID"]},
    {"name": "PHP", "category": "Programming Language", "headers": {"X-Powered-By": r"PHP"}, "cookies": [r"PHPSESSID"]},
    # Web Servers & CDN
    {"name": "Nginx", "category": "Web Server", "headers": {"Server": r"nginx"}},
    {"name": "Apache", "category": "Web Server", "headers": {"Server": r"Apache"}},
    {"name": "Cloudflare", "category": "CDN / WAF", "headers": {"Server": r"cloudflare", "CF-RAY": r".+", "cf-cache-status": r".+"}, "cookies": [r"__cf_bm"]},
    {"name": "Caddy", "category": "Web Server", "headers": {"Server": r"Caddy"}},
    {"name": "LiteSpeed", "category": "Web Server", "headers": {"Server": r"LiteSpeed"}},
]


def advanced_fingerprint(
    url: str,
    *,
    use_browser: bool = False,
    stealth: bool = False,
) -> Dict[str, Any]:
    """Wappalyzer-grade technology fingerprinting engine in pure Python.
    Analyzes response headers, cookies, and DOM signatures.
    """
    clean_url = url if url.startswith("http") else f"https://{url}"
    p_info = proxy_headers(stealth=stealth)
    headers = p_info["headers"]
    proxies = p_info["proxies"]

    resp_headers: Dict[str, str] = {}
    resp_cookies: List[str] = []
    body = ""
    title = ""

    try:
        if use_browser:
            r = fetch("GET", clean_url, headers=headers, timeout=8)
            body = getattr(r, "text", "")
            resp_headers = {k.lower(): str(v) for k, v in getattr(r, "headers", {}).items()}
        else:
            r = requests.get(clean_url, headers=headers, proxies=proxies, timeout=8, verify=False)
            body = r.text
            resp_headers = {k.lower(): str(v) for k, v in r.headers.items()}
            resp_cookies = [f"{k}={v}" for k, v in r.cookies.items()]

        m = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()
    except Exception:
        pass

    detected_technologies: List[Dict[str, Any]] = []
    seen_names: Set[str] = set()

    # Match signatures
    for sig in _TECH_SIGNATURES:
        name = sig["name"]
        cat = sig["category"]
        confidence = 0

        # Check headers
        if "headers" in sig:
            for h_key, pattern in sig["headers"].items():
                val = resp_headers.get(h_key.lower(), "")
                if val and re.search(pattern, val, re.IGNORECASE):
                    confidence = max(confidence, 100)

        # Check cookies
        if "cookies" in sig:
            cookie_text = " ".join(resp_cookies) + " " + resp_headers.get("set-cookie", "")
            for pattern in sig["cookies"]:
                if re.search(pattern, cookie_text, re.IGNORECASE):
                    confidence = max(confidence, 90)

        # Check html patterns
        if "html" in sig:
            for pattern in sig["html"]:
                if re.search(pattern, body, re.IGNORECASE):
                    confidence = max(confidence, 80)

        if confidence > 0 and name not in seen_names:
            seen_names.add(name)
            detected_technologies.append({
                "name": name,
                "category": cat,
                "confidence": confidence,
            })

    # External WhatWeb enrichment if installed
    whatweb_bin = shutil.which("whatweb")
    if whatweb_bin:
        try:
            res = subprocess.run([whatweb_bin, "-a", "1", "--color=never", clean_url], capture_output=True, text=True, timeout=12)
            if res.stdout:
                detected_technologies.append({
                    "name": "WhatWeb Extended",
                    "category": "External Engine",
                    "confidence": 100,
                    "details": res.stdout.strip()[:250],
                })
        except Exception:
            pass

    server = resp_headers.get("server", "Unknown / Hidden")
    powered_by = resp_headers.get("x-powered-by", "")

    return {
        "url": clean_url,
        "title": title,
        "server": server,
        "powered_by": powered_by,
        "technologies": detected_technologies,
        "headers": resp_headers,
    }


def fingerprint_target(
    url: str,
    *,
    use_browser: bool = False,
    stealth: bool = False,
) -> Dict[str, str]:
    """Lightweight backward-compatible fingerprinting wrapper."""
    adv = advanced_fingerprint(url, use_browser=use_browser, stealth=stealth)
    res = {}
    if adv.get("server"):
        res["Server"] = adv["server"]
    if adv.get("powered_by"):
        res["X-Powered-By"] = adv["powered_by"]
    if adv.get("title"):
        res["title"] = adv["title"]
    return res


# ---------------------------------------------------------------------------
# External APIs (Shodan / Censys)
# ---------------------------------------------------------------------------

def shodan_lookup(ip: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Query the Shodan API for an IP address. Returns parsed JSON or empty dict."""
    cfg = load_recon_config()
    if not api_key:
        api_key = cfg.get("shodan_api_key", "")
    if not api_key:
        return {}
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Pure-Python PDF Builder & Reporting (Item 2)
# ---------------------------------------------------------------------------

class PurePythonPDF:
    """Zero-dependency, pure-Python PDF document builder.
    Produces valid PDF 1.4 documents with custom margins, colors, and layout.
    """
    def __init__(self):
        self.pages: List[str] = []
        self.current_stream: List[str] = []
        self.page_width = 595.28   # A4 width in points
        self.page_height = 841.89  # A4 height in points
        self.y = 780.0
        self.page_count = 0
        self.new_page()

    def new_page(self):
        if self.current_stream:
            self.pages.append("\n".join(self.current_stream))
            self.current_stream = []
        self.page_count += 1
        self.y = 780.0
        # Draw squircle-like subtle border & footer
        self.draw_rect(24, 24, 547.28, 793.89, stroke=(0.14, 0.20, 0.32), fill=None, line_width=0.75)
        self.draw_text(
            36, 32,
            f"WEB-SEC // CYBER-DECK AUDIT REPORT  •  PAGE {self.page_count}  •  CRYSTAL & SQUIRCLE ARCHITECTURE",
            size=7, font="/F1", color=(0.45, 0.52, 0.65)
        )

    def check_space(self, needed: float):
        if self.y - needed < 50:
            self.new_page()

    def draw_rect(self, x: float, y: float, w: float, h: float, fill=None, stroke=None, line_width=1.0):
        ops = []
        if line_width:
            ops.append(f"{line_width:.2f} w")
        if fill:
            r, g, b = fill
            ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg")
        if stroke:
            r, g, b = stroke
            ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG")
        ops.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re")
        if fill and stroke:
            ops.append("B")
        elif fill:
            ops.append("f")
        elif stroke:
            ops.append("S")
        self.current_stream.append(" ".join(ops))

    def draw_text(self, x: float, y: float, text: str, size: float = 10, font: str = "/F1", color=(0.9, 0.9, 0.9)):
        r, g, b = color
        clean_text = str(text).replace("\r", " ").replace("\n", " ").replace("\t", " ")
        safe_text = clean_text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = (
            f"BT\n"
            f"{font} {size} Tf\n"
            f"{r:.3f} {g:.3f} {b:.3f} rg\n"
            f"1 0 0 1 {x:.2f} {y:.2f} Tm\n"
            f"({safe_text}) Tj\n"
            f"ET"
        )
        self.current_stream.append(stream)

    def write_heading(self, text: str, subtitle: Optional[str] = None):
        self.check_space(70)
        self.draw_rect(35, self.y - 36, 525, 46, fill=(0.04, 0.07, 0.14), stroke=(0.0, 0.94, 1.0), line_width=1.2)
        self.draw_text(45, self.y - 16, text, size=15, font="/F2", color=(0.0, 0.94, 1.0))
        if subtitle:
            self.draw_text(45, self.y - 30, subtitle, size=8.5, font="/F1", color=(0.7, 0.75, 0.85))
        self.y -= 56

    def write_section(self, title: str):
        self.check_space(36)
        self.draw_rect(35, self.y - 18, 525, 20, fill=(0.08, 0.12, 0.22), stroke=(0.2, 0.3, 0.45), line_width=0.8)
        self.draw_text(42, self.y - 13, f"// {title.upper()}", size=10, font="/F2", color=(0.0, 0.94, 1.0))
        self.y -= 28

    def write_key_value(self, key: str, value: Any, indent: float = 42):
        self.check_space(16)
        self.draw_text(indent, self.y, f"{key}:", size=8.5, font="/F2", color=(0.4, 0.8, 1.0))
        self.draw_text(indent + 130, self.y, str(value)[:75], size=8.5, font="/F1", color=(0.85, 0.88, 0.92))
        self.y -= 14

    def write_table_row(self, cols: list, widths: list, is_header: bool = False):
        self.check_space(16)
        x = 42.0
        row_h = 14.0
        if is_header:
            self.draw_rect(38, self.y - 3, 518, row_h + 2, fill=(0.06, 0.1, 0.18), stroke=(0.15, 0.25, 0.4))
        for col, w in zip(cols, widths):
            col_str = str(col)[:int(w // 5.5)]
            font = "/F2" if is_header else "/F1"
            color = (0.0, 0.94, 1.0) if is_header else (0.85, 0.88, 0.92)
            self.draw_text(x, self.y, col_str, size=8, font=font, color=color)
            x += w
        self.y -= 15

    def build_bytes(self) -> bytes:
        if self.current_stream:
            self.pages.append("\n".join(self.current_stream))
            self.current_stream = []

        total_pages = len(self.pages)
        objects = []

        # 1: Catalog
        objects.append("<< /Type /Catalog /Pages 2 0 R >>")

        # 2: Pages
        kids = [f"{3 + i * 2} 0 R" for i in range(total_pages)]
        objects.append(f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {total_pages} >>")

        # Page and Content objects
        for i in range(total_pages):
            page_obj_num = 3 + i * 2
            content_obj_num = page_obj_num + 1

            stream_data = self.pages[i].encode("cp1252", errors="replace")
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.page_width:.2f} {self.page_height:.2f}] "
                f"/Contents {content_obj_num} 0 R "
                f"/Resources << /Font << /F1 {3 + total_pages * 2} 0 R /F2 {4 + total_pages * 2} 0 R >> >> >>"
            )
            objects.append(
                f"<< /Length {len(stream_data)} >>\nstream\n{self.pages[i]}\nendstream"
            )

        # Standard Core 14 Type 1 Fonts
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")

        # Assemble PDF with cross reference
        output = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
        offsets = [0]
        curr_offset = len(output[0])

        for idx, obj in enumerate(objects, start=1):
            offsets.append(curr_offset)
            obj_bytes = f"{idx} 0 obj\n{obj}\nendobj\n".encode("cp1252", errors="replace")
            output.append(obj_bytes)
            curr_offset += len(obj_bytes)

        xref_offset = curr_offset
        xref_table = [f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"]
        for off in offsets[1:]:
            xref_table.append(f"{off:010d} 00000 n \n")

        trailer = (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        )

        output.append("".join(xref_table).encode("cp1252"))
        output.append(trailer.encode("cp1252"))
        return b"".join(output)


def export_html_report(data: dict, out_path: Path) -> Path:
    """Render a styled HTML report using Jinja2 or Crystal & Squircle fallback."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    template_dir = Path(__file__).parent / "templates"
    template_file = template_dir / "recon_report.html"

    if template_file.exists():
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
            env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html"]))
            template = env.get_template("recon_report.html")
            rendered = template.render(data=data)
            out_path.write_text(rendered, encoding="utf-8")
            return out_path
        except Exception:
            pass

    # Built-in robust HTML generator fallback
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Recon Report - {data.get('target', '')}</title>
<style>
body {{ background: #05070d; color: #f1f5f9; font-family: monospace; padding: 24px; }}
.card {{ background: rgba(13,20,36,0.8); border: 1px solid #38bdf8; border-radius: 14px; padding: 20px; margin-bottom: 20px; }}
h1, h2 {{ color: #00f0ff; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ border-bottom: 1px solid #1e293b; padding: 8px; text-align: left; }}
.badge {{ background: #00f0ff22; color: #00f0ff; padding: 4px 8px; border-radius: 6px; }}
</style></head>
<body>
<div class="card">
<h1>Web-Sec Recon // {data.get('target', '')}</h1>
<p>Generated: {data.get('timestamp', datetime.now().isoformat())} | Scope: Whitelist Enforced</p>
</div>
<div class="card">
<h2>Raw Discovery Payload</h2>
<pre>{json.dumps(data, indent=2, default=str)}</pre>
</div>
</body></html>"""
    out_path.write_text(html, encoding="utf-8")
    return out_path


def export_pdf_report(data: dict, out_path: Path) -> Path:
    """Render an executive PDF report.
    Attempts WeasyPrint if available; otherwise uses high-fidelity pure-Python PDF builder.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Try WeasyPrint if available
    try:
        import weasyprint
        html_tmp = out_path.with_suffix(".tmp.html")
        export_html_report(data, html_tmp)
        weasyprint.HTML(filename=str(html_tmp)).write_pdf(str(out_path))
        if html_tmp.exists():
            html_tmp.unlink()
        return out_path
    except Exception:
        pass

    # 2. Pure Python PDF generation
    pdf = PurePythonPDF()
    target = data.get("target", "Target")
    ts = data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    pdf.write_heading(
        f"WEB-SEC // RECON AUDIT: {target}",
        f"Generated: {ts} | Mode: {data.get('mode', 'Recon')} | Whitelist: Enforced"
    )

    pdf.write_section("1. Executive Summary & Telemetry")
    ports = data.get("ports", {})
    open_ports = [p for p, s in ports.items() if s == "open"]
    subdomains = data.get("subdomains", [])
    endpoints = data.get("endpoints", [])
    creds = data.get("creds", [])

    pdf.write_key_value("Target Host", target)
    pdf.write_key_value("Open TCP Ports", f"{len(open_ports)} open (probed: {len(ports)})")
    pdf.write_key_value("Subdomains Discovered", f"{len(subdomains)} active hosts")
    pdf.write_key_value("Endpoints Cataloged", f"{len(endpoints)} routes")
    pdf.write_key_value("Extracted Credentials", f"{len(creds)} leaks detected")
    if data.get("tor_active"):
        pdf.write_key_value("Tor / Proxy Routing", "ACTIVE (SOCKS5 Protected)")

    # Technology Stack
    techs = data.get("technologies", [])
    fp = data.get("fingerprint", {})
    if techs or fp:
        pdf.write_section("2. Technology Stack & Fingerprinting (Wappalyzer)")
        if isinstance(techs, list):
            for t in techs:
                name = t.get("name", str(t)) if isinstance(t, dict) else str(t)
                cat = t.get("category", "General") if isinstance(t, dict) else "General"
                conf = f"{t.get('confidence', 100)}%" if isinstance(t, dict) else "100%"
                pdf.write_key_value(f"[{cat}] {name}", f"Confidence: {conf}")
        if isinstance(fp, dict):
            for k, v in fp.items():
                pdf.write_key_value(f"Header: {k}", str(v))

    # Ports Table
    if ports:
        pdf.write_section("3. Port Scan Results")
        pdf.write_table_row(["PORT", "STATE", "SERVICE DESCRIPTION"], [80, 100, 338], is_header=True)
        for p, s in list(ports.items())[:25]:
            desc = "HTTP" if p == 80 else "HTTPS (SSL)" if p == 443 else "SSH" if p == 22 else "MySQL" if p == 3306 else "TCP Service"
            pdf.write_table_row([str(p), s.upper(), desc], [80, 100, 338])

    # Subdomains Table
    if subdomains:
        pdf.write_section("4. Subdomain Discovery (Mass OSINT & Active)")
        pdf.write_table_row(["SUBDOMAIN / HOST", "IP ADDRESS", "STATUS"], [240, 160, 118], is_header=True)
        for sub in subdomains[:30]:
            host = sub.get("host", sub.get("subdomain", str(sub))) if isinstance(sub, dict) else str(sub)
            ip = sub.get("ip", "DNS Resolv") if isinstance(sub, dict) else "Active"
            pdf.write_table_row([host, ip, "LIVE"], [240, 160, 118])

    # Endpoints & Leaks
    if endpoints or creds:
        pdf.write_section("5. Endpoints & Critical Leaks")
        if creds:
            pdf.write_table_row(["LEAK TYPE", "SNIPPET", "SEVERITY"], [120, 278, 120], is_header=True)
            for c in creds[:15]:
                pdf.write_table_row(["CREDENTIAL", str(c)[:35], "CRITICAL"], [120, 278, 120])
        if endpoints:
            pdf.write_table_row(["ENDPOINT PATH", "STATUS", "SOURCE"], [298, 100, 120], is_header=True)
            for ep in endpoints[:25]:
                pdf.write_table_row([str(ep), "200 OK", "CRAWL"], [298, 100, 120])

    pdf_bytes = pdf.build_bytes()
    out_path.write_bytes(pdf_bytes)
    return out_path


# ---------------------------------------------------------------------------
# Destructive / Stress Testing Helpers (Level 3 & void)
# ---------------------------------------------------------------------------

async def async_bulk_requests(requests_def: List[Tuple[str, str, Dict]]) -> List[Any]:
    """Execute many HTTP calls concurrently."""
    async def _single(method: str, url: str, kwargs: Dict) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: fetch(method, url, **kwargs))

    tasks = [_single(m, u, kw) for m, u, kw in requests_def]
    return await asyncio.gather(*tasks, return_exceptions=True)


async def ws_flood(ws_url: str, connections: int = 30, interval_ms: int = 200) -> List[Any]:
    """Simulated WebSocket connection flood."""
    results = []
    for i in range(connections):
        payload = "".join(random.choices(string.ascii_letters + string.digits, k=12))
        try:
            resp = fetch("GET", ws_url, timeout=8)
            results.append((i, getattr(resp, "status_code", None), payload))
        except Exception as e:
            results.append((i, None, str(e)))
        await asyncio.sleep(interval_ms / 1000.0)
    return results


def upload_bomb(
    target: str,
    upload_path: str = "/upload",
    count: int = 50,
    use_browser: bool = False,
    stealth: bool = False,
) -> List[Tuple[int, Optional[int]]]:
    """POST dummy files to stress test target upload endpoints."""
    results = []
    headers = stealth_headers() if stealth else {}
    for i in range(count):
        ftype = random.choice(["txt", "png", "zip"])
        if ftype == "txt":
            data = ("file.txt", f"dummy_{i}_{''.join(random.choices(string.ascii_letters, k=5))}".encode())
            h = {**headers, "Content-Type": "text/plain"}
        elif ftype == "png":
            data = ("file.png", base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/5+BAQAE/AL+XKJ9cQAAAABJRU5ErkJggg=="))
            h = {**headers, "Content-Type": "image/png"}
        else:
            data = ("file.zip", base64.b64decode("UEsDBBQAAAAAAKS0VV1iLyFxDQAAAA0AAAAIAAAAdGVzdC50eHRkdW1teV9jb250ZW50UEsBAhQDFAAAAAAApLRVXWIvIXENAAAADQAAAAgAAAAAAAAAAAAAAIABAAAAAHRlc3QudHh0UEsFBgAAAAABAAEANgAAADMAAAAAAA=="))
            h = {**headers, "Content-Type": "application/zip"}

        url = f"{target.rstrip('/')}{upload_path}"
        files = {"file": data}
        try:
            if use_browser:
                resp = fetch("POST", url, files=files, headers=h, timeout=10)
            else:
                resp = requests.post(url, files=files, headers=h, timeout=10, verify=False)
            results.append((i, getattr(resp, "status_code", None)))
        except Exception:
            results.append((i, None))
    return results


def temp_token_generator(
    target: str,
    user_id: str,
    use_browser: bool = False,
    stealth: bool = False,
) -> Optional[str]:
    """Ask target for temporary token."""
    url = f"{target.rstrip('/')}/api/temp-token"
    params = {"uid": user_id, "exp": 60}
    headers = stealth_headers() if stealth else {}
    try:
        if use_browser:
            resp = fetch("GET", url, params=params, headers=headers, timeout=8)
        else:
            resp = requests.get(url, params=params, headers=headers, timeout=8, verify=False)
        if getattr(resp, "status_code", None) == 200:
            return resp.json().get("access_token")
    except Exception:
        pass
    return None


def rollback_action(
    method: str,
    url: str,
    payload: Optional[Dict] = None,
    use_browser: bool = False,
    stealth: bool = False,
) -> Any:
    """Perform the inverse HTTP method to undo a previous change."""
    inverse = {"POST": "DELETE", "DELETE": "POST"}.get(method.upper())
    if not inverse:
        raise ValueError("Unsupported method for rollback")
    headers = stealth_headers() if stealth else {}
    try:
        if use_browser:
            return fetch(inverse, url, json=payload, headers=headers, timeout=10)
        else:
            if inverse == "DELETE":
                return requests.delete(url, headers=headers, timeout=10, verify=False)
            else:
                return requests.post(url, json=payload or {}, headers=headers, timeout=10, verify=False)
    except Exception as e:
        return e


def ddos_light(
    target: str,
    endpoint: str = "/ping",
    count: int = 20,
    use_browser: bool = False,
    stealth: bool = False,
) -> List[Tuple[int, float, Optional[int]]]:
    """Perform latency probe stress test."""
    results = []
    url = f"{target.rstrip('/')}{endpoint}"
    headers = stealth_headers() if stealth else {}
    for i in range(count):
        start = time.time()
        try:
            if use_browser:
                resp = fetch("GET", url, headers=headers, timeout=5)
            else:
                resp = requests.get(url, headers=headers, timeout=5, verify=False)
            latency = time.time() - start
            results.append((i, latency, getattr(resp, "status_code", None)))
        except Exception:
            latency = time.time() - start
            results.append((i, latency, None))
    return results


# ---------------------------------------------------------------------------
# Endpoint Enumeration & Database Download
# ---------------------------------------------------------------------------

_common_paths = [
    "/admin", "/login", "/debug", "/swagger.json", "/api/docs",
    "/graphql", "/.env", "/config", "/robots.txt", "/sitemap.xml",
    "/api/v1", "/dashboard", "/actuator/health", "/metrics", "/server-status"
]


def enumerate_endpoints(
    target: str,
    use_browser: bool = False,
    stealth: bool = False,
) -> Dict[str, Any]:
    """Probe a curated list of common admin / API endpoints."""
    results: Dict[str, Any] = {}
    headers = stealth_headers() if stealth else {}
    for path in _common_paths:
        url = f"{target.rstrip('/')}{path}"
        try:
            resp = fetch("GET", url, headers=headers, timeout=6) if use_browser else requests.get(url, headers=headers, timeout=6, verify=False)
            results[url] = resp
        except Exception:
            results[url] = None
    return results


def download_database(
    target: str,
    endpoint: str = "/dump",
    use_browser: bool = False,
    stealth: bool = False,
) -> Optional[Path]:
    """Download database dump from endpoint."""
    url = f"{target.rstrip('/')}{endpoint}"
    headers = stealth_headers() if stealth else {}
    out_dir = Path("outputs")
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    filename = out_dir / f"db_{safe_name}_{ts}.dump"
    try:
        if use_browser:
            resp = fetch("GET", url, headers=headers, timeout=30)
            if hasattr(resp, "content"):
                filename.write_bytes(resp.content)
            elif hasattr(resp, "text"):
                filename.write_text(resp.text)
            return filename
        else:
            resp = requests.get(url, headers=headers, stream=True, timeout=30, verify=False)
            with open(filename, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            return filename
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Credential Extraction Regexes
# ---------------------------------------------------------------------------

_jwt_regex = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
_aws_key_regex = re.compile(r"AKIA[0-9A-Z]{16}")
_bearer_regex = re.compile(r"Bearer\s+([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)


def extract_credentials_from_response(text: str) -> List[str]:
    """Return suspicious credential strings found in text."""
    creds: List[str] = []
    for match in _jwt_regex.findall(text):
        creds.append(f"JWT: {match}")
    for match in _aws_key_regex.findall(text):
        creds.append(f"AWS-KEY: {match}")
    for match in _bearer_regex.findall(text):
        creds.append(f"BEARER: {match}")
    return creds
