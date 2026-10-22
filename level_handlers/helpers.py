# level_handlers/helpers.py
"""Utility helpers for Level 3, void() and Recon front.
All functions are deliberately lightweight and avoid external heavy
dependencies – they rely on the existing `fetch` helper (Playwright) or
the standard `requests` library when `use_browser=False`.
"""
import asyncio
import random
import string
import base64
import re
from typing import List, Tuple, Dict, Any, Generator
from pathlib import Path

from browser_client import fetch
import requests

# ---------------------------------------------------------------------------
# Recon helper functions (new)
# ---------------------------------------------------------------------------

# Config file path for Recon options
_RECON_CFG_PATH = Path.home() / ".config" / "websec" / "recon.yaml"

def _ensure_cfg_file() -> dict:
    """Load recon config, creating defaults if missing.
    Returns the config dict.
    """
    default_cfg = {
        "stealth": False,
        "ghost_delay_ms": [100, 500],
        "shodan_api_key": "",
        "censys_api_key": "",
        "port_scan_range": [1, 1024],
        "subdomain_wordlist": str(Path.home() / ".config" / "websec" / "wordlists" / "subdomains.txt"),
    }
    cfg_dir = _RECON_CFG_PATH.parent
    cfg_dir.mkdir(parents=True, exist_ok=True)
    if not _RECON_CFG_PATH.exists():
        # Create file with defaults and secure perms
        _RECON_CFG_PATH.write_text(yaml.safe_dump(default_cfg))
        _RECON_CFG_PATH.chmod(0o600)
        return default_cfg
    try:
        cfg = yaml.safe_load(_RECON_CFG_PATH.read_text()) or {}
    except Exception:
        cfg = {}
    # Merge defaults for missing keys
    for k, v in default_cfg.items():
        cfg.setdefault(k, v)
    return cfg

def load_recon_config() -> dict:
    """Public API to load the recon configuration.
    Returns a dict with the configuration values.
    """
    return _ensure_cfg_file()

def save_recon_config(cfg: dict) -> None:
    """Write the provided config dict back to the yaml file.
    The file is stored with mode 600.
    """
    _RECON_CFG_PATH.write_text(yaml.safe_dump(cfg))
    _RECON_CFG_PATH.chmod(0o600)

async def scan_ports(target: str, ports: List[int] | None = None, *, use_browser: bool = False, stealth: bool = False) -> Dict[int, str]:
    """Asynchronously attempt TCP connections to a list of ports.
    Returns a mapping ``port -> 'open' | 'closed'``.
    """
    cfg = load_recon_config()
    if ports is None:
        start, end = cfg.get("port_scan_range", [1, 1024])
        ports = list(range(start, end + 1))
    results: Dict[int, str] = {}
    async def _probe(port: int):
        try:
            conn = asyncio.open_connection(target, port)
            await asyncio.wait_for(conn, timeout=1.0)
            results[port] = "open"
        except Exception:
            results[port] = "closed"
        if stealth:
            # random ghost delay within configured range
            lo, hi = cfg.get("ghost_delay_ms", [100, 500])
            await asyncio.sleep(random.uniform(lo, hi) / 1000.0)
    await asyncio.gather(*[_probe(p) for p in ports])
    return results

async def enumerate_subdomains(base: str, wordlist_path: str | None = None, *, use_browser: bool = False, stealth: bool = False) -> List[str]:
    """Generate possible subdomains from a wordlist and resolve them.
    Returns a list of successfully resolved sub‑domains (as ``host`` strings).
    """
    cfg = load_recon_config()
    if wordlist_path is None:
        wordlist_path = cfg.get("subdomain_wordlist")
    try:
        words = Path(wordlist_path).read_text().splitlines()
    except Exception:
        words = []
    results: List[str] = []
    async def _resolve(sub: str):
        fqdn = f"{sub}.{base}" if not sub.endswith(base) else sub
        try:
            # getaddrinfo works both with and without browser mode
            await asyncio.get_event_loop().getaddrinfo(fqdn, None)
            results.append(fqdn)
        except Exception:
            pass
        if stealth:
            lo, hi = cfg.get("ghost_delay_ms", [100, 500])
            await asyncio.sleep(random.uniform(lo, hi) / 1000.0)
    await asyncio.gather(*[_resolve(w.strip()) for w in words if w.strip()])
    return results

def fingerprint_target(url: str, *, use_browser: bool = False, stealth: bool = False) -> Dict[str, str]:
    """Fetch a URL (GET) and extract server‑side technology fingerprints.
    Returns a dict with keys like ``Server``, ``X-Powered-By`` and ``title``.
    """
    cfg = load_recon_config()
    headers = stealth_headers() if stealth else {}
    try:
        resp = fetch("GET", url, headers=headers, timeout=8) if use_browser else requests.get(url, headers=headers, timeout=8)
    except Exception:
        return {}
    result: Dict[str, str] = {}
    # Basic header extraction
    for h in ["Server", "X-Powered-By", "X-AspNet-Version"]:
        val = resp.headers.get(h)
        if val:
            result[h] = val
    # Simple HTML title extraction
    text = getattr(resp, "text", "")
    m = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if m:
        result["title"] = m.group(1).strip()
    return result

def shodan_lookup(ip: str, api_key: str | None = None) -> Dict[str, Any]:
    """Query the Shodan API for an IP address. Returns parsed JSON or empty dict.
    If ``api_key`` is None, attempts to read it from config.
    """
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

def export_html_report(data: dict, out_path: Path) -> Path:
    """Render a minimal HTML report using Jinja2 and write to ``out_path``.
    Returns the path of the generated file.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        # Fallback: plain string formatting if Jinja2 missing
        html = f"<html><body><pre>{json.dumps(data, indent=2)}</pre></body></html>"
        out_path.write_text(html)
        return out_path
    env = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")), autoescape=select_autoescape(["html"]))
    template = env.get_template("recon_report.html")
    rendered = template.render(data=data)
    out_path.write_text(rendered)
    return out_path

# Extend existing rate_limited_fetch to accept optional delay_range for stealth mode
def rate_limited_fetch(method: str, url: str, *, delay_range: tuple[int, int] | None = None, **kwargs) -> Any:
    """Wrap ``fetch`` with a semaphore and optional random delay.
    ``delay_range`` – (min_ms, max_ms) applied before the request when provided.
    """
    if delay_range:
        lo, hi = delay_range
        time.sleep(random.uniform(lo, hi) / 1000.0)
    loop = asyncio.get_event_loop()
    async def _wrapper():
        async with _rate_semaphore:
            return await loop.run_in_executor(None, lambda: fetch(method, url, **kwargs))
    return loop.run_until_complete(_wrapper())

# Existing helper imports remain unchanged above this new block.

async def async_bulk_requests(requests_def: List[Tuple[str, str, Dict]]) -> List[Any]:
    """Execute many HTTP calls concurrently.
    `requests_def` is a list of tuples: (method, url, kwargs).
    Returns a list with the responses (or exception objects).
    """
    async def _single(method: str, url: str, kwargs: Dict) -> Any:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: fetch(method, url, **kwargs))

    tasks = [_single(m, u, kw) for m, u, kw in requests_def]
    return await asyncio.gather(*tasks, return_exceptions=True)

# ---------------------------------------------------------------------------
# WebSocket flood (light version – uses HTTP upgrade via fetch)
# ---------------------------------------------------------------------------
async def ws_flood(ws_url: str, connections: int = 30, interval_ms: int = 200) -> List[Any]:
    """Open `connections` websockets to `ws_url` and send a random payload.
    This is a *simulated* flood using HTTP GET with Playwright's websocket API.
    Returns a list of results for each connection.
    """
    results = []
    for i in range(connections):
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        try:
            resp = fetch("GET", ws_url, timeout=8)
            results.append((i, getattr(resp, 'status_code', None), payload))
        except Exception as e:
            results.append((i, None, str(e)))
        await asyncio.sleep(interval_ms / 1000.0)
    return results

# ---------------------------------------------------------------------------
# File‑upload bomb
# ---------------------------------------------------------------------------
def upload_bomb(target: str, upload_path: str = "/upload", count: int = 50, use_browser: bool = False, stealth: bool = False) -> List[Tuple[int, int]]:
    """POST `count` dummy files (random txt / png / zip) to the target.
    Returns a list of tuples (index, status_code).
    """
    results = []
    for i in range(count):
        ftype = random.choice(["txt", "png", "zip"])
        if ftype == "txt":
            data = ("file.txt", f"dummy_{i}_{''.join(random.choices(string.ascii_letters, k=5))}".encode())
            headers = {"Content-Type": "text/plain"}
        elif ftype == "png":
            data = ("file.png", base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/5+BAQAE/AL+XKJ9cQAAAABJRU5ErkJggg=="
            ))
            headers = {"Content-Type": "image/png"}
        else:  # zip
            data = ("file.zip", base64.b64decode(
                "UEsDBBQAAAAIAAEAAADsAAAAAAAIAAAABwAAAAUAAAB4bWx2YWx1ZQpQSwECFAAUAAAACAAA"
                "BAAA7AAAAAAACAAAABwAAAAAAAAAAACAAAAAAAAAAB4bWx2YWx1ZVBLBQYAAAAAAQABADYA"
                "AABPAAAAAAA="
            ))
            headers = {"Content-Type": "application/zip"}

        url = f"{target.rstrip('/')}{upload_path}"
        files = {"file": data}
        try:
            if use_browser:
                resp = fetch("POST", url, files=files, headers=headers, timeout=10)
            else:
                resp = requests.post(url, files=files, headers=headers, timeout=10)
            results.append((i, getattr(resp, 'status_code', None)))
        except Exception:
            results.append((i, None))
    return results

# ---------------------------------------------------------------------------
# Temporary token generator (example endpoint /api/temp-token)
# ---------------------------------------------------------------------------
def temp_token_generator(target: str, user_id: str, use_browser: bool = False, stealth: bool = False) -> str | None:
    """Ask the target for a short‑lived token.
    Returns the token string or None on error.
    """
    url = f"{target.rstrip('/')}/api/temp-token"
    params = {"uid": user_id, "exp": 60}
    try:
        if use_browser:
            resp = fetch("GET", url, params=params, timeout=8)
        else:
            resp = requests.get(url, params=params, timeout=8)
        if getattr(resp, 'status_code', None) == 200:
            return resp.json().get("access_token")
    except Exception:
        pass
    return None

# ---------------------------------------------------------------------------
# Rollback helper – inverse of INSERT/DELETE actions
# ---------------------------------------------------------------------------
def rollback_action(method: str, url: str, payload: Dict | None = None, use_browser: bool = False, stealth: bool = False) -> Any:
    """Perform the inverse HTTP method to undo a previous change.
    * POST → DELETE (same URL)
    * DELETE → POST (empty payload)
    Returns the response object or exception.
    """
    inverse = {"POST": "DELETE", "DELETE": "POST"}.get(method.upper())
    if not inverse:
        raise ValueError("Unsupported method for rollback")
    try:
        if use_browser:
            return fetch(inverse, url, json=payload, timeout=10)
        else:
            if inverse == "DELETE":
                return requests.delete(url, timeout=10)
            else:
                return requests.post(url, json=payload or {}, timeout=10)
    except Exception as e:
        return e

# ---------------------------------------------------------------------------
# Stealth headers generator
# ---------------------------------------------------------------------------
def stealth_headers() -> Dict[str, str]:
    """Return a randomised set of headers to evade simple WAF signatures.
    Includes a plausible User‑Agent and a Referer.
    """
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ]
    referers = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://news.ycombinator.com/",
    ]
    return {"User-Agent": random.choice(agents), "Referer": random.choice(referers)}

# ---------------------------------------------------------------------------
# Simple DDoS light test (20 rapid GETs to /ping or /health)
# ---------------------------------------------------------------------------
def ddos_light(target: str, endpoint: str = "/ping", count: int = 20, use_browser: bool = False, stealth: bool = False) -> List[Tuple[int, float, int]]:
    """Perform `count` GET requests and record latency.
    Returns a list of (index, latency_seconds, status_code).
    """
    results = []
    url = f"{target.rstrip('/')}{endpoint}"
    for i in range(count):
        start = asyncio.get_event_loop().time()
        try:
            if use_browser:
                resp = fetch("GET", url, timeout=5)
            else:
                resp = requests.get(url, timeout=5)
            latency = asyncio.get_event_loop().time() - start
            results.append((i, latency, getattr(resp, 'status_code', None)))
        except Exception:
            latency = asyncio.get_event_loop().time() - start
            results.append((i, latency, None))
    return results

# ---------------------------------------------------------------------------
# Rate‑limited fetch wrapper (max 5 rps by default)
# ---------------------------------------------------------------------------
_rate_semaphore = asyncio.Semaphore(5)

def rate_limited_fetch(method: str, url: str, **kwargs) -> Any:
    """Wrap `fetch` with a global semaphore to avoid flooding.
    This function is *synchronous* – it blocks until a semaphore slot is free,
    then calls the underlying `fetch`.
    """
    loop = asyncio.get_event_loop()
    async def _wrapper():
        async with _rate_semaphore:
            return await loop.run_in_executor(None, lambda: fetch(method, url, **kwargs))
    return loop.run_until_complete(_wrapper())

# ---------------------------------------------------------------------------
# Endpoint enumeration for Recon front
# ---------------------------------------------------------------------------
_common_paths = [
    "/admin",
    "/login",
    "/debug",
    "/swagger.json",
    "/api/docs",
    "/graphql",
    "/.env",
    "/config",
    "/robots.txt",
    "/sitemap.xml",
]

def enumerate_endpoints(target: str, use_browser: bool = False, stealth: bool = False) -> Dict[str, Any]:
    """Probe a curated list of common admin / API endpoints.
    Returns a dict mapping URL -> response object (or None on error).
    """
    results: Dict[str, Any] = {}
    headers = stealth_headers() if stealth else {}
    for path in _common_paths:
        url = f"{target.rstrip('/')}{path}"
        try:
            resp = fetch("GET", url, headers={**headers}, timeout=8) if use_browser else requests.get(url, headers={**headers}, timeout=8)
            results[url] = resp
        except Exception:
            results[url] = None
    return results

# ---------------------------------------------------------------------------
# Database download utility (streamed GET)
# ---------------------------------------------------------------------------
def download_database(target: str, endpoint: str, use_browser: bool = False, stealth: bool = False) -> Path | None:
    """Download a database dump from `endpoint` (e.g., /dump, /backup).
    Writes the file under `outputs/` and returns the Path.
    """
    url = f"{target.rstrip('/')}{endpoint}"
    headers = stealth_headers() if stealth else {}
    out_dir = Path("outputs")
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = out_dir / f"db_{target.replace('https://', '').replace('http://', '').replace('/', '_')}_{ts}"  # extension left blank – keep raw content
    try:
        if use_browser:
            resp = fetch("GET", url, headers={**headers}, timeout=30)
        else:
            resp = requests.get(url, headers={**headers}, stream=True, timeout=30)
        # Assume response has .content or iterable
        with open(filename, "wb") as f:
            if hasattr(resp, "content"):
                f.write(resp.content)
            else:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        return filename
    except Exception as e:
        # Caller will log the error
        return None

# ---------------------------------------------------------------------------
# Credential extraction (enhanced)
# ---------------------------------------------------------------------------
_jwt_regex = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
_aws_key_regex = re.compile(r"AKIA[0-9A-Z]{16}")

def extract_credentials_from_response(text: str) -> List[str]:
    """Return a list of suspicious credential‑like strings found in `text`.
    Uses the existing `scan_text` (imported where needed) plus extra regexes for JWTs and AWS keys.
    """
    # Basic scan for patterns like "token=..." – we will delegate to caller's `scan_text`
    # Here we only add extra regex matches.
    creds: List[str] = []
    for match in _jwt_regex.findall(text):
        creds.append(match)
    for match in _aws_key_regex.findall(text):
        creds.append(match)
    return creds
