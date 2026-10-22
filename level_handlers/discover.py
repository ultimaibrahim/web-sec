"""discover.py – Dynamic endpoint discovery pipeline

Provides ``discover_routes`` which extracts candidate API endpoints from a web
application's HTML + JavaScript bundles, classifies them heuristically and returns
a mapping ``{route: [tags]}``.

The implementation is deliberately lightweight – only stdlib, ``requests`` and
``beautifulsoup4`` (already a dependency of the project) are used.  It can be
imported by any existing module (``void_plus``, ``upload_bomb`` …) without any
code changes; the caller simply does:

```python
from level_handlers.discover import discover_routes
routes = discover_routes(target_url)
```

If the environment variable ``ENABLE_DYNAMIC_DISCOVERY`` is not set, the function
returns an empty dict instantly, preserving backward‑compatibility.
"""

import os
import re
import json
import logging
import urllib.parse
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Configuration & helpers
# ---------------------------------------------------------------------------
_LOG = logging.getLogger(__name__)

# Simple keyword‑based tag definition (weights & thresholds are tuned for the
# default use‑case; they can be overridden by the caller if needed).
_TAG_DEFS: Dict[str, Tuple[List[str], float, float]] = {
    "upload": (
        ["upload", "file", "media", "attachment", "avatar", "image", "photo"],
        1.5,
        1.0,
    ),
    "create": (
        ["create", "new", "add", "register", "signup"],
        1.2,
        1.0,
    ),
    "update": (
        ["update", "edit", "modify", "patch", "change"],
        1.2,
        1.0,
    ),
    "delete": (
        ["delete", "remove", "purge", "erase", "destroy"],
        1.5,
        1.0,
    ),
    "auth": (
        ["login", "logout", "session", "token", "auth"],
        1.0,
        0.8,
    ),
    "admin": (
        ["admin", "manage", "dashboard", "control"],
        1.0,
        0.8,
    ),
    "read": (
        ["list", "get", "fetch", "view", "detail"],
        0.8,
        0.6,
    ),
}

# ---------------------------------------------------------------------------
# Core discovery logic
# ---------------------------------------------------------------------------

def _fetch_url(url: str) -> Optional[str]:
    """Return the text content of *url* or ``None`` on failure.

    ``requests`` is used with a short timeout and TLS verification disabled – the
    tool is designed for lab environments where self‑signed certs are common.
    """
    try:
        resp = requests.get(url, timeout=8, verify=False)
        resp.raise_for_status()
        return resp.text
    except Exception as exc:  # pragma: no cover – network failures are expected in CI
        _LOG.debug("Failed to fetch %s: %s", url, exc)
        return None


def _extract_scripts(base_url: str, html: str) -> List[str]:
    """Parse *html* and return absolute URLs of all ``<script src=…>`` assets.

    Relative URLs are resolved against *base_url* using ``urllib.parse.urljoin``.
    """
    soup = BeautifulSoup(html, "html.parser")
    scripts = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        abs_url = urllib.parse.urljoin(base_url, src)
        scripts.append(abs_url)
    return scripts


# Regex patterns for route extraction.  They capture the URL part and, when possible,
# the HTTP method used.
_FETCH_RE = re.compile(r"fetch\s*\(\s*(['\"])(/[^'\"]+)\1\s*,\s*\{[^}]*method\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]", re.IGNORECASE)
_AXIOS_RE = re.compile(r"axios\.(get|post|put|patch|delete)\s*\(\s*(['\"])(/[^'\"]+)\2", re.IGNORECASE)
_XHR_RE = re.compile(r"XMLHttpRequest\s*\(\s*\)\s*\.open\s*\(\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]\s*,\s*(['\"])(/[^'\"]+)\2", re.IGNORECASE)


def _mine_routes_from_js(js: str) -> List[Tuple[str, str]]:
    """Return a list of ``(route, method)`` tuples extracted from *js*.

    If the method cannot be inferred from the pattern, ``GET`` is assumed.
    """
    routes: List[Tuple[str, str]] = []
    for m in _FETCH_RE.finditer(js):
        routes.append((m.group(2), m.group(3).upper()))
    for m in _AXIOS_RE.finditer(js):
        routes.append((m.group(3), m.group(1).upper()))
    for m in _XHR_RE.finditer(js):
        routes.append((m.group(3), m.group(1).upper()))
    # Fallback – plain strings that look like '/api/...'
    plain = re.findall(r"['\"](/[^'\"]{1,100})['\"]", js)
    for p in plain:
        routes.append((p, "GET"))
    return routes


def _normalize_route(route: str) -> str:
    """Strip query strings, ensure leading slash and deduplicate.
    """
    route = urllib.parse.urlparse(route).path
    if not route.startswith('/'):
        route = '/' + route
    return route.rstrip('/') or '/'


def _score_route(route: str, method: str) -> List[str]:
    """Apply the heuristic scoring model and return a list of tags.

    The function follows the table in the design document.  Only tags whose score
    meets the per‑tag threshold are kept.
    """
    lowered = route.lower()
    tags: List[str] = []
    for tag, (keywords, weight, threshold) in _TAG_DEFS.items():
        score = 0.0
        for kw in keywords:
            if kw in lowered:
                score += weight
        # structural hints
        if tag == "upload" and re.search(r"\.(png|jpe?g|gif|zip|pdf)$", route, re.IGNORECASE):
            score += 0.5
        if tag == "delete" and method.upper() == "DELETE":
            score += 0.7
        if tag == "auth" and "/auth/" in lowered:
            score += 0.3
        if tag == "admin" and "admin" in lowered:
            score += 0.3
        if score >= threshold:
            tags.append(tag)
    return tags


def discover_routes(target: str, *, save_to: Optional[Path] = None) -> Dict[str, List[str]]:
    """Discover and classify routes for *target*.

    Parameters
    ----------
    target: str
        Base URL (e.g. ``https://example.com``).  ``file://`` URLs are also
        accepted – the function will read the file directly.
    save_to: Path | None, optional
        If supplied, a JSON report ``{route: [tags]}`` is written to *save_to*.

    Returns
    -------
    dict
        Mapping of normalized route → list of inferred tags.  An empty dict is
        returned when ``ENABLE_DYNAMIC_DISCOVERY`` is unset.
    """
    if not os.getenv("ENABLE_DYNAMIC_DISCOVERY"):
        _LOG.info("Dynamic discovery disabled via ENABLE_DYNAMIC_DISCOVERY.")
        return {}

    # ---------------------------------------------------------------------
    # 1️⃣ Fetch the HTML page
    # ---------------------------------------------------------------------
    html = _fetch_url(target)
    if html is None:
        _LOG.warning("Unable to fetch target %s – returning empty pool.", target)
        return {}

    # ---------------------------------------------------------------------
    # 2️⃣ Extract script URLs and download them
    # ---------------------------------------------------------------------
    script_urls = _extract_scripts(target, html)
    discovered: Dict[str, List[str]] = {}
    for script_url in script_urls:
        js = _fetch_url(script_url)
        if not js:
            continue
        raw_routes = _mine_routes_from_js(js)
        for raw_route, method in raw_routes:
            route = _normalize_route(raw_route)
            tags = _score_route(route, method)
            if tags:
                discovered[route] = tags

    # ---------------------------------------------------------------------
    # 3️⃣ Optional persistence
    # ---------------------------------------------------------------------
    if save_to:
        try:
            save_to.write_text(json.dumps(discovered, indent=2))
        except Exception as exc:  # pragma: no cover – best‑effort only
            _LOG.debug("Failed to write discovery report: %s", exc)

    return discovered

# ---------------------------------------------------------------------------
# Simple __main__ demo (useful for quick manual checks)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python -m level_handlers.discover <target_url>")
        sys.exit(1)
    result = discover_routes(sys.argv[1])
    print(json.dumps(result, indent=2))
