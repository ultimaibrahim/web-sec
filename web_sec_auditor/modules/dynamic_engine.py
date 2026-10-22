import os
import shutil
import subprocess
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class DynamicRenderEngine:
    """
    Motor de renderizado dinámico en modo headless utilizando el binario Chromium
    del sistema para aplicaciones de página única (SPAs) y frameworks reactivos (HTMX, Vue, React).
    Captura el DOM completamente hidratado y extrae atributos declarativos modernos (hx-*, data-*).
    """
    def __init__(self, timeout=12):
        self.timeout = timeout
        self.browser_bin = self._find_browser_binary()

    def _find_browser_binary(self):
        for candidate in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"]:
            path = shutil.which(candidate)
            if path:
                return path
        return None

    @property
    def is_available(self):
        return self.browser_bin is not None

    def render_and_extract(self, url):
        """Renderiza la página web usando Chromium headless y extrae el DOM junto con llamadas HTMX."""
        if not self.is_available:
            return None

        cmd = [
            self.browser_bin,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--dump-dom",
            url
        ]

        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout, text=True, errors="replace")
            if proc.returncode != 0 or not proc.stdout:
                return None
            
            raw_html = proc.stdout
            soup = BeautifulSoup(raw_html, "html.parser")

            discovered_links = set()
            htmx_endpoints = []

            # 1. Enlaces estándar hidratados
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    discovered_links.add(urljoin(url, href))

            # 2. Atributos HTMX dinámicos
            for elem in soup.find_all(True):
                for attr, verb in [("hx-get", "GET"), ("hx-post", "POST"), ("hx-put", "PUT"), ("hx-delete", "DELETE"), ("hx-patch", "PATCH")]:
                    if elem.has_attr(attr):
                        target_ep = elem[attr].strip()
                        if target_ep and not target_ep.startswith(("#", "javascript:")):
                            htmx_endpoints.append({
                                "endpoint": target_ep,
                                "method": verb,
                                "target": elem.get("hx-target", ""),
                                "trigger": elem.get("hx-trigger", ""),
                                "swap": elem.get("hx-swap", "")
                            })

            return {
                "rendered_html": raw_html,
                "discovered_links": list(discovered_links),
                "htmx_endpoints": htmx_endpoints
            }

        except Exception:
            return None
