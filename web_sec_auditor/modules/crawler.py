import os
import re
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from modules.dynamic_engine import DynamicRenderEngine

class WebCrawler:
    """
    Rastreador web que descarga y realiza un mirror completo (HTML, JS, CSS, JSON, imágenes, etc.)
    respetando el mismo host/origen para aislar la prueba.
    Soporta extracción estática y renderizado dinámico headless para SPAs/HTMX.
    """
    def __init__(self, base_url, output_dir, session=None, max_depth=3, max_pages=100, dynamic=False):
        self.base_url = base_url.rstrip('/')
        parsed = urlparse(self.base_url)
        self.target_netloc = parsed.netloc
        self.scheme = parsed.scheme
        self.output_dir = output_dir
        self.mirror_dir = os.path.join(output_dir, "site_mirror")
        os.makedirs(self.mirror_dir, exist_ok=True)

        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "WebSecAuditor/2.0 (Defensive Web Security Auditor)"
        })

        self.max_depth = max_depth
        self.max_pages = max_pages
        self.dynamic = dynamic
        self.dynamic_engine = DynamicRenderEngine() if dynamic else None

        self.visited_urls = set()
        self.downloaded_assets = set()
        self.discovered_html_urls = set()
        self.discovered_endpoints = set()

        # Detección de fallback de SPA (routing catch-all hacia index.html)
        self.fallback_content_hash = self._get_fallback_fingerprint()

    def _get_fallback_fingerprint(self):
        """
        Obtiene el hash del fallback (página por defecto cuando una ruta no existe)
        para no interpretar como nueva página HTML cualquier URL inexistente en SPAs.
        """
        try:
            probe_url = urljoin(self.base_url + '/', 'probe_fallback_check_987654321')
            r = self.session.get(probe_url, timeout=10)
            if r.status_code == 200 and "text/html" in r.headers.get("Content-Type", "").lower():
                import hashlib
                return hashlib.md5(r.content).hexdigest()
        except Exception:
            pass
        return None

    def _url_to_local_path(self, url):
        parsed = urlparse(url)
        path = parsed.path
        if not path or path.endswith('/'):
            path += "index.html"
        
        path = path.lstrip('/')
        if not path:
            path = "index.html"
            
        base_name = os.path.basename(path)
        if '.' not in base_name:
            path += ".html"

        full_path = os.path.join(self.mirror_dir, path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        return full_path

    def is_same_host(self, url):
        parsed = urlparse(url)
        return parsed.netloc == self.target_netloc or not parsed.netloc

    def normalize_url(self, url):
        parsed = urlparse(url)
        return f"{self.scheme}://{self.target_netloc}{parsed.path}"

    COMMON_WEB_ROUTES = [
        "admin.html", "admin", "login.html", "login", "dashboard.html", "dashboard",
        "portal.html", "portal", "mi-credencial.html", "credencial.html", "wallet.html",
        "wallet-pos.html", "pos.html", "lealtad.html", "loyalty.html", "reportes.html",
        "reportes-tiempo-real.html", "cliente-wallet.html", "login-cliente.html",
        "registro-cliente.html", "gift-card-shop.html", "auditoria.html"
    ]

    def crawl_and_mirror(self):
        """
        Ejecuta el rastreo recursivo y descarga todos los recursos.
        Incluye semillas comunes de vistas para mapear superficies no enlazadas en el hero/landing.
        """
        queue = [(self.base_url, 0)]
        self.visited_urls.add(self.base_url)

        # Semillas de descubrimiento para aplicaciones web modernas
        for route in self.COMMON_WEB_ROUTES:
            seed_url = urljoin(self.base_url + '/', route)
            norm_seed = self.normalize_url(seed_url)
            if norm_seed not in self.visited_urls:
                self.visited_urls.add(norm_seed)
                queue.append((norm_seed, 1))

        while queue and len(self.discovered_html_urls) < self.max_pages:
            current_url, depth = queue.pop(0)

            if depth > self.max_depth:
                continue

            try:
                resp = self.session.get(current_url, timeout=10, allow_redirects=True)
            except Exception:
                continue

            content_type = resp.headers.get("Content-Type", "").lower()
            local_file = self._url_to_local_path(current_url)

            # Guardar contenido
            try:
                with open(local_file, "wb") as f:
                    f.write(resp.content)
            except Exception:
                pass

            if "text/html" in content_type:
                import hashlib
                current_hash = hashlib.md5(resp.content).hexdigest()
                if current_url != self.base_url and current_url != self.base_url + '/' and self.fallback_content_hash and current_hash == self.fallback_content_hash:
                    continue

                self.discovered_html_urls.add(current_url)
                
                # Extracción estándar estática
                assets, links = self._extract_assets_and_links(resp.text, current_url)

                # Si el modo dinámico está activo y el motor está disponible, renderizar DOM hidratado
                if self.dynamic and self.dynamic_engine and self.dynamic_engine.is_available:
                    dyn_res = self.dynamic_engine.render_and_extract(current_url)
                    if dyn_res:
                        links.update(dyn_res.get("discovered_links", []))
                        for ep_info in dyn_res.get("htmx_endpoints", []):
                            full_ep = urljoin(current_url, ep_info["endpoint"])
                            self.discovered_endpoints.add((full_ep, ep_info["method"], f"HTMX {ep_info['method']}"))

                # Descargar assets (JS, CSS, JSON, imágenes)
                for asset_url in assets:
                    self._download_asset(asset_url)

                # Encolar nuevos enlaces HTML
                for link in links:
                    norm = self.normalize_url(link)
                    if self.is_same_host(norm) and norm not in self.visited_urls:
                        self.visited_urls.add(norm)
                        queue.append((norm, depth + 1))
            elif "application/json" in content_type or "text/json" in content_type:
                self.discovered_endpoints.add((current_url, "GET", "JSON Endpoint"))

        return {
            "discovered_pages": sorted(list(self.discovered_html_urls)),
            "downloaded_assets": sorted(list(self.downloaded_assets)),
            "all_visited_urls": sorted(list(self.visited_urls)),
            "form_endpoints": list(self.discovered_endpoints),
            "mirror_path": self.mirror_dir
        }

    def _download_asset(self, asset_url):
        norm = self.normalize_url(asset_url)
        if norm in self.downloaded_assets or not self.is_same_host(norm):
            return
        
        self.downloaded_assets.add(norm)
        try:
            r = self.session.get(norm, timeout=10)
            if r.status_code == 200:
                local_path = self._url_to_local_path(norm)
                with open(local_path, "wb") as f:
                    f.write(r.content)
        except Exception:
            pass

    def _extract_assets_and_links(self, html_content, base_url):
        assets = set()
        links = set()
        soup = BeautifulSoup(html_content, "html.parser")

        # Scripts JS
        for s in soup.find_all("script", src=True):
            assets.add(urljoin(base_url, s["src"]))

        # Estilos CSS
        for link in soup.find_all("link", rel=lambda val: val and "stylesheet" in val):
            if link.get("href"):
                assets.add(urljoin(base_url, link["href"]))

        # Imágenes / Media
        for img in soup.find_all(["img", "source"], src=True):
            assets.add(urljoin(base_url, img["src"]))

        # Enlaces <a>
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                links.add(urljoin(base_url, href))

        # Formularios (endpoints)
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            method = form.get("method", "GET").upper()
            action_url = urljoin(base_url, action)
            self.discovered_endpoints.add((action_url, method, "HTML Form"))

        # Atributos HTMX estáticos
        for elem in soup.find_all(True):
            for attr, verb in [("hx-get", "GET"), ("hx-post", "POST"), ("hx-put", "PUT"), ("hx-delete", "DELETE"), ("hx-patch", "PATCH")]:
                if elem.has_attr(attr):
                    ep = elem[attr].strip()
                    if ep and not ep.startswith(("#", "javascript:")):
                        full_ep = urljoin(base_url, ep)
                        self.discovered_endpoints.add((full_ep, verb, f"HTMX {verb}"))
                        if verb == "GET":
                            links.add(full_ep)

        return assets, links
