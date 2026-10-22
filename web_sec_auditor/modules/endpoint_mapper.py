import os
import re
from urllib.parse import urljoin, urlparse
import requests

class EndpointMapper:
    """
    Descubre endpoints, rutas relativas y llamadas de API analizando los archivos
    HTML y JavaScript descargados en el mirror local y enriqueciéndolos con OpenAPI / HTMX.
    Además, permite perfilar y medir de forma segura el volumen de datos (payload size)
    que devuelve cada endpoint (GET vs POST), clasificándolos por tamaño y detectando Verb Tampering.
    """
    ENDPOINT_PATTERNS = [
        re.compile(r"""(?:href|src|action|url|endpoint|path)\s*[:=]\s*["'](/[^"'<>#\s]+)["']""", re.IGNORECASE),
        re.compile(r"""(?:fetch|axios(?:\.get|\.post|\.put|\.delete)?|\$\.ajax|\$\.get|\$\.post)\s*\(\s*["'](/[^"'<>#\s]+)["']""", re.IGNORECASE),
        re.compile(r"""["'](/(?:api|v[0-9]+|auth|user|admin|rest|graphql|login|logout|webhook|service)/[^"'<>#\s]*)["']""", re.IGNORECASE),
    ]

    def __init__(self, base_url, mirror_dir, session=None):
        self.base_url = base_url.rstrip('/')
        self.mirror_dir = mirror_dir
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "WebSecAuditor/2.0 (Defensive Endpoint Data Profiler)"
        })

    def extract_endpoints_from_files(self, additional_endpoints=None):
        discovered = {}

        if os.path.exists(self.mirror_dir):
            for root, _, files in os.walk(self.mirror_dir):
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in ['.js', '.html', '.htm', '.json']:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, self.mirror_dir)

                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                        except Exception:
                            continue

                        endpoints_in_file = set()
                        for pattern in self.ENDPOINT_PATTERNS:
                            matches = pattern.findall(content)
                            for m in matches:
                                if not m or m.endswith(('.png', '.jpg', '.jpeg', '.svg', '.css', '.ico', '.woff', '.woff2')):
                                    continue
                                endpoints_in_file.add(m)

                        if endpoints_in_file:
                            discovered[rel_path] = sorted(list(endpoints_in_file))

        all_unique_routes = set()
        for routes in discovered.values():
            all_unique_routes.update(routes)

        if additional_endpoints:
            for extra in additional_endpoints:
                parsed = urlparse(extra)
                path = parsed.path
                if parsed.query:
                    path += f"?{parsed.query}"
                if path and not path.endswith(('.png', '.jpg', '.jpeg', '.svg', '.css', '.ico', '.woff', '.woff2')):
                    all_unique_routes.add(path)

        return {
            "by_file": discovered,
            "unique_endpoints": sorted(list(all_unique_routes))
        }

    def profile_data_volumes(self, unique_endpoints, max_endpoints=40):
        """
        Consulta de lectura no invasiva (GET y POST vacío/benigno) sobre los endpoints descubiertos
        para medir el volumen de datos que transfieren, clasificarlos y detectar si un endpoint
        restringe o falla en un método (ej. POST 405/403/400) pero entrega datos con otro (ej. GET 200).
        """
        profiled = []

        # Filtrar candidatos que parezcan APIs o rutas dinámicas
        candidates = [ep for ep in unique_endpoints if not ep.endswith(('.html', '.js', '.css', '.svg', '.png'))][:max_endpoints]

        for ep in candidates:
            target = urljoin(self.base_url + '/', ep.lstrip('/'))
            try:
                # 1. Probar GET
                resp_get = self.session.get(target, timeout=6, allow_redirects=False)
                get_size = len(resp_get.content)
                get_status = resp_get.status_code
                get_ct = resp_get.headers.get("Content-Type", "").split(';')[0]

                # 2. Probar POST (payload vacío sin mutaciones maliciosas)
                resp_post = self.session.post(target, timeout=6, allow_redirects=False)
                post_size = len(resp_post.content)
                post_status = resp_post.status_code
                post_ct = resp_post.headers.get("Content-Type", "").split(';')[0]

                # Analizar discrepancia de verbos (posible Verb Tampering)
                verb_insight = None
                if resp_get.status_code == 200 and resp_post.status_code in [401, 403, 405, 500]:
                    verb_insight = f"⚠️ Posible Verb Tampering: GET devuelve 200 ({self._format_size(get_size)}), pero POST responde {resp_post.status_code}"
                elif resp_get.status_code in [401, 403, 405] and resp_post.status_code == 200:
                    verb_insight = f"ℹ️ POST responde 200 ({self._format_size(post_size)}), pero GET responde {resp_get.status_code}"

                # Usar el tamaño más representativo
                size_bytes = max(get_size, post_size)
                primary_status = f"GET: {get_status} | POST: {post_status}"

                # Clasificación por tamaño
                if size_bytes >= 500 * 1024:
                    classification = "Alto Volumen (> 500 KB)"
                    badge = "ALTO"
                elif size_bytes >= 50 * 1024:
                    classification = "Medio Volumen (50 - 500 KB)"
                    badge = "MEDIO"
                else:
                    classification = "Bajo Volumen (< 50 KB)"
                    badge = "BAJO"

                profiled.append({
                    "endpoint": ep,
                    "url": target,
                    "status_code": primary_status,
                    "get_status": get_status,
                    "post_status": post_status,
                    "content_type": get_ct or post_ct or "desconocido",
                    "size_bytes": size_bytes,
                    "size_readable": self._format_size(size_bytes),
                    "classification": classification,
                    "badge": badge,
                    "verb_insight": verb_insight
                })
            except Exception:
                pass

        profiled.sort(key=lambda x: x["size_bytes"], reverse=True)
        return profiled

    @staticmethod
    def _format_size(size_bytes):
        if size_bytes >= 1024 * 1024:
            return f"{round(size_bytes / (1024 * 1024), 2)} MB"
        elif size_bytes >= 1024:
            return f"{round(size_bytes / 1024, 2)} KB"
        return f"{size_bytes} B"
