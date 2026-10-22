import requests
import time
from urllib.parse import urlparse

class NetworkAuditor:
    """
    Emula la inspección del panel DevTools Network y evalúa la higiene de cabeceras HTTP,
    tiempos de respuesta, cookies y políticas de seguridad.
    """
    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()

    def audit(self):
        start_time = time.time()
        try:
            resp = self.session.get(self.target_url, timeout=25, allow_redirects=True)
            latency_ms = round((time.time() - start_time) * 1000, 2)
        except Exception as e:
            return {"error": f"No se pudo conectar al objetivo: {str(e)}"}

        headers = resp.headers
        cookies = resp.cookies

        # Análisis de Cabeceras de Seguridad
        sec_headers_status = {
            "Content-Security-Policy": {
                "present": "Content-Security-Policy" in headers,
                "value": headers.get("Content-Security-Policy"),
                "description": "Mitiga inyecciones XSS y restricción de orígenes de recursos."
            },
            "Strict-Transport-Security": {
                "present": "Strict-Transport-Security" in headers,
                "value": headers.get("Strict-Transport-Security"),
                "description": "Fuerza conexiones HTTPS (HSTS)."
            },
            "X-Frame-Options": {
                "present": "X-Frame-Options" in headers,
                "value": headers.get("X-Frame-Options"),
                "description": "Protección contra Clickjacking (evita embebido en iframes)."
            },
            "X-Content-Type-Options": {
                "present": "X-Content-Type-Options" in headers,
                "value": headers.get("X-Content-Type-Options"),
                "description": "Previene MIME sniffing ('nosniff')."
            },
            "Referrer-Policy": {
                "present": "Referrer-Policy" in headers,
                "value": headers.get("Referrer-Policy"),
                "description": "Controla qué información de referencia se envía al navegar."
            },
            "Permissions-Policy": {
                "present": "Permissions-Policy" in headers,
                "value": headers.get("Permissions-Policy"),
                "description": "Restringe APIs del navegador (cámara, micrófono, geolocalización)."
            }
        }

        # Fuga de información en cabeceras de servidor
        info_leak_headers = {}
        for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]:
            if h in headers:
                info_leak_headers[h] = headers[h]

        # Auditoría de Cookies
        cookies_audit = []
        for c in cookies:
            cookies_audit.append({
                "name": c.name,
                "secure": c.secure,
                "httponly": c.has_nonstandard_attr("httponly") or c.has_nonstandard_attr("HttpOnly"),
                "domain": c.domain,
                "path": c.path
            })

        # Auditoría CORS
        cors_info = {
            "allow_origin": headers.get("Access-Control-Allow-Origin"),
            "allow_credentials": headers.get("Access-Control-Allow-Credentials"),
            "allow_methods": headers.get("Access-Control-Allow-Methods")
        }

        # Puntuación básica de cabeceras (0 a 100)
        total_sec = len(sec_headers_status)
        present_sec = sum(1 for v in sec_headers_status.values() if v["present"])
        header_score = round((present_sec / total_sec) * 100)

        return {
            "status_code": resp.status_code,
            "latency_ms": latency_ms,
            "content_type": headers.get("Content-Type", ""),
            "content_length": len(resp.content),
            "security_headers": sec_headers_status,
            "info_leak_headers": info_leak_headers,
            "cookies": cookies_audit,
            "cors": cors_info,
            "header_score": header_score
        }
