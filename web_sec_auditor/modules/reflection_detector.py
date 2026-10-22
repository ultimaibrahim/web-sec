import requests
import secrets
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

class ReflectionDetector:
    """
    Detector defensivo y no destructivo de reflexión de parámetros y cabeceras.
    Inyecta cadenas canario benignas únicas (sin payloads maliciosos) para evaluar
    si el servidor web refleja entradas de usuario sin sanitizar en el HTML o cabeceras.
    """
    PROBE_PARAMS = ["q", "s", "search", "query", "id", "redirect", "url", "next", "view", "ref"]

    def __init__(self, base_url, session=None, timeout=6):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.timeout = timeout
        self.session.headers.update({
            "User-Agent": "WebSecAuditor/2.0 (Defensive Input Reflection Checker)"
        })

    def _generate_canary(self):
        return f"wsec_{secrets.token_hex(4)}"

    def check_query_reflection(self, path="/", params=None):
        findings = []
        target_params = params or self.PROBE_PARAMS
        target_url = urljoin(self.base_url + '/', path.lstrip('/'))

        for param in target_params:
            canary = self._generate_canary()
            # Prueba 1: Canario plano
            try:
                resp = self.session.get(target_url, params={param: canary}, timeout=self.timeout, allow_redirects=False)
                
                # Chequeo en cuerpo de respuesta
                if canary in resp.text:
                    # Analizar contexto de reflexión
                    context = "HTML Body"
                    if f'"{canary}"' in resp.text or f"'{canary}'" in resp.text:
                        context = "HTML Attribute"
                    elif f'<script' in resp.text and canary in resp.text:
                        context = "Script Block"

                    findings.append({
                        "type": "Reflexión en Cuerpo de Respuesta",
                        "parameter": param,
                        "url": resp.url,
                        "reflected_in": context,
                        "status_code": resp.status_code,
                        "risk_level": "MEDIO",
                        "description": f"El valor enviado en '{param}' se refleja textualmente en {context} sin filtrado aparente."
                    })

                # Chequeo en cabeceras de respuesta (ej. Location en redirecciones)
                for header_name, header_value in resp.headers.items():
                    if canary in header_value:
                        findings.append({
                            "type": "Reflexión en Cabecera HTTP",
                            "parameter": param,
                            "url": resp.url,
                            "reflected_in": f"Header '{header_name}'",
                            "status_code": resp.status_code,
                            "risk_level": "ALTO" if header_name.lower() in ["location", "set-cookie"] else "MEDIO",
                            "description": f"El parámetro '{param}' se refleja directamente en la cabecera HTTP '{header_name}'."
                        })

            except Exception:
                continue

        return findings

    def check_header_reflection(self, path="/"):
        """Verifica si cabeceras como X-Forwarded-Host o User-Agent se reflejan en la respuesta."""
        findings = []
        target_url = urljoin(self.base_url + '/', path.lstrip('/'))
        
        headers_to_test = [
            ("X-Forwarded-Host", self._generate_canary() + ".example.com"),
            ("User-Agent", f"WebSecAuditor/{self._generate_canary()}")
        ]

        for h_name, h_val in headers_to_test:
            try:
                resp = self.session.get(target_url, headers={h_name: h_val}, timeout=self.timeout, allow_redirects=False)
                if h_val in resp.text:
                    findings.append({
                        "type": "Reflexión de Cabecera de Entrada en Cuerpo",
                        "header": h_name,
                        "url": target_url,
                        "status_code": resp.status_code,
                        "risk_level": "MEDIO",
                        "description": f"El valor inyectado en la cabecera '{h_name}' se refleja en el HTML de respuesta (potencial Host Header Injection / Log Poisoning)."
                    })
            except Exception:
                continue

        return findings
