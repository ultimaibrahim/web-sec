import requests
from urllib.parse import urljoin

class MethodFuzzer:
    """
    Fuzzer defensivo de métodos y verbos HTTP.
    Evalúa qué verbos están permitidos en rutas clave y detecta anomalías
    como soporte de TRACE (XST), PUT/DELETE no autenticado o bypass de métodos.
    """
    METHODS = ["OPTIONS", "HEAD", "GET", "POST", "PUT", "DELETE", "PATCH", "TRACE"]

    def __init__(self, base_url, session=None, timeout=6):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.timeout = timeout
        self.session.headers.update({
            "User-Agent": "WebSecAuditor/2.0 (Defensive HTTP Method Auditor)"
        })

    def audit_endpoint(self, path="/"):
        target_url = urljoin(self.base_url + '/', path.lstrip('/'))
        results = {
            "path": path,
            "url": target_url,
            "methods": {},
            "allow_header": None,
            "warnings": [],
            "risk_level": "BAJO"
        }

        for method in self.METHODS:
            try:
                # Enviar petición con body vacío y timeout controlado
                resp = self.session.request(
                    method=method,
                    url=target_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    data="" if method in ["POST", "PUT", "PATCH"] else None
                )
                
                results["methods"][method] = {
                    "status_code": resp.status_code,
                    "content_length": len(resp.content)
                }

                if method == "OPTIONS":
                    allow = resp.headers.get("Allow") or resp.headers.get("allow")
                    if allow:
                        results["allow_header"] = allow

                # Detección de TRACE (Riesgo XST)
                if method == "TRACE" and resp.status_code == 200:
                    if "message/http" in resp.headers.get("Content-Type", "").lower() or "trace" in resp.text.lower():
                        results["warnings"].append("Método TRACE habilitado y activo (Vulnerable a Cross-Site Tracing - XST)")
                        results["risk_level"] = "ALTO"

                # Detección de PUT/DELETE expuestos
                if method in ["PUT", "DELETE"] and resp.status_code in [200, 201, 204]:
                    results["warnings"].append(f"Método {method} respondió código exitoso ({resp.status_code}) sin credenciales aparentes.")
                    if results["risk_level"] != "CRÍTICO":
                        results["risk_level"] = "MEDIO"

            except Exception:
                results["methods"][method] = {
                    "status_code": None,
                    "content_length": 0
                }

        # Analizar Allow header si no hubo warnings directos
        if results["allow_header"]:
            allowed_upper = [m.strip().upper() for m in results["allow_header"].split(",")]
            if "TRACE" in allowed_upper:
                results["warnings"].append("La cabecera Allow anuncia soporte para TRACE.")
            if "PUT" in allowed_upper or "DELETE" in allowed_upper:
                results["warnings"].append("La cabecera Allow expone métodos de modificación (PUT/DELETE).")

        return results

    def audit_multiple(self, paths=None):
        if not paths:
            paths = ["/", "/login", "/api", "/admin"]
        
        matrix = []
        for p in paths:
            matrix.append(self.audit_endpoint(p))
        return matrix
