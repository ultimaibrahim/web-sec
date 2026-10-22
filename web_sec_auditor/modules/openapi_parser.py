import json
import requests
from urllib.parse import urljoin

class OpenAPIParser:
    """
    Parser defensivo de especificaciones OpenAPI (v3.x) y Swagger (v2.0).
    Extrae automáticamente rutas de API, métodos HTTP aceptados y parámetros
    para mapear la superficie de ataque sin requerir scraping manual de frontend.
    """
    COMMON_SPEC_PATHS = [
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger/v1/swagger.json",
        "/api/swagger.json",
        "/api/openapi.json"
    ]

    def __init__(self, base_url, session=None, timeout=6):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.timeout = timeout
        self.session.headers.update({
            "User-Agent": "WebSecAuditor/2.0 (OpenAPI & Swagger Schema Discovery)"
        })

    def discover_and_parse(self):
        """Sondea rutas habituales de especificación OpenAPI y las decodifica si están expuestas."""
        discovered_specs = []

        for path in self.COMMON_SPEC_PATHS:
            spec_url = urljoin(self.base_url + '/', path.lstrip('/'))
            try:
                resp = self.session.get(spec_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code == 200 and ("json" in resp.headers.get("Content-Type", "").lower() or resp.text.strip().startswith("{")):
                    try:
                        spec_data = json.loads(resp.text)
                        if isinstance(spec_data, dict) and ("swagger" in spec_data or "openapi" in spec_data or "paths" in spec_data):
                            parsed_info = self.parse_spec_dict(spec_data, source_url=spec_url)
                            discovered_specs.append(parsed_info)
                            # Si ya encontramos una especificación válida, retornar
                            break
                    except json.JSONDecodeError:
                        continue
            except Exception:
                continue

        return discovered_specs

    def parse_spec_dict(self, spec_data, source_url=None):
        version = spec_data.get("openapi") or spec_data.get("swagger") or "Desconocida"
        info = spec_data.get("info", {})
        title = info.get("title", "API sin título")
        api_version = info.get("version", "1.0")
        
        extracted_endpoints = []
        paths_dict = spec_data.get("paths", {})

        for route, methods in paths_dict.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.lower() in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    summary = ""
                    params = []
                    if isinstance(details, dict):
                        summary = details.get("summary") or details.get("description") or ""
                        for p in details.get("parameters", []):
                            if isinstance(p, dict) and "name" in p:
                                params.append({
                                    "name": p["name"],
                                    "in": p.get("in", "query"),
                                    "required": p.get("required", False)
                                })

                    extracted_endpoints.append({
                        "route": route,
                        "method": method.upper(),
                        "summary": summary[:80],
                        "parameters": params
                    })

        return {
            "source_url": source_url,
            "title": title,
            "api_version": api_version,
            "spec_format": f"OpenAPI/Swagger {version}",
            "total_operations": len(extracted_endpoints),
            "operations": extracted_endpoints
        }
