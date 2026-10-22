import requests
import hashlib
from urllib.parse import urljoin
from modules.template_engine import TemplateEngine

class VulnChecker:
    """
    Verificador de malas configuraciones y archivos sensibles expuestos.
    Integra el motor de plantillas declarativas YAML (estilo Nuclei) y
    un chequeo no invasivo con descarte inteligente de páginas de error de SPAs.
    """
    SENSITIVE_PATHS = [
        # Archivos de entorno y configuración
        (".env", "Variables de entorno y secretos del servidor"),
        (".env.example", "Plantilla de variables de entorno"),
        (".git/config", "Repositorio Git expuesto (fuga de código fuente)"),
        (".git/HEAD", "Puntero Git expuesto"),
        ("web.config", "Configuración de servidor IIS"),
        # Archivos de respaldo
        ("backup.zip", "Archivo de respaldo comprimido"),
        ("backup.sql", "Volcado de base de datos"),
        ("database.sql", "Volcado de base de datos"),
        # Paneles y diagnóstico
        ("robots.txt", "Archivo robots.txt (rutas del sitio)"),
        ("sitemap.xml", "Mapa del sitio XML"),
        ("phpinfo.php", "Diagnóstico PHP Info"),
        ("server-status", "Estado de Apache"),
        ("actuator/health", "Spring Boot Actuator Health"),
        ("swagger.json", "Definición de API OpenAPI / Swagger"),
        ("api-docs", "Documentación interactiva de API"),
    ]

    def __init__(self, base_url, session=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "WebSecAuditor/2.0 (Defensive Web Security Auditor)"
        })
        self.template_engine = TemplateEngine(self.base_url, session=self.session)

    def _get_fallback_hash(self):
        try:
            r = self.session.get(urljoin(self.base_url + '/', 'random_probe_fallback_check_12345'), timeout=5)
            if r.status_code == 200:
                return hashlib.md5(r.content).hexdigest()
        except Exception:
            pass
        return None

    def check_exposed_files(self):
        """
        Ejecuta primero las reglas declarativas YAML estructuradas.
        Si alguna ruta adicional no está cubierta en YAML, la sondea con descarte de fallback.
        """
        # 1. Ejecutar plantillas YAML estilo Nuclei
        yaml_findings = self.template_engine.run()
        
        findings = []
        covered_paths = set()

        for yf in yaml_findings:
            covered_paths.add(yf["path"].lstrip('/'))
            findings.append({
                "path": yf["path"],
                "url": yf["url"],
                "status_code": yf["status_code"],
                "description": f"[{yf['severity']}] {yf['name']}",
                "severity": yf["severity"],
                "impact": yf["impact"],
                "remediation": yf["remediation"],
                "size_bytes": len(yf.get("evidence_sample", ""))
            })

        # 2. Rutas legacy de SENSITIVE_PATHS que no se hayan evaluado todavía
        fallback_hash = self._get_fallback_hash()
        for path, desc in self.SENSITIVE_PATHS:
            if path in covered_paths:
                continue

            target_url = urljoin(self.base_url + '/', path)
            try:
                resp = self.session.get(target_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    content_hash = hashlib.md5(resp.content).hexdigest()
                    if fallback_hash and content_hash == fallback_hash:
                        continue

                    ct = resp.headers.get("Content-Type", "").lower()
                    if path.endswith(('.env', '.config', '.sql', 'HEAD', '.zip')) and "text/html" in ct:
                        continue

                    # Descartar páginas de error comunes
                    if any(err in resp.text.lower() for err in ["not_found", "error 404", "error 500", "página no encontrada"]):
                        continue

                    findings.append({
                        "path": path,
                        "url": target_url,
                        "status_code": resp.status_code,
                        "description": desc,
                        "severity": "ALTO" if any(k in path for k in [".env", ".git", ".sql"]) else "MEDIO",
                        "size_bytes": len(resp.content)
                    })
            except Exception:
                pass

        return findings
