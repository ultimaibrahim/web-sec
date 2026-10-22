import os
import re
import yaml
import requests
from urllib.parse import urljoin

class TemplateEngine:
    """
    Motor de ejecución de plantillas declarativas YAML estilo Nuclei.
    Carga reglas modulares de auditoría y ejecuta validaciones defensivas
    con soporte de palabras clave, expresiones regulares, códigos de estado
    y descarte inteligente de falsos positivos (como páginas de error HTML de SPAs).
    """
    def __init__(self, base_url, rules_dir=None, session=None, timeout=6):
        self.base_url = base_url.rstrip('/')
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
        self.session = session or requests.Session()
        self.timeout = timeout
        self.session.headers.update({
            "User-Agent": "WebSecAuditor/2.0 (Nuclei-Style Declarative Template Engine)"
        })

    def load_rules(self):
        """Carga recursivamente todas las plantillas YAML en el directorio de reglas."""
        rules = []
        if not os.path.exists(self.rules_dir):
            return rules

        for root, _, files in os.walk(self.rules_dir):
            for file in sorted(files):
                if file.endswith(('.yaml', '.yml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = yaml.safe_load(f)
                            if data and isinstance(data, dict) and "id" in data:
                                rules.append(data)
                    except Exception as e:
                        print(f"Error cargando regla {file_path}: {e}")
        return rules

    def _evaluate_matchers(self, resp, matchers, matchers_condition="and"):
        """Evalúa las condiciones de coincidencia de una respuesta HTTP."""
        results = []

        for m in matchers:
            m_type = m.get("type", "status")
            m_cond = m.get("condition", "or")
            m_matched = False

            if m_type == "status":
                expected_statuses = m.get("status", [200])
                m_matched = resp.status_code in expected_statuses

            elif m_type == "word":
                words = m.get("words", [])
                if m_cond == "and":
                    m_matched = all(w in resp.text for w in words)
                else:
                    m_matched = any(w in resp.text for w in words)

            elif m_type == "negative-word":
                words = m.get("words", [])
                # Debe NO contener ninguna de estas palabras
                m_matched = not any(w.lower() in resp.text.lower() for w in words)

            elif m_type == "regex":
                regexes = m.get("regex", [])
                compiled = [re.compile(r, re.IGNORECASE) for r in regexes]
                if m_cond == "and":
                    m_matched = all(c.search(resp.text) for c in compiled)
                else:
                    m_matched = any(c.search(resp.text) for c in compiled)

            elif m_type == "content-type":
                expected_cts = m.get("content-type", [])
                resp_ct = resp.headers.get("Content-Type", "").lower()
                m_matched = any(ct.lower() in resp_ct for ct in expected_cts)

            results.append(m_matched)

        if not results:
            return False

        if matchers_condition.lower() == "or":
            return any(results)
        return all(results)

    def run(self):
        """Ejecuta todas las reglas cargadas contra el objetivo."""
        findings = []
        rules = self.load_rules()

        for rule in rules:
            rule_id = rule.get("id")
            info = rule.get("info", {})
            requests_list = rule.get("requests", [])

            for req in requests_list:
                method = req.get("method", "GET").upper()
                paths = req.get("path", [])
                headers = req.get("headers", {})
                matchers = req.get("matchers", [])
                m_condition = req.get("matchers-condition", "and")

                for path in paths:
                    target_url = urljoin(self.base_url + '/', path.lstrip('/'))
                    try:
                        resp = self.session.request(
                            method=method,
                            url=target_url,
                            headers=headers,
                            timeout=self.timeout,
                            allow_redirects=False
                        )

                        if self._evaluate_matchers(resp, matchers, m_condition):
                            # Extraer muestra breve de evidencia
                            snippet = resp.text[:160].replace("\n", " ").strip()
                            findings.append({
                                "id": rule_id,
                                "name": info.get("name", rule_id),
                                "severity": info.get("severity", "MEDIO").upper(),
                                "url": target_url,
                                "path": path,
                                "status_code": resp.status_code,
                                "description": info.get("description", ""),
                                "impact": info.get("impact", ""),
                                "remediation": info.get("remediation", ""),
                                "evidence_sample": snippet
                            })
                            # Detener chequeo de paths adicionales para esta regla si ya se confirmó hallazgo
                            break

                    except Exception:
                        continue

        return findings
