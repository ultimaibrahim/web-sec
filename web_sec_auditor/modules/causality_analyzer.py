import os
import re

class ImpactCausalityAnalyzer:
    """
    Analizador defensivo y no destructivo de causalidad e impacto en lógica de negocio.
    Examina estáticamente los scripts JavaScript y HTML descargados en el mirror
    para mapear relaciones del tipo: 'Si un actor no autorizado accede a X, causa impacto Y'.
    """

    CRITICAL_FLOW_PATTERNS = [
        {
            "category": "Respaldo y Fuga de Base de Datos",
            "regex": re.compile(r"""(?:fetch|axios(?:\.get)?)\s*\(\s*["']([^"']*(?:backup|dump|export|database)[^"']*)["']""", re.IGNORECASE),
            "action": "Lectura / Extracción de Respaldo",
            "impact": "Exposición completa de la base de datos operativa, clientes o catálogos sin requerir permisos de superusuario.",
            "risk_level": "CRÍTICO"
        },
        {
            "category": "Restauración y Sobrescritura de Datos",
            "regex": re.compile(r"""(?:fetch|axios(?:\.post|\.put)?)\s*\(\s*["']([^"']*(?:restore|import|reset|wipe)[^"']*)["']""", re.IGNORECASE),
            "action": "Modificación / Reemplazo Masivo de Estado",
            "impact": "Posible sobreescritura, corrupción o borrado total de la base de datos si el endpoint no valida firma ni autenticación en el servidor.",
            "risk_level": "CATASTRÓFICO"
        },
        {
            "category": "Control de Precios y Finanzas",
            "regex": re.compile(r"""(?:fetch|axios(?:\.post|\.put|\.delete)?)\s*\(\s*["']([^"']*(?:prices?|currency|discount|points?|rate|wallet)[^"']*)["']""", re.IGNORECASE),
            "action": "Modificación de Precios / Puntos",
            "impact": "Alteración de tarifas comerciales, asignación fraudulenta de saldos o canje no autorizado en puntos de venta.",
            "risk_level": "ALTO"
        },
        {
            "category": "Gestión de Usuarios y Permisos",
            "regex": re.compile(r"""(?:fetch|axios(?:\.post|\.put|\.delete)?)\s*\(\s*["']([^"']*(?:users?|roles?|permissions?|admin-auth)[^"']*)["']""", re.IGNORECASE),
            "action": "Modificación de Cuentas / Privilegios",
            "impact": "Escalación de privilegios, creación de administradores espurios o secuestro de accesos.",
            "risk_level": "ALTO"
        }
    ]

    def __init__(self, mirror_dir):
        self.mirror_dir = mirror_dir

    def analyze(self):
        impact_matrix = []

        if not os.path.exists(self.mirror_dir):
            return impact_matrix

        seen_routes = set()

        for root, _, files in os.walk(self.mirror_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ['.js', '.html']:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.mirror_dir)

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                    except Exception:
                        continue

                    for line_num, line in enumerate(lines, start=1):
                        for flow in self.CRITICAL_FLOW_PATTERNS:
                            matches = flow["regex"].findall(line)
                            for match in matches:
                                endpoint = match.split('?')[0].strip()
                                key = (endpoint, flow["category"])
                                if key in seen_routes:
                                    continue
                                seen_routes.add(key)

                                impact_matrix.append({
                                    "endpoint": endpoint,
                                    "file": rel_path,
                                    "line": line_num,
                                    "category": flow["category"],
                                    "action": flow["action"],
                                    "impact": flow["impact"],
                                    "risk_level": flow["risk_level"]
                                })

        return impact_matrix
