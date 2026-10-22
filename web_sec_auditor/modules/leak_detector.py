import os
import re
import math
from collections import Counter

class LeakDetector:
    """
    Analizador estático avanzado de exposición de secretos, fugas de código y notas.
    Incorpora firmas regex de más de 10 proveedores de nube/SaaS y un motor
    de Entropía de Shannon para detectar credenciales no estructuradas de alta aleatoriedad.
    """
    SECRET_RULES = [
        ("Generic API Key / Secret", re.compile(r"""(?i)(?:api_key|apikey|secret|auth_token|access_token|private_key)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,})["']""")),
        ("JWT Token", re.compile(r"""\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b""")),
        ("Google Cloud API Key", re.compile(r"""\bAIza[0-9A-Za-z\-_]{35}\b""")),
        ("GitHub Personal Access Token", re.compile(r"""\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b""")),
        ("AWS Access Key ID", re.compile(r"""\bAKIA[0-9A-Z]{16}\b""")),
        ("AWS Secret Access Key", re.compile(r"""(?i)aws(?:_secret)?(?:_access)?(?:_key)?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']""")),
        ("Stripe API Key", re.compile(r"""\b[rs]k_(?:test|live)_[0-9a-zA-Z]{24,}\b""")),
        ("Stripe Publishable Key", re.compile(r"""\bpk_(?:test|live)_[0-9a-zA-Z]{24,}\b""")),
        ("SendGrid API Key", re.compile(r"""\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b""")),
        ("Firebase URL / Database", re.compile(r"""https://[a-z0-9-]+\.firebaseio\.com""")),
        ("Slack Webhook / Bot Token", re.compile(r"""https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+|xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}""")),
        ("Private Key Block", re.compile(r"""-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----""")),
        ("Bearer Token Literal", re.compile(r"""(?i)bearer\s+["']?([A-Za-z0-9_\-\.]{24,})["']?""")),
    ]

    TODO_PATTERNS = re.compile(r"""(?i)(?://|/\*|<!--)\s*(TODO|FIXME|HACK|BUG|PASSWORD|SECRET|CREDENTIALS)[:\s]+(.*?)(?:-->|\*/|\n|$)""")

    # Regex para extraer potenciales tokens candidatos a entropía (strings alfanuméricos largos)
    ENTROPY_CANDIDATE_REGEX = re.compile(r"""["']([A-Za-z0-9_\-\.]{24,64})["']""")

    def __init__(self, mirror_dir, entropy_threshold=4.5):
        self.mirror_dir = mirror_dir
        self.entropy_threshold = entropy_threshold

    @staticmethod
    def calculate_entropy(data):
        """Calcula la entropía de Shannon de una cadena de caracteres."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for count in Counter(data).values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 2)

    def _mask_secret(self, secret_str):
        if len(secret_str) <= 8:
            return "****"
        return secret_str[:4] + ("*" * (len(secret_str) - 8)) + secret_str[-4:]

    def scan(self):
        leaks = []
        source_maps = []
        developer_notes = []
        entropy_secrets = []

        if not os.path.exists(self.mirror_dir):
            return {
                "exposed_secrets": leaks,
                "source_maps": source_maps,
                "developer_notes": developer_notes,
                "high_entropy_tokens": entropy_secrets
            }

        # Ignorar librerías conocidas de vendors pesados para evitar falsos positivos
        ignored_files = {"bootstrap.min.js", "jquery.min.js", "htmx.js", "fontawesome.min.js", "tailwind.js"}

        for root, _, files in os.walk(self.mirror_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.mirror_dir)

                # Detección de Source Maps (.map)
                if file.endswith('.map'):
                    source_maps.append(rel_path)
                    continue

                if file.lower() in ignored_files:
                    continue

                # Analizar archivos de texto/código
                ext = os.path.splitext(file)[1].lower()
                if ext in ['.js', '.html', '.htm', '.json', '.env', '.txt', '.xml', '.yml', '.yaml']:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                    except Exception:
                        continue

                    for line_num, line in enumerate(lines, start=1):
                        # 1. Buscar Secretos por Firmas Regex
                        for name, regex in self.SECRET_RULES:
                            matches = regex.findall(line)
                            for match in matches:
                                val = match if isinstance(match, str) else match[0]
                                leaks.append({
                                    "file": rel_path,
                                    "line": line_num,
                                    "type": name,
                                    "evidence": self._mask_secret(val.strip())
                                })

                        # 2. Análisis de Entropía de Shannon en Tokens sospechosos
                        candidates = self.ENTROPY_CANDIDATE_REGEX.findall(line)
                        for token in candidates:
                            # Descartar data URIs, nombres de fuentes, URLs comunes o UUIDs predecibles
                            if token.startswith(("data:", "http", "image/")) or "/" in token:
                                continue
                            
                            ent = self.calculate_entropy(token)
                            if ent >= self.entropy_threshold and len(token) >= 28:
                                entropy_secrets.append({
                                    "file": rel_path,
                                    "line": line_num,
                                    "entropy": ent,
                                    "length": len(token),
                                    "evidence": self._mask_secret(token)
                                })

                        # 3. Buscar Comentarios / TODOs
                        todo_matches = self.TODO_PATTERNS.findall(line)
                        for tag, note in todo_matches:
                            clean_note = note.strip()
                            if len(clean_note) > 3:
                                developer_notes.append({
                                    "file": rel_path,
                                    "line": line_num,
                                    "tag": tag.upper(),
                                    "note": clean_note[:100]
                                })

        return {
            "exposed_secrets": leaks,
            "source_maps": source_maps,
            "developer_notes": developer_notes,
            "high_entropy_tokens": entropy_secrets
        }
