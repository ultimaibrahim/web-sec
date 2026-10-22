import re
from typing import Dict, List

# Catálogo ampliado de patrones de credenciales, tokens y secretos expuestos
CRED_PATTERNS = {
    "AWS AccessKey": r"\b(AKIA[0-9A-Z]{16})\b",
    "AWS SecretKey": r"\b([0-9a-zA-Z/+]{40})\b",
    "GitHub Token": r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b",
    "Google API Key": r"\b(AIza[0-9A-Za-z\\-_]{35})\b",
    "Stripe Secret Key": r"\b([sr]k_live_[0-9a-zA-Z]{24,34})\b",
    "Slack Webhook / Token": r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+|xox[baprs]-[0-9a-zA-Z]{10,48})",
    "JWT (JSON Web Token)": r"\b(ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b",
    "Microsoft Bearer": r"\b(Bearer\s+[A-Za-z0-9\-._~+/]+=*)\b",
    "Private Key Block": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "Generic High-Entropy Token": r"\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b"
}

def scan_text(text: str) -> Dict[str, List[str]]:
    """Analiza una cadena de texto y devuelve los hallazgos agrupados por tipo."""
    hits: Dict[str, List[str]] = {}
    for name, pat in CRED_PATTERNS.items():
        try:
            matches = re.findall(pat, text)
            if matches:
                # Si la expresión regular tiene grupos, aplanar resultados
                clean_matches = []
                for m in matches:
                    val = m[0] if isinstance(m, tuple) else m
                    if val and len(val.strip()) > 8:
                        clean_matches.append(val.strip())
                if clean_matches:
                    hits[name] = list(set(clean_matches))
        except Exception:
            continue
    return hits
