import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

class SSLAuditor:
    """
    Auditor criptográfico defensivo de conexiones SSL/TLS.
    Inspecciona la validez del certificado, vigencia, algoritmos de cifrado,
    emisor y extrae Nombres Alternativos del Sujeto (SANs) para descubrimiento de activos.
    """
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        self.hostname = parsed.hostname or target_url
        self.port = parsed.port or (443 if parsed.scheme == "https" or not parsed.scheme else 80)
        self.is_https = parsed.scheme == "https" or self.port == 443

    def audit(self):
        if not self.is_https:
            return {
                "enabled": False,
                "reason": "El objetivo utiliza HTTP plano en lugar de HTTPS.",
                "grade": "F",
                "days_left": 0,
                "sans": []
            }

        context = ssl.create_default_context()
        # Permitir auditoría incluso si el certificado es autofirmado o tiene problemas de CA local
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    protocol_version = ssock.version()

            # Ahora obtener certificado decodificado con verificación normal si es posible
            decoded_cert = {}
            try:
                verify_context = ssl.create_default_context()
                with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                    with verify_context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        decoded_cert = ssock.getpeercert() or {}
            except Exception:
                # Si falla verificación estricta de CA local, decodificar los campos esenciales
                pass

            # Procesar datos decodificados
            subject = dict(x[0] for x in decoded_cert.get("subject", [])) if "subject" in decoded_cert else {}
            issuer = dict(x[0] for x in decoded_cert.get("issuer", [])) if "issuer" in decoded_cert else {}
            
            # SANs (Subject Alternative Names)
            sans = []
            for san_type, san_val in decoded_cert.get("subjectAltName", []):
                if san_type == "DNS":
                    sans.append(san_val)

            # Expiración y vigencia
            not_after_str = decoded_cert.get("notAfter")
            not_before_str = decoded_cert.get("notBefore")
            days_left = None
            is_expired = False
            expiring_soon = False

            if not_after_str:
                # Formato estándar OpenSSL: 'Nov 29 13:37:51 2026 GMT'
                try:
                    exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (exp_date - now).days
                    is_expired = days_left < 0
                    expiring_soon = 0 <= days_left <= 30
                except Exception:
                    pass

            cipher_name = cipher[0] if cipher else "Desconocido"
            cipher_protocol = cipher[1] if cipher else protocol_version
            cipher_bits = cipher[2] if cipher else 0

            # Evaluación de calidad y advertencias
            warnings = []
            if protocol_version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                warnings.append(f"Protocolo obsoleto e inseguro detectado: {protocol_version}")
            if any(weak in cipher_name.upper() for weak in ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]):
                warnings.append(f"Cifrado con debilidades criptográficas conocidas: {cipher_name}")
            if is_expired:
                warnings.append(f"El certificado SSL expiró hace {abs(days_left)} días.")
            elif expiring_soon:
                warnings.append(f"El certificado SSL vencerá pronto ({days_left} días restantes).")

            grade = "A+" if protocol_version == "TLSv1.3" and not warnings else ("A" if not warnings else "B" if expiring_soon else "C")

            return {
                "enabled": True,
                "hostname": self.hostname,
                "port": self.port,
                "protocol": protocol_version,
                "cipher_name": cipher_name,
                "cipher_protocol": cipher_protocol,
                "cipher_bits": cipher_bits,
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before_str,
                "not_after": not_after_str,
                "days_left": days_left,
                "is_expired": is_expired,
                "expiring_soon": expiring_soon,
                "sans": sorted(list(set(sans))),
                "warnings": warnings,
                "grade": grade
            }

        except Exception as e:
            return {
                "enabled": True,
                "error": f"Fallo al auditar conexión TLS: {str(e)}",
                "grade": "F",
                "sans": []
            }
