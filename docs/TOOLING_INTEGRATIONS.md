# 🛠️ Web-Sec // Guía de Integración y Exploración de Herramientas Open-Source

> **Filosofía de Arquitectura de Ibrahim García**:  
> 1. *Toda herramienta externa debe ser opcional y auto-activarse en caso de detectar la necesidad o presencia.*  
> 2. *Priorizar siempre soluciones 100% de código abierto para usar, clonar e integrar sin dependencias propietarias rígidas.*  
> 3. *Garantizar fallbacks puros en Python para que el sistema funcione en cualquier máquina sin crasheos.*

---

## 🧭 1. Resumen de Herramientas Integradas

Web-Sec implementa una arquitectura híbrida: detecta automáticamente si el binario de la herramienta existe en `$PATH` o si las credenciales de entorno están configuradas. Si existen, las orquesta concurrentemente; si no están instaladas, utiliza sus motores nativos en Python.

| Herramienta | Categoría | Tipo | Estado en Web-Sec | Motor Fallback Puro en Python |
| :--- | :--- | :--- | :--- | :--- |
| **Nmap** | Port Scanning | Binario C | Auto-detectado (`/usr/bin/nmap`) | `helpers.scan_ports` (async TCP sockets) |
| **FFuf** | Web Fuzzing | Binario Go | Auto-detectado | `helpers.enumerate_endpoints` |
| **Gobuster** | Dir Bruteforce | Binario Go | Auto-detectado | Diccionario local + `deep_crawl` |
| **Amass (OWASP)** | OSINT Subdominios | Binario Go | Auto-detectado (`amass`) | `helpers.mass_subdomains` (crt.sh + DNS) |
| **Subfinder** | Subdominios Pasivos | Binario Go | Auto-detectado (`subfinder`) | `helpers.mass_subdomains` + HackerTarget |
| **Assetfinder** | Asset Discovery | Binario Go | Auto-detectado (`assetfinder`) | Parser de certificados TLS nativo |
| **Sublist3r** | Subdomain OSINT | Python CLI | Auto-detectado (`sublist3r`) | Motor multi-fuente asíncrono |
| **Nuclei** | Vulnerability Scan | Binario Go | Auto-detectado (`nuclei`) | `plugin_runner.audit_critical_leaks` |
| **WhatWeb** | Tech Fingerprint | Ruby CLI | Auto-detectado (`whatweb`) | `helpers.advanced_fingerprint` (Wappalyzer clone) |
| **SQLMap** | SQLi Audit | Python CLI | Auto-detectado (`/usr/bin/sqlmap`) | Nivel 2 Fuzzing no destructivo |
| **SpiderFoot** | OSINT Automation | Python CLI | Auto-detectado (`spiderfoot`) | Módulos DNS y whois en Python |
| **SecurityTrails** | DNS History API | REST API | Opcional (`SECURITYTRAILS_API_KEY`) | Certificate Transparency Logs |
| **Shodan / Censys** | Internet Telemetry | REST API | Opcional (`SHODAN_API_KEY`) | `helpers.fingerprint_target` |
| **Tor / SOCKS5** | Anonymity / Evasion | Proxy Daemon | Auto-detectado (`127.0.0.1:9050`) | Rotación de cabeceras antihuella |
| **WeasyPrint** | PDF Rendering | Python Lib | Auto-detectado | `PurePythonPDF` (motor PDF 1.4 sin librerías) |

---

## ⚡ 2. Detalle de Nuevas Integraciones

### 2.1 OWASP Amass & Subfinder
- **Propósito**: Mapeo exhaustivo de la superficie de ataque y subdominios pasivos mediante recolección de fuentes abiertas (CT logs, DNS archives, routing tables).
- **Invocación Segura**: Ejecución en modo pasivo (`-passive`) con límites de tiempo (`-timeout 1`) y aislamiento de procesos con `subprocess.run`.
- **Comando de Instalación**:
  ```bash
  go install -v github.com/owasp-amass/amass/v4/...@master
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```

### 2.2 Assetfinder (TomNomNom)
- **Propósito**: Herramienta en Go ultraligera y sin dependencias pesadas para encontrar subdominios y dominios asociados.
- **Comando de Instalación**:
  ```bash
  go install github.com/tomnomnom/assetfinder@latest
  ```

### 2.3 ProjectDiscovery Nuclei
- **Propósito**: Escaneo de vulnerabilidades conocido y reproducible basado en plantillas YAML comunitarias.
- **Seguridad**: Configurado en Web-Sec exclusivamente para severidades críticas/altas con argumentos no intrusivos (`-silent -jsonl`).
- **Comando de Instalación**:
  ```bash
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ```

### 2.4 Advanced Fingerprint (Wappalyzer Pure-Python Clone)
- **Propósito**: Detección de más de 60 tecnologías (WordPress, Drupal, React, Next.js, Vue, Nuxt, Laravel, Django, Express, Nginx, Apache, Cloudflare) sin librerías externas.
- **Funcionamiento**: Análisis de 3 capas:
  1. *Headers HTTP*: `Server`, `X-Powered-By`, `X-Generator`, cabeceras de CDN (`cf-ray`).
  2. *Cookies de sesión*: Firmas conocidas (`PHPSESSID`, `JSESSIONID`, `csrftoken`, `laravel_session`, `connect.sid`).
  3. *DOM & Scripts*: Atributos react (`data-reactroot`), scripts de frameworks, etiquetas de meta-generador.

### 2.5 Auto-Tor / SOCKS5 Proxy Evasion
- **Activación Inteligente**:
  - Si la puntuación del `PrivacyShield` cae por debajo de 60% o se detecta fuga DNS/IP, Web-Sec eleva automáticamente la necesidad de anonimización.
  - Verifica si el puerto local de Tor (`9050` o `9150`) está abierto. Si está activo, enruta todas las peticiones a través de `socks5h://127.0.0.1:9050`.
  - Si Tor no está activo, activa rotación continua de cabeceras evasivas (`User-Agent`, `X-Forwarded-For`, `Sec-Ch-Ua`).

---

## 🔒 3. Políticas Inamovibles de Seguridad y No Destrucción

1. **Aislamiento de Scope (Whitelist Enforced)**:
   - Toda llamada de red se compara contra `allowed_targets.txt`. Cualquier host no autorizado es abortado inmediatamente.
2. **Doble Confirmación Obligatoria para `void_plus`**:
   - `void_plus()` requiere:
     1. Modal interactivo `ConfirmScreen` confirmando la intención de mutar datos.
     2. Override textual exacto en `InputScreen`: el operador debe tipear `DESTROY-SCOPE-CONFIRM`.
3. **Mecanismo de Rollback Activo**:
   - Todo recurso creado en pruebas destructivas registra una acción inversa (`POST` -> `DELETE`) ejecutada de forma automática al finalizar.
