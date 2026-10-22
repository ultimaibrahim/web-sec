# ⚡ Ultima Web Sec // Cyber-Deck Intelligence & Defensive Forensic Suite

> **Autor y Arquitecto de Producto**: Ibrahim García (`ultimaibrahim`)  
> **Sistema de Diseño**: Crystal & Squircle • Glassmorphism TUI • Alta Densidad btop  
> **Licencia**: Open-Source Defensive Security

---

## 🧭 1. Filosofía & Arquitectura de Producto

**Ultima Web Sec** es la unificación definitiva de la suite de ciber-inteligencia interactiva (`web_sec_fork`) y el motor de auditoría estática, reglas YAML y mirroring forense (`web_sec_auditor`), consolidada bajo la filosofía de artesanía técnica y diseño visual de **Ibrahim García**:
- **Cero Mediocridad**: Interfaces de terminal hiper-densas con sparklines, barras de progreso animadas FLIP (180ms - 250ms) y micro-indicadores tipo btop / hollywood.
- **Aislamiento de Scope Inamovible**: Whitelist estricta (`allowed_targets.txt`). Ninguna acción se ejecuta fuera de los objetivos expresamente autorizados.
- **Doble Confirmación en Módulos Destructivos**: Acciones de estrés masivo (`void()` y `void_plus()`) exigen confirmación en modal interactivo y confirmación por token manual.
- **Rollback Transaccional**: Toda mutación en endpoints genera un registro inverso de rollback (`POST` -> `DELETE`) que devuelve el estado a su origen.
- **Resiliencia Pura en Python**: Fallbacks sin dependencias binarias pesadas. Si WeasyPrint o Wappalyzer no existen, Web-Sec compila PDFs válidos RFC y clasifica tecnologías mediante su motor nativo.

---

## 🎨 2. Experiencia de Usuario: Crystal & Squircle TUI

La interfaz en modo 2 (Textual reactivo) organiza la telemetría en una cuadrícula Bento:
```
┌─────────────────────────┬────────────────────────────────────────┬─────────────────────────┐
│ ■ 1. PRIVACY SHIELD     │ ■ 2. NETWORK TELEMETRY                 │ ■ 3. AUDIT ENGINE       │
│  PRIV-SCORE: 95%        │  STATE: LIVE PUMP                      │  MODE:    WebSec        │
│  VPN:  TUNNEL ON        │  NET-IO: ▂▃▅▇█▆▅▃                      │  LEVEL:   Recon·Intel   │
│  DNS:  10.2.0.1 (SECURE)│  FLOW:   128 KB sent                   │  STATUS:  RECON ARMED   │
│  IPV6: BLOCKED (SAFE)   │  AUD-IO: ▅▆▇█▆▅▄                       │  FLAGS: p m d F D s P v │
└─────────────────────────┴────────────────────────────────────────┴─────────────────────────┘
┌──────────────────────────────────────────────────────────────────┬─────────────────────────┐
│ ■ LIVE OPS STREAM (hollywood)                                    │ ■ 4. TARGETS & VAULT    │
│  ● [████████████████░░░░░░░░] 60%  STAGE: FINGERPRINTING TECH   │  TARGETS (3):           │
│  >>> KERNEL INITIALIZED: AUDIT ENGINE READY                      │   › api.target.local    │
│  › Probing host [1/3]: https://target.local                      │   › admin.target.local  │
│  ✔ Tech detected: Next.js, React, Tailwind CSS, Nginx            │  CREDS VAULT: 4 TOKENS  │
│  ✔ Subdomains found: 8 live hosts (crt.sh, DNS)                  │  LAST: [JWT] eyJhbGci...│
└──────────────────────────────────────────────────────────────────┴─────────────────────────┘
```

---

## 🔍 3. Suite de Reconocimiento y Banderas Inteligentes

El frente `recon` admite ejecución granular mediante flags independientes o combinados:

| Flag | Nombre | Descripción y Motor |
| :---: | :--- | :--- |
| **`p`** | **Port Scan** | Escaneo asíncrono no invasivo de puertos TCP mediante sockets directos (`asyncio`). |
| **`m`** | **Mass Subdomains** | Descubrimiento agresivo de subdominios combinando OSINT pasivo (crt.sh, HackerTarget) y resolución DNS. |
| **`d`** | **Deep Crawl** | Rastreo recursivo de rutas internas, formularios, scripts y endpoints con extracción de tokens. |
| **`F`** | **Wappalyzer Clone** | Clon puro en Python de Wappalyzer. Detecta +60 tecnologías analizando headers, cookies y firmas DOM. |
| **`D`** | **Database Snapshot** | Detección y descarga controlada de backups o dumps expuestos (`/dump`, `/backup`). |
| **`v`** | **Vault & SQLite** | Persistencia cifrada con AES-256 en SQLite (`websec_vault.db`) y `.vault.key`. |
| **`r`** | **Multi-Report** | Generación simultánea de reportes ejecutivos en HTML con Glassmorphism y PDF nativo. |
| **`s`** | **Stealth / Ghost** | Jitter aleatorio de latencia entre peticiones y rotación de cabeceras antihuella WAF. |
| **`P`** | **Auto-Tor / Proxy** | Activación automática de túnel SOCKS5 si Tor está disponible o si la privacidad está expuesta. |

---

## 🛡️ 4. Evasión Inteligente y Auto-Tor

1. **Auto-Detección de Necesidad**:
   - Web-Sec analiza en segundo plano las interfaces con `privacy_guard.evaluate_privacy()`.
   - Si detecta fugas de DNS o un score de privacidad inferior a 60%, **auto-activa** el modo de evasión.
2. **Detección de Tor SOCKS5**:
   - Comprueba de forma no bloqueante si el demonio Tor (`127.0.0.1:9050` o `9150`) está escuchando.
   - Si está activo, redirige automáticamente el tráfico HTTP/HTTPS a través de `socks5h://`.
   - Si no está activo, activa rotación continua de cabeceras evasivas (`User-Agent`, `Referer`, `X-Forwarded-For`, `Sec-Ch-Ua`).

---

## ☣️ 5. Módulo Destructivo Seguro `void_plus`

`void_plus()` está diseñado para pruebas de estrés y caos controlado en ambientes staging autorizados:
- **Doble Confirmación Requerida**:
  1. Primer modal interactivo `ConfirmScreen` confirmando la intención de mutar datos.
  2. Pantalla de seguridad `InputScreen` donde el operador debe ingresar textualmente:
     ```
     DESTROY-SCOPE-CONFIRM
     ```
- **Ráfaga Asíncrona Multi-Vector**: Envíos masivos concurrentes (`POST`, `PUT`, `PATCH`, `DELETE`).
- **Upload Bomb Polimórfico**: Estrés de subida de archivos (PNG, ZIP, TXT) para verificar límites del backend.
- **Rollback Automático**: Ejecuta métodos inversos (`rollback_action`) para eliminar o restaurar los recursos generados durante la prueba.

---

## 📊 6. Reportes Ejecutivos

Web-Sec genera reportes en el directorio `outputs/`:
- **Reporte HTML**: Construido con el sistema de diseño Crystal & Squircle, tarjetas de glassmorphism, métricas flotantes y badges de tecnologías.
- **Reporte PDF Puro en Python**: Implementa un compilador PDF 1.4 de bajo nivel (`PurePythonPDF`). **No requiere WeasyPrint ni binarios de Node**, garantizando que el PDF se genera con éxito en cualquier entorno Linux/Docker/WSL.
- **Reporte Markdown**: Historial consolidado exportable con `storage_vault.export_markdown_report()`.

---

## ⌨️ 7. Atajos de Teclado (Keybindings)

| Tecla | Acción |
| :---: | :--- |
| **`[SPACE]`** | Iniciar auditoría o ciclo de reconocimiento contra la whitelist |
| **`[M]`** | Alternar modo: `WebSec` (Defensivo) ↔ `WebScrap` (Extracción) |
| **`[L]`** | Ciclar nivel: `0·Passive` → `1·Active` → `2·Fuzzing` → `3·Destruct` → `recon` → `void` → `void_plus` |
| **`[T]`** | Abrir editor de Whitelist y objetivos autorizados |
| **`[P]`** | Alternar bandera de escaneo de puertos (`p`) |
| **`[D]`** | Alternar bandera de deep crawl (`d`) |
| **`[G]`** | Alternar bandera de enumeración de subdominios (`m`) |
| **`[F]`** | Alternar bandera de fingerprinting Wappalyzer (`F`) |
| **`[H]`** | Alternar modo Stealth / Ghost jitter (`s`) |
| **`[X]`** | Alternar auto-enrutamiento por Tor / SOCKS5 (`P`) |
| **`[R]`** | Alternar exportación automática de reportes HTML y PDF (`r`) |
| **`[V]`** | Alternar persistencia en bóveda SQLite (`v`) |
| **`[B]`** | Alternar enrutamiento con motor de navegador Playwright |
| **`[E]`** | Exportar resultados en JSON crudo |
| **`[C]`** | Limpiar terminal de logs |
| **`[Q]`** | Salir de la aplicación de forma segura |

---

## 🐳 8. Despliegue con Docker y Makefile

### Construir y Ejecutar con Makefile
```bash
# Ejecutar suite de pruebas
make test

# Validación sintáctica de todos los módulos
make lint

# Construir contenedor Docker
make docker-build

# Ejecutar contenedor interactivo
make docker-run
```

### Ejecutar Localmente
```bash
# Lanzar selector de interfaz
./run.sh

# Lanzar directamente TUI btop / Crystal & Squircle
./run.sh 2
```

---

## 🧩 9. Ecosistema de Herramientas Open-Source Soportadas

Web-Sec orquesta de forma nativa o mediante fallback:
- **Descubrimiento**: Nmap, Gobuster, FFuf, OWASP Amass, Subfinder, Assetfinder, Sublist3r.
- **Vulnerabilidades**: ProjectDiscovery Nuclei, SQLMap, OWASP Security Headers.
- **OSINT**: SpiderFoot, SecurityTrails API, Shodan API, Censys Search API.
- Consulta la guía técnica completa en [`docs/TOOLING_INTEGRATIONS.md`](docs/TOOLING_INTEGRATIONS.md).
