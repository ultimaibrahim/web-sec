# ⚡ Ultima Web Sec // Cyber-Deck Intelligence & Defensive Forensic Suite

> **Autor y Arquitecto de Producto**: Ibrahim García (`ultimaibrahim`)  
> **Sistema de Diseño**: Crystal & Squircle • Glassmorphism TUI • Bento Grid de Alta Densidad (btop / hollywood)  
> **Licencia**: Open-Source Defensive Security & Red/Blue Operations

---

## 🧭 1. Filosofía & Arquitectura de Producto

**Ultima Web Sec** es la suite definitiva de ciberseguridad ofensiva, inteligencia OSINT y defensa activa en tiempo real. Consolida tres pilares antes dispersos en un único motor de alto rendimiento:
1. **Cyber-Deck Interactivo Reactivo**: Telemetría continua de red, sparklines en vivo, atajos de teclado sin latencia y retroalimentación sonora PCM.
2. **Dynamic Endpoint Convergence (`discover_routes`)**: Minería automática de bundles JavaScript (`fetch`, `axios`, `XHR`) para erradicar falsos negativos causados por rutas estáticas en SPAs/Jamstack.
3. **Active Defense & Blue Team Engine**: Desinformación, trampas de sesión con canarios rastreables, bombas de descompresión para escáneres hostiles y *tarpitting* silencioso para secuestrar los hilos de atacantes.

---

## 🎛️ 2. Guía de Modos Operativos (Frentes de Trabajo)

La suite cuenta con **4 Modos Principales**. Al presionar **`[M]`** (o escribir `:mode` en el prompt), la interfaz muta de atmósfera, colores de borde y comportamiento:

```
[M] ──► 1. WebSec   (Bordes Azul/Verde  - Frente Ofensivo / Red Team)
        2. WebScrap (Bordes Magenta     - Extracción Silenciosa / Scraping)
        3. WebRecon (Bordes Oro/Ámbar   - OSINT, Superficie & Reconocimiento)
        4. BlueTeam (Bordes Rojo Alerta - Defensa Activa, Honeypots & Tarpit)
```

### ⚔️ Modo 1: `WebSec` (Red Team Offensive)
- **Propósito**: Evaluación de robustez, inyecciones, fuzzing de parámetros y pruebas de estrés asíncrono.
- **Niveles disponibles (`[L]` o `:lvl <0-void_plus>`)**:
  - `0·Passive`: Inspección de cabeceras OWASP, robots.txt, sitemaps y cookies seguras sin emitir tráfico anómalo.
  - `1·Active`: Sondeo de verbos HTTP no estándar (`PUT`, `DELETE`, `PATCH`, `TRACE`), análisis de reflexión con canarios y comprobación de métodos permitidos.
  - `2·Fuzzing`: Fuzzing agresivo de rutas ocultas mediante diccionarios locales (`wordlists/`) con motor nativo o FFuf/Gobuster.
  - `3·Destruct`: Pruebas de mutación concurrente con recolección de credenciales filtradas.
  - `void()`: Inyección de caos asíncrono con sobrecarga de peticiones.
  - `void_plus()`: **Chaos Suite Extrema**:
    - Requiere doble confirmación interactiva + token de seguridad manual (`DESTROY-SCOPE-CONFIRM`).
    - Minería previa de endpoints con `discover_routes` para atacar rutas reales en lugar de rutas ciegas.
    - Bombas de subida polimórficas (archivos anómalos para validar cuotas de memoria).
    - Inundación de sockets WebSocket (`101 Switching Protocols`).
    - Mapeo y ejecución de 24 binarios Red Team externos vía flags `ext_*` (Nuclei, SQLMap, Findomain, CME, etc.).
    - **Rollback Transaccional Inverso**: Genera llamadas inversas automáticas para limpiar los recursos modificados.

### 🕷️ Modo 2: `WebScrap` (Passive Extraction)
- **Propósito**: Recolección de inteligencia del lado del cliente sin perturbar el servidor.
- **Qué hace**:
  - Descarga y mapea todos los enlaces y metadatos HTML.
  - Descompila y extrae árboles de archivos JavaScript.
  - Identifica endpoints internos de API y credenciales filtradas (JWT, AWS keys, tokens Bearer) mediante `credential_scanner.py`.

### 📡 Modo 3: `WebRecon` (OSINT & Surface Intelligence)
- **Propósito**: Mapeo integral de superficie de ataque antes de cualquier interacción directa.
- **Banderas de Reconocimiento configurables**:
  - `p` (Port Scan): Escaneo asíncrono de puertos TCP comunes sin herramientas pesadas.
  - `m` (Mass Subdomains): Descubrimiento multicanal (crt.sh, HackerTarget, Amass, Subfinder, Assetfinder).
  - `d` (Deep Crawl): Rastreo recursivo de formularios, rutas dinámicas y endpoints ocultos.
  - `F` (Wappalyzer Native): Fingerprinting de más de 60 tecnologías de backend, frontend y servidores web.
  - `D` (Database Snapshot): Búsqueda y análisis de volcados o backups expuestos (`.sql`, `.env`, `.bak`).
  - `v` (Vault Storage): Cifrado automático de hallazgos en SQLite (`websec_vault.db`) con clave AES-256.
  - `r` (Multi-Report): Generación de reporte interactivo HTML con Glassmorphism y PDF nativo sin dependencias.
  - `s` (Ghost Jitter): Inyección de retrasos aleatorios y rotación de headers para burlar WAFs y sistemas de rate limiting.
  - `P` (Tor Proxy): Enrutamiento automático por túnel SOCKS5 (`127.0.0.1:9050`).

### 🛡️ Modo 4: `BlueTeam` (Active Counter-Measures & Tarpitting)
- **Propósito**: Contención activa, detección de adversarios y agotamiento de recursos del atacante cuando el laboratorio o servidor está bajo asedio.
- **Capacidades**:
  - **Tarpit Socket Drain**: Al detectar peticiones hostiles o repetidas, responde con HTTP chunked enviando 1 byte cada 10 segundos por 120s, congelando los escáneres del atacante.
  - **Decoy Endpoints & Honeypots**: Inyecta cebos altamente atractivos (`/api/v1/internal_auth`, `/.aws/credentials`, `/wp-login.php`, `/backup/admin.sql.gz`).
  - **Honeytokens Canario**: Entrega credenciales trampa con firmas únicas (AWS/JWT) para monitorear y perfilar al atacante si intenta usarlas en internet.
  - **Poisoned Gzip Bombs**: Entrega respuestas de 10 KB que se descomprimen a 100 MB en la memoria de escáneres mal configurados para forzar caídas por *Out-Of-Memory*.
  - **Shadow-Banning**: Registra la IP en la tabla de hostiles y le sirve respuestas nulas sin alertarlo mediante un `403` obvio.

---

## 🚀 3. Formas de Ejecución (CLI & TUI)

### A. Comando Rápido del Sistema (Recomendado)
Puedes lanzar la suite desde cualquier parte de tu terminal con:
```bash
web-sec
# o también:
ultima-web-sec
```
Abre de inmediato el **Cyber-Deck Principal** con Bento Grid interactivo, sonido táctil y controles reactivos.

### B. Modo Auditoría Forense y Clonación Espejo (Modo CLI sin TUI)
Si deseas auditar una web específica, descargar todo su frontend en local (estilo DevTools) y generar el reporte HTML:
```bash
web-sec -u https://mi-sitio.com -l 2
```
**Banderas avanzadas de CLI:**
```bash
web-sec --url https://mi-sitio.com --level 3 --dynamic --download-backup
```
- `--url` / `-u`: URL objetivo (obligatorio).
- `--level` / `-l`: `1` (Rápido/SSL), `2` (Estándar/Mirror/Nuclei), `3` (Forense/Headless Chromium).
- `--dynamic`: Activa renderizado dinámico con Chromium headless para SPAs e hidratación HTMX.
- `--download-backup`: Descarga y resguarda localmente backups descubiertos.

### C. Modo Escudos de Privacidad Previos
Para levantar los escudos anti-forenses a nivel sistema operativo (desactivar swap, inhabilitar historial bash, limpiar DNS leaks):
```bash
sudo ./activate_shields.sh
```

---

## ⌨️ 4. Mapa Completo de Atajos de Teclado (TUI Cyber-Deck)

| Tecla / Comando | Acción Ejecutada |
| :---: | :--- |
| **`[SPACE]`** | **Start Mission**: Inicia la auditoría, scraping o activa el daemon BlueTeam según el modo. |
| **`[M]`** | **Cycle Mode**: Rota entre `WebSec` ➔ `WebScrap` ➔ `WebRecon` ➔ `BlueTeam`. |
| **`[L]`** | **Cycle Level**: Rota el nivel de agresividad (`0` a `void_plus`). |
| **`[ENTER]` o `[:]`** | **Activar Prompt**: Abre la consola inferior para ingresar comandos internos o comandos shell nativos de Linux (`ls`, `curl`, `nmap`). |
| **`[S]`** | **Toggle Stealth**: Activa/desactiva la evasión de huella WAF y jitter de tiempo. |
| **`[D]`** | **Toggle Dry-Run**: Modo simulación; prueba la lógica de la suite sin enviar paquetes a los objetivos. |
| **`[W]`** | **Toggle Text Wrap**: Alterna entre ajuste de línea automático y desplazamiento horizontal. |
| **`[←] / [→]`** | **Scroll Horizontal**: Desplaza el panel de logs central a la izquierda o derecha (+5ch). |
| **`[↑] / [↓]`** | **Scroll Vertical**: Navega por el historial de eventos del registro central. |
| **`[T]`** | **Edit Scope / Targets**: Abre el diálogo interactivo para añadir o quitar dominios de la whitelist. |
| **`[Q]`** | **Quit**: Apaga la suite de forma segura. |

---

## 📊 5. Reportes y Artefactos Generados

Los informes se depositan automáticamente en la carpeta `outputs/`:
1. **Dashboard Interactivo HTML**: Sistema de tarjetas Crystal & Squircle, indicadores de estado de puertos, gráficas de causalidad y credenciales extraídas.
2. **Reporte Forense Markdown**: Resumen ejecutivo con timestamps y hallazgos catalogados por CVE/CWE.
3. **Site Mirror (`site_mirror/`)**: Espejo estático completo (archivos `.html`, `.js`, `.css`, imágenes) descargados 1:1 para auditoría offline en local.
4. **Bóveda SQLite Cifrada (`websec_vault.db`)**: Base de datos local protegida por cifrado simétrico donde se indexan tokens, contraseñas y metadatos de escaneos previos.

---

## 🎧 6. Retroalimentación Sonora y Alertas PCM

Ultima Web Sec cuenta con un sintetizador matemático nativo en Python (`sound_effects.py` vía `aplay`/ALSA) que genera retroalimentación táctil sin requerir librerías de audio externas:
- **Beep de Confirmación**: Tono ascendente en tríada armónica al activar escudos o conmutar a `WebRecon`.
- **Alarma Bitonal de Intrusión (880 Hz / 440 Hz)**: Disparada de golpe al detectar que una IP externa o bot tocó una ruta trampa (Honeytoken) en modo Blue Team.
- **Secuencia Burn (Frecuencias Descendentes)**: Señal acústica de emergencia al ejecutar el protocolo de evacuación o kill-switch.
