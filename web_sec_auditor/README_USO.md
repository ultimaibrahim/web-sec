# Guía de Uso y Comandos de Ejecución · WebSec Auditor 2.0

Esta guía documenta los comandos exactos y parámetros configurables para la suite de auditoría (`web_sec_auditor`) con arquitectura generalizada, motor declarativo de reglas YAML estilo Nuclei, auditoría SSL/TLS, fuzzing de verbos HTTP, render dinámico con Chromium headless y telemetría de endpoints.

---

## 1. Suite de Auditoría Web (`web_sec_auditor 2.0`)

Ubicación: `/home/ultimau/web_sec_auditor`  
Entorno virtual: `/home/ultimau/web_sec_auditor/venv`

### Parámetro de Niveles (`--level` o `-l`)

| Nivel | Nombre | Alcance de Rastreo | Acciones Ejecutadas |
| :---: | :--- | :---: | :--- |
| **1** | **Superficial / Rápido** | Hasta 10 páginas | Análisis de cabeceras HTTP, cifrado y certificado SSL/TLS, latencia y fingerprinting. |
| **2** | **Estándar / Pasivo** *(Default)* | Hasta 50 páginas | Mirroring completo, motor de reglas YAML (Nuclei-style), sondeo de verbos HTTP, canarios de reflexión, detección de secretos por entropía de Shannon y matriz de causalidad X ➔ Y. |
| **3** | **Forense / Profundo** | Hasta 150 páginas | Todo lo del Nivel 2 + render dinámico headless con Chromium para SPAs e hidratación HTMX, ingesta OpenAPI y extracción de respaldos. |

---

### Banderas y Parámetros Disponibles

- `--url` / `-u`: URL objetivo (obligatorio).
- `--level` / `-l`: `1`, `2` o `3` (por defecto: `2`).
- `--dynamic`: Activa renderizado DOM en modo headless con Chromium para descubrir enlaces dinámicos y atributos HTMX (`hx-get`, `hx-post`).
- `--output` / `-o`: Directorio de salida (por defecto crea `audit_<dominio>`).
- `--max-pages`: Sobrescribe manualmente el límite de páginas del nivel.
- `--no-ssl`: Omite la auditoría criptográfica TLS.
- `--no-fuzz`: Omite la matriz de métodos HTTP (OPTIONS, TRACE, PUT, DELETE).
- `--no-reflection`: Omite el test con canarios inofensivos de reflexión en HTML y cabeceras.
- `--download-backup`: Fuerza la descarga de endpoints de respaldo descubiertos.

---

### Ejemplos de Ejecución

#### A. Chequeo Rápido de Red y Criptografía (Nivel 1):
```bash
cd /home/ultimau/web_sec_auditor
./venv/bin/python main.py --url https://aula.pargo.mx/ --level 1
```

#### B. Auditoría Estándar Integral (Nivel 2 - Recomendada):
```bash
cd /home/ultimau/web_sec_auditor
./venv/bin/python main.py --url https://aula.pargo.mx/ --level 2
```

#### C. Auditoría Dinámica Completa con Chromium Headless (Nivel 3):
```bash
cd /home/ultimau/web_sec_auditor
./venv/bin/python main.py --url https://aula.pargo.mx/ --level 3 --dynamic
```

---

## 2. Motor de Reglas Declarativas YAML (`rules/`)

El auditor procesa automáticamente todas las plantillas ubicadas en el subdirectorio `rules/`:
- `rules/exposures/`: Archivos `.env`, repositorios `.git`, volcados de base de datos `.sql` y configuraciones del servidor.
- `rules/panels/`: Detección de `phpinfo()`, Spring Boot Actuator, Apache Server Status y consolas.
- `rules/apis/`: Especificaciones OpenAPI / Swagger y consolas GraphQL.
- `rules/cves/`: Modos de depuración activos (Werkzeug, Django, Laravel Telescope).
- `rules/libraries/`: Detección de versiones obsoletas de librerías frontend (estilo Retire.js).

---

## 3. Entregables y Salidas Generadas

Cada ejecución compila de forma no destructiva los siguientes artefactos en `audit_<dominio>/`:
1. `dashboard_report.html`: Visualizador interactivo SPA en Bento Grid Crystal & Squircle con navegación por hash sin recargar la página.
2. `security_report.md`: Informe técnico estructurado en Markdown con checklists para DevSecOps.
3. `audit_data.json`: Dataset completo estructurado para ingesta en pipelines CI/CD o herramientas externas.
4. `site_mirror/`: Espejo local de recursos públicos descargados para análisis estático offline.
