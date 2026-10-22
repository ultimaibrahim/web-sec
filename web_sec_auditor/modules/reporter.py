import os
import json
from datetime import datetime

class ReportGenerator:
    """
    Genera reportes de evaluación en formatos Markdown y Single Page Application (SPA) HTML interactiva.
    Arquitectura Bento Grid Crystal & Squircle con carga ultra-rápida, zero-lag y navegación por hash.
    Totalmente generalizado para cualquier objetivo web, API o infraestructura.
    """
    def __init__(self, target_url, audit_data, output_dir):
        self.target_url = target_url
        self.data = audit_data
        self.output_dir = output_dir

    def calculate_score(self):
        score = 100

        # 1. Cabeceras de seguridad
        sec_headers = self.data.get("network", {}).get("security_headers", {})
        missing_headers = [k for k, v in sec_headers.items() if not v.get("present")]
        score -= min(len(missing_headers) * 5, 25)

        # 2. Criptografía SSL/TLS
        ssl_data = self.data.get("ssl", {})
        if ssl_data.get("enabled"):
            if ssl_data.get("is_expired"):
                score -= 30
            elif ssl_data.get("expiring_soon"):
                score -= 10
            if ssl_data.get("protocol") in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                score -= 25
            if ssl_data.get("warnings"):
                score -= min(len(ssl_data["warnings"]) * 5, 15)
        elif "https://" in self.target_url:
            score -= 20

        # 3. Métodos HTTP y Fuzzing
        method_matrix = self.data.get("method_fuzzing", [])
        for m in method_matrix:
            if m.get("risk_level") == "ALTO":
                score -= 15
            elif m.get("risk_level") == "MEDIO":
                score -= 5

        # 4. Reflexión de parámetros / Canarios
        reflection_findings = self.data.get("reflections", [])
        if reflection_findings:
            score -= min(len(reflection_findings) * 8, 20)

        # 5. Secretos y Fugas
        secrets = self.data.get("leaks", {}).get("exposed_secrets", [])
        if secrets:
            score -= min(len(secrets) * 15, 30)

        high_entropy = self.data.get("leaks", {}).get("high_entropy_tokens", [])
        if high_entropy:
            score -= min(len(high_entropy) * 5, 15)

        # 6. Archivos y Reglas YAML Expuestas
        exposed_files = self.data.get("exposed_files", [])
        critical_exposed = [f for f in exposed_files if f.get("severity") in ["CRÍTICO", "CATASTRÓFICO", "ALTO"]]
        if critical_exposed:
            score -= min(len(critical_exposed) * 15, 30)
        elif exposed_files:
            score -= min(len(exposed_files) * 5, 15)

        # 7. Fugas en cabeceras de servidor
        leaked_info = self.data.get("network", {}).get("info_leak_headers", {})
        if leaked_info:
            score -= min(len(leaked_info) * 3, 10)

        return max(score, 0)

    def generate_markdown(self):
        score = self.calculate_score()
        md_file = os.path.join(self.output_dir, "security_report.md")

        net = self.data.get("network", {})
        sec_h = net.get("security_headers", {})
        info_h = net.get("info_leak_headers", {})
        ssl_info = self.data.get("ssl", {})
        crawler = self.data.get("crawler", {})
        endpoints = self.data.get("endpoints", {})
        leaks = self.data.get("leaks", {})
        exposed_f = self.data.get("exposed_files", [])
        reflections = self.data.get("reflections", [])
        method_fuzz = self.data.get("method_fuzzing", [])
        openapi_specs = self.data.get("openapi_specs", [])

        lines = [
            f"# Reporte de Auditoría de Seguridad Web - Evaluación Integral",
            f"**Objetivo:** `{self.target_url}`  ",
            f"**Fecha y Hora:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Puntuación de Seguridad (Score):** `{score} / 100`  ",
            "",
            "---",
            "",
            "## 1. Resumen Ejecutivo de Evaluación",
            f"- **Páginas HTML rastreadas:** {len(crawler.get('discovered_pages', []))}",
            f"- **Assets descargados en mirror local:** {len(crawler.get('downloaded_assets', []))}",
            f"- **Endpoints descubiertos:** {len(endpoints.get('unique_endpoints', []))}",
            f"- **Reglas declarativas / Archivos expuestos:** {len(exposed_f)}",
            f"- **Secretos y credenciales confirmadas:** {len(leaks.get('exposed_secrets', []))}",
            f"- **Tokens de alta entropía sospechosos:** {len(leaks.get('high_entropy_tokens', []))}",
            f"- **Hallazgos de reflexión canario:** {len(reflections)}",
            "",
            "---",
            "",
            "## 2. Auditoría Criptográfica SSL/TLS y Red",
        ]

        if ssl_info.get("enabled"):
            lines.extend([
                f"- **Protocolo:** `{ssl_info.get('protocol')}` | **Grado:** `{ssl_info.get('grade')}`",
                f"- **Cifrado Negociado:** `{ssl_info.get('cipher_name')}` ({ssl_info.get('cipher_bits')} bits)",
                f"- **Emisor (CA):** `{ssl_info.get('issuer', {}).get('organizationName', 'Desconocido')} ({ssl_info.get('issuer', {}).get('commonName', '')})`",
                f"- **Vigencia Restante:** `{ssl_info.get('days_left')} días` (Vence: `{ssl_info.get('not_after')}`)",
            ])
            if ssl_info.get("sans"):
                lines.append(f"- **Nombres Alternativos del Sujeto (SANs):** `{'`, `'.join(ssl_info['sans'])}`")
            if ssl_info.get("warnings"):
                lines.append(f"- **⚠️ Advertencias TLS:** {'; '.join(ssl_info['warnings'])}")
        else:
            lines.append(f"- **Estado SSL:** `{ssl_info.get('reason', 'No configurado o HTTP plano')}`")

        lines.extend([
            "",
            f"- **Código HTTP Principal:** `{net.get('status_code', 'N/A')}` | **Latencia:** `{net.get('latency_ms', 'N/A')} ms`",
            "",
            "| Cabecera de Seguridad | Estado | Valor / Descripción |",
            "| :--- | :---: | :--- |"
        ])

        for name, info in sec_h.items():
            st = "✅ Presente" if info.get("present") else "❌ Faltante"
            val = f"`{info['value']}`" if info.get("value") else info.get("description", "")
            lines.append(f"| `{name}` | {st} | {val} |")

        if info_h:
            lines.extend([
                "",
                "### ⚠️ Fuga de Versiones en Servidor (Information Disclosure)",
                "| Cabecera | Valor Expuesto |",
                "| :--- | :--- |"
            ])
            for k, v in info_h.items():
                lines.append(f"| `{k}` | `{v}` |")

        if method_fuzz:
            lines.extend([
                "",
                "---",
                "",
                "## 3. Matriz de Verbos HTTP y Fuzzing de Métodos",
                "| Ruta | GET | POST | PUT | DELETE | OPTIONS | TRACE | Nivel de Riesgo | Advertencias |",
                "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |"
            ])
            for mf in method_fuzz:
                m_dict = mf.get("methods", {})
                def code(v): return str(m_dict.get(v, {}).get("status_code", "-"))
                warns = "; ".join(mf.get("warnings", [])) or "Ninguna"
                lines.append(f"| `{mf['path']}` | {code('GET')} | {code('POST')} | {code('PUT')} | {code('DELETE')} | {code('OPTIONS')} | {code('TRACE')} | **{mf.get('risk_level', 'BAJO')}** | {warns} |")

        if reflections:
            lines.extend([
                "",
                "---",
                "",
                "## 4. Detección de Reflexión de Parámetros (Canarios)",
                "| Tipo de Reflexión | Parámetro / Cabecera | URL Objetivo | Contexto en Respuesta | Riesgo |",
                "| :--- | :--- | :--- | :--- | :---: |"
            ])
            for r in reflections:
                target_field = r.get("parameter") or r.get("header") or "-"
                lines.append(f"| {r.get('type')} | `{target_field}` | [{r.get('url')}]({r.get('url')}) | `{r.get('reflected_in')}` | **{r.get('risk_level')}** |")

        if exposed_f:
            lines.extend([
                "",
                "---",
                "",
                "## 5. Reglas Declarativas YAML y Archivos Sensibles Expuestos",
                "| Regla / Ruta | Código HTTP | Severidad | Impacto | Remediación Recomendada |",
                "| :--- | :---: | :---: | :--- | :--- |"
            ])
            for ef in exposed_f:
                lines.append(f"| `{ef.get('path')}` | `{ef.get('status_code')}` | **{ef.get('severity', 'MEDIO')}** | {ef.get('impact', ef.get('description', ''))} | {ef.get('remediation', 'Restringir acceso')} |")

        if openapi_specs:
            lines.extend([
                "",
                "---",
                "",
                "## 6. Especificaciones de API OpenAPI / Swagger Descubiertas"
            ])
            for spec in openapi_specs:
                lines.append(f"- **Título:** {spec.get('title')} ({spec.get('spec_format')}) | **Operaciones:** {spec.get('total_operations')}")
                lines.append(f"- **Fuente:** [{spec.get('source_url')}]({spec.get('source_url')})")

        lines.extend([
            "",
            "---",
            "",
            "## 7. Fugas de Información, Secretos y Entropía",
        ])

        if leaks.get("exposed_secrets"):
            lines.append("### 🚨 Secretos y Credenciales Confirmadas")
            lines.append("| Archivo | Línea | Tipo | Evidencia (Enmascarada) |")
            lines.append("| :--- | :---: | :--- | :--- |")
            for s in leaks["exposed_secrets"]:
                lines.append(f"| `{s['file']}` | {s['line']} | {s['type']} | `{s['evidence']}` |")
        else:
            lines.append("✅ No se detectaron secretos ni API keys hardcodeadas por firmas directas.")

        if leaks.get("high_entropy_tokens"):
            lines.append("\n### ⚡ Tokens de Alta Entropía de Shannon (Potenciales Claves)")
            lines.append("| Archivo | Línea | Entropía | Longitud | Muestra Enmascarada |")
            lines.append("| :--- | :---: | :---: | :---: | :--- |")
            for h in leaks["high_entropy_tokens"][:15]:
                lines.append(f"| `{h['file']}` | {h['line']} | `{h['entropy']}` | {h['length']} chars | `{h['evidence']}` |")

        if leaks.get("source_maps"):
            lines.append("\n### ⚠️ Source Maps (.map) Expuestos")
            for sm in leaks["source_maps"]:
                lines.append(f"- `{sm}`")

        profiled = endpoints.get("profiled_volumes", [])
        if profiled:
            lines.extend([
                "",
                "---",
                "",
                "## 8. Clasificación de Endpoints por Volumen de Datos (GET vs POST)",
                "| Endpoint | Código (GET / POST) | Tipo | Tamaño | Clasificación | Hallazgo / Verb Tampering |",
                "| :--- | :---: | :--- | :---: | :---: | :--- |"
            ])
            for p in profiled:
                insight = p.get("verb_insight") or "Normal"
                lines.append(f"| [{p['endpoint']}]({p['url']}) | `{p['status_code']}` | `{p['content_type']}` | **{p['size_readable']}** | {p['classification']} | {insight} |")

        lines.extend([
            "",
            "---",
            "",
            "## 9. Checklist de Remediación Táctica para DevSecOps",
            "- [ ] Implementar cabecera `Content-Security-Policy` estricta.",
            "- [ ] Activar `X-Frame-Options: DENY` o `SAMEORIGIN` contra clickjacking.",
            "- [ ] Añadir `X-Content-Type-Options: nosniff`.",
            "- [ ] Configurar `Strict-Transport-Security` con vigencia mínima de 6 meses.",
            "- [ ] Deshabilitar método HTTP `TRACE` en el servidor web.",
            "- [ ] Ocultar versiones de servidor (`server_tokens off;` / remover `X-Powered-By`).",
            "- [ ] Bloquear acceso público a archivos `.env`, `.git` y volcados `.sql` en el proxy inverso.",
            "- [ ] Sanitizar parámetros de entrada reflejados en el HTML o cabeceras de respuesta.",
            "- [ ] Reubicar secretos o llamadas con claves privadas exclusivamente al backend."
        ])

        content = "\n".join(lines)
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(content)

        return md_file

    def generate_html(self):
        score = self.calculate_score()
        html_file = os.path.join(self.output_dir, "dashboard_report.html")

        # Preparar JSON embebido limpio
        data_clean = dict(self.data)
        json_payload = json.dumps(data_clean, indent=2)

        score_badge_class = "score-good" if score >= 80 else ("score-mid" if score >= 50 else "score-bad")

        crawler_data = self.data.get('crawler') or {}
        pages_count = len(crawler_data.get('discovered_pages') or [])
        assets_count = len(crawler_data.get('downloaded_assets') or [])
        endpoints_data = self.data.get('endpoints') or {}
        endpoints_count = len(endpoints_data.get('unique_endpoints') or [])
        network_data = self.data.get('network') or {}
        ssl_data = self.data.get('ssl') or {}
        latency = network_data.get('latency_ms', 'N/A')
        server_name = (network_data.get('info_leak_headers') or {}).get('Server', 'Oculto / Protegido')
        leaks = self.data.get('leaks') or {}
        leaks_count = len(leaks.get('exposed_secrets') or [])
        entropy_count = len(leaks.get('high_entropy_tokens') or [])
        exposed_files = self.data.get('exposed_files') or []
        reflections = self.data.get('reflections') or []
        method_fuzz = self.data.get('method_fuzzing') or []
        openapi_specs = self.data.get('openapi_specs') or []

        html_template = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSec Auditor - {self.target_url}</title>
    <style>
        :root {{
            --bg: #070d18;
            --surface: #0f172a;
            --surface-card: #1e293b;
            --surface-hover: #334155;
            --text: #f8fafc;
            --text-dim: #94a3b8;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.2);
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #22c55e;
            --border: #1e293b;
            --border-light: #334155;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            display: flex;
            height: 100vh;
            overflow: hidden;
        }}
        /* SIDEBAR NAV (SPA) */
        .sidebar {{
            width: 280px;
            background: #030712;
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
        }}
        .brand {{
            padding: 22px 20px;
            border-bottom: 1px solid var(--border);
        }}
        .brand h1 {{
            font-size: 1.15rem;
            margin: 0 0 4px 0;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .brand small {{
            color: var(--text-dim);
            font-size: 0.74rem;
            letter-spacing: 0.5px;
        }}
        .nav-list {{
            list-style: none;
            margin: 0;
            padding: 14px 10px;
            flex: 1;
            overflow-y: auto;
        }}
        .nav-item a {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 14px;
            color: var(--text-dim);
            text-decoration: none;
            border-radius: 8px;
            font-size: 0.88rem;
            font-weight: 500;
            margin-bottom: 4px;
            transition: all 0.18s cubic-bezier(0.2, 1, 0.3, 1);
        }}
        .nav-item a:hover {{
            background: var(--surface);
            color: var(--text);
        }}
        .nav-item a.active {{
            background: linear-gradient(135deg, rgba(2, 132, 199, 0.25) 0%, rgba(56, 189, 248, 0.15) 100%);
            border: 1px solid var(--accent);
            color: #fff;
            font-weight: 600;
        }}
        .score-pill {{
            margin: 16px;
            padding: 14px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            text-align: center;
        }}
        .score-good {{ color: #4ade80; text-shadow: 0 0 16px rgba(74, 222, 128, 0.3); }}
        .score-mid {{ color: #fde047; text-shadow: 0 0 16px rgba(253, 224, 71, 0.3); }}
        .score-bad {{ color: #f87171; text-shadow: 0 0 16px rgba(248, 113, 113, 0.3); }}

        /* MAIN CONTENT VIEW */
        .main-content {{
            flex: 1;
            overflow-y: auto;
            padding: 30px 40px;
        }}
        .view-section {{
            display: none;
            animation: fadeIn 0.2s ease-in-out;
        }}
        .view-section.active {{
            display: block;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(4px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        }}
        .card h2 {{
            font-size: 1.25rem;
            margin-top: 0;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
        }}
        th, td {{
            padding: 11px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            color: var(--text-dim);
            background: rgba(3, 7, 18, 0.7);
            font-weight: 600;
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        tr:hover td {{
            background: rgba(255, 255, 255, 0.02);
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-success {{ background: rgba(34, 197, 94, 0.2); color: var(--success); border: 1px solid rgba(34, 197, 94, 0.3); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge-info {{ background: rgba(56, 189, 248, 0.2); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.3); }}
        pre {{
            background: #030712;
            padding: 16px;
            border-radius: 10px;
            overflow-x: auto;
            color: #38bdf8;
            font-size: 0.85rem;
            border: 1px solid var(--border);
            max-height: 520px;
        }}
        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: rgba(255, 255, 255, 0.06);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.85em;
        }}
    </style>
</head>
<body>

    <!-- SIDEBAR NAV -->
    <aside class="sidebar">
        <div class="brand">
            <h1>🛡️ WebSec Auditor 2.0</h1>
            <small>DevSecOps & Criptografía Integral</small>
        </div>
        <ul class="nav-list">
            <li class="nav-item"><a href="#resumen" class="nav-link active" onclick="navigate('#resumen')">📊 Resumen General</a></li>
            <li class="nav-item"><a href="#cripto" class="nav-link" onclick="navigate('#cripto')">🔐 Criptografía & Red</a></li>
            <li class="nav-item"><a href="#fuzzing" class="nav-link" onclick="navigate('#fuzzing')">⚡ Métodos & Fuzzing</a></li>
            <li class="nav-item"><a href="#reglas" class="nav-link" onclick="navigate('#reglas')">📜 Reglas YAML & CVEs</a></li>
            <li class="nav-item"><a href="#endpoints" class="nav-link" onclick="navigate('#endpoints')">🌐 Endpoints & APIs</a></li>
            <li class="nav-item"><a href="#fugas" class="nav-link" onclick="navigate('#fugas')">🔍 Fugas & Entropía</a></li>
            <li class="nav-item"><a href="#causalidad" class="nav-link" onclick="navigate('#causalidad')">🎯 Causalidad (X ➔ Y)</a></li>
            <li class="nav-item"><a href="#json" class="nav-link" onclick="navigate('#json')">📦 Datos Crudos JSON</a></li>
        </ul>
        <div class="score-pill">
            <div style="font-size:0.78rem; color:var(--text-dim); margin-bottom:4px; text-transform:uppercase; letter-spacing:0.5px;">Security Score</div>
            <div style="font-size:1.8rem; font-weight:bold;" class="{score_badge_class}">{score} / 100</div>
        </div>
    </aside>

    <!-- ÁREA PRINCIPAL -->
    <main class="main-content">

        <!-- 1. VISTA: RESUMEN GENERAL -->
        <section id="view-resumen" class="view-section active">
            <div style="margin-bottom: 24px;">
                <h2 style="margin:0 0 6px 0; border:none; padding:0;">Dashboard Ejecutivo de Seguridad</h2>
                <div style="color:var(--accent); font-family:monospace; font-size:0.95rem;">🎯 Objetivo: {self.target_url}</div>
            </div>

            <div class="grid">
                <div class="card">
                    <h3 style="margin-top:0; color:var(--accent); font-size:1rem;">Superficie & Crawler</h3>
                    <p><strong>Páginas HTML:</strong> {pages_count}</p>
                    <p><strong>Assets en Mirror:</strong> {assets_count}</p>
                    <p><strong>Rutas Únicas:</strong> {endpoints_count}</p>
                </div>
                <div class="card">
                    <h3 style="margin-top:0; color:var(--accent); font-size:1rem;">Conectividad & TLS</h3>
                    <p><strong>Protocolo:</strong> <code>{ssl_data.get('protocol', 'N/A')}</code></p>
                    <p><strong>Grado TLS:</strong> <span class="badge badge-success">{ssl_data.get('grade', 'N/A')}</span></p>
                    <p><strong>Latencia:</strong> {latency} ms</p>
                </div>
                <div class="card">
                    <h3 style="margin-top:0; color:var(--accent); font-size:1rem;">Hallazgos & Exposición</h3>
                    <p><strong>Reglas YAML / Archivos:</strong> <span class="badge {('badge-danger' if exposed_files else 'badge-success')}">{len(exposed_files)} activos</span></p>
                    <p><strong>Secretos / Tokens:</strong> <span class="badge {('badge-danger' if leaks_count else 'badge-success')}">{leaks_count} confirmados</span></p>
                    <p><strong>Reflexiones Canario:</strong> <span class="badge {('badge-warning' if reflections else 'badge-success')}">{len(reflections)} detectadas</span></p>
                </div>
            </div>

            <div class="card">
                <h2>🎯 Postura General de Seguridad</h2>
                <table>
                    <tr><th>Vector Evaluado</th><th>Estado</th><th>Observación Clave</th></tr>
                    <tr>
                        <td><strong>Cifrado en Tránsito (SSL/TLS)</strong></td>
                        <td><span class="badge {('badge-success' if ssl_data.get('grade') in ['A', 'A+'] else 'badge-warning')}">{ssl_data.get('protocol', 'HTTP')}</span></td>
                        <td>{ssl_data.get('cipher_name', 'No negociado')} · {ssl_data.get('days_left', 0)} días de vigencia restante.</td>
                    </tr>
                    <tr>
                        <td><strong>Higiene de Cabeceras HTTP</strong></td>
                        <td><span class="badge {('badge-danger' if len(sec_headers := [k for k,v in network_data.get('security_headers', {}).items() if not v.get('present')]) > 3 else 'badge-success')}">{len(network_data.get('security_headers', {})) - len(sec_headers)} / {len(network_data.get('security_headers', {}))} activas</span></td>
                        <td>Faltan cabeceras de endurecimiento como CSP, HSTS o X-Frame-Options.</td>
                    </tr>
                    <tr>
                        <td><strong>Fuga de Información y Secretos</strong></td>
                        <td><span class="badge {('badge-danger' if leaks_count else 'badge-success')}">{leaks_count} Fugas</span></td>
                        <td>{('Se detectaron credenciales en archivos estáticos.' if leaks_count else 'Código frontend limpio sin API keys expuestas.')}</td>
                    </tr>
                    <tr>
                        <td><strong>Archivos de Entorno y Configuración</strong></td>
                        <td><span class="badge {('badge-danger' if exposed_files else 'badge-success')}">{len(exposed_files)} Expuestos</span></td>
                        <td>{('Rutas sensibles accesibles sin autenticación.' if exposed_files else 'Sin dotfiles (.env, .git) ni volcados de base de datos públicos.')}</td>
                    </tr>
                </table>
            </div>
        </section>

        <!-- 2. VISTA: CRIPTOGRAFÍA & RED -->
        <section id="view-cripto" class="view-section">
            <div class="card">
                <h2>🔐 Auditoría Criptográfica SSL/TLS</h2>
"""
        if ssl_data.get("enabled"):
            html_template += f"""
                <div class="grid" style="margin-top:16px;">
                    <div>
                        <p><strong>Host / Puerto:</strong> <code>{ssl_data.get('hostname')}:{ssl_data.get('port')}</code></p>
                        <p><strong>Versión Negociada:</strong> <code>{ssl_data.get('protocol')}</code></p>
                        <p><strong>Cifrado (Cipher Suite):</strong> <code>{ssl_data.get('cipher_name')}</code> ({ssl_data.get('cipher_bits')} bits)</p>
                    </div>
                    <div>
                        <p><strong>Emisor (CA):</strong> {ssl_data.get('issuer', {}).get('organizationName', 'N/A')} ({ssl_data.get('issuer', {}).get('commonName', '')})</p>
                        <p><strong>Vencimiento:</strong> {ssl_data.get('not_after', 'N/A')} (<strong>{ssl_data.get('days_left')} días</strong>)</p>
                        <p><strong>Grado de Configuración:</strong> <span class="badge badge-success">{ssl_data.get('grade')}</span></p>
                    </div>
                </div>
            """
            if ssl_data.get("sans"):
                html_template += f"""
                <div style="margin-top:14px;">
                    <strong>Nombres Alternativos del Sujeto (SANs / Subdominios Descubiertos):</strong>
                    <div style="margin-top:8px; display:flex; flex-wrap:wrap; gap:8px;">
                """
                for san in ssl_data["sans"]:
                    html_template += f"<span class='badge badge-info'>🌐 {san}</span>"
                html_template += "</div></div>"
        else:
            html_template += f"<p style='color:var(--warning);'>⚠️ {ssl_data.get('reason', 'HTTPS no habilitado.')}</p>"

        html_template += """
            </div>

            <div class="card">
                <h2>🛡️ Cabeceras de Seguridad HTTP</h2>
                <table>
                    <tr><th>Cabecera</th><th>Estado</th><th>Detalle / Recomendación</th></tr>
"""
        for name, info in network_data.get("security_headers", {}).items():
            st = '<span class="badge badge-success">PRESENTE</span>' if info.get("present") else '<span class="badge badge-danger">FALTANTE</span>'
            val = info.get("value") or info.get("description", "")
            html_template += f"<tr><td><code>{name}</code></td><td>{st}</td><td>{val}</td></tr>"

        html_template += """
                </table>
            </div>
        </section>

        <!-- 3. VISTA: MÉTODOS & FUZZING -->
        <section id="view-fuzzing" class="view-section">
            <div class="card">
                <h2>⚡ Matriz de Métodos HTTP (Verb Fuzzing)</h2>
                <p style="color:var(--text-dim);">Evaluación de soporte de verbos estándar y anómalos para detectar bypass de control de acceso y Cross-Site Tracing (XST).</p>
                <table>
                    <tr>
                        <th>Ruta</th><th>GET</th><th>POST</th><th>PUT</th><th>DELETE</th><th>OPTIONS</th><th>TRACE</th><th>Riesgo</th><th>Observaciones</th>
                    </tr>
"""
        if method_fuzz:
            for mf in method_fuzz:
                m = mf.get("methods", {})
                def get_badge(code):
                    if not code: return "<span style='color:var(--text-dim);'>-</span>"
                    if code == 200: return f"<span class='badge badge-success'>{code}</span>"
                    if code in [401, 403]: return f"<span class='badge badge-info'>{code}</span>"
                    if code == 405: return f"<span class='badge badge-warning'>{code}</span>"
                    return f"<code>{code}</code>"

                warn_text = "; ".join(mf.get("warnings", [])) or "<span style='color:var(--text-dim);'>Normal</span>"
                risk_badge = "badge-danger" if mf.get("risk_level") in ["ALTO", "CRÍTICO"] else ("badge-warning" if mf.get("risk_level") == "MEDIO" else "badge-success")

                html_template += f"""
                <tr>
                    <td><code>{mf.get('path')}</code></td>
                    <td>{get_badge(m.get('GET', {}).get('status_code'))}</td>
                    <td>{get_badge(m.get('POST', {}).get('status_code'))}</td>
                    <td>{get_badge(m.get('PUT', {}).get('status_code'))}</td>
                    <td>{get_badge(m.get('DELETE', {}).get('status_code'))}</td>
                    <td>{get_badge(m.get('OPTIONS', {}).get('status_code'))}</td>
                    <td>{get_badge(m.get('TRACE', {}).get('status_code'))}</td>
                    <td><span class="badge {risk_badge}">{mf.get('risk_level', 'BAJO')}</span></td>
                    <td>{warn_text}</td>
                </tr>
                """
        else:
            html_template += "<tr><td colspan='9'>No se ejecutó sondeo de métodos en esta sesión.</td></tr>"

        html_template += """
                </table>
            </div>

            <div class="card">
                <h2>🎯 Inyección de Canarios No Destructivos (Reflexión)</h2>
                <p style="color:var(--text-dim);">Verifica si el servidor web refleja parámetros de entrada sin sanitización en el DOM o cabeceras (precursor de XSS y Open Redirect).</p>
"""
        if reflections:
            html_template += "<table><tr><th>Tipo</th><th>Parámetro / Cabecera</th><th>Contexto</th><th>Riesgo</th><th>Descripción</th></tr>"
            for r in reflections:
                f_name = r.get("parameter") or r.get("header") or "-"
                html_template += f"""
                <tr>
                    <td><strong>{r.get('type')}</strong></td>
                    <td><code>{f_name}</code></td>
                    <td><span class="badge badge-warning">{r.get('reflected_in')}</span></td>
                    <td><span class="badge badge-danger">{r.get('risk_level')}</span></td>
                    <td>{r.get('description')}</td>
                </tr>
                """
            html_template += "</table>"
        else:
            html_template += "<p style='color:var(--success);'>✅ Las cadenas canario enviadas no se reflejaron en el cuerpo HTML ni en cabeceras de respuesta.</p>"

        html_template += """
            </div>
        </section>

        <!-- 4. VISTA: REGLAS YAML & CVES -->
        <section id="view-reglas" class="view-section">
            <div class="card">
                <h2>📜 Reglas Declarativas YAML Estilo Nuclei Ejecutadas</h2>
                <p style="color:var(--text-dim);">Detección basada en plantillas de configuración, rutas críticas, volcados y consolas administrativas.</p>
"""
        if exposed_files:
            html_template += "<table><tr><th>Regla / Ruta</th><th>Código</th><th>Severidad</th><th>Impacto</th><th>Remediación</th></tr>"
            for ef in exposed_files:
                sev = ef.get("severity", "MEDIO")
                s_badge = "badge-danger" if sev in ["CRÍTICO", "CATASTRÓFICO", "ALTO"] else "badge-warning"
                html_template += f"""
                <tr>
                    <td><code>{ef.get('path')}</code></td>
                    <td><span class="badge badge-danger">{ef.get('status_code')}</span></td>
                    <td><span class="badge {s_badge}">{sev}</span></td>
                    <td>{ef.get('impact', ef.get('description', ''))}</td>
                    <td>{ef.get('remediation', 'Restringir acceso')}</td>
                </tr>
                """
            html_template += "</table>"
        else:
            html_template += "<p style='color:var(--success);'>✅ Ninguna regla declarativa disparó hallazgos positivos (0 exposiciones críticas de .env, .git o volcados).</p>"

        html_template += f"""
            </div>
        </section>

        <!-- 5. VISTA: ENDPOINTS & APIS -->
        <section id="view-endpoints" class="view-section">
            <div class="card">
                <h2>🌐 Clasificación de Endpoints y Telemetría de Volumen (GET vs POST)</h2>
                <table>
                    <tr><th>Endpoint</th><th>Código (GET / POST)</th><th>Tipo</th><th>Tamaño</th><th>Clasificación</th><th>Insight Verb Tampering</th></tr>
"""
        profiled = endpoints_data.get("profiled_volumes", [])
        if profiled:
            for p in profiled:
                b_class = "badge-danger" if p["badge"] == "ALTO" else ("badge-warning" if p["badge"] == "MEDIO" else "badge-success")
                insight_html = f"<span style='color:var(--warning); font-size:0.8rem;'>{p.get('verb_insight')}</span>" if p.get('verb_insight') else "<span style='color:var(--text-dim);'>Normal</span>"
                html_template += f"""
                <tr>
                    <td><a href="{p['url']}" target="_blank" style="color:var(--accent); text-decoration:none; font-family:monospace;">🔗 {p['endpoint']}</a></td>
                    <td><code>{p['status_code']}</code></td>
                    <td>{p['content_type']}</td>
                    <td><strong>{p['size_readable']}</strong></td>
                    <td><span class="badge {b_class}">{p['classification']}</span></td>
                    <td>{insight_html}</td>
                </tr>
                """
        else:
            html_template += "<tr><td colspan='6'>No se registraron endpoints para telemetría de volumen.</td></tr>"

        html_template += """
                </table>
            </div>
        </section>

        <!-- 6. VISTA: FUGAS & ENTROPÍA -->
        <section id="view-fugas" class="view-section">
            <div class="card">
                <h2>🚨 Secretos y Credenciales Confirmadas por Firma</h2>
"""
        sec_list = leaks.get("exposed_secrets", [])
        if sec_list:
            html_template += "<table><tr><th>Archivo</th><th>Línea</th><th>Tipo</th><th>Evidencia Enmascarada</th></tr>"
            for sl in sec_list:
                html_template += f"<tr><td><code>{sl['file']}</code></td><td>{sl['line']}</td><td>{sl['type']}</td><td><code>{sl['evidence']}</code></td></tr>"
            html_template += "</table>"
        else:
            html_template += "<p style='color:var(--success);'>✅ No se detectaron secretos ni API keys en las firmas de proveedores.</p>"

        html_template += """
            </div>

            <div class="card">
                <h2>⚡ Tokens de Alta Entropía de Shannon (Heurística Anti-Fugas)</h2>
                <p style="color:var(--text-dim);">Cadenas de alta aleatoriedad (> 4.5 bits de entropía) que podrían corresponder a llaves privadas, sales o hashes sin firma estructurada.</p>
"""
        ent_list = leaks.get("high_entropy_tokens", [])
        if ent_list:
            html_template += "<table><tr><th>Archivo</th><th>Línea</th><th>Entropía</th><th>Longitud</th><th>Muestra Enmascarada</th></tr>"
            for el in ent_list[:25]:
                html_template += f"<tr><td><code>{el['file']}</code></td><td>{el['line']}</td><td><span class='badge badge-warning'>{el['entropy']} bits</span></td><td>{el['length']} chars</td><td><code>{el['evidence']}</code></td></tr>"
            html_template += "</table>"
        else:
            html_template += "<p style='color:var(--success);'>✅ No se detectaron tokens con patrones de entropía anómala.</p>"

        html_template += """
            </div>
        </section>

        <!-- 7. VISTA: CAUSALIDAD -->
        <section id="view-causalidad" class="view-section">
            <div class="card">
                <h2>🎯 Matriz de Causalidad e Impacto en Lógica de Negocio (X ➔ Y)</h2>
                <p style="color:var(--text-dim);">Demostración técnica analítica: <em>"Si un actor interactúa con el punto X, produce el impacto Y en el negocio"</em>.</p>
                <table>
                    <tr><th>Superficie Expuesta (X)</th><th>Ubicación en Código</th><th>Nivel de Riesgo</th><th>Acción Identificada</th><th>Impacto Potencial (Y)</th></tr>
"""
        impact_matrix = self.data.get("impact_matrix", [])
        if impact_matrix:
            for item in impact_matrix:
                r_color = "badge-danger" if item["risk_level"] in ["CRÍTICO", "CATASTRÓFICO"] else "badge-warning"
                html_template += f"""
                <tr>
                    <td><code>{item['endpoint']}</code></td>
                    <td><small style="color:var(--text-dim);">{item['file']}:L{item['line']}</small></td>
                    <td><span class="badge {r_color}">{item['risk_level']}</span></td>
                    <td>{item['action']}</td>
                    <td>{item['impact']}</td>
                </tr>
                """
        else:
            html_template += "<tr><td colspan='5'>No se detectaron flujos críticos de modificación de base de datos o lógica de precios en el código frontend analizado.</td></tr>"

        html_template += f"""
                </table>
            </div>
        </section>

        <!-- 8. VISTA: JSON CRUDO -->
        <section id="view-json" class="view-section">
            <div class="card">
                <h2>📦 Dataset Crudo de Auditoría (JSON Estructurado)</h2>
                <pre>{json_payload}</pre>
            </div>
        </section>

    </main>

    <!-- SPA HASH ROUTING -->
    <script>
        function navigate(hash) {{
            if (!hash) hash = "#resumen";
            const sectionId = "view-" + hash.replace("#", "");
            
            document.querySelectorAll(".view-section").forEach(sec => sec.classList.remove("active"));
            document.querySelectorAll(".nav-link").forEach(link => link.classList.remove("active"));

            const target = document.getElementById(sectionId);
            if (target) target.classList.add("active");

            const activeLink = document.querySelector(`.nav-link[href="${{hash}}"]`);
            if (activeLink) activeLink.classList.add("active");
            
            window.location.hash = hash;
        }}

        window.addEventListener("DOMContentLoaded", () => {{
            navigate(window.location.hash || "#resumen");
        }});
        window.addEventListener("hashchange", () => {{
            navigate(window.location.hash);
        }});
    </script>
</body>
</html>
"""
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_template)

        return html_file
