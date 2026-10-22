#!/usr/bin/env python3
import argparse
import sys
import os
import json
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.crawler import WebCrawler
from modules.network_audit import NetworkAuditor
from modules.ssl_auditor import SSLAuditor
from modules.method_fuzzer import MethodFuzzer
from modules.reflection_detector import ReflectionDetector
from modules.endpoint_mapper import EndpointMapper
from modules.openapi_parser import OpenAPIParser
from modules.leak_detector import LeakDetector
from modules.vuln_checker import VulnChecker
from modules.causality_analyzer import ImpactCausalityAnalyzer
from modules.reporter import ReportGenerator

console = Console()

def print_banner():
    banner = """
    [bold cyan]WebSec Auditor & DevSecOps Toolkit 2.0[/bold cyan]
    [dim]Auditoría Web Defensiva, Criptografía SSL, Reglas YAML (Nuclei-Style), Fuzzing de Métodos y Mirroring[/dim]
    """
    console.print(Panel(banner.strip(), border_style="cyan"))

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Auditoría web defensiva, extracción de recursos (mirror) y evaluación de seguridad.")
    parser.add_argument("--url", "-u", required=True, help="URL de la aplicación web a evaluar (ej. https://aula.pargo.mx/)")
    parser.add_argument("--output", "-o", default=None, help="Directorio de salida para el mirror y reportes")
    parser.add_argument("--level", "-l", type=int, choices=[1, 2, 3], default=2,
                        help="Nivel de auditoría: 1=Rápido/Cabeceras/SSL (máx 10 págs), 2=Estándar (Mirroring, reglas YAML, fuzzing y causalidad), 3=Forense Completo (Nivel 2 + render dinámico + descarga de backups). Default: 2")
    parser.add_argument("--max-pages", type=int, default=None, help="Límite manual de páginas HTML a rastrear (sobrescribe el default del nivel)")
    parser.add_argument("--dynamic", action="store_true", help="Activar renderizado dinámico con Chromium headless para SPAs/HTMX")
    parser.add_argument("--no-ssl", action="store_true", help="Omitir auditoría criptográfica SSL/TLS")
    parser.add_argument("--no-fuzz", action="store_true", help="Omitir fuzzing de métodos HTTP")
    parser.add_argument("--no-reflection", action="store_true", help="Omitir detección de reflexión con canarios")
    parser.add_argument("--download-backup", action="store_true", help="Descargar copia local segura de endpoints de backup descubiertos")

    args = parser.parse_args()

    audit_level = args.level
    if audit_level == 1:
        max_pages = args.max_pages if args.max_pages is not None else 10
        use_dynamic = args.dynamic
        auto_backup = False
    elif audit_level == 2:
        max_pages = args.max_pages if args.max_pages is not None else 50
        use_dynamic = args.dynamic
        auto_backup = args.download_backup
    else:  # audit_level == 3
        max_pages = args.max_pages if args.max_pages is not None else 150
        use_dynamic = True
        auto_backup = True

    target_url = args.url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed_target = urlparse(target_url)
    domain_folder = parsed_target.netloc.replace(":", "_")
    base_folder_name = f"audit_{domain_folder}"

    if args.output:
        output_dir = args.output
    else:
        candidate_dir = os.path.join(os.getcwd(), base_folder_name)
        if not os.path.exists(candidate_dir):
            output_dir = candidate_dir
        else:
            version = 2
            while True:
                versioned_dir = os.path.join(os.getcwd(), f"{base_folder_name}_v{version}")
                if not os.path.exists(versioned_dir):
                    output_dir = versioned_dir
                    break
                version += 1

    os.makedirs(output_dir, exist_ok=True)

    level_descriptions = {
        1: "[cyan]Nivel 1 (Superficial / Rápido)[/cyan] - Inspección de cabeceras, SSL y landing (<= 10 págs)",
        2: "[yellow]Nivel 2 (Estándar / Pasivo)[/yellow] - Mirroring completo, reglas YAML, fuzzing, leaks y causalidad X->Y",
        3: "[red]Nivel 3 (Forense / Profundo)[/red] - Auditoría total con Chromium headless, extracción de assets y mapeo exhaustivo"
    }

    console.print(f"\n[bold green][+][/bold green] Objetivo fijado: [cyan]{target_url}[/cyan]")
    console.print(f"[bold green][+][/bold green] Nivel seleccionado: {level_descriptions[audit_level]}")
    console.print(f"[bold green][+][/bold green] Modo dinámico headless: {'[green]ACTIVADO[/green]' if use_dynamic else '[dim]DESACTIVADO[/dim]'}")
    console.print(f"[bold green][+][/bold green] Directorio de salida: [yellow]{output_dir}[/yellow]\n")

    # 1. Auditoría de Network, Cabeceras y Criptografía SSL/TLS
    console.print("[bold blue][1/8][/bold blue] Analizando tráfico, latencia y cabeceras de seguridad...")
    net_auditor = NetworkAuditor(target_url)
    net_results = net_auditor.audit()

    if "error" in net_results:
        console.print(f"[bold red][!] Error al conectar con el objetivo:[/bold red] {net_results['error']}")
        sys.exit(1)

    table_headers = Table(title="Inspección de Cabeceras de Seguridad")
    table_headers.add_column("Cabecera", style="cyan")
    table_headers.add_column("Estado", justify="center")
    table_headers.add_column("Detalle", style="dim")

    for name, info in net_results.get("security_headers", {}).items():
        status_text = "[green]PRESENTE[/green]" if info.get("present") else "[red]FALTANTE[/red]"
        detail = info.get("value") if info.get("value") else info.get("description", "")
        table_headers.add_row(name, status_text, detail)

    console.print(table_headers)

    ssl_results = {}
    if not args.no_ssl:
        console.print("\n[bold blue][2/8][/bold blue] Evaluando criptografía SSL/TLS, ciphers y certificados...")
        ssl_auditor = SSLAuditor(target_url)
        ssl_results = ssl_auditor.audit()

        if ssl_results.get("enabled"):
            grade_color = "green" if ssl_results.get("grade") in ["A", "A+"] else "yellow"
            console.print(f"    - Protocolo TLS: [cyan]{ssl_results.get('protocol')}[/cyan] | Cifrado: [cyan]{ssl_results.get('cipher_name')}[/cyan] ({ssl_results.get('cipher_bits')} bits)")
            console.print(f"    - Emisor: [dim]{ssl_results.get('issuer', {}).get('organizationName', 'Desconocido')}[/dim] | Días restantes: [bold {grade_color}]{ssl_results.get('days_left')}[/bold {grade_color}]")
            if ssl_results.get("sans"):
                console.print(f"    - SANs (Subdominios descubiertos): [yellow]{', '.join(ssl_results['sans'][:4])}[/yellow]")
        else:
            console.print(f"    - [yellow]Estado TLS:[/yellow] {ssl_results.get('reason', 'Sin SSL')}")

    # 2. Ingesta Automática de OpenAPI / Swagger
    console.print("\n[bold blue][3/8][/bold blue] Buscando especificaciones de API expuestas (OpenAPI / Swagger)...")
    api_parser = OpenAPIParser(target_url)
    openapi_specs = api_parser.discover_and_parse()
    extra_endpoints = []
    if openapi_specs:
        for spec in openapi_specs:
            console.print(f"    - [bold green]✓ OpenAPI Detectado:[/bold green] [cyan]{spec['title']}[/cyan] ({spec['spec_format']}) con [yellow]{spec['total_operations']}[/yellow] operaciones documentadas.")
            for op in spec.get("operations", []):
                extra_endpoints.append(op["route"])
    else:
        console.print("    - No se detectaron especificaciones OpenAPI/Swagger públicas.")

    # 3. Rastreo y Extracción Completa (Mirroring)
    console.print(f"\n[bold blue][4/8][/bold blue] Extrayendo archivos y recursos en modo mirror (Dinámico: {use_dynamic})...")
    crawler = WebCrawler(target_url, output_dir=output_dir, max_pages=max_pages, dynamic=use_dynamic)
    crawl_results = crawler.crawl_and_mirror()
    console.print(f"    - Páginas HTML rastreadas: [cyan]{len(crawl_results['discovered_pages'])}[/cyan]")
    console.print(f"    - Recursos descargados en mirror: [cyan]{len(crawl_results['downloaded_assets'])}[/cyan]")
    console.print(f"    - Directorio offline: [yellow]{crawl_results['mirror_path']}[/yellow]")

    # 4. Mapeo de Endpoints y Perfilado de Volumen de Datos
    console.print(f"\n[bold blue][5/8][/bold blue] Analizando código fuente y scripts para descubrir endpoints...")
    ep_mapper = EndpointMapper(target_url, crawl_results["mirror_path"])
    
    # Inyectar rutas descubiertas en formularios, HTMX y OpenAPI
    for form_url, _, _ in crawl_results.get("form_endpoints", []):
        parsed = urlparse(form_url)
        extra_endpoints.append(parsed.path)

    ep_results = ep_mapper.extract_endpoints_from_files(additional_endpoints=extra_endpoints)
    console.print(f"    - Rutas únicas identificadas: [cyan]{len(ep_results['unique_endpoints'])}[/cyan]")

    console.print("    - Perfilando y clasificando volumen de datos transferido (GET vs POST)...")
    profiled_volumes = ep_mapper.profile_data_volumes(ep_results["unique_endpoints"])
    ep_results["profiled_volumes"] = profiled_volumes
    console.print(f"    - Endpoints clasificados: [cyan]{len(profiled_volumes)}[/cyan]")

    # 5. Fuzzing de Métodos HTTP y Detección de Reflexión (Canarios)
    method_fuzz_results = []
    if not args.no_fuzz:
        console.print("\n[bold blue][6/8][/bold blue] Ejecutando matriz de métodos HTTP (OPTIONS, TRACE, PUT, DELETE)...")
        sample_paths = ["/", "/login", "/api", "/admin"]
        for p in ep_results["unique_endpoints"][:3]:
            if p not in sample_paths:
                sample_paths.append(p)
        fuzzer = MethodFuzzer(target_url)
        method_fuzz_results = fuzzer.audit_multiple(sample_paths[:6])
        warn_count = sum(len(m.get("warnings", [])) for m in method_fuzz_results)
        console.print(f"    - Rutas evaluadas: [cyan]{len(method_fuzz_results)}[/cyan] | Advertencias de verbos: [yellow]{warn_count}[/yellow]")

    reflection_findings = []
    if not args.no_reflection:
        console.print("    - Inyectando canarios no destructivos para probar reflexión en HTML y cabeceras...")
        ref_detector = ReflectionDetector(target_url)
        reflection_findings = ref_detector.check_query_reflection("/") + ref_detector.check_header_reflection("/")
        if reflection_findings:
            console.print(f"    - [bold yellow]⚠️ Reflexiones detectadas:[/bold yellow] [yellow]{len(reflection_findings)}[/yellow]")
        else:
            console.print("    - 0 reflexiones de entrada detectadas (seguro contra canarios básicos).")

    # 6. Detección de Fugas de Información, Secretos y Entropía de Shannon
    console.print(f"\n[bold blue][7/8][/bold blue] Buscando exposición de secretos, entropía de Shannon y comentarios...")
    leak_detector = LeakDetector(crawl_results["mirror_path"])
    leak_results = leak_detector.scan()

    if leak_results["exposed_secrets"]:
        console.print(f"    - [bold red]¡Alerta![/bold red] Se detectaron [red]{len(leak_results['exposed_secrets'])}[/red] secretos/tokens expuestos en el frontend.")
    else:
        console.print("    - No se detectaron credenciales ni API keys obvias por firmas directas.")

    if leak_results.get("high_entropy_tokens"):
        console.print(f"    - Tokens sospechosos de alta entropía de Shannon: [yellow]{len(leak_results['high_entropy_tokens'])}[/yellow]")

    # 7. Reglas Declarativas YAML Estilo Nuclei
    console.print(f"\n[bold blue][8/8][/bold blue] Ejecutando motor de reglas declarativas YAML estilo Nuclei...")
    vuln_checker = VulnChecker(target_url)
    exposed_files = vuln_checker.check_exposed_files()
    console.print(f"    - Hallazgos de reglas YAML / archivos sensibles: [cyan]{len(exposed_files)}[/cyan]")

    # Análisis de Causalidad e Impacto en Lógica de Negocio
    causality_analyzer = ImpactCausalityAnalyzer(crawl_results["mirror_path"])
    impact_matrix = causality_analyzer.analyze()

    # Descarga de respaldo si aplica
    backup_file_saved = None
    if auto_backup:
        backup_candidates = [item["endpoint"] for item in impact_matrix if "backup" in item["endpoint"].lower()]
        for bc in backup_candidates:
            b_url = target_url.rstrip('/') + '/' + bc.lstrip('/')
            try:
                import requests
                r = requests.get(b_url, timeout=15)
                if r.status_code == 200 and len(r.content) > 100:
                    backup_filename = os.path.join(output_dir, "server_backup_dump.json")
                    with open(backup_filename, "wb") as bf:
                        bf.write(r.content)
                    backup_file_saved = backup_filename
                    break
            except Exception:
                pass

    # Consolidación del Dataset Completo
    audit_data = {
        "target_url": target_url,
        "network": net_results,
        "ssl": ssl_results,
        "method_fuzzing": method_fuzz_results,
        "reflections": reflection_findings,
        "openapi_specs": openapi_specs,
        "crawler": crawl_results,
        "endpoints": ep_results,
        "leaks": leak_results,
        "exposed_files": exposed_files,
        "impact_matrix": impact_matrix,
        "backup_downloaded": backup_file_saved
    }

    raw_json_file = os.path.join(output_dir, "audit_data.json")
    with open(raw_json_file, "w", encoding="utf-8") as f:
        json.dump(audit_data, f, indent=2)

    # Generación de Reportes Finales
    reporter = ReportGenerator(target_url, audit_data, output_dir)
    md_report = reporter.generate_markdown()
    html_report = reporter.generate_html()
    score = reporter.calculate_score()

    score_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
    console.print(Panel(f"[bold {score_color}]Puntuación de Seguridad Obtenida: {score} / 100[/bold {score_color}]\n\n"
                        f"📊 Visualizador Dashboard SPA HTML: [bold cyan]{html_report}[/bold cyan]\n"
                        f"📄 Reporte Técnico Markdown: [bold]{md_report}[/bold]\n"
                        f"📦 Sitio Extraído (Mirror): [bold]{crawl_results['mirror_path']}[/bold]\n"
                        f"📋 Dataset JSON Completo: [bold]{raw_json_file}[/bold]",
                        title="[bold green]Auditoría Web 2.0 Finalizada con Éxito[/bold green]",
                        border_style="green"))

if __name__ == "__main__":
    main()
