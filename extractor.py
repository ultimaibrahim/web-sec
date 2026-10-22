#!/usr/bin/env python3
"""extractor.py - Scraping y extracción inteligente de metadatos HTML (BS4 + LXML)."""

from bs4 import BeautifulSoup
from typing import Dict, List, Any
import re

def extract_page_intelligence(html_content: str, base_url: str = "") -> Dict[str, Any]:
    """Extrae enlaces, formularios, rutas de scripts y comentarios HTML que puedan filtrar datos."""
    soup = BeautifulSoup(html_content, "lxml")

    # 1. Título y meta etiquetas
    title = soup.title.string.strip() if soup.title and soup.title.string else "Sin título"
    meta_desc = ""
    meta_tag = soup.find("meta", attrs={"name": "description"})
    if meta_tag and meta_tag.get("content"):
        meta_desc = meta_tag["content"].strip()

    # 2. Enlaces internos y externos
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href and not href.startswith("#") and not href.startswith("javascript:"):
            links.add(href)

    # 3. Scripts JS cargados
    scripts = set()
    for s in soup.find_all("script", src=True):
        scripts.add(s["src"].strip())

    # 4. Formularios y campos de entrada sensibles
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        inputs = [inp.get("name") for inp in form.find_all(["input", "textarea"]) if inp.get("name")]
        forms.append({"action": action, "method": method, "inputs": inputs})

    # 5. Comentarios HTML ocultos
    comments = []
    for comment in soup.find_all(string=lambda text: isinstance(text, str) and "<!--" in text):
        clean_c = comment.strip()
        if len(clean_c) > 5:
            comments.append(clean_c[:100])

    return {
        "title": title,
        "description": meta_desc,
        "links_count": len(links),
        "links_sample": list(links)[:10],
        "scripts_count": len(scripts),
        "forms_count": len(forms),
        "forms": forms,
        "comments_count": len(comments)
    }
