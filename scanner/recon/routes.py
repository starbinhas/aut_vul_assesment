"""Descoberta determinística de rotas (etapa 2): lê o que o próprio site publica.

Em vez de depender só do rastreio ao vivo (que varia), lemos `robots.txt` e `sitemap.xml` — arquivos
que muitos sites publicam listando as próprias páginas. É um GET simples; se não existir, devolve
vazio e o pipeline segue no crawl normal. As rotas achadas são semeadas na árvore do ZAP, deixando
a cobertura estável e repetível.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

# Extrai as URLs das tags <loc> por regex, de propósito: o sitemap vem de um alvo potencialmente
# hostil, e um parser de XML completo abre espaço para ataques (XXE, "billion laughs"). Só queremos
# os <loc>, então um regex simples é mais seguro e robusto a XML malformado.
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def parse_sitemap(xml_text: str) -> list[str]:
    """URLs de um sitemap.xml (conteúdo das tags <loc>). Seguro contra XML malicioso."""
    return [m.group(1).strip() for m in _LOC.finditer(xml_text)]


def parse_robots(text: str, base_url: str) -> tuple[list[str], list[str]]:
    """De um robots.txt: (sitemaps apontados, caminhos Allow/Disallow como URLs absolutas)."""
    sitemaps: list[str] = []
    paths: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "sitemap" and value:
            sitemaps.append(value)
        elif key in ("allow", "disallow") and value and value != "/" and "*" not in value:
            paths.append(urljoin(base_url, value))
    return sitemaps, paths
