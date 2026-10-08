"""Descoberta de rotas por sitemap/robots (etapa 2) — parsers puros."""

from __future__ import annotations

from scanner.recon.routes import parse_robots, parse_sitemap

SITEMAP = """<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://loja.com/produtos</loc></url>
  <url><loc>https://loja.com/carrinho</loc></url>
</urlset>"""


def test_parse_sitemap_with_namespace() -> None:
    urls = parse_sitemap(SITEMAP)
    assert urls == ["https://loja.com/produtos", "https://loja.com/carrinho"]


def test_parse_sitemap_invalid_is_empty() -> None:
    assert parse_sitemap("isto não é xml <<<") == []


def test_parse_robots_extracts_sitemaps_and_paths() -> None:
    robots = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Allow: /publico\n"
        "Disallow: /\n"  # raiz: ignorado
        "Disallow: /tmp/*\n"  # curinga: ignorado
        "Sitemap: https://loja.com/sitemap.xml\n"
    )
    sitemaps, paths = parse_robots(robots, "https://loja.com/")
    assert sitemaps == ["https://loja.com/sitemap.xml"]
    assert "https://loja.com/admin" in paths and "https://loja.com/publico" in paths
    assert all("*" not in p for p in paths) and "https://loja.com/" not in paths
