"""Importa rotas de uma especificação OpenAPI/Swagger (paridade com DAST do mercado).

Sem isto, a API só é testada se o spider tropeçar nela. Com o spec, semeamos cada caminho (com os
parâmetros preenchidos com um valor de exemplo) na árvore do ZAP, que então rastreia e testa esses
endpoints. Suporta OpenAPI v3 (`servers`) e Swagger v2 (`basePath`). Parser puro, sem rede.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlencode, urljoin

_PATH_PARAM = re.compile(r"\{[^}]+\}")

# Locais convencionais do spec (tentados em ordem). Cobre a maioria dos frameworks.
COMMON_SPEC_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
)


def _server_base(spec: dict[str, Any], base_url: str) -> str:
    """Base das rotas: `servers[0].url` (v3) ou `basePath` (v2), resolvido contra o alvo."""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url")
        if isinstance(url, str) and url:
            return urljoin(base_url, url)
    base_path = spec.get("basePath")
    if isinstance(base_path, str) and base_path:
        return urljoin(base_url, base_path)
    return base_url


def _query_sample(path_item: dict[str, Any]) -> str:
    """Monta uma query de exemplo com os parâmetros `in: query` (no item e em cada método)."""
    names: list[str] = []
    sources = [path_item, *(v for v in path_item.values() if isinstance(v, dict))]
    for src in sources:
        for param in src.get("parameters", []) or []:
            if isinstance(param, dict) and param.get("in") == "query":
                name = param.get("name")
                if isinstance(name, str) and name and name not in names:
                    names.append(name)
    return urlencode({name: "1" for name in names})


def parse_openapi(spec: dict[str, Any], base_url: str, max_routes: int = 500) -> list[str]:
    """Extrai URLs testáveis do spec, dentro do alvo, com parâmetros preenchidos. Puro."""
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _server_base(spec, base_url).rstrip("/") + "/"
    seen: set[str] = set()
    out: list[str] = []
    for raw_path, item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(item, dict):
            continue
        concrete = _PATH_PARAM.sub("1", raw_path).lstrip("/")  # /users/{id} -> users/1
        url = urljoin(base, concrete)
        query = _query_sample(item)
        if query:
            url = f"{url}?{query}"
        if url not in seen:
            seen.add(url)
            out.append(url)
        if len(out) >= max_routes:
            break
    return out
