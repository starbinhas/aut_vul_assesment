"""Orquestra o SCA: lê o manifesto, consulta o OSV e monta o resultado por componente."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from scanner.sca.manifest import load_manifest, load_manifest_content
from scanner.sca.models import Component, Vuln
from scanner.sca.osv import fetch_vuln, query_vulnerable


@dataclass
class ComponentResult:
    component: Component
    vulns: list[Vuln]


def scan_components(
    components: list[Component], client: httpx.Client | None = None
) -> list[ComponentResult]:
    """Consulta o OSV e devolve só os componentes com falha conhecida (ordenados por nome)."""
    own = client or httpx.Client()
    try:
        hits = query_vulnerable(components, own)
        results = [
            ComponentResult(comp, [fetch_vuln(vid, own) for vid in ids])
            for comp, ids in hits.items()
        ]
    finally:
        if client is None:
            own.close()
    results.sort(key=lambda r: r.component.name)
    return results


def scan_manifest(path: str | Path, client: httpx.Client | None = None) -> list[ComponentResult]:
    """Lê o manifesto de um arquivo e varre os componentes."""
    return scan_components(load_manifest(path), client)


def scan_manifest_content(
    content: str, filename: str, client: httpx.Client | None = None
) -> list[ComponentResult]:
    """Varre a partir do CONTEÚDO do manifesto (upload/payload), não de um arquivo em disco."""
    return scan_components(load_manifest_content(content, filename), client)
