"""Orquestra o SCA: lê o manifesto, consulta o OSV e monta o resultado por componente."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from scanner.sca.manifest import load_manifest
from scanner.sca.models import Component, Vuln
from scanner.sca.osv import fetch_vuln, query_vulnerable


@dataclass
class ComponentResult:
    component: Component
    vulns: list[Vuln]


def scan_manifest(path: str | Path, client: httpx.Client | None = None) -> list[ComponentResult]:
    """Devolve só os componentes com falhas conhecidas, com detalhes (ordenados por nome)."""
    components = load_manifest(path)
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
