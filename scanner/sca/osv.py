"""Consulta o catálogo público de falhas conhecidas (OSV, https://osv.dev) para as dependências.

Só leitura (consulta): não toca no alvo. A parte de rede fica isolada; a leitura das respostas é
pura e testável.
"""

from __future__ import annotations

from typing import Any

import httpx

from scanner.sca.models import Component, Vuln

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/"


def parse_batch_response(
    components: list[Component], data: dict[str, Any]
) -> dict[Component, list[str]]:
    """Mapeia a resposta do querybatch (ids por consulta, na ordem) para cada componente."""
    results = data.get("results", [])
    out: dict[Component, list[str]] = {}
    for comp, res in zip(components, results, strict=False):
        ids = [v["id"] for v in (res or {}).get("vulns", []) if "id" in v]
        if ids:
            out[comp] = ids
    return out


def parse_vuln(data: dict[str, Any]) -> Vuln:
    """Extrai id, resumo e severidade (melhor esforço) de um registro do OSV."""
    sev = "UNKNOWN"
    db = data.get("database_specific") or {}
    if isinstance(db.get("severity"), str):
        sev = db["severity"].upper()
    elif data.get("severity"):
        sev = "CVSS"  # vem como vetor CVSS; marcamos que há pontuação
    return Vuln(id=data.get("id", "?"), summary=(data.get("summary") or "").strip(), severity=sev)


def query_vulnerable(
    components: list[Component], client: httpx.Client
) -> dict[Component, list[str]]:
    """Uma chamada em lote: devolve, por componente, os ids das falhas conhecidas."""
    queries: list[dict[str, Any]] = [
        {"package": {"ecosystem": c.ecosystem, "name": c.name}, "version": c.version}
        for c in components
    ]
    resp = client.post(BATCH_URL, json={"queries": queries}, timeout=30)
    resp.raise_for_status()
    return parse_batch_response(components, resp.json())


def fetch_vuln(vuln_id: str, client: httpx.Client) -> Vuln:
    resp = client.get(f"{VULN_URL}{vuln_id}", timeout=30)
    resp.raise_for_status()
    return parse_vuln(resp.json())
