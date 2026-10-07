"""Open redirect: parâmetro que manda o navegador para um host externo controlado pelo atacante.

Prova não destrutiva: injeta um host sentinela (TLD reservado `.example`, que não existe) no
parâmetro e lê só o cabeçalho `Location` da resposta. Nada é seguido — o `ProbeClient` não segue
redirect —, nenhum dado é lido ou alterado. Confirma só se o redirect aponta para fora do host
original.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from scanner.common.models import Finding, Outcome, Validation
from scanner.validation.http import ProbeClient
from scanner.validation.validators.base import (
    is_query_param,
    proof_from,
    register,
    result,
    with_param,
)

NAME = "open_redirect"


def make_sentinel() -> str:
    # Host inexistente (TLD reservado): se aparecer no Location, veio do nosso parâmetro.
    return f"zxredir{secrets.token_hex(4)}.example"


def _location_host(location: str, base_url: str) -> str | None:
    """Host para onde o Location aponta, resolvido contra a URL da requisição."""
    if not location:
        return None
    parts = urlsplit(location)
    if parts.netloc:
        return parts.hostname
    # Location relativo (mesmo host): urljoin manteria o host original.
    if location.startswith("//"):  # protocolo-relativo: //host/...
        return urlsplit("http:" + location).hostname
    return urlsplit(base_url).hostname


@register(NAME, zap_rules=("20019",), cwes=(601,))
def validate(f: Finding, client: ProbeClient, sentinel: str | None = None) -> Validation:
    url, param = f.location.url, f.location.parameter
    if f.location.method != "GET" or not is_query_param(url, param):
        return result(
            NAME, Outcome.UNCONFIRMED, "prova automática só para parâmetros de query em GET"
        )
    assert param is not None
    sentinel = sentinel or make_sentinel()
    probe_url = with_param(url, param, f"https://{sentinel}/")
    resp = client.request("GET", probe_url)

    origin_host = urlsplit(url).hostname
    if resp.status not in range(300, 400):
        return result(NAME, Outcome.UNCONFIRMED, f"sem redirect (status {resp.status})")

    location = resp.headers.get("location", "")
    dest_host = _location_host(location, probe_url)
    proof = proof_from("GET", probe_url, resp, sentinel, f"Location: {location[:200]}")
    if dest_host == sentinel:
        return result(
            NAME,
            Outcome.CONFIRMED,
            f"o parâmetro '{param}' redireciona para um host externo arbitrário",
            proof,
        )
    if dest_host and dest_host != origin_host and sentinel in location:
        return result(
            NAME,
            Outcome.LIKELY,
            f"o parâmetro '{param}' aparece no destino de um redirect para fora do host",
            proof,
        )
    return result(NAME, Outcome.UNCONFIRMED, "o redirect não foi para o host injetado")
