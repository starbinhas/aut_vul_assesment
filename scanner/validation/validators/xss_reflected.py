"""XSS refletido: marcador único refletido sem escape numa resposta HTML."""

from __future__ import annotations

import html
import secrets

from scanner.common.models import Finding, Outcome, Validation
from scanner.validation.http import ProbeClient
from scanner.validation.validators.base import (
    is_query_param,
    proof_from,
    register,
    result,
    with_param,
)

NAME = "xss_reflected"


def make_marker() -> str:
    # Inofensivo: uma tag inexistente, sem script. Prova que '<' e '"' chegam crus ao HTML.
    return f'zx{secrets.token_hex(4)}"<zxtag>'


@register(NAME, zap_rules=("40012",), cwes=(79,))
def validate(f: Finding, client: ProbeClient, marker: str | None = None) -> Validation:
    url, param = f.location.url, f.location.parameter
    if f.location.method != "GET" or not is_query_param(url, param):
        return result(
            NAME, Outcome.UNCONFIRMED, "prova automática só para parâmetros de query em GET"
        )
    assert param is not None
    marker = marker or make_marker()
    probe_url = with_param(url, param, marker)
    resp = client.request("GET", probe_url)

    ctype = resp.headers.get("content-type", "").lower()
    if marker in resp.text and "html" in ctype:
        proof = proof_from("GET", probe_url, resp, marker, "marcador refletido sem escape")
        return result(
            NAME, Outcome.CONFIRMED, f"o parâmetro '{param}' é refletido sem escape", proof
        )
    if html.escape(marker) in resp.text or marker in resp.text:
        proof = proof_from("GET", probe_url, resp, html.escape(marker), "marcador refletido")
        return result(
            NAME,
            Outcome.UNCONFIRMED,
            "marcador refletido com escape ou fora de HTML; pode haver outro contexto explorável",
            proof,
        )
    return result(NAME, Outcome.UNCONFIRMED, "marcador não foi refletido na resposta")
