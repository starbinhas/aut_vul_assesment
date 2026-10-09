"""CRLF / injeção de cabeçalho HTTP: um parâmetro consegue inserir cabeçalhos na resposta.

Prova não destrutiva: injeta uma quebra de linha (CRLF) seguida de um cabeçalho sentinela único e
confirma só se esse cabeçalho VOLTA na resposta — ou seja, o servidor deixou o parâmetro escrever no
cabeçalho. Nada é alterado no alvo; é só um GET cujo valor contém `\\r\\n`.
"""

from __future__ import annotations

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

NAME = "crlf_injection"
HEADER = "X-Pitchy-CRLF"


@register(NAME, zap_rules=("40003",), cwes=(93, 113))
def validate(f: Finding, client: ProbeClient, sentinel: str | None = None) -> Validation:
    url, param = f.location.url, f.location.parameter
    if f.location.method != "GET" or not is_query_param(url, param):
        return result(
            NAME, Outcome.UNCONFIRMED, "prova automática só para parâmetros de query em GET"
        )
    assert param is not None
    sentinel = sentinel or f"pitchycrlf{secrets.token_hex(4)}"
    # O valor carrega um CRLF + um cabeçalho sentinela; with_param urlencoda (%0D%0A).
    probe = with_param(url, param, f"1\r\n{HEADER}: {sentinel}")
    resp = client.request("GET", probe)
    if resp.headers.get(HEADER.lower()) == sentinel:
        proof = proof_from(
            "GET", probe, resp, sentinel, f"cabeçalho injetado refletido: {HEADER}: {sentinel}"
        )
        return result(
            NAME,
            Outcome.CONFIRMED,
            f"o parâmetro '{param}' permite injetar cabeçalhos HTTP na resposta (CRLF)",
            proof,
        )
    return result(NAME, Outcome.UNCONFIRMED, "o cabeçalho injetado não voltou na resposta")
