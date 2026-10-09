"""SSTI (Server-Side Template Injection): o parâmetro é interpretado como template no servidor.

Prova não destrutiva: injeta uma conta aritmética única em várias sintaxes de template
(`{{a*b}}`, `${a*b}`...) e confirma só se o RESULTADO (a*b) aparece na resposta e a expressão crua
NÃO — ou seja, o servidor avaliou o template em vez de só refletir o texto. Números aleatórios
tornam a coincidência improvável; nada é gravado nem alterado.
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

NAME = "ssti"


def _templates(a: int, b: int) -> tuple[str, ...]:
    expr = f"{a}*{b}"
    return (f"{{{{{expr}}}}}", f"${{{expr}}}", f"#{{{expr}}}", f"<%= {expr} %>")


@register(NAME, zap_rules=("90035", "90036"), cwes=(1336, 94))
def validate(f: Finding, client: ProbeClient, numbers: tuple[int, int] | None = None) -> Validation:
    url, param = f.location.url, f.location.parameter
    if f.location.method != "GET" or not is_query_param(url, param):
        return result(
            NAME, Outcome.UNCONFIRMED, "prova automática só para parâmetros de query em GET"
        )
    assert param is not None
    a, b = numbers or (secrets.randbelow(900) + 100, secrets.randbelow(900) + 100)
    product = str(a * b)
    for payload in _templates(a, b):
        probe = with_param(url, param, payload)
        resp = client.request("GET", probe)
        # Resultado presente E expressão crua ausente = o servidor avaliou (não só refletiu).
        if product in resp.text and payload not in resp.text:
            proof = proof_from(
                "GET", probe, resp, product, f"template avaliado: {payload} -> {product}"
            )
            return result(
                NAME,
                Outcome.CONFIRMED,
                f"o parâmetro '{param}' é avaliado como template no servidor (SSTI)",
                proof,
            )
    return result(NAME, Outcome.UNCONFIRMED, "o parâmetro não foi avaliado como template")
