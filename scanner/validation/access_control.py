"""Controle de acesso entre usuários (quebra de acesso / IDOR) — etapa 5.

Nenhum scanner de caixa-preta acha isso sozinho: é preciso comparar o que um usuário vê com o que
outro consegue ver. Esta é a decisão determinística do teste, separada da orquestração (que precisa
de dois usuários autenticados e roda contra o laboratório).

Prova não destrutiva (regra 3/5 do CLAUDE.md): só requisições de leitura (GET). Comparamos três
observações de um recurso privado do "dono":
  - o dono acessa o próprio recurso e vê um marcador que só ele deveria ver (estabelece a base);
  - um segundo usuário acessa o MESMO recurso com a própria sessão.
Se o segundo usuário recebe os dados privados do dono, o controle de acesso está quebrado. Se o
recurso nega o acesso, o controle funciona — e isso só vira `false_positive` por esta checagem
determinística, nunca por decisão de um LLM.
"""

from __future__ import annotations

from scanner.common.models import Outcome, Validation
from scanner.validation.http import ProbeResponse
from scanner.validation.validators.base import proof_from, result

NAME = "broken_access_control"

# Respostas que indicam que o acesso foi corretamente negado ao outro usuário.
DENIED_STATUSES = frozenset({401, 403})


def classify_access(
    url: str,
    owner_resp: ProbeResponse,
    other_resp: ProbeResponse,
    owner_marker: str,
    name: str = NAME,
) -> Validation:
    """Decide se um recurso privado do dono vazou para outro usuário.

    `owner_marker` é um trecho que só aparece quando o dono vê o próprio dado (ex.: o e-mail, o id
    ou um valor único do dono). Precisa estar na resposta do dono para a prova fazer sentido.
    """
    if owner_resp.status != 200 or owner_marker not in owner_resp.text:
        return result(
            name,
            Outcome.UNCONFIRMED,
            "não foi possível estabelecer que o recurso é privado do dono (base inconclusiva)",
        )

    if other_resp.status in DENIED_STATUSES:
        proof = proof_from(
            "GET",
            url,
            other_resp,
            None,
            f"acesso negado ao outro usuário (status {other_resp.status})",
        )
        return result(
            name,
            Outcome.FALSE_POSITIVE,
            "o recurso nega acesso a outro usuário: o controle de acesso funciona",
            proof,
        )

    if other_resp.status == 200 and owner_marker in other_resp.text:
        proof = proof_from(
            "GET", url, other_resp, owner_marker, "outro usuário recebeu os dados privados do dono"
        )
        return result(
            name,
            Outcome.CONFIRMED,
            "outro usuário acessou os dados privados do dono: controle de acesso quebrado",
            proof,
        )

    # 200 sem o marcador, redirect para login, etc.: não prova vazamento nem prova negação.
    return result(
        name,
        Outcome.UNCONFIRMED,
        f"resposta ambígua para o outro usuário (status {other_resp.status}); requer revisão",
    )
