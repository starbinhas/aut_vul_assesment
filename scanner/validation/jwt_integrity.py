"""Falha de integridade (A08): o servidor aceita um token sem assinatura válida.

Um token (JWT) é assinado para que o servidor confie nele. Se o servidor aceita um token com
"alg: none" (sem assinatura), ele confia em dado que qualquer um pode forjar — falha de integridade.

A prova é determinística e não destrutiva: montamos um token sem assinatura com o payload do NOSSO
próprio usuário e só lemos um recurso nosso. Nada é alterado. Comparamos com um token de assinatura
adulterada (controle): se o endpoint rejeita o adulterado (exige assinatura) mas aceita o sem
assinatura, a falha está confirmada.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from scanner.common.models import Outcome, Validation
from scanner.validation.validators.base import result

NAME = "jwt_integrity"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unsigned_token(payload: dict[str, Any]) -> str:
    """Monta um JWT 'alg: none' (sem assinatura) com o payload dado."""
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header}.{body}."


def decode_payload(token: str) -> dict[str, Any]:
    """Lê o payload (parte do meio) de um JWT, sem verificar assinatura."""
    part = token.split(".")[1]
    pad = "=" * (-len(part) % 4)
    data: dict[str, Any] = json.loads(base64.urlsafe_b64decode(part + pad))
    return data


def classify_jwt_integrity(
    unsigned_status: int, control_status: int, name: str = NAME
) -> Validation:
    """Decide a partir do status com token sem assinatura e com token adulterado (controle)."""
    if control_status not in (401, 403):
        # O recurso de controle precisa exigir autenticação válida, senão o 200 não prova nada.
        return result(
            name, Outcome.UNCONFIRMED, "recurso de controle não exige autenticação válida"
        )
    if unsigned_status == 200:
        return result(
            name,
            Outcome.CONFIRMED,
            "o servidor aceita um token sem assinatura (alg:none): confia em dado forjável",
        )
    if unsigned_status in (401, 403):
        return result(
            name,
            Outcome.FALSE_POSITIVE,
            "o servidor rejeita token sem assinatura: verifica assinatura",
        )
    return result(
        name,
        Outcome.UNCONFIRMED,
        f"resposta ambígua ao token sem assinatura (status {unsigned_status})",
    )
