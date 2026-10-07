"""Falhas de autenticação (A07) — detecção não destrutiva.

Sinal seguro e determinístico: o login que não bloqueia após tentativas repetidas permite força
bruta de senha. Testamos só com um número PEQUENO de tentativas, contra uma conta de teste nossa —
nunca brutalizamos o alvo nem mexemos em conta de cliente.
"""

from __future__ import annotations

from collections.abc import Sequence

from scanner.common.models import Outcome, Validation
from scanner.validation.validators.base import result

NAME = "weak_authentication"

# Respostas que indicam que o login travou/limitou (proteção contra força bruta funcionando).
PROTECTED_STATUSES = frozenset({423, 429})  # Locked / Too Many Requests
MIN_ATTEMPTS = 5  # mínimo de tentativas para concluir que não há bloqueio


def classify_login_protection(
    statuses: Sequence[int], fail_status: int = 401, name: str = NAME
) -> Validation:
    """Decide se o login protege contra força bruta, a partir dos status de tentativas falhas."""
    if any(s in PROTECTED_STATUSES for s in statuses):
        return result(
            name, Outcome.FALSE_POSITIVE, "o login bloqueia após tentativas repetidas: protegido"
        )
    if len(statuses) >= MIN_ATTEMPTS and all(s == fail_status for s in statuses):
        return result(
            name,
            Outcome.CONFIRMED,
            f"o login não bloqueia após {len(statuses)} tentativas erradas: permite força bruta",
        )
    return result(name, Outcome.UNCONFIRMED, "comportamento de bloqueio do login indefinido")
