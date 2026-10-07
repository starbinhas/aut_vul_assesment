"""Detecção de falha de integridade (A08): token sem assinatura aceito."""

from __future__ import annotations

from scanner.common.models import Outcome
from scanner.validation.jwt_integrity import classify_jwt_integrity, decode_payload, unsigned_token


def test_unsigned_token_roundtrips_payload() -> None:
    tok = unsigned_token({"id": 42, "email": "a@b.c"})
    assert tok.endswith(".")  # sem assinatura
    assert decode_payload(tok) == {"id": 42, "email": "a@b.c"}


def test_confirmed_when_unsigned_accepted_but_tampered_rejected() -> None:
    v = classify_jwt_integrity(unsigned_status=200, control_status=401)
    assert v.outcome is Outcome.CONFIRMED


def test_false_positive_when_unsigned_rejected() -> None:
    v = classify_jwt_integrity(unsigned_status=401, control_status=401)
    assert v.outcome is Outcome.FALSE_POSITIVE


def test_unconfirmed_when_control_does_not_require_auth() -> None:
    # Se o recurso de controle responde 200 mesmo adulterado, o teste não prova nada.
    v = classify_jwt_integrity(unsigned_status=200, control_status=200)
    assert v.outcome is Outcome.UNCONFIRMED
