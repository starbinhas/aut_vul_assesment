"""A decisão determinística do teste de controle de acesso entre usuários."""

from __future__ import annotations

from scanner.common.models import Outcome
from scanner.validation.access_control import classify_access
from tests.conftest import resp

URL = "http://juice-shop:3000/rest/basket/1"
MARKER = "pedido-secreto-do-dono-42"


def test_broken_when_other_user_gets_owner_data() -> None:
    owner = resp(f'{{"dados":"{MARKER}"}}', status=200)
    other = resp(f'{{"dados":"{MARKER}"}}', status=200)  # mesmo conteúdo privado do dono
    v = classify_access(URL, owner, other, MARKER)
    assert v.outcome is Outcome.CONFIRMED and v.proof is not None


def test_ok_when_other_user_is_denied() -> None:
    owner = resp(f'{{"dados":"{MARKER}"}}', status=200)
    for status in (401, 403):
        v = classify_access(URL, owner, resp("", status=status), MARKER)
        # false_positive só por checagem determinística — e aqui é exatamente isso.
        assert v.outcome is Outcome.FALSE_POSITIVE


def test_unconfirmed_when_other_gets_200_without_owner_data() -> None:
    owner = resp(f'{{"dados":"{MARKER}"}}', status=200)
    other = resp('{"dados":"conteudo-generico"}', status=200)
    v = classify_access(URL, owner, other, MARKER)
    assert v.outcome is Outcome.UNCONFIRMED


def test_unconfirmed_when_owner_baseline_fails() -> None:
    # Se nem o dono vê o próprio dado, não dá para provar nada.
    owner = resp("", status=404)
    other = resp(f'{{"dados":"{MARKER}"}}', status=200)
    v = classify_access(URL, owner, other, MARKER)
    assert v.outcome is Outcome.UNCONFIRMED


def test_redirect_to_login_is_unconfirmed_not_confirmed() -> None:
    owner = resp(f'{{"dados":"{MARKER}"}}', status=200)
    other = resp("", status=302, headers={"location": "/login"})
    v = classify_access(URL, owner, other, MARKER)
    assert v.outcome is Outcome.UNCONFIRMED
