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


# --- orquestração (run_access_probe) -----------------------------------------------------

from scanner.validation.access_probe import AccessProbe, Identity, run_access_probe  # noqa: E402
from tests.conftest import FakeClient  # noqa: E402

OWNER = Identity("Authorization", "Bearer owner-token")
OTHER = Identity("Authorization", "Bearer other-token")
PROBE = AccessProbe(resource_url=URL, owner_marker=MARKER)


def test_probe_injects_each_identity_header() -> None:
    seen = []

    def responder(url):
        return resp(f'{{"d":"{MARKER}"}}', status=200)

    class RecordingClient(FakeClient):
        def request(self, method, url, headers=None):
            seen.append(headers)
            return super().request(method, url, headers)

    run_access_probe(PROBE, OWNER, OTHER, RecordingClient(responder))
    assert seen == [OWNER.as_header(), OTHER.as_header()]


def test_probe_confirms_leak_end_to_end() -> None:
    client = FakeClient(lambda url: resp(f'{{"d":"{MARKER}"}}', status=200))
    v = run_access_probe(PROBE, OWNER, OTHER, client)
    assert v.outcome is Outcome.CONFIRMED


def test_token_is_not_in_identity_repr() -> None:
    assert "owner-token" not in repr(OWNER)
