"""O aviso de 'desisti' (dead-letter) marca o scan como falho, sem derrubar o loop."""

from __future__ import annotations

from scanner.common.models import StageMessage
from scanner.common.queue import _give_up
from tests.conftest import make_finding  # noqa: F401  (garante o pacote de testes)


def _raw(scan_id: str) -> bytes:
    msg = StageMessage(
        message_id=f"{scan_id}:web.requested",
        scan_id=scan_id,
        target_id="t-1",
        stage="web.requested",
        scope={
            "scope_id": "s",
            "verified": True,
            "locked": True,
            "base_urls": ["http://juice-shop:3000/"],
            "allowed_hosts": ["juice-shop"],
        },
        payload={},
    )
    return msg.model_dump_json().encode()


def test_give_up_calls_back_with_parsed_message() -> None:
    seen = []
    _give_up(lambda m: seen.append(m.scan_id), _raw("scan-xyz"), "max_deliveries")
    assert seen == ["scan-xyz"]


def test_give_up_without_callback_is_noop() -> None:
    _give_up(None, _raw("scan-1"), "x")  # não levanta


def test_give_up_swallows_bad_payload() -> None:
    called = []
    _give_up(lambda m: called.append(1), b"{nao-e-json", "x")  # não levanta
    assert called == []  # não chamou com lixo


def test_give_up_swallows_callback_error() -> None:
    def boom(m: StageMessage) -> None:
        raise RuntimeError("falha ao gravar")

    _give_up(boom, _raw("scan-1"), "x")  # erro do callback não propaga
