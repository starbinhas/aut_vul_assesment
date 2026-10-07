"""A trava do perfil destrutivo: só roda contra hosts de laboratório."""

import pytest

from scanner.common.models import Scope, StageMessage
from scanner.web_scan.service import ProfileNotAllowedError, resolve_profile

LAB_HOSTS = ["juice-shop", "dvwa", "localhost"]


def msg_for(host: str, profile: str | None) -> StageMessage:
    scope = Scope(
        scope_id="s",
        verified=True,
        locked=True,
        base_urls=[f"http://{host}/"],
        allowed_hosts=[host],
    )
    return StageMessage(
        message_id="m",
        scan_id="scan-1",
        target_id="t",
        stage="web.requested",
        scope=scope,
        payload={"profile": profile} if profile else {},
    )


def test_default_is_safe() -> None:
    assert resolve_profile(msg_for("loja.com.br", None), LAB_HOSTS).name == "safe"


def test_unknown_profile_falls_back_to_safe() -> None:
    assert resolve_profile(msg_for("loja.com.br", "inexistente"), LAB_HOSTS).name == "safe"


def test_balanced_is_allowed_on_real_site() -> None:
    # Completo seguro não altera dados: pode rodar em cliente.
    assert resolve_profile(msg_for("loja.com.br", "balanced"), LAB_HOSTS).name == "balanced"


def test_aggressive_allowed_on_lab() -> None:
    assert resolve_profile(msg_for("juice-shop", "aggressive"), LAB_HOSTS).name == "aggressive"


def test_aggressive_refused_on_real_site() -> None:
    with pytest.raises(ProfileNotAllowedError):
        resolve_profile(msg_for("loja.com.br", "aggressive"), LAB_HOSTS)


def test_aggressive_refused_when_any_host_is_not_lab() -> None:
    scope = Scope(
        scope_id="s",
        verified=True,
        locked=True,
        base_urls=["http://juice-shop/"],
        allowed_hosts=["juice-shop", "loja.com.br"],  # um host real misturado
    )
    msg = StageMessage(
        message_id="m",
        scan_id="scan-1",
        target_id="t",
        stage="web.requested",
        scope=scope,
        payload={"profile": "aggressive"},
    )
    with pytest.raises(ProfileNotAllowedError):
        resolve_profile(msg, LAB_HOSTS)
