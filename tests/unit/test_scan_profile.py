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


# --- limites por tipo de alvo (laboratório x cliente) ------------------------------------

from scanner.common.config import Settings  # noqa: E402
from scanner.web_scan.service import resolve_limits  # noqa: E402


def _settings() -> Settings:
    return Settings(
        web_session_secret="x" * 40,
        scan_max_requests_per_second=10,
        scan_threads_per_host=2,
        scan_lab_max_requests_per_second=100,
        scan_lab_threads_per_host=10,
        lab_hosts=LAB_HOSTS,
    )


def test_lab_scope_gets_loose_limits() -> None:
    limits = resolve_limits(["juice-shop"], _settings())
    assert limits.max_requests_per_second == 100 and limits.threads_per_host == 10


def test_client_scope_keeps_conservative_limits() -> None:
    limits = resolve_limits(["loja.com.br"], _settings())
    assert limits.max_requests_per_second == 10 and limits.threads_per_host == 2


def test_mixed_scope_falls_back_to_conservative_limits() -> None:
    # Um host real misturado reprova: nunca acelerar contra produção.
    limits = resolve_limits(["juice-shop", "loja.com.br"], _settings())
    assert limits.max_requests_per_second == 10


# --- parsing de credencial ---------------------------------------------------------------

from scanner.web_scan.service import _credential  # noqa: E402
from scanner.web_scan.zap import HeaderCredential, LoginCredential  # noqa: E402


def test_credential_header() -> None:
    c = _credential({"credential": {"type": "header", "name": "Cookie", "value": "x"}})
    assert isinstance(c, HeaderCredential) and c.name == "Cookie"


def test_credential_login() -> None:
    c = _credential(
        {
            "credential": {
                "type": "login",
                "login_url": "http://juice-shop:3000/rest/user/login",
                "email": "a@b.c",
                "password": "p",
            }
        }
    )
    assert isinstance(c, LoginCredential) and c.email == "a@b.c"


def test_credential_none_and_unknown() -> None:
    assert _credential({}) is None
    with pytest.raises(ValueError):
        _credential({"credential": {"type": "mágico"}})
