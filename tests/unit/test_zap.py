"""Perfis de scan e a configuração da política no ZAP.

O cliente `zaproxy` devolve erros como texto: o scanner precisa recusar, não seguir em frente.
"""

from types import SimpleNamespace

import pytest

from scanner.web_scan import policy
from scanner.web_scan.zap import ScanLimits, ZapError, ZapScanner


class FakeAscan:
    def __init__(self, available: set[str]) -> None:
        self.available = available
        self.enabled: set[str] = set()
        self.strengths: dict[str, str] = {}
        self.scan_policy_names: list[str] = []

    def add_scan_policy(self, *a, **kw):
        return "OK"

    def disable_all_scanners(self, **kw):
        self.enabled.clear()
        return "OK"

    def enable_all_scanners(self, **kw):
        self.enabled |= self.available
        return "OK"

    def enable_scanners(self, ids, scanpolicyname):
        wanted = set(ids.split(","))
        if not wanted <= self.available:
            return "does_not_exist"  # comportamento real do ZAP
        self.enabled |= wanted
        return "OK"

    def set_scanner_attack_strength(self, scanner_id, strength, scanpolicyname):
        self.strengths[scanner_id] = strength
        return "OK"

    def scanners(self, name):
        return [{"id": i, "enabled": str(i in self.enabled).lower()} for i in self.available]


def scanner_with(available: set[str]) -> tuple[ZapScanner, FakeAscan]:
    z = ZapScanner.__new__(ZapScanner)
    z.limits = ScanLimits(10, 1, 5)
    ascan = FakeAscan(available)
    z.zap = SimpleNamespace(ascan=ascan)
    return z, ascan


SAFE = policy.PROFILES["safe"]
AGGRESSIVE = policy.PROFILES["aggressive"]


def test_safe_profile_skips_rules_missing_in_this_zap() -> None:
    all_ids = {str(i) for i in policy.SAFE_ACTIVE_RULES}
    z, ascan = scanner_with((all_ids - {"10095"}) | {"30001"})  # 30001 = destrutiva, existe no ZAP
    z.configure_policy(SAFE)
    assert ascan.enabled == all_ids - {"10095"}
    assert "30001" not in ascan.enabled  # destrutiva não entra no perfil seguro


def test_safe_profile_with_no_rules_refuses_scan() -> None:
    z, _ = scanner_with({"30001"})
    with pytest.raises(ZapError):
        z.configure_policy(SAFE)


def test_aggressive_profile_enables_every_rule() -> None:
    z, ascan = scanner_with(
        {str(i) for i in policy.SAFE_ACTIVE_RULES} | {"30001", "40043", "40046"}
    )
    z.configure_policy(AGGRESSIVE)
    # Inclui as destrutivas (30001 overflow, 40043 Log4Shell, 40046 SSRF).
    assert {"30001", "40043", "40046"} <= ascan.enabled
    assert ascan.strengths["30001"] == "HIGH"


# --- login (autenticação pelo ZAP) -------------------------------------------------------

from scanner.web_scan.zap import (  # noqa: E402
    HeaderCredential,
    LoginCredential,
    build_login_request,
    extract_token,
    login_response_body,
)

LOGIN = LoginCredential(
    login_url="http://juice-shop:3000/rest/user/login",
    email="scanner@lab.local",
    password="s3nha-secreta",
)


def test_extract_token_follows_path() -> None:
    body = {"authentication": {"token": "abc.def.ghi", "umail": "x"}}
    assert extract_token(body, ("authentication", "token")) == "abc.def.ghi"


def test_extract_token_missing_raises() -> None:
    with pytest.raises(ZapError):
        extract_token({"authentication": {}}, ("authentication", "token"))


def test_extract_token_empty_raises() -> None:
    with pytest.raises(ZapError):
        extract_token({"authentication": {"token": ""}}, ("authentication", "token"))


def test_build_login_request_is_well_formed() -> None:
    raw = build_login_request(LOGIN)
    assert raw.startswith("POST http://juice-shop:3000/rest/user/login HTTP/1.1")
    assert "Host: juice-shop:3000" in raw
    assert "Content-Type: application/json" in raw
    assert '"email": "scanner@lab.local"' in raw


def test_password_never_in_repr() -> None:
    # Dado sensível: a senha não pode vazar em log nem em repr do objeto.
    assert "s3nha-secreta" not in repr(LOGIN)


def test_login_response_body_takes_last_message() -> None:
    sent = [{"responseBody": "{}"}, {"responseBody": '{"authentication":{"token":"t"}}'}]
    assert '"token":"t"' in login_response_body(sent)


def test_login_response_body_raises_on_zap_error_string() -> None:
    with pytest.raises(ZapError, match="mode_violation"):
        login_response_body("mode_violation")


def test_zap_login_returns_header_credential() -> None:
    captured = {}

    def send_request(raw, followredirects):
        captured["raw"] = raw
        return [{"responseBody": '{"authentication":{"token":"JWT123"}}'}]

    z = ZapScanner.__new__(ZapScanner)
    z.zap = SimpleNamespace(core=SimpleNamespace(send_request=send_request))
    cred = z.login(LOGIN)
    assert isinstance(cred, HeaderCredential)
    assert cred.name == "Authorization" and cred.value == "Bearer JWT123"
    assert "scanner@lab.local" in captured["raw"]


# --- credencial: regra do Replacer é idempotente -----------------------------------------


class FakeReplacer:
    def __init__(self) -> None:
        self.rules: set[str] = set()

    def remove_rule(self, description):
        self.rules.discard(description)
        return "OK"

    def add_rule(self, description, **kw):
        if description in self.rules:
            return "already_exists"  # comportamento real do ZAP
        self.rules.add(description)
        return "OK"


def test_set_credential_is_idempotent_across_scans() -> None:
    z = ZapScanner.__new__(ZapScanner)
    z.zap = SimpleNamespace(replacer=FakeReplacer())
    cred = HeaderCredential(name="Authorization", value="Bearer t")
    z.set_credential(cred)
    z.set_credential(cred)  # segundo scan na mesma instância do ZAP: não pode falhar
    assert z.zap.replacer.rules == {ZapScanner.CREDENTIAL_RULE}
