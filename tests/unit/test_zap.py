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

    def disable_scanners(self, ids, scanpolicyname):
        self.enabled -= set(ids.split(","))
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
INTRUSIVE = policy.PROFILES["intrusive"]


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


def test_intrusive_profile_enables_writes_but_not_overload() -> None:
    z, ascan = scanner_with(
        {str(i) for i in policy.SAFE_ACTIVE_RULES} | {"30001", "40044", "40014", "40046"}
    )
    z.configure_policy(INTRUSIVE)
    # Grava dados (40014 XSS persistente) e faz o alvo sair (40046 SSRF)...
    assert {"40014", "40046"} <= ascan.enabled
    # ...mas nunca sobrecarga (30001 overflow, 40044 Billion Laughs).
    assert not {"30001", "40044"} & ascan.enabled


def test_intrusive_refuses_when_zap_keeps_overload_rule_on() -> None:
    z, ascan = scanner_with({"40014", "30001"})
    ascan.disable_scanners = lambda ids, scanpolicyname: "OK"  # type: ignore[method-assign]
    with pytest.raises(ZapError):
        z.configure_policy(INTRUSIVE)


# --- login (autenticação pelo ZAP) -------------------------------------------------------

from scanner.web_scan.zap import (  # noqa: E402
    HeaderCredential,
    LoginCredential,
    build_login_request,
    extract_token,
    login_response_body,
    login_response_cookies,
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


# --- login por formulário (cookie de sessão) ---------------------------------------------

FORM_LOGIN = LoginCredential(
    login_url="http://dvwa/login.php",
    email="admin",
    password="s3nha",
    mode="form",
    username_field="username",
    password_field="password",
)


def test_build_login_request_form_is_urlencoded() -> None:
    raw = build_login_request(FORM_LOGIN)
    assert "Content-Type: application/x-www-form-urlencoded" in raw
    assert "username=admin" in raw and "password=s3nha" in raw
    assert '"email"' not in raw  # não é JSON


def test_login_response_cookies_builds_cookie_header() -> None:
    sent = [
        {
            "responseHeader": (
                "HTTP/1.1 302 Found\r\n"
                "Set-Cookie: PHPSESSID=abc123; path=/; HttpOnly\r\n"
                "Set-Cookie: security=low; path=/\r\n"
            )
        }
    ]
    assert login_response_cookies(sent) == "PHPSESSID=abc123; security=low"


def test_zap_login_form_returns_cookie_credential() -> None:
    captured = {}

    def send_request(raw, followredirects):
        captured["raw"] = raw
        captured["follow"] = followredirects
        return [{"responseHeader": "HTTP/1.1 302 Found\r\nSet-Cookie: SESS=xyz; path=/\r\n"}]

    z = ZapScanner.__new__(ZapScanner)
    z.zap = SimpleNamespace(core=SimpleNamespace(send_request=send_request))
    cred = z.login(FORM_LOGIN)
    assert isinstance(cred, HeaderCredential)
    assert cred.name == "Cookie" and cred.value == "SESS=xyz"
    assert captured["follow"] is False  # form não segue o redirect (capturaria sem o Set-Cookie)


def test_zap_login_form_raises_without_cookie() -> None:
    def send_request(raw, followredirects):
        return [{"responseHeader": "HTTP/1.1 200 OK\r\n"}]  # sem Set-Cookie = falha de login

    z = ZapScanner.__new__(ZapScanner)
    z.zap = SimpleNamespace(core=SimpleNamespace(send_request=send_request))
    with pytest.raises(ZapError):
        z.login(FORM_LOGIN)


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


# --- prontidão do alvo (readiness) -------------------------------------------------------

from scanner.web_scan.zap import (  # noqa: E402
    TargetNotReadyError,
    build_get_request,
    response_status,
)


def test_response_status_parses_status_line() -> None:
    assert response_status([{"responseHeader": "HTTP/1.1 200 OK\r\nServer: x"}]) == 200
    assert response_status([{"responseHeader": "HTTP/1.1 503 Service Unavailable\r\n"}]) == 503
    assert response_status({"responseHeader": "HTTP/1.1 301 Moved\n"}) == 301


def test_response_status_handles_no_response() -> None:
    assert response_status("mode_violation") is None  # ZAP devolve texto em erro
    assert response_status([]) is None
    assert response_status([{"responseHeader": ""}]) is None


def test_build_get_request_has_host() -> None:
    req = build_get_request("http://juice-shop:3000/")
    assert req.startswith("GET http://juice-shop:3000/ HTTP/1.1\r\n")
    assert "Host: juice-shop:3000\r\n" in req


class FakeCore:
    """send_request devolve, em sequência, cada resposta de `responses`."""

    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls = 0

    def send_request(self, request, followredirects=False):
        self.calls += 1
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def scanner_with_core(responses: list[object]) -> ZapScanner:
    z = ZapScanner.__new__(ZapScanner)
    z.limits = ScanLimits(10, 1, 5)
    z.on_progress = None
    z.zap = SimpleNamespace(core=FakeCore(responses))
    return z


def test_wait_until_ready_returns_on_first_good_status() -> None:
    z = scanner_with_core([[{"responseHeader": "HTTP/1.1 200 OK\r\n"}]])
    assert z.wait_until_ready("http://t/", attempts=3, delay_s=0) == 200
    assert z.zap.core.calls == 1


def test_wait_until_ready_retries_through_cold_start() -> None:
    # Duas falhas (conexão recusada / 503) e então sobe.
    z = scanner_with_core(
        [
            ConnectionError("refused"),
            [{"responseHeader": "HTTP/1.1 503 Service Unavailable\r\n"}],
            [{"responseHeader": "HTTP/1.1 200 OK\r\n"}],
        ]
    )
    assert z.wait_until_ready("http://t/", attempts=5, delay_s=0) == 200
    assert z.zap.core.calls == 3


def test_wait_until_ready_raises_when_never_up() -> None:
    z = scanner_with_core([ConnectionError("refused")] * 3)
    with pytest.raises(TargetNotReadyError):
        z.wait_until_ready("http://t/", attempts=3, delay_s=0)
    assert z.zap.core.calls == 3


# --- espera de recuperação do alvo (instabilidade no meio do scan) ------------------------

from scanner.web_scan.service import (  # noqa: E402
    GAVE_UP,
    RECOVERED,
    STOPPED,
    partial_reason_for,
    wait_for_target_recovery,
)


def test_partial_reason_distinguishes_cause() -> None:
    # Agressivo derrubou o alvo (esperado) vs. alvo instável sozinho vs. operador parou.
    assert partial_reason_for(GAVE_UP, destructive=True) == "aggressive-dos"
    assert partial_reason_for(GAVE_UP, destructive=False) == "target-unstable"
    assert partial_reason_for(STOPPED, destructive=True) == "operator-stopped"
    assert partial_reason_for(STOPPED, destructive=False) == "operator-stopped"


class FakeZapUp:
    """is_target_up devolve, em sequência, cada valor de `ups` (depois, sempre False)."""

    def __init__(self, ups: list[bool]) -> None:
        self.ups = list(ups)
        self.on_progress = None
        self.probes = 0

    def is_target_up(self, url: str) -> bool:
        self.probes += 1
        return self.ups.pop(0) if self.ups else False


def test_recovery_returns_recovered_when_up() -> None:
    z = FakeZapUp([True])
    assert wait_for_target_recovery(z, ["http://t/"], 0, 60, lambda: False) == RECOVERED


def test_recovery_waits_then_recovers() -> None:
    z = FakeZapUp([False, False, True])
    assert wait_for_target_recovery(z, ["http://t/"], 0, 60, lambda: False) == RECOVERED
    assert z.probes == 3


def test_recovery_stopped_by_operator() -> None:
    z = FakeZapUp([False])  # segue caído
    assert wait_for_target_recovery(z, ["http://t/"], 0, 60, lambda: True) == STOPPED


def test_recovery_gives_up_after_max_wait() -> None:
    z = FakeZapUp([False])  # caído; max_wait=0 -> desiste na hora
    assert wait_for_target_recovery(z, ["http://t/"], 0, 0, lambda: False) == GAVE_UP


# --- exclusão da armadilha de spider (caminho com segmento repetido) -------------------------

import re  # noqa: E402

from scanner.web_scan.zap import REPEATED_SEGMENT_REGEX  # noqa: E402

_TRAP_RX = re.compile(REPEATED_SEGMENT_REGEX)


@pytest.mark.parametrize(
    "url",
    [
        "http://juice-shop:3000/assets/assets",
        "http://juice-shop:3000/assets/assets/assets/public",
        "http://juice-shop:3000/assets/i18n/assets/public",  # repetição não consecutiva
        "http://juice-shop:3000/juice-shop/juice-shop/assets",
    ],
)
def test_trap_regex_excludes_repeated_segments(url: str) -> None:
    assert _TRAP_RX.fullmatch(url) is not None


@pytest.mark.parametrize(
    "url",
    [
        "http://juice-shop:3000/",
        "http://juice-shop:3000/rest/products/search?q=",
        "http://juice-shop:3000/rest/user/login",
        "http://juice-shop:3000/assets/public/images/products",
        "http://juice-shop:3000/ftp/quarantine/juicy_malware_windows_64.exe.url",
        "http://juice-shop:3000/api/Challenges/?name=Score%20Board",
    ],
)
def test_trap_regex_keeps_real_routes(url: str) -> None:
    assert _TRAP_RX.fullmatch(url) is None
