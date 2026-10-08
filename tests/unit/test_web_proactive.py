"""Checagens próprias de autenticação na etapa 4 (A07 login sem bloqueio, A08 token alg:none)."""

from __future__ import annotations

from scanner.validation.jwt_integrity import unsigned_token
from scanner.web_scan.proactive import (
    _tamper_signature,
    run_jwt_integrity,
    run_login_lockout,
)
from scanner.web_scan.zap import LoginCredential

LOGIN = LoginCredential(
    login_url="http://juice-shop:3000/rest/user/login",
    email="scanner-test@lab.local",
    password="x",
    protected_path="/rest/user/whoami",
)


class FakeAuthZap:
    """ZAP fake: devolve status de login e de requisição autenticada em sequência."""

    def __init__(self, login: list[int] | None = None, auth: list[int] | None = None) -> None:
        self.login = list(login or [])
        self.auth = list(auth or [])

    def login_attempt_status(self, spec: LoginCredential, password: str) -> int:
        return self.login.pop(0) if self.login else 401

    def auth_request_status(self, url: str, header_name: str, header_value: str) -> int:
        return self.auth.pop(0) if self.auth else 401


# --- A07: login sem bloqueio -------------------------------------------------------------


def test_a07_confirms_when_no_lockout() -> None:
    f = run_login_lockout(FakeAuthZap(login=[401] * 5), LOGIN, "scan-1", "t-1")
    assert f is not None
    assert f.source.tool == "scanner"
    assert f.owasp == "A07:2025"
    assert f.status.value == "confirmed"


def test_a07_no_finding_when_locked() -> None:
    # 429 (Too Many Requests) = o login bloqueia -> FALSE_POSITIVE -> sem achado.
    assert run_login_lockout(FakeAuthZap(login=[401, 429]), LOGIN, "scan-1", "t-1") is None


# --- A08: token sem assinatura -----------------------------------------------------------


def test_a08_confirms_when_unsigned_accepted() -> None:
    # sem-assinatura aceito (200) e controle (assinatura adulterada) rejeitado (401) -> confirma.
    zap = FakeAuthZap(auth=[200, 401])
    hv = "Bearer " + unsigned_token({"id": 1, "email": "x"})
    f = run_jwt_integrity(
        zap, "Authorization", hv, "http://juice-shop:3000/rest/user/whoami", "s", "t"
    )
    assert f is not None
    assert f.owasp == "A08:2025"
    assert f.status.value == "confirmed"


def test_a08_no_finding_when_unsigned_rejected() -> None:
    zap = FakeAuthZap(auth=[401, 401])  # rejeita o sem-assinatura -> seguro
    hv = "Bearer " + unsigned_token({"id": 1})
    assert run_jwt_integrity(zap, "Authorization", hv, "http://x/whoami", "s", "t") is None


def test_tamper_signature_changes_only_signature() -> None:
    assert _tamper_signature("aaa.bbb.ccc").startswith("aaa.bbb.")
    assert _tamper_signature("aaa.bbb.ccc") != "aaa.bbb.ccc"
    assert _tamper_signature("aaa.bbb.").endswith("AAAA")  # assinatura vazia -> preenche
