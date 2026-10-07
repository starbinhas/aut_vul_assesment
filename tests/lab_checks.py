"""Checagens proativas contra o laboratório (as que o ZAP não faz sozinho).

Cada checagem é não destrutiva (só leitura, ou um número pequeno e seguro de tentativas) e devolve
um veredito por categoria do OWASP. O boletim (`lab_coverage`) roda estas checagens e soma o
resultado à cobertura — assim o número reflete o que a nossa lógica detecta, além do ZAP.

Produção: integrar isto ao pipeline exige estender o contrato de achado (uma fonte "scanner" além
de zap/nuclei) e propagar credenciais — mudança combinada com o time. Aqui é laboratório.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from scanner.common.models import Scope
from scanner.common.scope import ScopeGuard
from scanner.validation.access_probe import AccessProbe, Identity, run_access_probe
from scanner.validation.exposed_files import SENSITIVE_PATHS, classify_exposure
from scanner.validation.http import ProbeClient

BASE = os.environ.get("LAB_JUICE_SHOP_URL", "http://juice-shop:3000").rstrip("/")
PASSWORD = "ScannerLab123!"


@dataclass
class CheckResult:
    owasp: str
    name: str
    outcome: str  # confirmed | false_positive | unconfirmed | error
    detail: str


def _register(email: str) -> None:
    body = {
        "email": email,
        "password": PASSWORD,
        "passwordRepeat": PASSWORD,
        "securityQuestion": {"id": 1},
        "securityAnswer": "lab",
    }
    try:
        httpx.post(f"{BASE}/api/Users", json=body, timeout=15)  # 2x: já existe, tudo bem
    except httpx.HTTPError:
        pass


def _login(email: str) -> dict[str, object]:
    r = httpx.post(
        f"{BASE}/rest/user/login", json={"email": email, "password": PASSWORD}, timeout=15
    )
    r.raise_for_status()
    return dict(r.json()["authentication"])


def _scope() -> Scope:
    return Scope(
        scope_id="lab-juice-shop",
        verified=True,
        locked=True,
        base_urls=[f"{BASE}/"],
        allowed_hosts=["juice-shop"],
    )


def check_access_control() -> CheckResult:
    """A01 — um usuário consegue ler o recurso privado de outro (IDOR na cesta do Juice Shop)."""
    name = "acesso entre usuários"
    try:
        for email in ("scanner-owner@lab.local", "scanner-other@lab.local"):
            _register(email)
        owner = _login("scanner-owner@lab.local")
        other = _login("scanner-other@lab.local")
        resource = f"{BASE}/rest/basket/{owner['bid']}"
        owned = httpx.get(
            resource, headers={"Authorization": f"Bearer {owner['token']}"}, timeout=15
        ).json()
        marker = f'"UserId":{owned["data"]["UserId"]}'
        client = ProbeClient(ScopeGuard(_scope()), max_rps=10)
        try:
            v = run_access_probe(
                AccessProbe(resource_url=resource, owner_marker=marker),
                Identity("Authorization", f"Bearer {owner['token']}"),
                Identity("Authorization", f"Bearer {other['token']}"),
                client,
            )
        finally:
            client.close()
        return CheckResult("A01:2025", name, v.outcome.value, v.reason)
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return CheckResult("A01:2025", name, "error", f"checagem falhou: {exc}")


def check_exposed_files() -> CheckResult:
    """A04 — arquivos sensíveis acessíveis sem autenticação (só leitura)."""
    name = "arquivos sensíveis expostos"
    client = ProbeClient(ScopeGuard(_scope()), max_rps=10)
    exposed: list[str] = []
    try:
        for path in SENSITIVE_PATHS:
            url = f"{BASE}{path}"
            v = classify_exposure(path, url, client.request("GET", url))
            if v.outcome.value == "confirmed":
                exposed.append(path)
    except httpx.HTTPError as exc:
        return CheckResult("A04:2025", name, "error", f"checagem falhou: {exc}")
    finally:
        client.close()
    if exposed:
        return CheckResult(
            "A04:2025", name, "confirmed", f"acessível sem autenticação: {', '.join(exposed)}"
        )
    return CheckResult("A04:2025", name, "unconfirmed", "nenhum arquivo sensível conhecido exposto")


CHECKS: list[Callable[[], CheckResult]] = [
    check_access_control,
    check_exposed_files,
]


def run_all() -> list[CheckResult]:
    return [check() for check in CHECKS]
