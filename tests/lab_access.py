"""Prova de controle de acesso entre usuários contra o Juice Shop (frente 3, ponta a ponta).

Loga dois usuários de teste do laboratório e usa a nossa lógica (`run_access_probe` +
`classify_access`) para verificar se um consegue ler o recurso privado do outro. Só leitura; o
registro dos usuários é passo de laboratório (o alvo é vulnerável de propósito).

    docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile test \
        run --rm tests python -m tests.lab_access
"""

from __future__ import annotations

import os
import sys

import httpx

from scanner.common.models import Scope
from scanner.common.scope import ScopeGuard
from scanner.validation.access_control import NAME
from scanner.validation.access_probe import AccessProbe, Identity, run_access_probe
from scanner.validation.http import ProbeClient

BASE = os.environ.get("LAB_JUICE_SHOP_URL", "http://juice-shop:3000").rstrip("/")
PASSWORD = "ScannerLab123!"
OWNER_EMAIL = "scanner-owner@lab.local"
OTHER_EMAIL = "scanner-other@lab.local"


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
    except httpx.HTTPError as exc:
        print(f"aviso: registro de {email} falhou ({exc})")


def _login(email: str) -> dict[str, object]:
    r = httpx.post(
        f"{BASE}/rest/user/login", json={"email": email, "password": PASSWORD}, timeout=15
    )
    r.raise_for_status()
    return dict(r.json()["authentication"])


def main() -> None:
    for email in (OWNER_EMAIL, OTHER_EMAIL):
        _register(email)
    owner_auth = _login(OWNER_EMAIL)
    other_auth = _login(OTHER_EMAIL)

    bid = owner_auth["bid"]
    resource = f"{BASE}/rest/basket/{bid}"

    # Marcador: o UserId do dono aparece no recurso e é único dele — prova que o dado é do dono.
    owned = httpx.get(
        resource, headers={"Authorization": f"Bearer {owner_auth['token']}"}, timeout=15
    ).json()
    marker = f'"UserId":{owned["data"]["UserId"]}'

    scope = Scope(
        scope_id="lab-juice-shop",
        verified=True,
        locked=True,
        base_urls=[f"{BASE}/"],
        allowed_hosts=["juice-shop"],
    )
    client = ProbeClient(ScopeGuard(scope), max_rps=10)
    try:
        verdict = run_access_probe(
            AccessProbe(resource_url=resource, owner_marker=marker),
            Identity("Authorization", f"Bearer {owner_auth['token']}"),
            Identity("Authorization", f"Bearer {other_auth['token']}"),
            client,
        )
    finally:
        client.close()

    print(f"\nTeste de acesso entre usuários — {NAME}")
    print(f"recurso: {resource}")
    print(f"veredito: {verdict.outcome.value.upper()}")
    print(f"motivo:   {verdict.reason}")
    if verdict.outcome.value == "confirmed":
        print(
            "\n>> Falha de controle de acesso CONFIRMADA: um usuário leu o dado privado do outro."
        )
    sys.exit(0 if verdict.outcome.value in ("confirmed", "false_positive") else 1)


if __name__ == "__main__":
    main()
