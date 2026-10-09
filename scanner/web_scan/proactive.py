"""Checagens próprias de autenticação (A07, A08) rodadas na etapa 4, pelo ZAP.

Ficam aqui (e não na validação) porque precisam da credencial/token do login, que o web_scan já
tem — reaproveita sem expor de novo. Produzem Finding JÁ confirmado (prova determinística); por
isso vão para a mensagem como `proactive` (a validação faz upsert direto, sem re-testar: a
re-validação rebaixaria um achado sem validador correspondente).
"""

from __future__ import annotations

import logging
from dataclasses import replace

import httpx

from scanner.common.models import Finding, Outcome
from scanner.validation.access_control import classify_access
from scanner.validation.auth_checks import MIN_ATTEMPTS, classify_login_protection
from scanner.validation.http import ProbeResponse
from scanner.validation.jwt_integrity import (
    classify_jwt_integrity,
    decode_payload,
    unsigned_token,
)
from scanner.validation.proactive import build_finding
from scanner.web_scan.zap import HeaderCredential, LoginCredential, ZapError, ZapScanner

log = logging.getLogger(__name__)


def run_login_lockout(
    zap: ZapScanner, login: LoginCredential, scan_id: str, target_id: str
) -> Finding | None:
    """A07: o login bloqueia após senhas erradas repetidas? Sem bloqueio = força bruta possível.

    Faz MIN_ATTEMPTS tentativas com senha errada contra a conta de teste (nada é alterado). Só
    emite achado se CONFIRMED (sem bloqueio); se o alvo trava (423/429), é FALSE_POSITIVE.
    """
    statuses = [zap.login_attempt_status(login, f"wrong-pass-{i}") for i in range(MIN_ATTEMPTS)]
    validation = classify_login_protection(statuses)
    log.info("A07 login lockout", extra={"statuses": statuses, "outcome": validation.outcome})
    if validation.outcome == Outcome.CONFIRMED:
        return build_finding(scan_id, target_id, login.login_url, validation)
    return None


def run_access_control(
    zap: ZapScanner,
    owner: HeaderCredential,
    login: LoginCredential,
    resource_urls: list[str],
    scan_id: str,
    target_id: str,
) -> list[Finding]:
    """A01: outro usuário consegue ler os dados privados do dono (IDOR / quebra de acesso)?

    Loga um SEGUNDO usuário pelo ZAP e lê cada recurso privado do dono com as duas sessões. A
    decisão é determinística (`classify_access`): confirma só quando o outro usuário recebe 200 com
    o marcador do dono. Só leitura (GET) — não destrutivo, pode rodar em cliente. Emite achado só
    nos recursos CONFIRMED; acesso corretamente negado não vira achado.
    """
    other_spec = replace(login, email=login.other_email, password=login.other_password)
    try:
        other = zap.login(other_spec)
    except ZapError:
        log.warning("A01: login do segundo usuário falhou; IDOR não checado")
        return []
    marker = login.owner_marker or login.email
    found: list[Finding] = []
    for url in resource_urls:
        owner_status, owner_body = zap.authed_get(url, owner.name, owner.value)
        other_status, other_body = zap.authed_get(url, other.name, other.value)
        owner_resp = ProbeResponse(
            status=owner_status, headers=httpx.Headers(), text=owner_body, url=url
        )
        other_resp = ProbeResponse(
            status=other_status, headers=httpx.Headers(), text=other_body, url=url
        )
        validation = classify_access(url, owner_resp, other_resp, marker)
        log.info("A01 access control", extra={"url": url, "outcome": validation.outcome})
        if validation.outcome == Outcome.CONFIRMED:
            found.append(build_finding(scan_id, target_id, url, validation))
    return found


def _tamper_signature(token: str) -> str:
    """Token de controle: mesma estrutura, assinatura inválida (para o endpoint rejeitar)."""
    parts = token.split(".")
    if len(parts) != 3:
        return token + "x"
    sig = parts[2]
    tampered = (sig[:-1] + ("A" if sig[-1:] != "A" else "B")) if sig else "AAAA"
    return f"{parts[0]}.{parts[1]}.{tampered}"


def run_jwt_integrity(
    zap: ZapScanner,
    header_name: str,
    header_value: str,
    protected_url: str,
    scan_id: str,
    target_id: str,
) -> Finding | None:
    """A08: o servidor aceita um token sem assinatura (alg:none)?

    Monta um token sem assinatura com o payload do NOSSO login e um de controle (assinatura
    adulterada), e compara os status num recurso protegido. Confirma só se o controle é rejeitado
    (exige assinatura) e o sem-assinatura é aceito.
    """
    token = header_value.split()[-1]  # tira o "Bearer "
    try:
        payload = decode_payload(token)
    except Exception:
        log.warning("A08: token do login não é um JWT legível; pulando")
        return None
    unsigned_value = header_value.replace(token, unsigned_token(payload))
    control_value = header_value.replace(token, _tamper_signature(token))
    unsigned_status = zap.auth_request_status(protected_url, header_name, unsigned_value)
    control_status = zap.auth_request_status(protected_url, header_name, control_value)
    validation = classify_jwt_integrity(unsigned_status, control_status)
    log.info(
        "A08 jwt integrity",
        extra={
            "unsigned": unsigned_status,
            "control": control_status,
            "outcome": validation.outcome,
        },
    )
    if validation.outcome == Outcome.CONFIRMED:
        return build_finding(scan_id, target_id, protected_url, validation)
    return None
