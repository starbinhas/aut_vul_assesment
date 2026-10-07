"""Orquestra um scan da etapa 4 e publica os candidatos."""

from __future__ import annotations

import logging
from typing import Any

import redis
from sqlalchemy.orm import Session, sessionmaker

from scanner.common.authz import UnauthorizedScanError, check_authorized
from scanner.common.config import Settings
from scanner.common.db import ScanStatus, set_scan_status
from scanner.common.models import Finding, StageMessage
from scanner.common.queue import STREAM_CANDIDATES, make_message, publish
from scanner.common.scope import ScopeGuard
from scanner.web_scan import policy
from scanner.web_scan.alerts import alert_to_finding
from scanner.web_scan.policy import ScanProfile
from scanner.web_scan.zap import HeaderCredential, ScanLimits, ScanTimeoutError, ZapScanner

log = logging.getLogger(__name__)


class ProfileNotAllowedError(Exception):
    """Perfil destrutivo pedido contra um alvo que não é de laboratório."""


def resolve_profile(msg: StageMessage, lab_hosts: list[str]) -> ScanProfile:
    """Perfil pedido na mensagem, com a trava do nível destrutivo (regra 3 + 4 do CLAUDE.md).

    Um perfil que pode causar dano só é liberado quando TODO host do escopo é de laboratório.
    Contra qualquer outro alvo, recusa — não rebaixa em silêncio, para o pedido ficar explícito.
    """
    profile = policy.resolve(msg.payload.get("profile"))
    if profile.destructive and not policy.is_lab_scope(msg.scope.allowed_hosts, lab_hosts):
        outside = {h.lower() for h in msg.scope.allowed_hosts} - {h.lower() for h in lab_hosts}
        raise ProfileNotAllowedError(
            f"perfil '{profile.name}' só roda em laboratório; fora da allowlist: {sorted(outside)}"
        )
    return profile


def resolve_limits(hosts: list[str], settings: Settings) -> ScanLimits:
    """Limites de laboratório (soltos) só se TODO o escopo é de laboratório; senão, os de cliente.

    Mesma trava do perfil agressivo (`policy.is_lab_scope`): um host real no escopo já reprova e
    cai nos limites conservadores, para nunca sobrecarregar produção (regra 3 do CLAUDE.md).
    """
    if policy.is_lab_scope(hosts, settings.lab_hosts):
        return ScanLimits(
            settings.scan_lab_max_duration_minutes,
            settings.scan_lab_threads_per_host,
            settings.scan_lab_max_requests_per_second,
        )
    return ScanLimits(
        settings.scan_max_duration_minutes,
        settings.scan_threads_per_host,
        settings.scan_max_requests_per_second,
    )


def run_scan(
    zap: ZapScanner,
    msg: StageMessage,
    scope_routes: list[str],
    credential: HeaderCredential | None,
    profile: ScanProfile,
) -> list[Finding]:
    guard = ScopeGuard(msg.scope)
    zap.start_session(msg.scan_id)
    context_name, context_id = zap.create_context(msg.scan_id, msg.scope)
    zap.configure_limits()
    zap.configure_policy(profile)
    if credential:
        zap.set_credential(credential)

    timed_out = False
    try:
        zap.seed_routes(scope_routes, guard)
        for base in msg.scope.base_urls:
            guard.require(base)
            zap.spider(base, context_name)
            zap.ajax_spider(base, context_name)
        zap.passive_scan()
        for base in msg.scope.base_urls:
            zap.active_scan(base, context_id)
    except ScanTimeoutError as exc:
        # Entrega o que já foi achado; o tempo máximo é um limite de segurança, não um erro.
        log.warning("scan interrompido pelo tempo máximo", extra={"error": str(exc)})
        timed_out = True

    findings: dict[str, Finding] = {}
    for base in msg.scope.base_urls:
        for alert in zap.alerts(base):
            if not guard.allows(alert.get("url", "")):
                continue
            message = zap.message(alert["messageId"]) if alert.get("messageId") else None
            f = alert_to_finding(alert, message, msg.scan_id, msg.target_id)
            findings.setdefault(f.finding_id, f)
    log.info(
        "scan web concluído",
        extra={"candidates": len(findings), "timed_out": timed_out, "profile": profile.name},
    )
    return list(findings.values())


def _credential(payload: dict[str, Any]) -> HeaderCredential | None:
    cred = payload.get("credential")
    if not cred:
        return None
    if cred.get("type") != "header":
        raise ValueError("tipo de credencial não suportado (só 'header' por enquanto)")
    return HeaderCredential(name=cred["name"], value=cred["value"])


def handle(
    session: Session,
    msg: StageMessage,
    settings: Settings,
    r: redis.Redis,
    sessions: sessionmaker,  # type: ignore[type-arg]
) -> None:
    # Checagem em transação própria e curta: a transação do `consume` fica aberta o scan inteiro
    # (até o tempo máximo), e uma leitura de `scans` nela seguraria lock na tabela até o fim —
    # foi o que travou a migração 0003 por 25 min. A de fora só guarda a marca de idempotência.
    with sessions() as authz:
        check_authorized(authz, msg)
    try:
        profile = resolve_profile(msg, settings.lab_hosts)
    except ProfileNotAllowedError as exc:
        # Pedido explícito e recusado: marca como falha e não tenta de novo (vai para dead-letter).
        log.error("perfil recusado", extra={"error": str(exc)})
        set_scan_status(
            sessions, msg.scan_id, ScanStatus.FAILED, "perfil não permitido para o alvo"
        )
        raise UnauthorizedScanError(str(exc)) from exc

    def progress(phase: str, pct: int | None = None, info: str | None = None) -> None:
        set_scan_status(sessions, msg.scan_id, ScanStatus.WEB_SCANNING, phase, pct, info)

    limits = resolve_limits(msg.scope.allowed_hosts, settings)
    log.info(
        "limites do scan",
        extra={
            "lab": policy.is_lab_scope(msg.scope.allowed_hosts, settings.lab_hosts),
            "rps": limits.max_requests_per_second,
            "threads": limits.threads_per_host,
        },
    )
    zap = ZapScanner(
        settings.zap_api_url,
        settings.zap_api_key.get_secret_value(),
        limits,
        on_progress=progress,
    )
    progress("starting")
    try:
        findings = run_scan(
            zap, msg, msg.payload.get("routes", []), _credential(msg.payload), profile
        )
    except Exception:
        set_scan_status(sessions, msg.scan_id, ScanStatus.WEB_SCANNING, "retrying")
        raise
    set_scan_status(sessions, msg.scan_id, ScanStatus.VALIDATING, f"{len(findings)} candidatos")
    out = make_message(
        msg,
        "candidates",
        {"tool": "zap", "findings": [f.model_dump(mode="json") for f in findings]},
    )
    publish(r, STREAM_CANDIDATES, out)
