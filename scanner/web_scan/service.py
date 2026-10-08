"""Orquestra um scan da etapa 4 e publica os candidatos."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import redis
from sqlalchemy.orm import Session, sessionmaker

from scanner.common.authz import UnauthorizedScanError, check_authorized
from scanner.common.config import Settings
from scanner.common.db import (
    ScanStatus,
    get_known_routes,
    remember_routes,
    set_pages_crawled,
    set_scan_status,
)
from scanner.common.models import Finding, StageMessage
from scanner.common.queue import STREAM_CANDIDATES, make_message, publish
from scanner.common.scope import ScopeGuard
from scanner.web_scan import policy
from scanner.web_scan.alerts import alert_to_finding
from scanner.web_scan.policy import ScanProfile
from scanner.web_scan.zap import (
    HeaderCredential,
    LoginCredential,
    ScanLimits,
    ScanTimeoutError,
    ZapScanner,
)

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
            settings.scan_lab_ajax_browsers,
        )
    return ScanLimits(
        settings.scan_max_duration_minutes,
        settings.scan_threads_per_host,
        settings.scan_max_requests_per_second,
        settings.scan_ajax_browsers,
    )


def run_scan(
    zap: ZapScanner,
    msg: StageMessage,
    scope_routes: list[str],
    credential: HeaderCredential | LoginCredential | None,
    profile: ScanProfile,
    on_crawl_done: Callable[[list[str]], None] | None = None,
) -> list[Finding]:
    guard = ScopeGuard(msg.scope)
    zap.start_session(msg.scan_id)
    context_name, context_id = zap.create_context(msg.scan_id, msg.scope)
    zap.configure_limits()
    zap.configure_policy(profile)
    if isinstance(credential, LoginCredential):
        # Login do tipo "login": o ZAP autentica e nos devolve o cabeçalho com o token.
        credential = zap.login(credential)
    if credential is not None:
        zap.set_credential(credential)

    timed_out = False
    try:
        zap.seed_routes(scope_routes, guard)
        for base in msg.scope.base_urls:
            guard.require(base)
            zap.spider(base, context_name)
            zap.ajax_spider(base, context_name)
        zap.passive_scan()
        # Cobertura medida AQUI (fim do rastreio, antes do ativo): o scan ativo gera muitas URLs
        # de teste e inflaria a conta. Isto mede (e memoriza) o que o rastreio realmente alcançou.
        if on_crawl_done is not None:
            crawled: list[str] = []
            for base in msg.scope.base_urls:
                crawled.extend(zap.crawled_urls(base))
            on_crawl_done(crawled)
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


def _credential(payload: dict[str, Any]) -> HeaderCredential | LoginCredential | None:
    cred = payload.get("credential")
    if not cred:
        return None
    kind = cred.get("type")
    if kind == "header":
        return HeaderCredential(name=cred["name"], value=cred["value"])
    if kind == "login":
        # Senha vem no payload só em laboratório; em produção, a referência ao cofre (pendente
        # de alinhar com o time). O login é feito pelo ZAP em run_scan, não aqui.
        return LoginCredential(
            login_url=cred["login_url"],
            email=cred["email"],
            password=cred["password"],
            token_path=tuple(cred.get("token_path", ("authentication", "token"))),
            header_name=cred.get("header_name", "Authorization"),
            header_template=cred.get("header_template", "Bearer {token}"),
        )
    raise ValueError(f"tipo de credencial não suportado: {kind!r}")


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

    def on_crawl_done(urls: list[str]) -> None:
        # Portão de cobertura: grava o que o rastreio alcançou e avisa se saiu raso.
        set_pages_crawled(sessions, msg.scan_id, len(urls))
        if len(urls) < settings.coverage_min_pages:
            log.warning("cobertura possivelmente parcial", extra={"pages_crawled": len(urls)})
        # Memória de rastreio: acumula as URLs neste alvo para semear o próximo scan.
        remember_routes(
            sessions, msg.target_id, msg.scan_id, urls, settings.crawl_memory_max_routes
        )

    # Semeadura: rotas da mensagem (sitemap/robots da etapa 2) + memória dos scans anteriores.
    # O ScopeGuard em run_scan descarta qualquer rota fora do escopo atual.
    seed_routes = sorted(
        set(msg.payload.get("routes", [])) | set(get_known_routes(sessions, msg.target_id))
    )
    log.info(
        "semeadura de rotas",
        extra={"from_message": len(msg.payload.get("routes", [])), "total": len(seed_routes)},
    )
    progress("starting")
    try:
        findings = run_scan(
            zap,
            msg,
            seed_routes,
            _credential(msg.payload),
            profile,
            on_crawl_done=on_crawl_done,
        )
    except Exception:
        set_scan_status(sessions, msg.scan_id, ScanStatus.WEB_SCANNING, "retrying")
        raise
    set_scan_status(sessions, msg.scan_id, ScanStatus.VALIDATING, "validate")
    out = make_message(
        msg,
        "candidates",
        {"tool": "zap", "findings": [f.model_dump(mode="json") for f in findings]},
    )
    publish(r, STREAM_CANDIDATES, out)
