"""Orquestra um scan da etapa 4 e publica os candidatos."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

import redis
from sqlalchemy.orm import Session, sessionmaker

from scanner.common.authz import UnauthorizedScanError, check_authorized
from scanner.common.config import Settings
from scanner.common.db import (
    ScanStatus,
    canonical_routes,
    get_known_routes,
    is_stop_requested,
    last_pages_crawled,
    mark_partial,
    remember_routes,
    set_pages_crawled,
    set_scan_status,
)
from scanner.common.models import Finding, StageMessage
from scanner.common.queue import STREAM_CANDIDATES, make_message, publish
from scanner.common.scope import ScopeGuard
from scanner.common.staging import staging_cleared, stress_cleared
from scanner.web_scan import policy
from scanner.web_scan.alerts import alert_to_finding
from scanner.web_scan.policy import ScanProfile
from scanner.web_scan.proactive import run_jwt_integrity, run_login_lockout
from scanner.web_scan.zap import (
    HeaderCredential,
    LoginCredential,
    ScanLimits,
    ScanTimeoutError,
    TargetNotReadyError,
    ZapScanner,
)

log = logging.getLogger(__name__)


class ProfileNotAllowedError(Exception):
    """Perfil que pode causar dano pedido contra um alvo que não tem liberação para ele."""


def resolve_profile(
    msg: StageMessage, lab_hosts: list[str], staging: bool = False, stress: bool = False
) -> ScanProfile:
    """Perfil pedido na mensagem, com a trava dos níveis que causam dano (regras 3 e 4).

    `aggressive` (sobrecarga/DoS) só em laboratório ou numa cópia liberada para resiliência
    (`stress`). `intrusive` também numa cópia liberada para o intrusivo (`staging`). Ambos vêm do
    banco (`staging_cleared`/`stress_cleared`). Contra qualquer outro alvo, recusa — não rebaixa em
    silêncio, para o pedido ficar explícito.
    """
    profile = policy.resolve(msg.payload.get("profile"))
    lab = policy.is_lab_scope(msg.scope.allowed_hosts, lab_hosts)
    if not policy.is_cleared(profile, lab=lab, staging=staging, stress=stress):
        if profile.clearance == policy.LAB:
            where = "laboratório"
        elif profile.clearance == policy.STRESS_STAGING:
            where = "laboratório ou cópia liberada para resiliência"
        else:
            where = "cópia de teste autorizada"
        outside = {h.lower() for h in msg.scope.allowed_hosts} - {h.lower() for h in lab_hosts}
        raise ProfileNotAllowedError(
            f"perfil '{profile.name}' só roda em {where}; fora da liberação: {sorted(outside)}"
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


def should_recrawl(
    pages: int, min_pages: int, previous: int | None, regression_ratio: float
) -> bool:
    """Rastreio saiu raso e vale repetir? Abaixo do mínimo, ou regressão frente ao anterior."""
    if pages < min_pages:
        return True
    return previous is not None and previous > 0 and pages < previous * regression_ratio


# Resultado da espera pelo alvo voltar (instabilidade no meio do scan).
RECOVERED = "recovered"  # alvo voltou -> retoma a busca
STOPPED = "stopped"  # operador pediu para entregar o parcial agora
GAVE_UP = "gave_up"  # estourou o tempo de espera -> entrega o parcial


def partial_reason_for(outcome: str, destructive: bool) -> str:
    """Por que o scan virou parcial — para a interface explicar a causa, não só o fato.

    Distingue o alvo derrubado PELO nosso teste agressivo (esperado nesse perfil) do alvo que
    caiu por conta própria; e da parada pedida pelo operador. Vira texto na interface.
    """
    if outcome == STOPPED:
        return "operator-stopped"
    return "aggressive-dos" if destructive else "target-unstable"


def wait_for_target_recovery(
    zap: ZapScanner,
    base_urls: list[str],
    probe_interval_s: float,
    max_wait_s: float,
    should_stop: Callable[[], bool],
    on_wait: Callable[[float], None] | None = None,
) -> str:
    """Espera o alvo (caído no meio do scan) voltar, para retomar a busca.

    Sonda todos os `base_urls` a cada `probe_interval_s`. Devolve assim que:
    - todos respondem de novo -> RECOVERED (o scan retoma o ativo);
    - o operador manda parar   -> STOPPED  (entrega o parcial);
    - estoura `max_wait_s`     -> GAVE_UP  (entrega o parcial).
    """
    start = time.monotonic()
    while True:
        if all(zap.is_target_up(b) for b in base_urls):
            return RECOVERED
        if should_stop():
            return STOPPED
        waited = time.monotonic() - start
        if waited >= max_wait_s:
            return GAVE_UP
        if on_wait is not None:
            on_wait(waited)
        time.sleep(probe_interval_s)


def run_scan(
    zap: ZapScanner,
    msg: StageMessage,
    scope_routes: list[str],
    credential: HeaderCredential | LoginCredential | None,
    profile: ScanProfile,
    on_crawl_done: Callable[[list[str]], None] | None = None,
    readiness_attempts: int = 10,
    readiness_delay_s: float = 3.0,
    recrawl_decider: Callable[[int], bool] | None = None,
    recrawl_max_retries: int = 0,
    should_stop: Callable[[], bool] | None = None,
    on_partial: Callable[[str], None] | None = None,
    on_proactive: Callable[[list[Finding]], None] | None = None,
    recovery_probe_interval_s: float = 15.0,
    recovery_max_wait_s: float = 600.0,
) -> list[Finding]:
    guard = ScopeGuard(msg.scope)
    zap.start_session(msg.scan_id)
    context_name, context_id = zap.create_context(msg.scan_id, msg.scope)
    zap.configure_limits()
    zap.configure_policy(profile)
    # Prontidão: confirma que o alvo responde antes de qualquer login/rastreio (evita 'alvo frio').
    # Erra para fora de run_scan (não é ScanTimeout): o handler decide re-tentar via fila.
    for base in msg.scope.base_urls:
        zap.wait_until_ready(base, readiness_attempts, readiness_delay_s)
    login_spec: LoginCredential | None = None
    if isinstance(credential, LoginCredential):
        login_spec = credential
        # Login do tipo "login": o ZAP autentica e nos devolve o cabeçalho com o token.
        credential = zap.login(credential)
    if credential is not None:
        zap.set_credential(credential)

    # Checagens próprias de autenticação (A07/A08), que precisam do login/token: rodam aqui,
    # emitem achados JÁ confirmados e vão à parte (não passam pela re-validação, que rebaixaria).
    if login_spec is not None and isinstance(credential, HeaderCredential) and on_proactive:
        found: list[Finding] = []
        if a07 := run_login_lockout(zap, login_spec, msg.scan_id, msg.target_id):
            found.append(a07)
        if login_spec.protected_path:
            protected = urljoin(msg.scope.base_urls[0], login_spec.protected_path)
            if guard.allows(protected) and (
                a08 := run_jwt_integrity(
                    zap,
                    credential.name,
                    credential.value,
                    protected,
                    msg.scan_id,
                    msg.target_id,
                )
            ):
                found.append(a08)
        if found:
            on_proactive(found)

    timed_out = False
    partial = False
    crawled: list[str] = []
    retries = 0
    crawl_seconds = active_seconds = 0.0
    crawl_start = time.monotonic()
    try:
        zap.seed_routes(scope_routes, guard)
        for base in msg.scope.base_urls:
            guard.require(base)
            zap.spider(base, context_name)
            zap.ajax_spider(base, context_name)
        zap.passive_scan()

        # Cobertura medida AQUI (fim do rastreio, antes do ativo): o scan ativo gera muitas URLs
        # de teste e inflaria a conta. Isto mede o que o rastreio realmente alcançou.
        # Conta ROTAS distintas (assinatura: caminho + nomes de parâmetro), não cada URL permutada.
        # É o que torna "páginas visitadas" estável entre scans do mesmo site.
        def measure() -> list[str]:
            urls: list[str] = []
            for base in msg.scope.base_urls:
                urls.extend(zap.crawled_urls(base))
            return canonical_routes(urls)

        crawled = measure()
        # Re-rastreio quando a cobertura sai rasa/regride: refaz o AJAX spider (a parte variável)
        # e remede. Limitado (recrawl_max_retries) para não arrastar o scan.
        while (
            recrawl_decider is not None
            and retries < recrawl_max_retries
            and recrawl_decider(len(crawled))
        ):
            retries += 1
            log.warning(
                "cobertura rasa; refazendo o rastreio",
                extra={"pages": len(crawled), "retry": retries},
            )
            for base in msg.scope.base_urls:
                guard.require(base)
                zap.ajax_spider(base, context_name)
            zap.passive_scan()
            crawled = measure()
        if on_crawl_done is not None:
            on_crawl_done(crawled)
        crawl_seconds = time.monotonic() - crawl_start

        # Guarda de saúde no meio do scan: o alvo estava de pé no início, mas pode ter caído
        # durante o rastreio. Se caiu, espera ele voltar para RETOMAR a busca (ativo). Se demorar
        # demais ou o operador mandar parar, entrega o PARCIAL (pula o ativo) e marca 'instável'.
        if not all(zap.is_target_up(base) for base in msg.scope.base_urls):
            log.warning("alvo caiu no meio do scan; aguardando voltar")

            def _waiting(waited: float) -> None:
                if zap.on_progress is not None:
                    zap.on_progress(
                        "target-unstable", None, f"aguardando o alvo voltar ({int(waited)}s)"
                    )

            outcome = wait_for_target_recovery(
                zap,
                msg.scope.base_urls,
                recovery_probe_interval_s,
                recovery_max_wait_s,
                should_stop or (lambda: False),
                on_wait=_waiting,
            )
            if outcome == RECOVERED:
                log.info("alvo voltou; retomando o scan ativo")
            else:
                partial = True
                # Só o agressivo tem regras de sobrecarga; o intrusivo não derruba de propósito.
                reason = partial_reason_for(outcome, profile.clearance == policy.LAB)
                log.warning("entregando parcial (alvo instável)", extra={"reason": reason})
                if on_partial is not None:
                    on_partial(reason)

        if not partial:
            active_start = time.monotonic()
            for base in msg.scope.base_urls:
                zap.active_scan(base, context_id)
            active_seconds = time.monotonic() - active_start
    except ScanTimeoutError as exc:
        # Entrega o que já foi achado; o tempo máximo é um limite de segurança, não um erro.
        log.warning("scan interrompido pelo tempo máximo", extra={"error": str(exc)})
        timed_out = True
        # Atribui o tempo decorrido à fase em que parou (para a medição refletir onde demorou).
        if crawl_seconds == 0.0:
            crawl_seconds = time.monotonic() - crawl_start
        else:
            active_seconds = time.monotonic() - crawl_start - crawl_seconds

    # Medição permanente: onde o tempo foi (rastreio vs. ativo). O ativo costuma dominar.
    log.info(
        "tempos do scan",
        extra={
            "crawl_seconds": round(crawl_seconds, 1),
            "active_seconds": round(active_seconds, 1),
            "pages_crawled": len(crawled),
            "recrawl_retries": retries,
            "timed_out": timed_out,
            "partial": partial,
        },
    )

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
            protected_path=cred.get("protected_path", ""),
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
        staging = staging_cleared(authz, msg.target_id, msg.scope.allowed_hosts)
        stress = stress_cleared(authz, msg.target_id, msg.scope.allowed_hosts)
    try:
        profile = resolve_profile(msg, settings.lab_hosts, staging, stress)
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
    seed_routes = canonical_routes(
        set(msg.payload.get("routes", [])) | set(get_known_routes(sessions, msg.target_id))
    )

    # Baseline para detectar regressão de cobertura (cobertura do scan anterior deste alvo).
    previous_pages = last_pages_crawled(sessions, msg.target_id, msg.scan_id)

    def recrawl_decider(pages: int) -> bool:
        return should_recrawl(
            pages, settings.coverage_min_pages, previous_pages, settings.recrawl_regression_ratio
        )

    log.info(
        "semeadura de rotas",
        extra={"from_message": len(msg.payload.get("routes", [])), "total": len(seed_routes)},
    )
    progress("starting")
    try:
        proactive: list[Finding] = []
        findings = run_scan(
            zap,
            msg,
            seed_routes,
            _credential(msg.payload),
            profile,
            on_crawl_done=on_crawl_done,
            readiness_attempts=settings.readiness_attempts,
            readiness_delay_s=settings.readiness_delay_seconds,
            recrawl_decider=recrawl_decider,
            recrawl_max_retries=settings.recrawl_max_retries,
            should_stop=lambda: is_stop_requested(sessions, msg.scan_id),
            on_partial=lambda reason: mark_partial(sessions, msg.scan_id, reason),
            on_proactive=proactive.extend,
            recovery_probe_interval_s=settings.target_recovery_probe_interval_seconds,
            recovery_max_wait_s=settings.target_recovery_max_wait_minutes * 60,
        )
    except TargetNotReadyError as exc:
        # Alvo fora do ar: não rastreia vazio. Sem ack -> a fila re-tenta mais tarde (o alvo pode
        # subir); após o limite de entregas, o give-up marca o scan como falho.
        log.warning("alvo não respondeu; adiando", extra={"error": str(exc)})
        set_scan_status(sessions, msg.scan_id, ScanStatus.WEB_SCANNING, "target-unreachable")
        raise
    except Exception:
        set_scan_status(sessions, msg.scan_id, ScanStatus.WEB_SCANNING, "retrying")
        raise
    set_scan_status(sessions, msg.scan_id, ScanStatus.VALIDATING, "validate")
    out = make_message(
        msg,
        "candidates",
        {
            "tool": "zap",
            "findings": [f.model_dump(mode="json") for f in findings],
            # Achados próprios já confirmados (A07/A08): upsert direto na validação, sem re-testar.
            "proactive": [f.model_dump(mode="json") for f in proactive],
        },
    )
    publish(r, STREAM_CANDIDATES, out)
