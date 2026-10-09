"""Tabelas do Postgres. O schema é versionado em `migrations/` (Alembic) — dono: Ahmed."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

JsonType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


class Scan(Base):
    """Escrita pela etapa 1 (autorização). As etapas 4-6 só leem `verified`/`scope`."""

    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(64), index=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    scope_locked: Mapped[bool] = mapped_column(Boolean, default=False)
    scope: Mapped[dict[str, object]] = mapped_column(JsonType)
    # requested → web_scanning → validating → reporting → done (ou failed). Ver ScanStatus.
    status: Mapped[str] = mapped_column(String(32), default="pending")
    status_detail: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Progresso da fase atual (para a tela não parecer travada). pct=None = indeterminado.
    progress_pct: Mapped[int | None] = mapped_column(nullable=True)
    progress_info: Mapped[str | None] = mapped_column(String(80), nullable=True)
    phase_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    progress_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Etapa 4: páginas rastreadas (para o portão de cobertura; None = ainda não medido).
    pages_crawled: Mapped[int | None] = mapped_column(nullable=True)
    # Entrega parcial: o alvo caiu/ficou instável no meio e o scan não completou o ativo.
    partial: Mapped[bool] = mapped_column(Boolean, default=False)
    partial_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Operador pediu para parar a espera e entregar o parcial agora (lido pelo worker no laço).
    stop_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    requested_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_scan_status", "scan_id", "status"),)

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id"), index=True)
    status: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    cwe: Mapped[int | None]
    data: Mapped[dict[str, object]] = mapped_column(JsonType)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ProcessedMessage(Base):
    """Idempotência: (stream, message_id) processado uma única vez."""

    __tablename__ = "processed_messages"

    stream: Mapped[str] = mapped_column(String(64), primary_key=True)
    message_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Report(Base):
    __tablename__ = "reports"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id"), primary_key=True)
    report_json: Mapped[dict[str, object]] = mapped_column(JsonType)
    html: Mapped[str] = mapped_column(Text)
    pdf: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RemediationCache(Base):
    """Texto de remediação por (CWE/regra, stack, idioma) — independe do cliente."""

    __tablename__ = "remediation_cache"

    cache_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule: Mapped[str] = mapped_column(String(64))
    stack: Mapped[str] = mapped_column(String(128))
    language: Mapped[str] = mapped_column(String(16))
    prompt_version: Mapped[str] = mapped_column(String(32))
    content: Mapped[dict[str, object]] = mapped_column(JsonType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TargetAuthConfig(Base):
    """Config de scan autenticado por site — só a parte NÃO sensível.

    A senha nunca fica aqui (regra do CLAUDE.md: credencial de teste não é persistida). É digitada
    ao iniciar o scan e usada só naquela execução. Aqui guardamos o "formato" do login: para onde
    enviar, qual usuário, onde achar o token na resposta e um recurso protegido (checagem A08).
    """

    __tablename__ = "target_auth_config"

    target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"), primary_key=True)
    login_url: Mapped[str] = mapped_column(String(2048))
    email: Mapped[str] = mapped_column(String(320))
    # Caminho pontuado onde o token está na resposta de login, ex.: "authentication.token".
    token_path: Mapped[str] = mapped_column(String(200), default="token")
    protected_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ManualCheckResult(Base):
    """Estado de um item de revisão manual (A06/A09) por scan — marcado por uma pessoa.

    O catálogo dos itens é estático (scanner/report/manual_checks.py); aqui fica só o que o
    revisor decidiu: pending (padrão) | ok | fail | na, com nota opcional.
    """

    __tablename__ = "manual_check_results"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id"), primary_key=True)
    check_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    state: Mapped[str] = mapped_column(String(16), default="pending")
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class CrawlMemory(Base):
    """Memória de rastreio por alvo: as URLs já descobertas em scans anteriores.

    Semeadas no início do próximo scan (etapa 4), para a cobertura ser monotônica — um site
    raramente encolhe, então o scan de hoje começa do que já conhecíamos e só acrescenta. Uma
    linha por alvo; `routes` é a união acumulada (limitada por `crawl_memory_max_routes`).
    """

    __tablename__ = "crawl_memory"

    target_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    routes: Mapped[list[str]] = mapped_column(JsonType, default=list)
    scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)  # último que atualizou
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ScanStatus:
    REQUESTED = "requested"
    RECON = "recon"
    CVE_SCANNING = "cve_scanning"
    WEB_SCANNING = "web_scanning"
    VALIDATING = "validating"
    REPORTING = "reporting"
    DONE = "done"
    FAILED = "failed"
    ACTIVE = (REQUESTED, RECON, CVE_SCANNING, WEB_SCANNING, VALIDATING, REPORTING)


class Organization(Base):
    """Cliente (empresa). Usuários `client` só enxergam o que é da própria organização."""

    __tablename__ = "organizations"

    org_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(16))  # "admin" | "client"
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.org_id"), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Target(Base):
    """Site de um cliente. Só vira alvo de scan depois de verificado (regra 1).

    `scans.target_id` aponta para cá (sem FK: a etapa 1 também cria scans).
    """

    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("org_id", "domain", name="uq_targets_org_domain"),)

    target_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.org_id"), index=True)
    domain: Mapped[str] = mapped_column(String(253))
    base_url: Mapped[str] = mapped_column(String(2048))
    verification_token: Mapped[str] = mapped_column(String(64))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_check_error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    # Preferência lida pela etapa 7 (recorrência): manual | weekly | monthly.
    recurrence: Mapped[str] = mapped_column(String(16), default="manual")
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """Quem fez o quê: login, revisão humana de achado, gestão de usuários, scans iniciados."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    org_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detail: Mapped[dict[str, object]] = mapped_column(JsonType, default=dict)


def set_pages_crawled(sessions, scan_id: str, pages: int) -> None:  # type: ignore[no-untyped-def]
    """Grava quantas páginas o rastreio alcançou (portão de cobertura)."""
    with sessions.begin() as session:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            scan.pages_crawled = pages


def get_known_routes(sessions, target_id: str) -> list[str]:  # type: ignore[no-untyped-def]
    """URLs já descobertas em scans anteriores deste alvo (vazio se for o primeiro)."""
    with sessions() as session:
        mem = session.get(CrawlMemory, target_id)
        return list(mem.routes) if mem is not None else []


_STATIC_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|webp|js|mjs|css|woff2?|ttf|eot|map)(\?|$)", re.I
)


def route_signature(url: str) -> str:
    """Identidade ESTÁVEL de uma rota: esquema://host/caminho?nomes-de-parâmetro (ordenados).

    O valor dos parâmetros e o fragmento são descartados, a barra final e o host são normalizados.
    Assim `/search?q=a` e `/search?q=b` são a MESMA rota (`/search?q`): o scan ativo injeta nos
    parâmetros, não depende do valor. É a unidade de "página" e de memória; sem ela, a contagem de
    páginas e de achados oscila conforme os valores que o rastreio sorteou visitar.
    """
    parts = urlsplit(url.strip())
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    base = f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}"
    return f"{base}?{','.join(names)}" if names else base


def has_repeated_segment(url: str) -> bool:
    """True se o caminho repete o nome de uma pasta (`/assets/assets/…`, `/a/i18n/a/…`).

    É a assinatura da "armadilha de spider": links relativos num SPA resolvem para combinações de
    pastas sem fim, cada profundidade virando um caminho distinto. Essas URLs não têm superfície de
    ataque nova (o app serve o mesmo conteúdo) e, pior, QUANTAS aparecem depende da profundidade que
    o rastreio alcançou naquele run — a causa da variação de páginas/achados entre scans.
    """
    segments = [s for s in urlsplit(url).path.split("/") if s]
    return len(segments) != len(set(segments))


def canonical_routes(urls: Iterable[str]) -> list[str]:
    """Rotas distintas, determinísticas e estáveis a partir de uma lista de URLs rastreadas.

    1. DESCARTA artefatos de armadilha de spider (caminho com pasta repetida). O descarte não
       depende da profundidade alcançada, então o conjunto é o mesmo a cada scan — base da
       consistência. (Custo aceito: uma rota real que repita o NOME de uma pasta, raro, fica de
       fora do scan; nunca gera falso negativo de falha, só evita contar reflexos.)
    2. Agrupa o resto por assinatura de rota, com representante determinístico (a URL mais curta;
       empate: alfabética) para semear a forma limpa.
    """
    best: dict[str, str] = {}
    for url in urls:
        if has_repeated_segment(url):
            continue
        sig = route_signature(url)
        current = best.get(sig)
        if current is None or (len(url), url) < (len(current), current):
            best[sig] = url
    return sorted(best.values())


def route_priority(url: str) -> int:
    """Valor de uma URL para re-testar: maior = mais importante manter na memória.

    O scan ativo só rende em URL com parâmetro ou endpoint de API; arquivo estático (imagem/js/css)
    não tem superfície de ataque. Ao estourar o teto, guardamos primeiro o que vale.
    """
    u = url.lower()
    if "?" in u:  # tem parâmetro -> diretamente atacável
        return 3
    if "/rest/" in u or "/api/" in u or "/graphql" in u:  # endpoint de API
        return 2
    if _STATIC_EXT.search(u):  # estático -> menor valor
        return 0
    return 1  # página/rota comum


def remember_routes(  # type: ignore[no-untyped-def]
    sessions, target_id: str, scan_id: str, routes: list[str], max_routes: int = 2000
) -> None:
    """Acumula as URLs rastreadas na memória do alvo (união com o que já havia).

    Ao estourar `max_routes`, mantém as URLs de MAIOR valor para re-teste (parâmetro > API >
    página > estático) em vez de cortar por ordem alfabética — senão o teto enche de imagem/js e
    descarta o endpoint que tem a falha. Idempotente: reprocessar o mesmo scan não muda o conjunto.
    """
    with sessions.begin() as session:
        mem = session.get(CrawlMemory, target_id)
        existing = [] if mem is None else list(mem.routes)
        # Colapsa por assinatura de rota: a memória CONVERGE para as rotas distintas do site e para
        # de crescer (idempotente). Sem isto, cada permutação de query inflava o conjunto por scan.
        merged = canonical_routes(existing + list(routes))
        if len(merged) > max_routes:
            # Teto de segurança: ao estourar, mantém o de MAIOR valor (parâmetro > API > página).
            merged = sorted(merged, key=lambda u: (-route_priority(u), u))[:max_routes]
            merged.sort()  # ordem estável (alfabética) para leitura/diff
        if mem is None:
            session.add(CrawlMemory(target_id=target_id, routes=merged, scan_id=scan_id))
        else:
            mem.routes = merged
            mem.scan_id = scan_id


def last_pages_crawled(  # type: ignore[no-untyped-def]
    sessions, target_id: str, exclude_scan_id: str
) -> int | None:
    """Cobertura do scan anterior deste alvo (para detectar regressão); None se não houver."""
    with sessions() as session:
        row = (
            session.query(Scan.pages_crawled)
            .filter(
                Scan.target_id == target_id,
                Scan.scan_id != exclude_scan_id,
                Scan.pages_crawled.isnot(None),
            )
            .order_by(Scan.created_at.desc())
            .first()
        )
        return row[0] if row is not None else None


def request_stop(sessions, scan_id: str) -> None:  # type: ignore[no-untyped-def]
    """Interface pede ao worker para parar a espera e entregar o parcial (marca a hora)."""
    with sessions.begin() as session:
        scan = session.get(Scan, scan_id)
        if scan is not None and scan.stop_requested_at is None:
            scan.stop_requested_at = datetime.now(UTC)


def is_stop_requested(sessions, scan_id: str) -> bool:  # type: ignore[no-untyped-def]
    """O worker consulta no laço de espera se o operador pediu para entregar o parcial."""
    with sessions() as session:
        scan = session.get(Scan, scan_id)
        return scan is not None and scan.stop_requested_at is not None


def mark_partial(sessions, scan_id: str, reason: str) -> None:  # type: ignore[no-untyped-def]
    """Marca o scan como entrega parcial (alvo instável), com o motivo, para a interface avisar."""
    with sessions.begin() as session:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            scan.partial = True
            scan.partial_reason = reason


def set_scan_status(
    sessions: sessionmaker,  # type: ignore[type-arg]
    scan_id: str,
    status: str,
    detail: str | None = None,
    pct: int | None = None,
    info: str | None = None,
) -> None:
    """Atualiza o andamento numa transação própria (a do worker pode durar o scan inteiro).

    `pct` (0-100) e `info` descrevem a fase atual; a tela usa a hora em que a fase começou
    (`phase_started_at`) e a da última medição (`progress_at`) para estimar o tempo que falta.
    """
    now = datetime.now(UTC)
    with sessions.begin() as session:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            if scan.status_detail != detail:  # mudou de fase: reinicia o relógio da fase
                scan.phase_started_at = now
            scan.status = status
            scan.status_detail = detail
            scan.progress_pct = pct
            scan.progress_info = info
            scan.progress_at = now


def make_session_factory(database_url: str) -> sessionmaker:  # type: ignore[type-arg]
    engine: Engine = create_engine(database_url, pool_pre_ping=True)
    return sessionmaker(engine, expire_on_commit=False)


class StageProgress(Base):
    """Quais fontes (zap/nuclei) já entregaram candidatos para o scan.

    PROVISÓRIO: como a etapa 3 sinaliza "terminei" ainda precisa ser combinado com o time.
    """

    __tablename__ = "stage_progress"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id"), primary_key=True)
    tool: Mapped[str] = mapped_column(String(16), primary_key=True)
    done_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class StagingAuthorization(Base):
    """Liberação do perfil intrusivo para uma CÓPIA de teste (homologação) do site do cliente.

    Fluxo e regras em `scanner/common/staging.py`. Guarda o que foi assinado (versão e hash do
    termo, checklist, quem, de onde) e a revisão do time. Nunca vale para o site oficial: o
    escopo do scan tem de ser exatamente `staging_host`.
    """

    __tablename__ = "staging_authorizations"

    auth_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.org_id"), index=True)
    production_target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"), index=True)
    staging_target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"), index=True)
    staging_host: Mapped[str] = mapped_column(String(253))
    status: Mapped[str] = mapped_column(String(16))  # draft|requested|approved|rejected|revoked
    scope_level: Mapped[str] = mapped_column(  # intrusive|stress (stress libera o agressivo)
        String(16), default="intrusive", server_default="intrusive"
    )
    checklist: Mapped[dict[str, object]] = mapped_column(JsonType, default=dict)
    term_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    term_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signer_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    signer_role: Mapped[str | None] = mapped_column(String(200), nullable=True)
    signer_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signer_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    emergency_contact: Mapped[str | None] = mapped_column(String(200), nullable=True)
    valid_days: Mapped[int | None] = mapped_column(nullable=True)
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
