"""Tabelas do Postgres. O schema é versionado em `migrations/` (Alembic) — dono: Ahmed."""

from __future__ import annotations

from datetime import UTC, datetime

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


def remember_routes(  # type: ignore[no-untyped-def]
    sessions, target_id: str, scan_id: str, routes: list[str], max_routes: int = 2000
) -> None:
    """Acumula as URLs rastreadas na memória do alvo (união com o que já havia).

    Monotônico: só cresce. Ordenado e limitado a `max_routes` para não inchar a linha nem a
    próxima semeadura. Idempotente: reprocessar o mesmo scan não muda o conjunto.
    """
    with sessions.begin() as session:
        mem = session.get(CrawlMemory, target_id)
        merged = sorted(set(routes) if mem is None else set(mem.routes) | set(routes))[:max_routes]
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
