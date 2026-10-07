"""Regras da interface: iniciar scan, comparar scans, revisão humana, auditoria e operação."""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError
from sqlalchemy import event, func, select
from sqlalchemy.orm import Session, sessionmaker

from scanner.common.db import (
    AuditLog,
    FindingRow,
    Report,
    Scan,
    ScanStatus,
    Target,
    set_scan_status,
)
from scanner.common.models import Finding, Outcome, Scope, StageMessage, Status, Validation
from scanner.common.queue import (
    DEAD_LETTER_SUFFIX,
    STREAM_CANDIDATES,
    STREAM_REPORT_READY,
    STREAM_VALIDATED,
    STREAM_WEB_REQUESTED,
)
from scanner.report.models import Report as ReportModel
from scanner.report.models import ReportItem
from scanner.web.tenancy import Viewer
from scanner.web_scan import policy

Publisher = Callable[[str, StageMessage], None]
log = logging.getLogger(__name__)


class ScanNotAllowedError(Exception):
    """`code` é o que a rota põe na URL (`?erro=`); só códigos conhecidos viram texto na tela."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def audit(
    session: Session,
    viewer: Viewer | None,
    action: str,
    *,
    org_id: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    **detail: Any,
) -> None:
    session.add(
        AuditLog(
            user_id=viewer.user_id if viewer else None,
            org_id=org_id if org_id is not None else (viewer.org_id if viewer else None),
            action=action,
            object_type=object_type,
            object_id=object_id,
            detail=detail,
        )
    )


# --- scans ------------------------------------------------------------------------------


def active_scan(session: Session, target_id: str) -> Scan | None:
    return session.scalars(
        select(Scan)
        .where(Scan.target_id == target_id, Scan.status.in_(ScanStatus.ACTIVE))
        .order_by(Scan.created_at.desc())
        .limit(1)
    ).first()


def scope_for(target: Target) -> Scope:
    host = urlsplit(target.base_url).hostname or target.domain
    return Scope(
        scope_id=f"site-{target.target_id}",
        verified=True,
        locked=True,
        base_urls=[target.base_url],
        allowed_hosts=[host],
    )


def profiles_for(viewer: Viewer, target: Target, lab_hosts: list[str]) -> list[policy.ScanProfile]:
    """Perfis que esta pessoa pode pedir para este site.

    Os não destrutivos, para todos. O agressivo só para admin E só em site de laboratório: a
    interface é por onde o cliente aponta o scanner para produção, e lá ele nunca aparece.
    """
    lab = policy.is_lab_scope(scope_for(target).allowed_hosts, lab_hosts)
    return [p for p in policy.PROFILES.values() if not p.destructive or (viewer.is_admin and lab)]


def start_scan(
    session: Session,
    viewer: Viewer,
    target: Target,
    publish: Publisher,
    lab_hosts: list[str],
    profile: str = "safe",
) -> Scan:
    """Regra 1: só site verificado; e um scan por vez por site.

    Perfil destrutivo: só admin e só em site de laboratório (`profiles_for`), conferido aqui de
    novo porque o formulário pode ser forjado. A trava definitiva continua no worker-web
    (`resolve_profile`), que vale para qualquer origem da mensagem.
    """
    if target.verified_at is None:
        raise ScanNotAllowedError(
            "nao-verificado", "Comprove que o domínio é seu antes de iniciar um scan."
        )
    if active_scan(session, target.target_id) is not None:
        raise ScanNotAllowedError("em-andamento", "Já existe um scan em andamento para este site.")
    requested = policy.resolve(profile)
    if requested not in profiles_for(viewer, target, lab_hosts):
        raise ScanNotAllowedError(
            "perfil-nao-permitido", "Esse nível de scan não está liberado para este site."
        )
    scope = scope_for(target)
    scan = Scan(
        scan_id=f"scan-{uuid.uuid4().hex[:12]}",
        target_id=target.target_id,
        verified=True,
        scope_locked=True,
        scope=scope.model_dump(mode="json"),
        status=ScanStatus.REQUESTED,
        requested_by=viewer.user_id,
    )
    session.add(scan)
    session.flush()
    audit(
        session,
        viewer,
        "scan.start",
        org_id=target.org_id,
        object_type="scan",
        object_id=scan.scan_id,
        target=target.domain,
        profile=requested.name,
        destructive=requested.destructive,
    )
    msg = StageMessage(
        message_id=f"{scan.scan_id}:web.requested",
        scan_id=scan.scan_id,
        target_id=target.target_id,
        stage="web.requested",
        scope=scope,
        payload={"profile": requested.name},
    )
    # Publicar só depois do commit: o worker confere o scan no banco (`check_authorized`) assim que
    # lê a mensagem; antes do commit ele não acharia a linha e recusaria o scan como não autorizado.
    bind = session.get_bind()

    def publish_committed(_session: Session) -> None:
        try:
            publish(STREAM_WEB_REQUESTED, msg)
        except Exception:
            # Já está gravado: sem a mensagem ninguém o processaria e o site ficaria "em andamento"
            # para sempre. Fecha como falha, e a pessoa pode pedir de novo.
            log.exception("fila indisponível ao pedir scan", extra={"scan_id": msg.scan_id})
            set_scan_status(sessionmaker(bind), msg.scan_id, ScanStatus.FAILED, "fila indisponível")

    event.listen(session, "after_commit", publish_committed, once=True)
    return scan


def load_report(report: Report | None) -> ReportModel | None:
    """None também para relatório num formato antigo: a tela trata como "sem relatório"."""
    if report is None:
        return None
    try:
        return ReportModel.model_validate(report.report_json)
    except ValidationError:
        log.warning("relatório em formato antigo", extra={"scan": report.scan_id})
        return None


def previous_done_scan(session: Session, scan: Scan) -> Scan | None:
    return session.scalars(
        select(Scan)
        .join(Report, Report.scan_id == Scan.scan_id)
        .where(
            Scan.target_id == scan.target_id,
            Scan.created_at < scan.created_at,
            Scan.status == ScanStatus.DONE,
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    ).first()


@dataclass
class Comparison:
    new: list[ReportItem] = field(default_factory=list)
    fixed: list[ReportItem] = field(default_factory=list)
    persisting: list[ReportItem] = field(default_factory=list)

    @property
    def has_previous(self) -> bool:
        return bool(self.new or self.fixed or self.persisting)


def compare(current: ReportModel, previous: ReportModel | None) -> Comparison | None:
    """O que mudou desde o scan anterior do mesmo site (por falha, não por página)."""
    if previous is None:
        return None
    before = {i.group_key: i for i in previous.items}
    now = {i.group_key: i for i in current.items}
    return Comparison(
        new=[i for k, i in now.items() if k not in before],
        fixed=[i for k, i in before.items() if k not in now],
        persisting=[i for k, i in now.items() if k in before],
    )


def item_id(group_key: str) -> str:
    """Identificador curto e estável de uma falha (grupo) para usar na URL."""
    return hashlib.sha256(group_key.encode()).hexdigest()[:12]


# --- revisão humana (admin) -------------------------------------------------------------


def review_finding(
    session: Session,
    viewer: Viewer,
    scan: Scan,
    finding_id: str,
    decision: str,
    reason: str,
) -> None:
    """Admin marca falso positivo (com motivo) ou reabre. Nunca automático, nunca pelo LLM."""
    if not viewer.is_admin:
        raise PermissionError("só admin revisa achados")
    reason = reason.strip()
    if decision == "false_positive" and len(reason) < 10:
        raise ValueError("Explique o motivo (pelo menos 10 caracteres).")
    row = session.get(FindingRow, finding_id)
    if row is None or row.scan_id != scan.scan_id:
        raise LookupError("achado não encontrado neste scan")
    finding = Finding.model_validate(row.data)
    before = finding.status
    if decision == "false_positive":
        status, outcome = Status.FALSE_POSITIVE, Outcome.FALSE_POSITIVE
    elif decision == "reopen":
        status, outcome = Status.UNCONFIRMED, Outcome.UNCONFIRMED
        reason = reason or "reaberto na revisão humana"
    else:
        raise ValueError("decisão inválida")
    updated = finding.model_copy(
        update={
            "status": status,
            "validation": Validation(
                validator=f"revisao_humana:{viewer.email}",
                outcome=outcome,
                reason=reason,
                proof=finding.validation.proof if finding.validation else None,
                validated_at=datetime.now(UTC),
            ),
        }
    )
    row.status = status.value
    row.data = updated.model_dump(mode="json")
    target = session.get(Target, scan.target_id)
    audit(
        session,
        viewer,
        "finding.review",
        org_id=target.org_id if target else None,
        object_type="finding",
        object_id=finding_id,
        scan_id=scan.scan_id,
        before=before.value,
        after=status.value,
        reason=reason,
    )


def reviews_since_report(session: Session, scan_id: str, report: Report | None) -> int:
    if report is None:
        return 0
    return (
        session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == "finding.review",
                AuditLog.detail["scan_id"].as_string() == scan_id,
                AuditLog.at > report.created_at,
            )
        )
        or 0
    )


def request_report_regeneration(
    session: Session, viewer: Viewer, scan: Scan, publish: Publisher, tools_done: list[str]
) -> None:
    target = session.get(Target, scan.target_id)
    audit(
        session,
        viewer,
        "report.regenerate",
        org_id=target.org_id if target else None,
        object_type="scan",
        object_id=scan.scan_id,
    )
    publish(
        STREAM_VALIDATED,
        StageMessage(
            message_id=f"{scan.scan_id}:regenerate:{uuid.uuid4().hex[:8]}",
            scan_id=scan.scan_id,
            target_id=scan.target_id,
            stage="validated",
            scope=Scope.model_validate(scan.scope),
            payload={"tools_done": tools_done, "regenerate": True},
        ),
    )


# --- operação (admin) -------------------------------------------------------------------

STREAMS = [
    (STREAM_WEB_REQUESTED, "web_scan"),
    (STREAM_CANDIDATES, "validation"),
    (STREAM_VALIDATED, "report"),
    (STREAM_REPORT_READY, None),
]


@dataclass
class StreamInfo:
    name: str
    group: str | None
    length: int
    pending: int
    dead: int
    consumers: list[dict[str, Any]]
    dead_entries: list[dict[str, str]]


def queue_status(r: Any) -> list[StreamInfo]:
    out = []
    for name, group in STREAMS:
        pending, consumers = 0, []
        if group:
            try:
                pending = int(r.xpending(name, group).get("pending", 0))
                consumers = [
                    {
                        "name": c["name"].decode() if isinstance(c["name"], bytes) else c["name"],
                        "pending": c["pending"],
                        "idle_s": int(c["idle"]) // 1000,
                    }
                    for c in r.xinfo_consumers(name, group)
                ]
            except Exception as exc:  # grupo ainda não criado: mostra só o tamanho
                log.debug("sem grupo de consumo", extra={"stream": name, "error": str(exc)})
        dead_name = name + DEAD_LETTER_SUFFIX
        dead_entries = []
        for entry_id, fields in r.xrevrange(dead_name, count=10):
            error = fields.get(b"error", b"")
            dead_entries.append(
                {
                    "id": entry_id.decode() if isinstance(entry_id, bytes) else str(entry_id),
                    "error": error.decode(errors="replace")[:300]
                    if isinstance(error, bytes)
                    else str(error),
                }
            )
        out.append(
            StreamInfo(
                name=name,
                group=group,
                length=int(r.xlen(name)),
                pending=pending,
                dead=int(r.xlen(dead_name)),
                consumers=consumers,
                dead_entries=dead_entries,
            )
        )
    return out
