"""Lógica da recorrência: quais alvos estão vencidos e disparo do novo scan."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from scanner.common.db import Scan, ScanStatus, Target
from scanner.common.models import StageMessage
from scanner.common.queue import STREAM_RECON_REQUESTED
from scanner.common.scope import scope_for

log = logging.getLogger(__name__)

# Intervalo por preferência de recorrência. "manual" não entra (só roda quando o cliente pede).
INTERVALS: dict[str, timedelta] = {
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
}

Publisher = Callable[[str, StageMessage], None]


def is_due(recurrence: str, last_scan_at: datetime | None, now: datetime) -> bool:
    """True se o alvo deve ser re-escaneado agora (função pura)."""
    interval = INTERVALS.get(recurrence)
    if interval is None:
        return False
    if last_scan_at is None:
        return True  # nunca escaneado, mas com recorrência ligada
    if last_scan_at.tzinfo is None:  # SQLite devolve sem fuso; Postgres já vem com fuso
        last_scan_at = last_scan_at.replace(tzinfo=UTC)
    return now - last_scan_at >= interval


def _latest_scan_at(session: Session, target_id: str) -> datetime | None:
    return session.scalars(
        select(Scan.created_at)
        .where(Scan.target_id == target_id)
        .order_by(Scan.created_at.desc())
        .limit(1)
    ).first()


def _has_active_scan(session: Session, target_id: str) -> bool:
    return (
        session.scalars(
            select(Scan.scan_id)
            .where(Scan.target_id == target_id, Scan.status.in_(ScanStatus.ACTIVE))
            .limit(1)
        ).first()
        is not None
    )


def due_targets(session: Session, now: datetime) -> list[Target]:
    """Alvos verificados, com recorrência ligada, vencidos e sem scan em andamento."""
    candidates = session.scalars(
        select(Target).where(
            Target.recurrence.in_(tuple(INTERVALS)), Target.verified_at.is_not(None)
        )
    ).all()
    due: list[Target] = []
    for t in candidates:
        if _has_active_scan(session, t.target_id):
            continue  # um scan por vez por site
        if is_due(t.recurrence, _latest_scan_at(session, t.target_id), now):
            due.append(t)
    return due


def run_once(
    sessions: sessionmaker,  # type: ignore[type-arg]
    publish: Publisher,
    now: datetime | None = None,
) -> int:
    """Dispara um scan para cada alvo vencido. Devolve quantos foram disparados."""
    now = now or datetime.now(UTC)
    pending: list[StageMessage] = []
    with sessions.begin() as session:
        for target in due_targets(session, now):
            scan_id = f"scan-{uuid.uuid4().hex[:12]}"
            scope = scope_for(target)
            session.add(
                Scan(
                    scan_id=scan_id,
                    target_id=target.target_id,
                    verified=True,
                    scope_locked=True,
                    scope=scope.model_dump(mode="json"),
                    status=ScanStatus.REQUESTED,
                    requested_by="recurrence",
                )
            )
            pending.append(
                StageMessage(
                    message_id=f"{scan_id}:recon.requested",
                    scan_id=scan_id,
                    target_id=target.target_id,
                    stage="recon.requested",
                    scope=scope,
                    payload={"profile": "safe"},
                )
            )
    # Publicar só após o commit: o worker-recon confere o scan no banco ao ler a mensagem.
    for msg in pending:
        publish(STREAM_RECON_REQUESTED, msg)
    if pending:
        log.info("recorrência disparou scans", extra={"count": len(pending)})
    return len(pending)
