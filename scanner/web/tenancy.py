"""Isolamento entre clientes. TODA leitura de site/scan/relatório da interface passa por aqui.

Cliente só enxerga a própria organização; admin enxerga todas. Objeto de outra organização
responde 404 — não 403 — para não revelar que ele existe.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from scanner.common.db import Organization, Report, Scan, StagingAuthorization, Target, User


@dataclass(frozen=True)
class Viewer:
    user_id: str
    name: str
    email: str
    role: str
    org_id: str | None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @classmethod
    def of(cls, user: User) -> Viewer:
        return cls(user.user_id, user.name, user.email, user.role, user.org_id)


def not_found() -> HTTPException:
    return HTTPException(status_code=404, detail="Não encontrado.")


def targets_query(viewer: Viewer) -> Select[Target]:
    q = select(Target).order_by(Target.created_at)
    if not viewer.is_admin:
        q = q.where(Target.org_id == viewer.org_id)
    return q


def get_target(session: Session, viewer: Viewer, target_id: str) -> Target:
    target = session.get(Target, target_id)
    if target is None or (not viewer.is_admin and target.org_id != viewer.org_id):
        raise not_found()
    return target


def get_scan(session: Session, viewer: Viewer, scan_id: str) -> tuple[Scan, Target | None]:
    """Scan sem site cadastrado (ex.: criado só pela etapa 1) é visível apenas para admin."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise not_found()
    target = session.get(Target, scan.target_id)
    if not viewer.is_admin and (target is None or target.org_id != viewer.org_id):
        raise not_found()
    return scan, target


def scans_query(viewer: Viewer, target_id: str | None = None) -> Select[Scan]:
    q = select(Scan).order_by(Scan.created_at.desc())
    if target_id is not None:
        q = q.where(Scan.target_id == target_id)
    if not viewer.is_admin:
        q = q.join(Target, Target.target_id == Scan.target_id).where(Target.org_id == viewer.org_id)
    return q


def get_report(session: Session, viewer: Viewer, scan_id: str) -> tuple[Scan, Report | None]:
    scan, _ = get_scan(session, viewer, scan_id)
    return scan, session.get(Report, scan_id)


def org_name(session: Session, org_id: str | None) -> str | None:
    org = session.get(Organization, org_id) if org_id else None
    return org.name if org else None


def get_staging(session: Session, viewer: Viewer, auth_id: str) -> StagingAuthorization:
    """Pedido de cópia de teste (homologação) — mesma regra: de outra organização, 404."""
    row = session.get(StagingAuthorization, auth_id)
    if row is None or (not viewer.is_admin and row.org_id != viewer.org_id):
        raise not_found()
    return row
