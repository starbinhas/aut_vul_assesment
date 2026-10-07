"""Dependências das rotas: sessão do banco, usuário logado e renderização dos templates."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from scanner.common.db import User
from scanner.web import labels
from scanner.web.security import CSRF_FIELD, CSRF_HEADER, csrf_token
from scanner.web.tenancy import Viewer, not_found, org_name

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
TZ = ZoneInfo("America/Sao_Paulo")


class LoginRequiredError(Exception):
    def __init__(self, next_path: str) -> None:
        self.next_path = next_path


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.sessions.begin() as session:
        yield session


def current_viewer(request: Request, db: Session = Depends(get_db)) -> Viewer:
    uid = request.session.get("uid")
    user = db.get(User, uid) if uid else None
    if user is None or not user.is_active:
        request.session.clear()
        raise LoginRequiredError(request.url.path)
    return Viewer.of(user)


def admin_viewer(viewer: Viewer = Depends(current_viewer)) -> Viewer:
    if not viewer.is_admin:
        raise not_found()  # a área admin "não existe" para o cliente
    return viewer


def _local(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(TZ)


def fmt_dt(dt: datetime | None) -> str:
    local = _local(dt)
    return local.strftime("%d/%m/%Y %H:%M") if local else "—"


def fmt_ago(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    seconds = int((datetime.now(UTC) - dt).total_seconds())
    if seconds < 60:
        return "agora"
    if seconds < 3600:
        return f"há {seconds // 60} min"
    if seconds < 86400:
        return f"há {seconds // 3600} h"
    days = seconds // 86400
    return "ontem" if days == 1 else f"há {days} dias"


def _human_duration(seconds: float) -> str:
    if seconds < 60:
        return "menos de 1 min"
    minutes = round(seconds / 60)
    if minutes < 60:
        return f"~{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"~{hours} h {minutes} min" if minutes else f"~{hours} h"


def scan_eta(scan: Any) -> str | None:
    """Tempo estimado para a fase atual terminar, a partir do ritmo observado até agora.

    É uma estimativa: o percentual do ZAP não é perfeitamente linear. Só para dar noção.
    """
    pct = scan.progress_pct
    started, at = scan.phase_started_at, scan.progress_at
    if not pct or pct <= 0 or pct >= 100 or started is None or at is None:
        return None
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    elapsed = (at - started).total_seconds()
    if elapsed <= 0:
        return None
    return _human_duration(elapsed * (100 - pct) / pct)


TEMPLATES.env.filters.update(
    severity=labels.severity,
    status=labels.status,
    phase=labels.phase,
    scan_status=labels.scan_status,
    dt=fmt_dt,
    ago=fmt_ago,
    plural=labels.plural,
    audit=labels.audit_action,
    sentence=labels.sentence,
)
TEMPLATES.env.globals["scan_eta"] = scan_eta


def render(
    request: Request,
    template: str,
    viewer: Viewer | None,
    db: Session | None = None,
    status_code: int = 200,
    **context: Any,
) -> HTMLResponse:
    context.update(
        viewer=viewer,
        org_name=org_name(db, viewer.org_id) if (db and viewer) else None,
        csrf=csrf_token(request),
        csrf_field=CSRF_FIELD,
        csrf_header=CSRF_HEADER,
        path=request.url.path,
        htmx=request.headers.get("hx-request") == "true",
    )
    return TEMPLATES.TemplateResponse(request, template, context, status_code=status_code)
