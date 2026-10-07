"""Área admin: tudo do cliente (todas as organizações) + clientes, equipe, operação, revisão."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scanner.common.db import (
    AuditLog,
    Organization,
    Report,
    Scan,
    ScanStatus,
    StageProgress,
    Target,
    User,
)
from scanner.web.deps import admin_viewer, get_db, render
from scanner.web.security import csrf_protect, generate_password, hash_password
from scanner.web.services import (
    audit,
    queue_status,
    request_report_regeneration,
    review_finding,
)
from scanner.web.tenancy import Viewer, get_scan, not_found

router = APIRouter(prefix="/admin", dependencies=[Depends(csrf_protect), Depends(admin_viewer)])


def _count(db: Session, stmt) -> int:  # type: ignore[no-untyped-def]
    return int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)


@router.get("")
def overview(
    request: Request, viewer: Viewer = Depends(admin_viewer), db: Session = Depends(get_db)
) -> Response:
    running = db.scalars(
        select(Scan).where(Scan.status.in_(ScanStatus.ACTIVE)).order_by(Scan.created_at.desc())
    ).all()
    try:
        queues = queue_status(request.app.state.redis)
        queue_error = None
    except Exception as exc:  # Redis fora do ar não pode derrubar a tela admin
        queues, queue_error = [], str(exc)
    return render(
        request,
        "admin/overview.html",
        viewer,
        db,
        counts={
            "orgs": _count(db, select(Organization)),
            "clients": _count(db, select(User).where(User.role == "client")),
            "sites": _count(db, select(Target)),
            "verified": _count(db, select(Target).where(Target.verified_at.is_not(None))),
            "scans": _count(db, select(Scan)),
        },
        running=running,
        queues=queues,
        queue_error=queue_error,
        dead_total=sum(q.dead for q in queues),
        recent_audit=db.scalars(select(AuditLog).order_by(AuditLog.at.desc()).limit(8)).all(),
        sites={t.target_id: t for t in db.scalars(select(Target))},
    )


# --- clientes (organizações) e usuários --------------------------------------------------


@router.get("/clientes")
def orgs(
    request: Request, viewer: Viewer = Depends(admin_viewer), db: Session = Depends(get_db)
) -> Response:
    rows = []
    for org in db.scalars(select(Organization).order_by(Organization.name)):
        rows.append(
            (
                org,
                _count(db, select(User).where(User.org_id == org.org_id)),
                _count(db, select(Target).where(Target.org_id == org.org_id)),
            )
        )
    return render(request, "admin/orgs.html", viewer, db, rows=rows, error=None)


@router.post("/clientes")
def org_create(
    request: Request,
    name: str = Form(...),
    viewer: Viewer = Depends(admin_viewer),
    db: Session = Depends(get_db),
) -> Response:
    name = name.strip()
    if len(name) < 2:
        return RedirectResponse("/admin/clientes", 303)
    org = Organization(org_id=f"org-{uuid.uuid4().hex[:12]}", name=name[:200])
    db.add(org)
    audit(
        db,
        viewer,
        "org.create",
        org_id=org.org_id,
        object_type="org",
        object_id=org.org_id,
        name=org.name,
    )
    return RedirectResponse(f"/admin/clientes/{org.org_id}", 303)


def _org_page(
    request: Request,
    db: Session,
    viewer: Viewer,
    org: Organization,
    status_code: int = 200,
    **extra: object,
) -> Response:
    users = db.scalars(select(User).where(User.org_id == org.org_id).order_by(User.name)).all()
    sites = db.scalars(select(Target).where(Target.org_id == org.org_id)).all()
    extra.setdefault("new_password", None)
    extra.setdefault("error", None)
    return render(
        request,
        "admin/org.html",
        viewer,
        db,
        status_code=status_code,
        org=org,
        users=users,
        sites=sites,
        **extra,
    )


@router.get("/clientes/{org_id}")
def org_detail(
    request: Request,
    org_id: str,
    viewer: Viewer = Depends(admin_viewer),
    db: Session = Depends(get_db),
) -> Response:
    org = db.get(Organization, org_id) or _raise()
    return _org_page(request, db, viewer, org)


def _raise() -> Organization:
    raise not_found()


def _create_user(
    db: Session, viewer: Viewer, email: str, name: str, role: str, org_id: str | None
) -> tuple[User | None, str | None, str | None]:
    email = email.strip().lower()
    if "@" not in email or len(email) > 320 or not name.strip():
        return None, None, "Informe nome e e-mail válidos."
    if db.scalars(select(User).where(func.lower(User.email) == email)).first():
        return None, None, "Já existe um usuário com esse e-mail."
    password = generate_password()
    user = User(
        user_id=f"user-{uuid.uuid4().hex[:12]}",
        email=email,
        name=name.strip()[:200],
        password_hash=hash_password(password),
        role=role,
        org_id=org_id,
    )
    db.add(user)
    audit(
        db,
        viewer,
        "user.create",
        org_id=org_id,
        object_type="user",
        object_id=user.user_id,
        email=email,
        role=role,
    )
    return user, password, None


@router.post("/clientes/{org_id}/usuarios")
def org_user_create(
    request: Request,
    org_id: str,
    email: str = Form(...),
    name: str = Form(...),
    viewer: Viewer = Depends(admin_viewer),
    db: Session = Depends(get_db),
) -> Response:
    org = db.get(Organization, org_id) or _raise()
    user, password, error = _create_user(db, viewer, email, name, "client", org.org_id)
    return _org_page(
        request,
        db,
        viewer,
        org,
        status_code=400 if error else 200,
        new_password=(user.email, password) if user else None,
        error=error,
    )


@router.post("/usuarios/{user_id}/ativo")
def user_toggle(
    request: Request,
    user_id: str,
    viewer: Viewer = Depends(admin_viewer),
    db: Session = Depends(get_db),
) -> Response:
    user = db.get(User, user_id)
    if user is None:
        raise not_found()
    if user.user_id != viewer.user_id:  # ninguém se desativa sozinho
        user.is_active = not user.is_active
        audit(
            db,
            viewer,
            "user.active" if user.is_active else "user.inactive",
            org_id=user.org_id,
            object_type="user",
            object_id=user.user_id,
        )
    return RedirectResponse(
        f"/admin/clientes/{user.org_id}" if user.org_id else "/admin/equipe", 303
    )


@router.post("/usuarios/{user_id}/senha")
def user_reset_password(
    request: Request,
    user_id: str,
    viewer: Viewer = Depends(admin_viewer),
    db: Session = Depends(get_db),
) -> Response:
    user = db.get(User, user_id)
    if user is None:
        raise not_found()
    password = generate_password()
    user.password_hash = hash_password(password)
    user.failed_logins = 0
    user.locked_until = None
    audit(
        db,
        viewer,
        "user.password_reset",
        org_id=user.org_id,
        object_type="user",
        object_id=user.user_id,
    )
    if user.org_id:
        org = db.get(Organization, user.org_id) or _raise()
        return _org_page(request, db, viewer, org, new_password=(user.email, password))
    return _team_page(request, db, viewer, new_password=(user.email, password))


# --- equipe (admins) --------------------------------------------------------------------


def _team_page(
    request: Request, db: Session, viewer: Viewer, status_code: int = 200, **extra: object
) -> Response:
    admins = db.scalars(select(User).where(User.role == "admin").order_by(User.name)).all()
    extra.setdefault("new_password", None)
    extra.setdefault("error", None)
    return render(
        request, "admin/team.html", viewer, db, status_code=status_code, admins=admins, **extra
    )


@router.get("/equipe")
def team(
    request: Request, viewer: Viewer = Depends(admin_viewer), db: Session = Depends(get_db)
) -> Response:
    return _team_page(request, db, viewer)


@router.post("/equipe")
def team_create(
    request: Request,
    email: str = Form(...),
    name: str = Form(...),
    viewer: Viewer = Depends(admin_viewer),
    db: Session = Depends(get_db),
) -> Response:
    user, password, error = _create_user(db, viewer, email, name, "admin", None)
    return _team_page(
        request,
        db,
        viewer,
        status_code=400 if error else 200,
        new_password=(user.email, password) if user else None,
        error=error,
    )


# --- scans, operação e auditoria --------------------------------------------------------


@router.get("/scans")
def all_scans(
    request: Request, viewer: Viewer = Depends(admin_viewer), db: Session = Depends(get_db)
) -> Response:
    status = request.query_params.get("status")
    q = select(Scan).order_by(Scan.created_at.desc()).limit(200)
    if status:
        q = q.where(Scan.status == status)
    scans = db.scalars(q).all()
    sites = {t.target_id: t for t in db.scalars(select(Target))}
    orgs = {o.org_id: o.name for o in db.scalars(select(Organization))}
    return render(
        request, "admin/scans.html", viewer, db, scans=scans, sites=sites, orgs=orgs, status=status
    )


@router.get("/operacao")
def operations(
    request: Request, viewer: Viewer = Depends(admin_viewer), db: Session = Depends(get_db)
) -> Response:
    try:
        queues, error = queue_status(request.app.state.redis), None
    except Exception as exc:
        queues, error = [], str(exc)
    return render(request, "admin/operations.html", viewer, db, queues=queues, error=error)


@router.get("/auditoria")
def audit_log(
    request: Request, viewer: Viewer = Depends(admin_viewer), db: Session = Depends(get_db)
) -> Response:
    action = request.query_params.get("acao")
    q = select(AuditLog).order_by(AuditLog.at.desc()).limit(200)
    if action:
        q = q.where(AuditLog.action == action)
    entries = db.scalars(q).all()
    users = {u.user_id: u for u in db.scalars(select(User))}
    actions = sorted(db.scalars(select(AuditLog.action).distinct()))
    return render(
        request,
        "admin/audit.html",
        viewer,
        db,
        entries=entries,
        users=users,
        actions=actions,
        action=action,
    )


@router.post("/scans/{scan_id}/revisao")
def finding_review(
    request: Request,
    scan_id: str,
    finding_id: list[str] = Form(...),
    decision: str = Form(...),
    reason: str = Form(""),
    item: str = Form(""),
    viewer: Viewer = Depends(admin_viewer),
    db: Session = Depends(get_db),
) -> Response:
    scan, _ = get_scan(db, viewer, scan_id)
    item = item if item.isalnum() else ""
    try:
        for fid in finding_id[:500]:
            review_finding(db, viewer, scan, fid, decision, reason)
    except LookupError:
        raise not_found() from None
    except ValueError:
        return RedirectResponse(f"/scans/{scan_id}?revisao=motivo#item-{item}", 303)
    return RedirectResponse(f"/scans/{scan_id}#item-{item}", 303)


@router.post("/scans/{scan_id}/regerar")
def report_regenerate(
    request: Request,
    scan_id: str,
    viewer: Viewer = Depends(admin_viewer),
    db: Session = Depends(get_db),
) -> Response:
    scan, _ = get_scan(db, viewer, scan_id)
    if db.get(Report, scan_id) is None:
        raise not_found()
    tools = list(db.scalars(select(StageProgress.tool).where(StageProgress.scan_id == scan_id)))
    scan.status = ScanStatus.REPORTING
    scan.status_detail = "regerando após revisão"
    request_report_regeneration(db, viewer, scan, request.app.state.publish, tools)
    return RedirectResponse(f"/scans/{scan_id}", 303)
