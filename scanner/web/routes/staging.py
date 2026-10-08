"""Cópia de teste (homologação): o passo a passo do cliente e a revisão do time.

Toda leitura passa por `tenancy` (pedido de outra organização responde 404).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.common import staging as rules
from scanner.common.db import Organization, StagingAuthorization, Target, User
from scanner.web import staging, verification
from scanner.web.deps import admin_viewer, current_viewer, get_db, render
from scanner.web.security import csrf_protect
from scanner.web.tenancy import Viewer, get_staging, get_target, not_found

router = APIRouter(dependencies=[Depends(csrf_protect)])
admin_router = APIRouter(
    prefix="/admin", dependencies=[Depends(csrf_protect), Depends(admin_viewer)]
)


def _wizard(
    request: Request,
    viewer: Viewer,
    db: Session,
    production: Target,
    *,
    error: str | None = None,
    form: dict[str, Any] | None = None,
    status_code: int = 200,
) -> Response:
    row = staging.for_production(db, production.target_id)
    copy = db.get(Target, row.staging_target_id) if row else None
    org = db.get(Organization, production.org_id)
    days = (form or {}).get("days") or (row.valid_days if row and row.valid_days else 30)
    step = staging.step_of(row, copy)
    return render(
        request,
        "staging/wizard.html",
        viewer,
        db,
        status_code=status_code,
        t=production,
        row=row,
        copy=copy,
        step=step,
        expired=bool(row and rules.is_expired(row)),
        checks=staging.automatic_checks(copy, production) if copy and step >= 3 else [],
        checklist=staging.CHECKLIST,
        optional=staging.OPTIONAL,
        validity=rules.VALIDITY_DAYS,
        term=staging.term_paragraphs(
            org.name if org else "", production.domain, copy.domain if copy else "", int(days)
        ),
        dev_message=staging.developer_message(production),
        dns_message=staging.dns_message(copy) if copy else "",
        record_name=verification.record_name(copy.domain) if copy else "",
        record_value=verification.record_value(copy.verification_token) if copy else "",
        error=error,
        form=form or {},
        days=int(days),
    )


@router.get("/sites/{target_id}/copia-de-teste")
def wizard(
    request: Request,
    target_id: str,
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    return _wizard(request, viewer, db, get_target(db, viewer, target_id))


@router.post("/sites/{target_id}/copia-de-teste")
def register(
    request: Request,
    target_id: str,
    copy_url: str = Form(""),
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    production = get_target(db, viewer, target_id)
    try:
        staging.register_copy(db, viewer, production, copy_url)
    except ValueError as exc:  # StagingError e InvalidSiteError
        return _wizard(
            request,
            viewer,
            db,
            production,
            error=str(exc),
            form={"copy_url": copy_url},
            status_code=400,
        )
    return RedirectResponse(f"/sites/{target_id}/copia-de-teste#passo", 303)


def _production_of(db: Session, viewer: Viewer, row: StagingAuthorization) -> Target:
    return get_target(db, viewer, row.production_target_id)


@router.post("/copias-de-teste/{auth_id}/verificar")
def verify(
    auth_id: str, viewer: Viewer = Depends(current_viewer), db: Session = Depends(get_db)
) -> Response:
    row = get_staging(db, viewer, auth_id)
    staging.verify_copy(db, viewer, get_target(db, viewer, row.staging_target_id))
    return RedirectResponse(f"/sites/{row.production_target_id}/copia-de-teste#passo", 303)


@router.post("/copias-de-teste/{auth_id}/assinar")
async def sign(
    request: Request,
    auth_id: str,
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    row = get_staging(db, viewer, auth_id)
    production = _production_of(db, viewer, row)
    form = await request.form()
    confirmed = {str(v) for v in form.getlist("confirm")}
    values = {k: str(form.get(k, "")) for k in ("signer_name", "signer_role", "contact", "days")}
    try:
        days = int(values["days"] or 0)
    except ValueError:
        days = 0
    try:
        staging.sign(
            db,
            viewer,
            row,
            staging=get_target(db, viewer, row.staging_target_id),
            production=production,
            confirmed=confirmed,
            signer_name=values["signer_name"],
            signer_role=values["signer_role"],
            emergency_contact=values["contact"],
            days=days,
            accepted=form.get("accept") == "yes",
            ip=request.client.host if request.client else None,
        )
    except staging.StagingError as exc:
        return _wizard(
            request,
            viewer,
            db,
            production,
            error=str(exc),
            form=values | {"confirmed": confirmed, "days": days or None},
            status_code=400,
        )
    return RedirectResponse(f"/sites/{production.target_id}/copia-de-teste#passo", 303)


@router.post("/copias-de-teste/{auth_id}/encerrar")
def revoke(
    request: Request,
    auth_id: str,
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    row = get_staging(db, viewer, auth_id)
    try:
        staging.revoke(db, viewer, row)
    except staging.StagingError as exc:
        production = _production_of(db, viewer, row)
        return _wizard(request, viewer, db, production, error=str(exc), status_code=400)
    back = (
        "/admin/copias-de-teste"
        if viewer.is_admin and request.query_params.get("admin")
        else (f"/sites/{row.production_target_id}/copia-de-teste")
    )
    return RedirectResponse(back, 303)


@router.post("/copias-de-teste/{auth_id}/renovar")
def renew(
    request: Request,
    auth_id: str,
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    row = get_staging(db, viewer, auth_id)
    try:
        staging.renew(db, viewer, row)
    except staging.StagingError as exc:
        production = _production_of(db, viewer, row)
        return _wizard(request, viewer, db, production, error=str(exc), status_code=400)
    return RedirectResponse(f"/sites/{row.production_target_id}/copia-de-teste#passo", 303)


# --- revisão do time --------------------------------------------------------------------


def _review_rows(db: Session) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(StagingAuthorization)
        .where(StagingAuthorization.status != rules.DRAFT)
        .order_by(StagingAuthorization.signed_at.desc())
        .limit(100)
    ).all()
    out = []
    for row in rows:
        production = db.get(Target, row.production_target_id)
        copy = db.get(Target, row.staging_target_id)
        if production is None or copy is None:
            continue
        org = db.get(Organization, row.org_id)
        signer = db.get(User, row.signer_user_id) if row.signer_user_id else None
        out.append(
            {
                "row": row,
                "production": production,
                "copy_site": copy,
                "org": org.name if org else row.org_id,
                "signer_email": signer.email if signer else None,
                "expired": rules.is_expired(row),
                "active": rules.is_active(row),
                # DNS só para o que está esperando decisão (a lista não espera o DNS de todos).
                "checks": staging.automatic_checks(copy, production)
                if row.status == rules.REQUESTED
                else [],
            }
        )
    # Esperando decisão primeiro.
    return sorted(out, key=lambda r: r["row"].status != rules.REQUESTED)


@admin_router.get("/copias-de-teste")
def review_list(
    request: Request,
    viewer: Viewer = Depends(admin_viewer),
    db: Session = Depends(get_db),
    error: str | None = None,
) -> Response:
    return render(
        request,
        "staging/review.html",
        viewer,
        db,
        items=_review_rows(db),
        checklist=staging.CHECKLIST,
        error=error,
    )


@admin_router.post("/copias-de-teste/{auth_id}/decidir")
def review_decide(
    request: Request,
    auth_id: str,
    decision: str = Form(...),
    note: str = Form(""),
    viewer: Viewer = Depends(admin_viewer),
    db: Session = Depends(get_db),
) -> Response:
    row = get_staging(db, viewer, auth_id)
    if decision not in ("approve", "reject"):
        raise not_found()
    try:
        staging.decide(db, viewer, row, decision == "approve", note)
    except staging.StagingError as exc:
        return render(
            request,
            "staging/review.html",
            viewer,
            db,
            status_code=400,
            items=_review_rows(db),
            checklist=staging.CHECKLIST,
            error=str(exc),
        )
    return RedirectResponse("/admin/copias-de-teste", 303)
