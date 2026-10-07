"""Entrar, sair e trocar a senha."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scanner.common.db import User
from scanner.web.deps import current_viewer, get_db, render
from scanner.web.security import authenticate, csrf_protect, hash_password
from scanner.web.services import audit
from scanner.web.tenancy import Viewer

router = APIRouter(dependencies=[Depends(csrf_protect)])


def _safe_next(value: str | None) -> str:
    # Só caminhos internos: evita redirecionamento aberto para outro site.
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/painel"


@router.get("/")
def root(request: Request) -> Response:
    return RedirectResponse("/painel" if request.session.get("uid") else "/entrar", 303)


@router.get("/entrar")
def login_form(request: Request, next: str | None = None) -> Response:
    return render(request, "auth/login.html", None, next=_safe_next(next), error=None, email="")


@router.post("/entrar")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form("/painel"),
    db: Session = Depends(get_db),
) -> Response:
    user = db.scalars(select(User).where(func.lower(User.email) == email.strip().lower())).first()
    ok = authenticate(user, password)
    if not ok or user is None:
        audit(db, None, "auth.login_failed", email=email.strip().lower()[:320])
        return render(
            request,
            "auth/login.html",
            None,
            status_code=400,
            next=_safe_next(next),
            email=email,
            error="E-mail ou senha incorretos. Depois de 5 tentativas, a conta fica bloqueada "
            "por 15 minutos.",
        )
    request.session.clear()  # nova sessão a cada login
    request.session["uid"] = user.user_id
    audit(db, Viewer.of(user), "auth.login")
    return RedirectResponse(_safe_next(next), 303)


@router.post("/sair")
def logout(request: Request) -> Response:
    request.session.clear()
    return RedirectResponse("/entrar", 303)


@router.get("/conta")
def account(
    request: Request, viewer: Viewer = Depends(current_viewer), db: Session = Depends(get_db)
) -> Response:
    return render(request, "auth/account.html", viewer, db, message=None, error=None)


@router.post("/conta/senha")
def change_password(
    request: Request,
    current: str = Form(...),
    new: str = Form(...),
    confirm: str = Form(...),
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    user = db.get(User, viewer.user_id)
    error = None
    if user is None or not authenticate(user, current):
        error = "A senha atual não confere."
    elif new != confirm:
        error = "A confirmação é diferente da nova senha."
    else:
        try:
            user.password_hash = hash_password(new)
        except ValueError as exc:
            error = str(exc).capitalize() + "."
    if error:
        return render(
            request, "auth/account.html", viewer, db, status_code=400, message=None, error=error
        )
    audit(db, viewer, "auth.password_changed")
    return render(request, "auth/account.html", viewer, db, message="Senha alterada.", error=None)
