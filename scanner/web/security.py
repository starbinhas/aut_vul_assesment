"""Senhas (Argon2id), bloqueio de login, CSRF e cabeçalhos de segurança da própria interface."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import HTTPException, Request

from scanner.common.db import User

_hasher = PasswordHasher()  # Argon2id com os parâmetros recomendados pela biblioteca

MIN_PASSWORD_LENGTH = 12
MAX_FAILED_LOGINS = 5
LOCK_MINUTES = 15
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Usado quando o e-mail não existe, para o tempo de resposta não revelar quem tem conta.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"a senha precisa ter pelo menos {MIN_PASSWORD_LENGTH} caracteres")
    return _hasher.hash(password)


def generate_password() -> str:
    return secrets.token_urlsafe(15)  # 20 caracteres


def _verify(hash_: str, password: str) -> bool:
    try:
        return _hasher.verify(hash_, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def authenticate(user: User | None, password: str, now: datetime | None = None) -> bool:
    """Confere a senha e aplica o bloqueio temporário. Atualiza os contadores no `user`."""
    now = now or datetime.now(UTC)
    if user is None or not user.is_active:
        _verify(_DUMMY_HASH, password)
        return False
    locked_until = user.locked_until
    if locked_until is not None and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=UTC)
    if locked_until is not None and locked_until > now:
        _verify(_DUMMY_HASH, password)
        return False
    if not _verify(user.password_hash, password):
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
            user.failed_logins = 0
        return False
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = _hasher.hash(password)
    return True


# --- CSRF -------------------------------------------------------------------------------


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return str(token)


async def csrf_protect(request: Request) -> None:
    """Dependência dos routers: todo método que altera estado exige o token da sessão."""
    if request.method in SAFE_METHODS:
        return
    expected = request.session.get("csrf")
    sent = request.headers.get(CSRF_HEADER)
    if sent is None:
        form = await request.form()  # o Starlette guarda o form; a rota reaproveita
        value = form.get(CSRF_FIELD)
        sent = value if isinstance(value, str) else None
    if not expected or not sent or not secrets.compare_digest(str(expected), sent):
        raise HTTPException(status_code=403, detail="Sessão expirada. Recarregue a página.")


# --- cabeçalhos ---------------------------------------------------------------------------

CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)

# O relatório HTML guardado tem CSS embutido; é servido isolado, sem script nenhum.
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"


def security_headers(path: str, secure: bool) -> dict[str, str]:
    headers = {
        "Content-Security-Policy": REPORT_CSP if path.endswith("/relatorio.html") else CSP,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "same-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin",
    }
    # Páginas: nunca em cache (dados do cliente). Estáticos: o navegador revalida (ETag) antes
    # de usar a cópia guardada; CSS/JS ainda levam a versão na URL (`asset`).
    headers["Cache-Control"] = "no-cache" if path.startswith("/static/") else "no-store"
    if secure:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers
