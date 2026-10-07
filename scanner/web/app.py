"""Aplicação web (FastAPI). `create_app` recebe as dependências para os testes trocarem."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from scanner.common.config import Settings
from scanner.common.models import StageMessage
from scanner.common.queue import publish
from scanner.web.deps import LoginRequiredError, render
from scanner.web.routes import admin, auth, client
from scanner.web.security import security_headers

STATIC = Path(__file__).parent / "static"


def create_app(
    settings: Settings,
    sessions: sessionmaker,  # type: ignore[type-arg]
    redis_client: Any,
) -> FastAPI:
    secret = settings.web_session_secret.get_secret_value()
    if len(secret) < 32:
        raise RuntimeError("WEB_SESSION_SECRET ausente ou curto (mínimo 32 caracteres).")

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.sessions = sessions
    app.state.redis = redis_client
    app.state.settings = settings

    def publisher(stream: str, msg: StageMessage) -> None:
        publish(redis_client, stream, msg)

    app.state.publish = publisher

    app.add_middleware(
        SessionMiddleware,
        secret_key=secret,
        session_cookie="pitchy_scan",
        max_age=settings.web_session_hours * 3600,
        same_site="lax",
        https_only=settings.web_secure_cookies,
    )

    @app.middleware("http")
    async def headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for name, value in security_headers(request.url.path, settings.web_secure_cookies).items():
            response.headers.setdefault(name, value)
        return response

    @app.exception_handler(LoginRequiredError)
    async def login_required(request: Request, exc: LoginRequiredError) -> Response:
        target = f"/entrar?next={exc.next_path}"
        if request.headers.get("hx-request") == "true":
            return Response(status_code=204, headers={"HX-Redirect": target})
        return RedirectResponse(target, 303)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        return render(
            request,
            "error.html",
            None,
            status_code=exc.status_code,
            code=exc.status_code,
            message=exc.detail if exc.status_code != 404 else "Esta página não existe.",
        )

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    app.include_router(auth.router)
    app.include_router(client.router)
    app.include_router(admin.router)
    return app
