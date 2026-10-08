"""Interface web: login, isolamento entre clientes, CSRF, cabeçalhos, scans e revisão humana."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from scanner.common.config import Settings
from scanner.common.db import (
    AuditLog,
    Base,
    FindingRow,
    Organization,
    Report,
    Scan,
    ScanStatus,
    Target,
    User,
)
from scanner.common.models import Status
from scanner.common.queue import STREAM_RECON_REQUESTED, STREAM_VALIDATED
from scanner.report.builder import build_report
from scanner.report.catalog import static_remediation
from scanner.web import verification
from scanner.web.app import create_app
from scanner.web.security import hash_password
from tests.conftest import make_finding

PASSWORD = "senha-de-teste-longa"


class DeadRedis:
    """Redis fora do ar: a tela admin precisa continuar abrindo."""

    def __getattr__(self, name):
        raise ConnectionError("redis indisponível")


@pytest.fixture
def env():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions.begin() as s:
        s.add_all(
            [
                Organization(org_id="org-a", name="Loja A"),
                Organization(org_id="org-b", name="Loja B"),
                User(
                    user_id="u-admin",
                    email="admin@pitchy.test",
                    name="Admin Pitchy",
                    password_hash=hash_password(PASSWORD),
                    role="admin",
                ),
                User(
                    user_id="u-a",
                    email="ana@loja-a.test",
                    name="Ana",
                    org_id="org-a",
                    password_hash=hash_password(PASSWORD),
                    role="client",
                ),
                User(
                    user_id="u-b",
                    email="bia@loja-b.test",
                    name="Bia",
                    org_id="org-b",
                    password_hash=hash_password(PASSWORD),
                    role="client",
                ),
                Target(
                    target_id="t-a",
                    org_id="org-a",
                    domain="loja-a.com.br",
                    base_url="https://loja-a.com.br/",
                    verification_token="tok-a",
                    verified_at=datetime.now(UTC),
                ),
                Target(
                    target_id="t-a2",
                    org_id="org-a",
                    domain="nova-a.com.br",
                    base_url="https://nova-a.com.br/",
                    verification_token="tok-a2",
                ),
                Target(
                    target_id="t-b",
                    org_id="org-b",
                    domain="loja-b.com.br",
                    base_url="https://loja-b.com.br/",
                    verification_token="tok-b",
                    verified_at=datetime.now(UTC),
                ),
            ]
        )
        for scan_id, target in (("scan-a", "t-a"), ("scan-b", "t-b")):
            host = "loja-a.com.br" if target == "t-a" else "loja-b.com.br"
            scope = {
                "scope_id": f"site-{target}",
                "verified": True,
                "locked": True,
                "base_urls": [f"https://{host}/"],
                "allowed_hosts": [host],
                "include_paths": [],
                "exclude_paths": [],
            }
            s.add(
                Scan(
                    scan_id=scan_id,
                    target_id=target,
                    verified=True,
                    scope_locked=True,
                    scope=scope,
                    status=ScanStatus.DONE,
                    created_at=datetime.now(UTC) - timedelta(hours=1),
                )
            )
            f = make_finding(status=Status.CONFIRMED).model_copy(update={"scan_id": scan_id})
            s.add(
                FindingRow(
                    finding_id=f.finding_id + scan_id[-1],
                    scan_id=scan_id,
                    status=f.status.value,
                    severity=f.severity.value,
                    cwe=f.cwe,
                    data=f.model_copy(update={"finding_id": f.finding_id}).model_dump(mode="json"),
                )
            )
            report = build_report(
                scan_id, target, [f], lambda f: (static_remediation(f), "catalog")
            )
            s.add(
                Report(
                    scan_id=scan_id,
                    report_json=report.model_dump(mode="json"),
                    html="<html><body>rel</body></html>",
                    pdf=b"%PDF-1.7 teste",
                    created_at=datetime.now(UTC) - timedelta(minutes=30),
                )
            )
    settings = Settings(
        web_session_secret=SecretStr("x" * 40),
        web_secure_cookies=False,
        database_url="sqlite://",
    )
    app = create_app(settings, sessions, DeadRedis())
    published: list[tuple[str, object]] = []
    app.state.publish = lambda stream, msg: published.append((stream, msg))
    return app, sessions, published


def client_for(app) -> TestClient:
    return TestClient(app, base_url="http://testserver", follow_redirects=False)


def csrf_of(c: TestClient, path: str = "/entrar") -> str:
    html = c.get(path).text
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(app, email: str, password: str = PASSWORD) -> TestClient:
    c = client_for(app)
    r = c.post(
        "/entrar",
        data={"email": email, "password": password, "next": "/painel", "csrf_token": csrf_of(c)},
    )
    assert r.status_code == 303, r.text
    return c


# --- login ------------------------------------------------------------------------------


def test_wrong_password_and_lockout(env) -> None:
    app, sessions, _ = env
    c = client_for(app)
    for _ in range(5):
        r = c.post(
            "/entrar",
            data={"email": "ana@loja-a.test", "password": "errada", "csrf_token": csrf_of(c)},
        )
        assert r.status_code == 400
    # bloqueada: nem a senha certa entra
    r = c.post(
        "/entrar", data={"email": "ana@loja-a.test", "password": PASSWORD, "csrf_token": csrf_of(c)}
    )
    assert r.status_code == 400
    with sessions() as s:
        assert s.get(User, "u-a").locked_until is not None


def test_login_is_case_insensitive_and_audited(env) -> None:
    app, sessions, _ = env
    c = login(app, "ANA@loja-a.test")
    assert c.get("/painel").status_code == 200
    with sessions() as s:
        assert s.scalars(select(AuditLog).where(AuditLog.action == "auth.login")).first()


def test_open_redirect_is_blocked(env) -> None:
    app, _, _ = env
    c = client_for(app)
    r = c.post(
        "/entrar",
        data={
            "email": "ana@loja-a.test",
            "password": PASSWORD,
            "next": "//evil.example/x",
            "csrf_token": csrf_of(c),
        },
    )
    assert r.headers["location"] == "/painel"


def test_pages_require_login(env) -> None:
    app, _, _ = env
    r = client_for(app).get("/sites")
    assert r.status_code == 303 and r.headers["location"].startswith("/entrar")


# --- isolamento entre clientes ------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/sites/t-b",
        "/scans/scan-b",
        "/scans/scan-b/relatorio.pdf",
        "/scans/scan-b/relatorio.html",
        "/scans/scan-b/andamento",
    ],
)
def test_client_cannot_see_other_organization(env, path) -> None:
    app, _, _ = env
    c = login(app, "ana@loja-a.test")
    assert c.get(path).status_code == 404


def test_client_lists_only_own_sites(env) -> None:
    app, _, _ = env
    html = login(app, "ana@loja-a.test").get("/sites").text
    assert "loja-a.com.br" in html and "loja-b.com.br" not in html


def test_admin_sees_everything(env) -> None:
    app, _, _ = env
    c = login(app, "admin@pitchy.test")
    html = c.get("/sites").text
    assert "loja-a.com.br" in html and "loja-b.com.br" in html
    assert c.get("/scans/scan-b").status_code == 200
    assert c.get("/scans/scan-b/relatorio.pdf").content.startswith(b"%PDF")


@pytest.mark.parametrize(
    "path", ["/admin", "/admin/clientes", "/admin/auditoria", "/admin/operacao"]
)
def test_admin_area_does_not_exist_for_clients(env, path) -> None:
    app, _, _ = env
    assert login(app, "ana@loja-a.test").get(path).status_code == 404


def test_admin_overview_survives_redis_down(env) -> None:
    app, _, _ = env
    r = login(app, "admin@pitchy.test").get("/admin")
    assert r.status_code == 200 and "A fila não respondeu" in r.text


# --- CSRF e cabeçalhos --------------------------------------------------------------------


def test_post_without_csrf_is_rejected(env) -> None:
    app, _, published = env
    c = login(app, "ana@loja-a.test")
    assert c.post("/sites/t-a/scans").status_code == 403
    assert c.post("/sites/t-a/scans", data={"csrf_token": "forjado"}).status_code == 403
    assert published == []


def test_security_headers(env) -> None:
    app, _, _ = env
    r = client_for(app).get("/entrar")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_static_assets_are_versioned_and_revalidated(env) -> None:
    app, _, _ = env
    c = client_for(app)
    css = re.search(r'href="(/static/css/app\.css\?v=[0-9a-f]{10})"', c.get("/entrar").text)
    assert css, "CSS sem versão na URL: o navegador mistura HTML novo com CSS antigo"
    r = c.get(css.group(1))
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-cache"


def test_stored_report_html_is_sandboxed(env) -> None:
    app, _, _ = env
    r = login(app, "ana@loja-a.test").get("/scans/scan-a/relatorio.html")
    assert "sandbox" in r.headers["content-security-policy"]
    assert "script-src" not in r.headers["content-security-policy"]


def test_session_cookie_flags(env) -> None:
    app, _, _ = env
    c = client_for(app)
    r = c.post(
        "/entrar", data={"email": "ana@loja-a.test", "password": PASSWORD, "csrf_token": csrf_of(c)}
    )
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie


# --- sites e scans ------------------------------------------------------------------------


def test_start_scan_requires_verified_site(env) -> None:
    app, _, published = env
    c = login(app, "ana@loja-a.test")
    r = c.post("/sites/t-a2/scans", data={"csrf_token": csrf_of(c, "/sites/t-a2")})
    assert r.headers["location"] == "/sites/t-a2?erro=nao-verificado"
    assert published == []


def test_start_scan_publishes_locked_scope_once(env) -> None:
    app, _, published = env
    c = login(app, "ana@loja-a.test")
    token = csrf_of(c, "/sites/t-a")
    r = c.post("/sites/t-a/scans", data={"csrf_token": token})
    assert r.status_code == 303 and r.headers["location"].startswith("/scans/scan-")
    [(stream, msg)] = published
    assert stream == STREAM_RECON_REQUESTED
    assert msg.scope.allowed_hosts == ["loja-a.com.br"] and msg.scope.locked
    # segundo pedido enquanto o primeiro roda: recusado
    r = c.post("/sites/t-a/scans", data={"csrf_token": token})
    assert r.headers["location"] == "/sites/t-a?erro=em-andamento"
    assert len(published) == 1


def add_lab_site(sessions) -> None:
    """Site de laboratório na org A (como o `tests.lab_scan seed` cria)."""
    with sessions.begin() as s:
        s.add(
            Target(
                target_id="t-lab",
                org_id="org-a",
                domain="juice-shop",
                base_url="http://juice-shop:3000/",
                verification_token="laboratorio",
                verified_at=datetime.now(UTC),
            )
        )


def test_aggressive_is_offered_only_to_admin_on_lab_site(env) -> None:
    app, sessions, _ = env
    add_lab_site(sessions)
    admin = login(app, "admin@pitchy.test")
    assert 'value="aggressive"' in admin.get("/sites/t-lab").text
    assert 'value="aggressive"' not in admin.get("/sites/t-a").text  # site de cliente
    client_html = login(app, "ana@loja-a.test").get("/sites/t-lab").text
    assert 'value="balanced"' in client_html and 'value="aggressive"' not in client_html


def test_profile_cards_explain_risks_and_real_limits(env) -> None:
    app, _, _ = env
    html = login(app, "ana@loja-a.test").get("/sites/t-a").text
    settings = app.state.settings
    # limites do site de cliente, não os de laboratório
    assert f"no máximo {settings.scan_max_requests_per_second} requisições" in html
    assert "O que nunca faz" in html and "Atenção" in html
    assert "um formulário de contato pode disparar e-mails" in html  # risco real em todo nível
    assert "Só laboratório" not in html


def test_admin_starts_aggressive_on_lab_site(env) -> None:
    app, sessions, published = env
    add_lab_site(sessions)
    c = login(app, "admin@pitchy.test")
    data = {"csrf_token": csrf_of(c, "/sites/t-lab"), "profile": "aggressive"}
    r = c.post("/sites/t-lab/scans", data=data)
    assert r.headers["location"].startswith("/scans/scan-")
    [(_, msg)] = published
    assert msg.payload == {"profile": "aggressive"}
    with sessions() as s:
        entry = s.scalars(select(AuditLog).where(AuditLog.action == "scan.start")).one()
        assert entry.detail["destructive"] is True


@pytest.mark.parametrize(
    ("email", "site"),
    [
        ("ana@loja-a.test", "t-lab"),  # cliente, mesmo em site de laboratório
        ("admin@pitchy.test", "t-a"),  # admin, mas site de cliente
    ],
)
def test_forged_aggressive_post_is_refused(env, email, site) -> None:
    app, sessions, published = env
    add_lab_site(sessions)
    c = login(app, email)
    data = {"csrf_token": csrf_of(c, f"/sites/{site}"), "profile": "aggressive"}
    r = c.post(f"/sites/{site}/scans", data=data)
    assert r.headers["location"] == f"/sites/{site}?erro=perfil-nao-permitido"
    assert published == []
    page = c.get(r.headers["location"]).text
    assert "não está liberado" in page and "em andamento" not in page


def test_scan_is_committed_before_it_is_published(env) -> None:
    """O worker confere o scan no banco ao ler a mensagem: a linha já precisa estar lá."""
    app, sessions, _ = env
    seen: list[bool] = []
    # Os testes dividem uma conexão SQLite (StaticPool), então outra sessão enxergaria a linha
    # mesmo sem commit. O que prova a ordem é a conexão não ter transação aberta no publish.
    raw = sessions.kw["bind"].raw_connection().driver_connection

    def publish(stream, msg) -> None:
        seen.append(not raw.in_transaction)

    app.state.publish = publish
    c = login(app, "ana@loja-a.test")
    c.post("/sites/t-a/scans", data={"csrf_token": csrf_of(c, "/sites/t-a")})
    assert seen == [True]


def test_queue_down_fails_the_scan_instead_of_blocking_the_site(env) -> None:
    app, sessions, _ = env

    def publish(stream, msg) -> None:
        raise ConnectionError("redis indisponível")

    app.state.publish = publish
    c = login(app, "ana@loja-a.test")
    r = c.post("/sites/t-a/scans", data={"csrf_token": csrf_of(c, "/sites/t-a")})
    scan_id = r.headers["location"].removeprefix("/scans/")
    with sessions() as s:
        scan = s.get(Scan, scan_id)
        assert scan.status == ScanStatus.FAILED and scan.status_detail == "fila indisponível"


def test_error_message_is_not_free_text(env) -> None:
    app, _, _ = env
    html = login(app, "ana@loja-a.test").get("/sites/t-a?erro=Ligue+para+0800").text
    assert "0800" not in html


@pytest.mark.parametrize(
    "site",
    [
        "localhost",
        "http://juice-shop:3000",
        "10.0.0.5",
        "https://user:pw@loja.com.br",
        "intranet",
        "loja.local",
        "ftp://loja.com.br",
    ],
)
def test_site_normalization_rejects_non_public(site) -> None:
    with pytest.raises(verification.InvalidSiteError):
        verification.normalize_site(site)


def test_site_normalization() -> None:
    assert verification.normalize_site(" Loja.COM.br/app ") == (
        "loja.com.br",
        "https://loja.com.br/app",
    )
    assert verification.normalize_site("http://loja.com.br:8080") == (
        "loja.com.br",
        "http://loja.com.br:8080/",
    )


def test_txt_check() -> None:
    value = verification.record_value("abc")
    assert verification.check_txt("loja.com.br", "abc", lambda name: ["outra coisa", value]) is None
    assert "não confere" in verification.check_txt("loja.com.br", "abc", lambda name: ["x"])


def test_client_creates_site_in_own_org_only(env) -> None:
    app, sessions, _ = env
    c = login(app, "ana@loja-a.test")
    r = c.post(
        "/sites",
        data={
            "site": "minha-loja.com.br",
            "org_id": "org-b",
            "csrf_token": csrf_of(c, "/sites/novo"),
        },
    )
    assert r.status_code == 303
    with sessions() as s:
        t = s.scalars(select(Target).where(Target.domain == "minha-loja.com.br")).one()
        assert t.org_id == "org-a" and t.verified_at is None


# --- revisão humana -----------------------------------------------------------------------


def test_review_requires_admin_and_reason(env) -> None:
    app, sessions, published = env
    with sessions() as s:
        fid = s.scalars(select(FindingRow.finding_id).where(FindingRow.scan_id == "scan-a")).one()
    client = login(app, "ana@loja-a.test")
    r = client.post(
        "/admin/scans/scan-a/revisao",
        data={
            "finding_id": fid,
            "decision": "false_positive",
            "reason": "não existe",
            "csrf_token": csrf_of(client, "/painel"),
        },
    )
    assert r.status_code == 404

    admin = login(app, "admin@pitchy.test")
    token = csrf_of(admin, "/painel")
    r = admin.post(
        "/admin/scans/scan-a/revisao",
        data={
            "finding_id": fid,
            "decision": "false_positive",
            "reason": "curto",
            "csrf_token": token,
        },
    )
    assert "revisao=motivo" in r.headers["location"]
    with sessions() as s:
        assert s.get(FindingRow, fid).status == "confirmed"

    admin.post(
        "/admin/scans/scan-a/revisao",
        data={
            "finding_id": fid,
            "decision": "false_positive",
            "reason": "o parâmetro é escapado no template",
            "csrf_token": token,
        },
    )
    with sessions() as s:
        assert s.get(FindingRow, fid).status == "false_positive"
        entry = s.scalars(select(AuditLog).where(AuditLog.action == "finding.review")).one()
        assert entry.user_id == "u-admin" and entry.detail["before"] == "confirmed"

    assert "ainda fora do relatório" in admin.get("/scans/scan-a").text
    admin.post("/admin/scans/scan-a/regerar", data={"csrf_token": token})
    [(stream, msg)] = published
    assert stream == STREAM_VALIDATED and msg.payload["regenerate"] is True


def test_admin_creates_user_and_password_is_shown_once(env) -> None:
    app, _, _ = env
    admin = login(app, "admin@pitchy.test")
    r = admin.post(
        "/admin/clientes/org-a/usuarios",
        data={"name": "Caio", "email": "caio@loja-a.test", "csrf_token": csrf_of(admin, "/painel")},
    )
    password = re.search(r'id="newpass">([^<]+)<', r.text).group(1)
    assert "newpass" not in admin.get("/admin/clientes/org-a").text
    new = login(app, "caio@loja-a.test", password)
    assert "loja-a.com.br" in new.get("/sites").text


def test_old_format_report_does_not_break_pages(env) -> None:
    app, sessions, _ = env
    with sessions.begin() as s:
        s.get(Report, "scan-a").report_json = {"items": [{"finding": {}}]}
    c = login(app, "ana@loja-a.test")
    for path in ("/painel", "/sites/t-a", "/scans/scan-a"):
        assert c.get(path).status_code == 200


def test_severity_legend_has_fixed_order() -> None:
    from scanner.web.deps import TEMPLATES

    macro = TEMPLATES.env.get_template("partials/macros.html").module.sevbar
    html = str(macro({"low": 5, "info": 1, "high": 1, "medium": 2, "critical": 0}))
    labels = re.findall(r"</b>(\w+)</span>", html)
    assert labels == ["alta", "média", "baixa", "informativa"]


def test_progress_shows_percent_and_eta(env) -> None:
    from datetime import timedelta

    app, sessions, _ = env
    with sessions.begin() as s:
        scan = s.get(Scan, "scan-a")
        scan.status = ScanStatus.WEB_SCANNING
        scan.status_detail = "active"
        scan.progress_pct = 25
        scan.progress_info = "1240 requisições enviadas"
        scan.phase_started_at = datetime.now(UTC) - timedelta(minutes=5)
        scan.progress_at = datetime.now(UTC)
    html = login(app, "ana@loja-a.test").get("/scans/scan-a/andamento").text
    assert "25%" in html
    # número cru de engenharia não aparece para o cliente; a fase, sim
    assert "1240 requisições enviadas" not in html
    assert "Testes ativos" in html
    # 25% em 5 min → faltam ~15 min
    assert "faltam ~15 min" in html
    assert "<meter" in html and 'value="25"' in html
    # sem estilo inline (CSP estrita)
    assert "style=" not in html


def test_progress_indeterminate_when_no_percent(env) -> None:
    app, sessions, _ = env
    with sessions.begin() as s:
        scan = s.get(Scan, "scan-a")
        scan.status = ScanStatus.WEB_SCANNING
        scan.status_detail = "passive"
        scan.progress_pct = None
        scan.progress_info = "30 respostas na fila"
    html = login(app, "ana@loja-a.test").get("/scans/scan-a/andamento").text
    assert "indeterminate" in html
    assert "30 respostas na fila" not in html  # número cru fora
    assert "Analisando as respostas" in html  # fase legível no lugar


# --- parar e entregar parcial (alvo instável) --------------------------------------------


def test_client_can_stop_own_scan_for_partial(env) -> None:
    app, sessions, _ = env
    c = login(app, "ana@loja-a.test")
    r = c.post("/scans/scan-a/parar", data={"csrf_token": csrf_of(c, "/painel")})
    assert r.status_code == 303
    with sessions() as s:
        assert s.get(Scan, "scan-a").stop_requested_at is not None
        assert s.scalars(select(AuditLog).where(AuditLog.action == "scan.stop_partial")).first()


def test_client_cannot_stop_other_org_scan(env) -> None:
    app, sessions, _ = env
    c = login(app, "ana@loja-a.test")
    r = c.post("/scans/scan-b/parar", data={"csrf_token": csrf_of(c, "/painel")})
    assert r.status_code == 404
    with sessions() as s:
        assert s.get(Scan, "scan-b").stop_requested_at is None  # não tocou no de outra org


def test_stop_requires_csrf(env) -> None:
    app, sessions, _ = env
    c = login(app, "ana@loja-a.test")
    r = c.post("/scans/scan-a/parar", data={})
    assert r.status_code == 403
    with sessions() as s:
        assert s.get(Scan, "scan-a").stop_requested_at is None


def test_partial_reason_label_explains_aggressive() -> None:
    from scanner.web import labels

    agg = labels.partial_reason("aggressive-dos")
    assert "agressivo" in agg.lower() and "Completo seguro" in agg
    assert labels.partial_reason("target-unstable") != agg
    assert labels.partial_reason("")  # fallback não vazio
