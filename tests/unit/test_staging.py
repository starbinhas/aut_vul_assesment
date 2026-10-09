# ruff: noqa: F811  (os testes recebem o fixture `env`, importado de test_web)
"""Cópia de teste (homologação): o perfil intrusivo só roda numa cópia autorizada e aprovada.

Cobre a trava (política + worker + interface) e o passo a passo do cliente até a aprovação.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from scanner.common import staging as rules
from scanner.common.db import AuditLog, StagingAuthorization, Target
from scanner.common.models import Scope, StageMessage
from scanner.web import staging as flow
from scanner.web import verification
from scanner.web_scan import policy
from scanner.web_scan.service import ProfileNotAllowedError, resolve_profile
from tests.unit.test_web import (
    csrf_of,
    env,  # noqa: F401  (fixture do banco em memória + app)
    login,
)

LAB_HOSTS = ["juice-shop", "dvwa", "localhost"]
COPY = "teste.loja-a.com.br"


@pytest.fixture(autouse=True)
def no_real_dns(monkeypatch):
    """Nenhum teste resolve DNS de verdade: TXT confere e os IPs são diferentes."""
    monkeypatch.setattr(verification, "check_txt", lambda domain, token: None)
    monkeypatch.setattr(
        flow, "_addresses", lambda host: {"203.0.113.10"} if host == COPY else {"203.0.113.20"}
    )


# --- política ---------------------------------------------------------------------------


def test_intrusive_never_carries_overload_rules() -> None:
    intrusive = policy.PROFILES["intrusive"]
    assert intrusive.rules is None and intrusive.destructive
    assert {30001, 30002, 30003, 40044} <= intrusive.excluded
    assert intrusive.clearance == policy.STAGING


def test_balanced_stays_read_only() -> None:
    balanced = policy.PROFILES["balanced"].rules or frozenset()
    # Fazem o alvo sair (OAST/SSRF/RFI), gravam dados ou pesam: nunca no completo seguro.
    forbidden = {7, 40014, 40016, 40017, 40031, 40043, 40046, 40047, 90036, 10107, 20015}
    forbidden |= {90034, 90028, 40023, 40039, 30001, 30002, 30003, 40044, 50000}
    assert not balanced & forbidden
    assert {90035, 40033, 41, 42, 40040} <= balanced  # as que entraram


@pytest.mark.parametrize(
    ("name", "lab", "staging", "stress", "ok"),
    [
        ("balanced", False, False, False, True),
        ("intrusive", False, False, False, False),  # produção
        ("intrusive", False, True, False, True),  # cópia liberada para o intrusivo
        ("intrusive", False, False, True, True),  # a liberação de resiliência cobre o intrusivo
        ("intrusive", True, False, False, True),  # laboratório
        ("aggressive", False, True, False, False),  # cópia só-intrusivo não basta para sobrecarga
        ("aggressive", False, False, True, True),  # cópia liberada para resiliência
        ("aggressive", True, False, False, True),  # laboratório
    ],
)
def test_clearance_matrix(name, lab, staging, stress, ok) -> None:
    assert policy.is_cleared(policy.PROFILES[name], lab=lab, staging=staging, stress=stress) is ok


def _msg(host: str, profile: str) -> StageMessage:
    scope = Scope(
        scope_id="s",
        verified=True,
        locked=True,
        base_urls=[f"https://{host}/"],
        allowed_hosts=[host],
    )
    return StageMessage(
        message_id="m",
        scan_id="scan-1",
        target_id="t",
        stage="web.requested",
        scope=scope,
        payload={"profile": profile},
    )


def test_worker_refuses_intrusive_without_authorization() -> None:
    with pytest.raises(ProfileNotAllowedError):
        resolve_profile(_msg(COPY, "intrusive"), LAB_HOSTS)
    assert resolve_profile(_msg(COPY, "intrusive"), LAB_HOSTS, staging=True).name == "intrusive"
    with pytest.raises(ProfileNotAllowedError):
        resolve_profile(_msg(COPY, "aggressive"), LAB_HOSTS, staging=True)


# --- regra de vigência ------------------------------------------------------------------


def _approved(
    sessions,
    *,
    host: str = COPY,
    until: timedelta = timedelta(days=7),
    level: str = rules.INTRUSIVE,
) -> None:
    with sessions.begin() as s:
        s.add(
            Target(
                target_id="t-copy",
                org_id="org-a",
                domain=COPY,
                base_url=f"https://{COPY}/",
                verification_token="tok-copy",
                verified_at=datetime.now(UTC),
            )
        )
        s.add(
            StagingAuthorization(
                auth_id="hml-1",
                org_id="org-a",
                production_target_id="t-a",
                staging_target_id="t-copy",
                staging_host=host,
                status=rules.APPROVED,
                scope_level=level,
                checklist={},
                valid_days=7,
                valid_until=datetime.now(UTC) + until,
                created_at=datetime.now(UTC),
            )
        )


def test_cleared_only_for_exact_host_and_while_valid(env) -> None:
    _, sessions, _ = env
    _approved(sessions)
    with sessions() as s:
        assert rules.staging_cleared(s, "t-copy", [COPY])
        assert not rules.staging_cleared(s, "t-copy", [COPY, "loja-a.com.br"])  # host a mais
        assert not rules.staging_cleared(s, "t-a", ["loja-a.com.br"])  # o site oficial
        later = datetime.now(UTC) + timedelta(days=8)
        assert not rules.staging_cleared(s, "t-copy", [COPY], now=later)  # venceu


def test_revoked_is_not_cleared(env) -> None:
    _, sessions, _ = env
    _approved(sessions)
    with sessions.begin() as s:
        s.get(StagingAuthorization, "hml-1").status = rules.REVOKED
    with sessions() as s:
        assert not rules.staging_cleared(s, "t-copy", [COPY])


# --- nível de resiliência (stress) ------------------------------------------------------


def test_intrusive_copy_does_not_clear_stress(env) -> None:
    # Uma cópia liberada só para o intrusivo nunca libera o agressivo.
    _, sessions, _ = env
    _approved(sessions, level=rules.INTRUSIVE)
    with sessions() as s:
        assert rules.staging_cleared(s, "t-copy", [COPY])
        assert not rules.stress_cleared(s, "t-copy", [COPY])


def test_stress_copy_clears_both(env) -> None:
    # A liberação de resiliência cobre o intrusivo e o agressivo, só para o host exato e vigente.
    _, sessions, _ = env
    _approved(sessions, level=rules.STRESS)
    with sessions() as s:
        assert rules.staging_cleared(s, "t-copy", [COPY])
        assert rules.stress_cleared(s, "t-copy", [COPY])
        assert not rules.stress_cleared(s, "t-copy", [COPY, "loja-a.com.br"])  # host a mais
        later = datetime.now(UTC) + timedelta(days=8)
        assert not rules.stress_cleared(s, "t-copy", [COPY], now=later)  # venceu


def test_worker_aggressive_needs_stress_clearance() -> None:
    # Cópia só-intrusivo (staging) não basta; a liberação de resiliência (stress) sim.
    with pytest.raises(ProfileNotAllowedError):
        resolve_profile(_msg(COPY, "aggressive"), LAB_HOSTS, staging=True)
    assert (
        resolve_profile(_msg(COPY, "aggressive"), LAB_HOSTS, staging=True, stress=True).name
        == "aggressive"
    )


# --- passo a passo na interface ---------------------------------------------------------

SIGN_FORM = {
    "confirm": [k for k, _, _ in flow.CHECKLIST if k not in flow.OPTIONAL],
    "signer_name": "Ana Souza",
    "signer_role": "Sócia",
    "contact": "+55 11 99999-0000",
    "days": "30",
    "accept": "yes",
}


def _register_and_sign(app, sessions) -> str:
    c = login(app, "ana@loja-a.test")
    r = c.post(
        "/sites/t-a/copia-de-teste",
        data={"csrf_token": csrf_of(c, "/sites/t-a/copia-de-teste"), "copy_url": COPY},
    )
    assert r.status_code == 303, r.text
    with sessions() as s:
        row = s.scalars(select(StagingAuthorization)).one()
    assert row.status == rules.DRAFT
    # Passo 2: comprovar o domínio da cópia.
    r = c.post(
        f"/copias-de-teste/{row.auth_id}/verificar",
        data={"csrf_token": csrf_of(c, "/sites/t-a/copia-de-teste")},
    )
    assert r.status_code == 303
    # Passo 3: o formulário só aparece depois da prova.
    page = c.get("/sites/t-a/copia-de-teste").text
    assert "Termo de autorização" in page and "Servidor separado" in page
    r = c.post(
        f"/copias-de-teste/{row.auth_id}/assinar",
        data={"csrf_token": csrf_of(c, "/sites/t-a/copia-de-teste"), **SIGN_FORM},
    )
    assert r.status_code == 303, r.text
    return row.auth_id


def test_full_flow_unlocks_intrusive_only_on_the_copy(env) -> None:
    app, sessions, published = env
    auth_id = _register_and_sign(app, sessions)
    client = login(app, "ana@loja-a.test")
    copy_id = "/sites/" + sessions().get(StagingAuthorization, auth_id).staging_target_id
    assert 'value="intrusive"' not in client.get(copy_id).text  # assinado, mas falta o time
    assert "Agora é com o time" in client.get("/sites/t-a/copia-de-teste").text

    admin = login(app, "admin@pitchy.test")
    assert "1 cópia espera revisão" in admin.get("/admin/copias-de-teste").text
    r = admin.post(
        f"/admin/copias-de-teste/{auth_id}/decidir",
        data={"csrf_token": csrf_of(admin, "/admin/copias-de-teste"), "decision": "approve"},
    )
    assert r.status_code == 303

    assert 'value="intrusive"' in client.get(copy_id).text
    assert 'value="intrusive"' not in client.get("/sites/t-a").text  # nunca no site oficial
    r = client.post(
        f"{copy_id}/scans", data={"csrf_token": csrf_of(client, copy_id), "profile": "intrusive"}
    )
    assert r.headers["location"].startswith("/scans/scan-")
    [(_, msg)] = published
    assert msg.payload["profile"] == "intrusive" and msg.scope.allowed_hosts == [COPY]
    with sessions() as s:
        row = s.get(StagingAuthorization, auth_id)
        assert row.term_sha256 and row.signer_ip and row.valid_days == 30
        start = s.scalars(select(AuditLog).where(AuditLog.action == "scan.start")).one()
        assert start.detail["staging_copy"] is True


STRESS_SIGN_FORM = SIGN_FORM | {
    "confirm": [k for k, _, _ in flow.STRESS_CHECKLIST if k not in flow.OPTIONAL],
    "level": "stress",
}


def test_full_flow_unlocks_aggressive_only_with_stress_clearance(env) -> None:
    app, sessions, published = env
    c = login(app, "ana@loja-a.test")
    c.post(
        "/sites/t-a/copia-de-teste",
        data={"csrf_token": csrf_of(c, "/sites/t-a/copia-de-teste"), "copy_url": COPY},
    )
    with sessions() as s:
        auth_id = s.scalars(select(StagingAuthorization)).one().auth_id
    token = csrf_of(c, "/sites/t-a/copia-de-teste")
    c.post(f"/copias-de-teste/{auth_id}/verificar", data={"csrf_token": token})
    r = c.post(
        f"/copias-de-teste/{auth_id}/assinar", data={"csrf_token": token, **STRESS_SIGN_FORM}
    )
    assert r.status_code == 303, r.text
    with sessions() as s:
        assert s.get(StagingAuthorization, auth_id).scope_level == rules.STRESS

    admin = login(app, "admin@pitchy.test")
    admin.post(
        f"/admin/copias-de-teste/{auth_id}/decidir",
        data={"csrf_token": csrf_of(admin, "/admin/copias-de-teste"), "decision": "approve"},
    )
    copy_id = "/sites/" + sessions().get(StagingAuthorization, auth_id).staging_target_id
    assert 'value="aggressive"' in c.get(copy_id).text
    assert 'value="aggressive"' not in c.get("/sites/t-a").text  # nunca no site oficial
    r = c.post(
        f"{copy_id}/scans", data={"csrf_token": csrf_of(c, copy_id), "profile": "aggressive"}
    )
    assert r.headers["location"].startswith("/scans/scan-")
    [(_, msg)] = published
    assert msg.payload["profile"] == "aggressive" and msg.scope.allowed_hosts == [COPY]


def test_intrusive_copy_never_offers_aggressive(env) -> None:
    # Cópia assinada só para o intrusivo: o agressivo nunca aparece nem é aceito.
    app, sessions, published = env
    auth_id = _register_and_sign(app, sessions)  # nível intrusivo (SIGN_FORM sem level)
    admin = login(app, "admin@pitchy.test")
    admin.post(
        f"/admin/copias-de-teste/{auth_id}/decidir",
        data={"csrf_token": csrf_of(admin, "/admin/copias-de-teste"), "decision": "approve"},
    )
    c = login(app, "ana@loja-a.test")
    copy_id = "/sites/" + sessions().get(StagingAuthorization, auth_id).staging_target_id
    assert 'value="intrusive"' in c.get(copy_id).text
    assert 'value="aggressive"' not in c.get(copy_id).text
    r = c.post(
        f"{copy_id}/scans", data={"csrf_token": csrf_of(c, copy_id), "profile": "aggressive"}
    )
    assert r.headers["location"].endswith("erro=perfil-nao-permitido")
    assert published == []


def test_forged_intrusive_on_production_is_refused(env) -> None:
    app, sessions, published = env
    _approved(sessions)
    c = login(app, "ana@loja-a.test")
    r = c.post(
        "/sites/t-a/scans", data={"csrf_token": csrf_of(c, "/sites/t-a"), "profile": "intrusive"}
    )
    assert r.headers["location"] == "/sites/t-a?erro=perfil-nao-permitido"
    assert published == []


def test_sign_requires_every_confirmation_and_a_real_person(env) -> None:
    app, sessions, _ = env
    c = login(app, "ana@loja-a.test")
    c.post(
        "/sites/t-a/copia-de-teste",
        data={"csrf_token": csrf_of(c, "/sites/t-a/copia-de-teste"), "copy_url": COPY},
    )
    with sessions() as s:
        auth_id = s.scalars(select(StagingAuthorization)).one().auth_id
    token = csrf_of(c, "/sites/t-a/copia-de-teste")
    c.post(f"/copias-de-teste/{auth_id}/verificar", data={"csrf_token": token})
    partial = SIGN_FORM | {"confirm": SIGN_FORM["confirm"][:-1]}
    r = c.post(f"/copias-de-teste/{auth_id}/assinar", data={"csrf_token": token, **partial})
    assert r.status_code == 400 and "Falta confirmar" in r.text
    # O admin não assina pelo cliente.
    admin = login(app, "admin@pitchy.test")
    r = admin.post(
        f"/copias-de-teste/{auth_id}/assinar",
        data={"csrf_token": csrf_of(admin, "/sites/t-a/copia-de-teste"), **SIGN_FORM},
    )
    assert r.status_code == 400
    with sessions() as s:
        assert s.get(StagingAuthorization, auth_id).status == rules.DRAFT


def test_copy_must_differ_from_production(env) -> None:
    app, _, _ = env
    c = login(app, "ana@loja-a.test")
    r = c.post(
        "/sites/t-a/copia-de-teste",
        data={"csrf_token": csrf_of(c, "/sites/t-a/copia-de-teste"), "copy_url": "loja-a.com.br"},
    )
    assert r.status_code == 400 and "endereço próprio" in r.text


def test_other_org_cannot_see_or_touch_the_request(env) -> None:
    app, sessions, _ = env
    auth_id = _register_and_sign(app, sessions)
    bia = login(app, "bia@loja-b.test")
    assert bia.get("/sites/t-a/copia-de-teste").status_code == 404
    token = csrf_of(bia, "/sites/t-b")
    assert (
        bia.post(f"/copias-de-teste/{auth_id}/encerrar", data={"csrf_token": token}).status_code
        == 404
    )
    assert bia.get("/admin/copias-de-teste").status_code == 404


def test_reject_needs_a_reason_and_client_sees_it(env) -> None:
    app, sessions, _ = env
    auth_id = _register_and_sign(app, sessions)
    admin = login(app, "admin@pitchy.test")
    token = csrf_of(admin, "/admin/copias-de-teste")
    url = f"/admin/copias-de-teste/{auth_id}/decidir"
    r = admin.post(url, data={"csrf_token": token, "decision": "reject", "note": "não"})
    assert r.status_code == 400
    note = "A cópia aponta para o mesmo banco do site oficial."
    admin.post(url, data={"csrf_token": token, "decision": "reject", "note": note})
    page = login(app, "ana@loja-a.test").get("/sites/t-a/copia-de-teste").text
    assert "pediu um ajuste" in page and "mesmo banco" in page


def test_revoke_takes_the_profile_away(env) -> None:
    app, sessions, _ = env
    _approved(sessions)
    c = login(app, "ana@loja-a.test")
    assert 'value="intrusive"' in c.get("/sites/t-copy").text
    c.post("/copias-de-teste/hml-1/encerrar", data={"csrf_token": csrf_of(c, "/sites/t-copy")})
    assert 'value="intrusive"' not in c.get("/sites/t-copy").text
    assert "Pedir nova autorização" in c.get("/sites/t-a/copia-de-teste").text


def test_same_server_is_flagged(monkeypatch) -> None:
    prod = Target(target_id="p", org_id="o", domain="loja.com.br", base_url="https://loja.com.br/")
    copy = Target(
        target_id="c",
        org_id="o",
        domain="teste.loja.com.br",
        base_url="https://teste.loja.com.br/",
        verified_at=datetime.now(UTC),
    )
    checks = flow.automatic_checks(copy, prod, resolve=lambda host: {"198.51.100.7"})
    server = next(c for c in checks if c.label == "Servidor separado")
    assert server.ok is False and "198.51.100.7" in server.detail
