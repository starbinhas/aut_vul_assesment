"""Dispara um scan de ponta a ponta contra os alvos de laboratório e exporta o relatório.

Faz o papel da etapa 1 (registrar o alvo como verificado e o escopo travado) SOMENTE para os
alvos de `docker-compose.lab.yml`. Não aceita nenhum outro host: não é um atalho para alvos reais.

    # disparar
    docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile test \
        run --rm tests python -m tests.lab_scan start juice-shop

    # interface: organização de demonstração, sites de laboratório e acessos (admin + cliente).
    # As senhas saem no stdout: redirecione para um arquivo, não para a tela.
    docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile test \
        run --rm -T tests python -m tests.lab_scan seed > out/credenciais-lab.txt

    # exportar o PDF para ./out/
    docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile test \
        run --rm --user "$(id -u):$(id -g)" -v "$PWD/out:/app/out" \
        tests python -m tests.lab_scan report <scan_id>
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.common.config import get_settings
from scanner.common.db import Organization, Report, Scan, Target, User, make_session_factory
from scanner.common.models import Scope, StageMessage
from scanner.common.queue import STREAM_RECON_REQUESTED, connect, publish
from scanner.web.security import generate_password, hash_password
from scanner.web_scan.policy import PROFILES

# Únicos alvos aceitos. `exclude_paths` evita páginas que derrubam a sessão ou resetam o lab.
LAB_TARGETS: dict[str, Scope] = {
    "juice-shop": Scope(
        scope_id="lab-juice-shop",
        verified=True,
        locked=True,
        base_urls=["http://juice-shop:3000/"],
        allowed_hosts=["juice-shop"],
    ),
    "dvwa": Scope(
        scope_id="lab-dvwa",
        verified=True,
        locked=True,
        base_urls=["http://dvwa/"],
        allowed_hosts=["dvwa"],
        exclude_paths=[r"^/logout\.php", r"^/setup\.php"],
    ),
}


# Credenciais de teste do laboratório (registradas no próprio alvo). Só laboratório: nunca um alvo real.
LAB_LOGIN: dict[str, dict[str, str]] = {
    "juice-shop": {
        "login_url": "http://juice-shop:3000/rest/user/login",
        "register_url": "http://juice-shop:3000/api/Users",
        "email": "scanner-test@lab.local",
        "password": "ScannerLab123!",
    },
}


LAB_ORG = "org-laboratorio"


def _ensure_lab_targets(session: Session) -> None:
    """Sites de laboratório na organização de demonstração (verificados: são só o lab)."""
    if session.get(Organization, LAB_ORG) is None:
        session.add(Organization(org_id=LAB_ORG, name="Laboratório Pitchy"))
        session.flush()
    for name, scope in LAB_TARGETS.items():
        if session.get(Target, f"lab-{name}") is None:
            session.add(
                Target(
                    target_id=f"lab-{name}",
                    org_id=LAB_ORG,
                    domain=name,
                    base_url=scope.base_urls[0],
                    verification_token="laboratorio",
                    verified_at=datetime.now(UTC),
                )
            )


def seed() -> None:
    sessions = make_session_factory(get_settings().database_url)
    lines = ["Acessos do laboratório (gerados agora; guarde e apague este arquivo depois).", ""]
    with sessions.begin() as session:
        _ensure_lab_targets(session)
        for email, name, role, org in (
            ("admin@laboratorio.pitchy", "Admin do Laboratório", "admin", None),
            ("cliente@laboratorio.pitchy", "Cliente de Demonstração", "client", LAB_ORG),
        ):
            password = generate_password()
            user = session.scalars(select(User).where(User.email == email)).first()
            if user is None:
                user = User(
                    user_id=f"user-{uuid.uuid4().hex[:12]}",
                    email=email,
                    name=name,
                    role=role,
                    org_id=org,
                    password_hash="",
                )
                session.add(user)
            user.password_hash = hash_password(password)
            user.failed_logins, user.locked_until, user.is_active = 0, None, True
            lines += [f"{role:6}  {email}  {password}"]
    lines += ["", "Interface: http://localhost:8000"]
    print("\n".join(lines))


def start(target: str, profile: str = "safe", login: bool = False) -> None:
    settings = get_settings()
    scope = LAB_TARGETS[target]
    scan_id = f"lab-{target}-{uuid.uuid4().hex[:8]}"
    sessions = make_session_factory(settings.database_url)
    with sessions.begin() as session:
        _ensure_lab_targets(session)
        session.add(
            Scan(
                scan_id=scan_id,
                target_id=f"lab-{target}",
                verified=True,
                scope_locked=True,
                scope=scope.model_dump(mode="json"),
                status="requested",
                requested_by="laboratorio",
            )
        )
    payload: dict[str, object] = {"profile": profile}
    if login:
        payload["credential"] = _lab_login_credential(target)
    msg = StageMessage(
        message_id=f"{scan_id}:recon.requested",
        scan_id=scan_id,
        target_id=f"lab-{target}",
        stage="recon.requested",
        scope=scope,
        payload=payload,
    )
    publish(connect(settings.redis_url), STREAM_RECON_REQUESTED, msg)
    extra = " (autenticado)" if login else ""
    print(f"scan disparado: {scan_id} (perfil {profile}){extra}")


def _lab_login_credential(target: str) -> dict[str, str]:
    """Garante o usuário de teste no alvo de laboratório e devolve a credencial de login.

    Registrar o usuário é passo de laboratório (o alvo é vulnerável de propósito). Em produção, a
    credencial vem por referência a um cofre — pendente de alinhar com o time.
    """
    import httpx

    if target not in LAB_LOGIN:
        sys.exit(f"sem credencial de laboratório para {target}")
    cfg = LAB_LOGIN[target]
    body = {
        "email": cfg["email"],
        "password": cfg["password"],
        "passwordRepeat": cfg["password"],
        "securityQuestion": {"id": 1},
        "securityAnswer": "lab",
    }
    try:
        httpx.post(cfg["register_url"], json=body, timeout=15)  # 2xº: já existe, tudo bem
    except httpx.HTTPError as exc:
        print(f"aviso: registro do usuário de teste falhou ({exc}); tentando login mesmo assim")
    return {
        "type": "login",
        "login_url": cfg["login_url"],
        "email": cfg["email"],
        "password": cfg["password"],
    }


def report(scan_id: str) -> None:
    sessions = make_session_factory(get_settings().database_url)
    with sessions() as session:
        row = session.get(Report, scan_id)
        if row is None:
            sys.exit(f"ainda não há relatório para {scan_id} (o scan pode estar rodando)")
        out = Path("out")
        out.mkdir(exist_ok=True)
        (out / f"{scan_id}.pdf").write_bytes(row.pdf)
        (out / f"{scan_id}.html").write_text(row.html, encoding="utf-8")
        print(f"relatório salvo em out/{scan_id}.pdf e out/{scan_id}.html")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    start_cmd = sub.add_parser("start")
    start_cmd.add_argument("target", choices=sorted(LAB_TARGETS))
    start_cmd.add_argument(
        "--profile", choices=sorted(PROFILES), default="safe", help="nível de scan (padrão: safe)"
    )
    start_cmd.add_argument(
        "--login", action="store_true", help="scan autenticado (usuário de teste do laboratório)"
    )
    sub.add_parser("report").add_argument("scan_id")
    sub.add_parser("coverage").add_argument("scan_id")
    sub.add_parser("seed")
    args = parser.parse_args()
    if args.cmd == "seed":
        seed()
    elif args.cmd == "start":
        start(args.target, args.profile, args.login)
    elif args.cmd == "coverage":
        from tests.lab_coverage import coverage

        coverage(args.scan_id)
    else:
        report(args.scan_id)


if __name__ == "__main__":
    main()
