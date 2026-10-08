"""Cópia de teste (homologação): o caminho guiado para o cliente liberar o perfil intrusivo.

O cliente não precisa saber segurança. A interface leva em quatro passos:
1. criar a cópia — com uma mensagem pronta para mandar a quem cuida do site;
2. cadastrar e comprovar o domínio da cópia (mesma etapa 1 de qualquer site);
3. confirmar o checklist em linguagem simples e assinar o termo;
4. esperar o time aprovar.

A regra de quando o intrusivo pode rodar fica em `scanner/common/staging.py`; aqui só o fluxo.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import dns.exception
import dns.resolver
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.common import staging as rules
from scanner.common.db import Organization, StagingAuthorization, Target
from scanner.common.scope import scope_for
from scanner.web import verification
from scanner.web.services import audit
from scanner.web.tenancy import Viewer
from scanner.web_scan import policy


class StagingError(ValueError):
    """Mensagem pronta para mostrar ao cliente."""


# --- textos (versionados: o hash do que foi mostrado vai para a assinatura) ---------------

TERM_VERSION = "2026-10-08"

# (chave, o que a pessoa confirma, por que importa). Todas obrigatórias, menos as de `OPTIONAL`.
CHECKLIST: list[tuple[str, str, str]] = [
    (
        "separate_copy",
        "É uma cópia separada: mexer nela não muda nada no site oficial.",
        "Os testes gravam dados de propósito. Na cópia, isso não chega aos seus clientes.",
    ),
    (
        "separate_database",
        "O banco de dados da cópia é outro, não o mesmo do site oficial.",
        "Se a cópia usar o banco do site oficial, os dados de teste aparecem lá.",
    ),
    (
        "no_real_messages",
        "A cópia não manda e-mail, SMS ou WhatsApp para pessoas de verdade.",
        "O teste preenche formulários centenas de vezes. Cada envio pode virar uma mensagem.",
    ),
    (
        "payments_sandbox",
        "Pagamentos e integrações estão em modo de teste ou desligados.",
        "Assim nenhum pedido, cobrança ou nota fiscal de verdade é gerado.",
    ),
    (
        "disposable",
        "Posso apagar e refazer a cópia se o teste bagunçar os dados.",
        "É normal a cópia ficar cheia de cadastros e textos estranhos depois do teste.",
    ),
    (
        "fake_personal_data",
        "A cópia não tem dados pessoais reais (ou foram trocados por fictícios).",
        "Recomendado pela LGPD: se uma falha expuser dados, não serão de pessoas reais.",
    ),
]
OPTIONAL = frozenset({"fake_personal_data"})


def term_paragraphs(org: str, production_host: str, staging_host: str, days: int) -> list[str]:
    return [
        f"{org} autoriza a Pitchy a fazer o teste intrusivo em {staging_host}, cópia de teste "
        f"do site {production_host}, por {days} dias a partir da aprovação do time.",
        "No teste intrusivo, o scanner grava dados na cópia (cadastros, comentários, pedidos de "
        "teste), envia valores que tentam fazer o servidor da cópia acessar endereços externos "
        "e repete formulários muitas vezes.",
        f"O teste fica restrito a {staging_host}. Nunca acessa {production_host} nem outro "
        "endereço, não faz testes de sobrecarga para derrubar o servidor e respeita o limite de "
        "requisições por segundo.",
        "Quem assina declara que responde por esses sites (ou foi autorizado por quem responde), "
        "que as confirmações acima são verdadeiras e que pode encerrar a autorização a qualquer "
        "momento por esta página.",
    ]


def term_digest(paragraphs: list[str]) -> str:
    return hashlib.sha256(f"{TERM_VERSION}\n".encode() + "\n".join(paragraphs).encode()).hexdigest()


def developer_message(production: Target) -> str:
    """Mensagem para o cliente encaminhar a quem cuida do site (agência, dev, hospedagem)."""
    host = production.domain
    return (
        f"Oi! Preciso de uma cópia de teste do site {host} para um teste de segurança.\n\n"
        f"1. Crie a cópia num endereço próprio, por exemplo teste.{host}.\n"
        "2. Use um banco de dados separado (uma cópia do atual serve). Se der, troque os dados "
        "pessoais de clientes por dados fictícios.\n"
        "3. Desligue o envio de e-mail, SMS e WhatsApp na cópia, ou mande tudo para uma caixa "
        "de teste (Mailtrap, MailHog).\n"
        "4. Deixe pagamentos e integrações em modo sandbox/teste.\n"
        "5. Se possível, coloque a cópia num servidor diferente do site oficial: o teste pode "
        "deixar o servidor lento.\n\n"
        "Depois me passe o endereço da cópia. Vou precisar também que você crie um registro DNS "
        "(TXT) que o scanner vai mostrar."
    )


def dns_message(staging: Target) -> str:
    return (
        f"Oi! Preciso de um registro DNS no domínio da cópia de teste ({staging.domain}):\n\n"
        "Tipo: TXT\n"
        f"Nome: {verification.record_name(staging.domain)}\n"
        f"Valor: {verification.record_value(staging.verification_token)}\n\n"
        "É só para comprovar que o domínio é nosso. Me avise quando estiver criado."
    )


# --- conferências automáticas -----------------------------------------------------------


@dataclass(frozen=True)
class Check:
    label: str
    ok: bool | None  # None = não deu para conferir agora
    detail: str


AddressResolver = Callable[[str], set[str]]


def _addresses(host: str) -> set[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    found: set[str] = set()
    for kind in ("A", "AAAA"):
        try:
            found |= {r.to_text() for r in resolver.resolve(host, kind)}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
    return found


def automatic_checks(
    staging: Target, production: Target, resolve: AddressResolver | None = None
) -> list[Check]:
    """O que dá para conferir sem a pessoa: ajuda o cliente e o time na revisão."""
    resolve = resolve or _addresses
    checks = [
        Check(
            "Domínio da cópia comprovado",
            staging.verified_at is not None,
            "Registro TXT encontrado."
            if staging.verified_at
            else "Falta criar o registro TXT da cópia.",
        ),
        Check(
            "Endereço diferente do site oficial",
            staging.domain != production.domain,
            f"{staging.domain} e {production.domain}.",
        ),
    ]
    try:
        mine, theirs = resolve(staging.domain), resolve(production.domain)
    except (dns.exception.DNSException, OSError):
        checks.append(Check("Servidor separado", None, "O DNS não respondeu agora."))
    else:
        shared = sorted(mine & theirs)
        if not mine:
            checks.append(Check("Servidor separado", None, "A cópia ainda não tem endereço IP."))
        elif shared:
            checks.append(
                Check(
                    "Servidor separado",
                    False,
                    f"A cópia e o site oficial apontam para {', '.join(shared)}. Pode ser o mesmo "
                    "servidor (ou só a mesma CDN): o teste pode deixar o site oficial lento.",
                )
            )
        else:
            checks.append(Check("Servidor separado", True, "Endereços IP diferentes."))
    return checks


# --- fluxo ------------------------------------------------------------------------------


def for_production(session: Session, production_target_id: str) -> StagingAuthorization | None:
    """Pedido mais recente ligado a este site oficial."""
    return session.scalars(
        select(StagingAuthorization)
        .where(StagingAuthorization.production_target_id == production_target_id)
        .order_by(StagingAuthorization.created_at.desc(), StagingAuthorization.auth_id.desc())
        .limit(1)
    ).first()


def _new_row(production: Target, staging: Target, viewer: Viewer) -> StagingAuthorization:
    return StagingAuthorization(
        auth_id=f"hml-{uuid.uuid4().hex[:12]}",
        org_id=production.org_id,
        production_target_id=production.target_id,
        staging_target_id=staging.target_id,
        staging_host=scope_for(staging).allowed_hosts[0].lower(),  # o mesmo host do escopo
        status=rules.DRAFT,
        checklist={},
        created_by=viewer.user_id,
        created_at=datetime.now(UTC),
    )


def register_copy(
    session: Session, viewer: Viewer, production: Target, raw: str
) -> StagingAuthorization:
    """Passo 2: cadastra o endereço da cópia (como um site da mesma organização)."""
    domain, base_url = verification.normalize_site(raw)  # InvalidSiteError é um ValueError
    if domain == production.domain:
        raise StagingError(
            "A cópia precisa de um endereço próprio, diferente do site oficial "
            f"(por exemplo teste.{production.domain})."
        )
    staging = session.scalars(
        select(Target).where(Target.org_id == production.org_id, Target.domain == domain)
    ).first()
    if staging is None:
        staging = Target(
            target_id=f"site-{verification.new_token()[:12]}",
            org_id=production.org_id,
            domain=domain,
            base_url=base_url,
            verification_token=verification.new_token(),
            created_by=viewer.user_id,
        )
        session.add(staging)
        session.flush()
        audit(
            session,
            viewer,
            "site.create",
            org_id=production.org_id,
            object_type="site",
            object_id=staging.target_id,
            domain=domain,
        )
    elif (taken := rules.latest(session, staging.target_id)) is not None:
        if taken.production_target_id != production.target_id:
            raise StagingError("Esse endereço já está cadastrado como cópia de outro site.")
        if taken.status in (rules.DRAFT, rules.REJECTED, rules.REQUESTED) or rules.is_active(taken):
            return taken  # mesmo pedido em andamento: segue de onde parou
    row = _new_row(production, staging, viewer)
    session.add(row)
    session.flush()
    audit(
        session,
        viewer,
        "staging.register",
        org_id=production.org_id,
        object_type="staging",
        object_id=row.auth_id,
        production=production.domain,
        copy=domain,
    )
    return row


def verify_copy(session: Session, viewer: Viewer, staging: Target) -> None:
    """Mesma prova de domínio da etapa 1, chamada de dentro do passo a passo."""
    if staging.verified_at is not None:
        return
    problem = verification.check_txt(staging.domain, staging.verification_token)
    staging.last_check_at = datetime.now(UTC)
    staging.last_check_error = problem
    if problem is None:
        staging.verified_at = staging.last_check_at
        audit(
            session,
            viewer,
            "site.verified",
            org_id=staging.org_id,
            object_type="site",
            object_id=staging.target_id,
            domain=staging.domain,
        )


def sign(
    session: Session,
    viewer: Viewer,
    row: StagingAuthorization,
    *,
    staging: Target,
    production: Target,
    confirmed: set[str],
    signer_name: str,
    signer_role: str,
    emergency_contact: str,
    days: int,
    accepted: bool,
    ip: str | None,
) -> None:
    """Passo 3: checklist + termo. Só quem é da organização assina (o admin não assina por ela)."""
    if viewer.is_admin or viewer.org_id != row.org_id:
        raise StagingError("Quem assina é alguém da empresa dona do site, não o time da Pitchy.")
    if row.status not in (rules.DRAFT, rules.REJECTED):
        raise StagingError("Este pedido já foi assinado.")
    if staging.verified_at is None:
        raise StagingError("Comprove o domínio da cópia antes de assinar.")
    missing = [text for key, text, _ in CHECKLIST if key not in OPTIONAL and key not in confirmed]
    if missing:
        raise StagingError(f"Falta confirmar: {missing[0]}")
    signer_name, signer_role = signer_name.strip(), signer_role.strip()
    emergency_contact = emergency_contact.strip()
    if len(signer_name) < 5 or " " not in signer_name:
        raise StagingError("Escreva seu nome completo.")
    if not signer_role:
        raise StagingError("Diga qual é o seu cargo ou papel na empresa.")
    if len(emergency_contact) < 8:
        raise StagingError("Deixe um telefone ou e-mail para avisarmos se algo der errado.")
    if days not in rules.VALIDITY_DAYS:
        raise StagingError("Escolha por quanto tempo a autorização vale.")
    if not accepted:
        raise StagingError("Marque que leu e autoriza o teste.")
    org = session.get(Organization, row.org_id)
    paragraphs = term_paragraphs(org.name if org else "", production.domain, staging.domain, days)
    row.checklist = {key: key in confirmed for key, _, _ in CHECKLIST}
    row.term_version = TERM_VERSION
    row.term_sha256 = term_digest(paragraphs)
    row.signer_name = signer_name[:200]
    row.signer_role = signer_role[:200]
    row.signer_user_id = viewer.user_id
    row.signer_ip = (ip or "")[:64] or None
    row.emergency_contact = emergency_contact[:200]
    row.valid_days = days
    row.signed_at = datetime.now(UTC)
    row.status = rules.REQUESTED
    row.reviewed_by = row.reviewed_at = row.review_note = None
    audit(
        session,
        viewer,
        "staging.sign",
        org_id=row.org_id,
        object_type="staging",
        object_id=row.auth_id,
        copy=staging.domain,
        term_version=TERM_VERSION,
        term_sha256=row.term_sha256,
        days=days,
    )


def decide(
    session: Session, viewer: Viewer, row: StagingAuthorization, approve: bool, note: str
) -> None:
    """Passo 4 (time): aprova ou recusa. Recusar exige motivo, que o cliente vê."""
    if not viewer.is_admin:
        raise PermissionError("só o time aprova cópias de teste")
    if row.status != rules.REQUESTED:
        raise StagingError("Este pedido não está esperando revisão.")
    note = note.strip()
    if not approve and len(note) < 10:
        raise StagingError("Explique ao cliente o motivo da recusa (pelo menos 10 caracteres).")
    now = datetime.now(UTC)
    row.reviewed_by = viewer.user_id
    row.reviewed_at = now
    row.review_note = note[:500] or None
    if approve:
        row.status = rules.APPROVED
        row.valid_until = now + timedelta(days=row.valid_days or rules.VALIDITY_DAYS[0])
    else:
        row.status = rules.REJECTED
    audit(
        session,
        viewer,
        "staging.approve" if approve else "staging.reject",
        org_id=row.org_id,
        object_type="staging",
        object_id=row.auth_id,
        note=note,
    )


def revoke(session: Session, viewer: Viewer, row: StagingAuthorization) -> None:
    """Encerra antes do prazo. O cliente e o time podem, a qualquer momento."""
    if row.status not in (rules.REQUESTED, rules.APPROVED) or rules.is_expired(row):
        raise StagingError("Esta autorização já não está valendo.")
    row.status = rules.REVOKED
    audit(
        session,
        viewer,
        "staging.revoke",
        org_id=row.org_id,
        object_type="staging",
        object_id=row.auth_id,
    )


def renew(session: Session, viewer: Viewer, row: StagingAuthorization) -> StagingAuthorization:
    """Nova autorização para a mesma cópia (depois de vencida ou encerrada): assina de novo."""
    if not (row.status == rules.REVOKED or rules.is_expired(row)):
        raise StagingError("A autorização atual ainda está em andamento.")
    production = session.get(Target, row.production_target_id)
    staging = session.get(Target, row.staging_target_id)
    if production is None or staging is None:
        raise StagingError("O site ou a cópia não existem mais.")
    new = _new_row(production, staging, viewer)
    session.add(new)
    session.flush()
    audit(
        session,
        viewer,
        "staging.renew",
        org_id=row.org_id,
        object_type="staging",
        object_id=new.auth_id,
        previous=row.auth_id,
    )
    return new


def step_of(row: StagingAuthorization | None, staging: Target | None) -> int:
    """Em que passo do caminho a pessoa está (1 a 4; 5 = liberado)."""
    if row is None or staging is None:
        return 1
    if row.status in (rules.DRAFT, rules.REJECTED):
        return 2 if staging.verified_at is None else 3
    if row.status == rules.REQUESTED:
        return 4
    if rules.is_active(row):
        return 5
    return 3  # vencida ou encerrada: assinar de novo


@dataclass(frozen=True)
class StagingView:
    """O que a página do site mostra sobre cópia de teste."""

    role: str | None  # "production" (tem cópia), "copy" (é a cópia), None (nada ainda)
    row: StagingAuthorization | None
    other: Target | None  # a cópia (se role=production) ou o site oficial (se role=copy)
    active: bool
    offer: bool  # mostrar o convite para criar uma cópia


def staging_view(session: Session, target: Target, lab_hosts: list[str]) -> StagingView:
    as_copy = rules.latest(session, target.target_id)
    if as_copy is not None:
        return StagingView(
            "copy",
            as_copy,
            session.get(Target, as_copy.production_target_id),
            rules.is_active(as_copy),
            False,
        )
    as_production = for_production(session, target.target_id)
    if as_production is not None:
        return StagingView(
            "production",
            as_production,
            session.get(Target, as_production.staging_target_id),
            rules.is_active(as_production),
            False,
        )
    lab = policy.is_lab_scope(scope_for(target).allowed_hosts, lab_hosts)
    return StagingView(None, None, None, False, target.verified_at is not None and not lab)
