"""Cópia de teste (homologação) autorizada: o único lugar fora do laboratório onde o perfil
intrusivo (que grava dados e faz o alvo sair para a internet) pode rodar.

Regra 3 do CLAUDE.md: nada que grave dados roda em produção. O cliente libera o intrusivo para uma
CÓPIA do site quando, nesta ordem:
1. a cópia é um site cadastrado, separado do oficial, com domínio comprovado (etapa 1);
2. alguém da organização confirma o checklist e assina o termo (nome, versão e hash do texto);
3. o time aprova (revisão humana);
4. ainda está dentro da validade.

A interface (para mostrar e aceitar o perfil) e o worker-web (de novo, porque a mensagem da fila
pode vir de qualquer origem) consultam `staging_cleared`.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.common.db import StagingAuthorization

DRAFT = "draft"  # cópia cadastrada; falta comprovar o domínio e/ou assinar
REQUESTED = "requested"  # assinada; esperando o time
APPROVED = "approved"  # liberada até `valid_until`
REJECTED = "rejected"  # o time recusou (motivo em `review_note`); o cliente pode corrigir
REVOKED = "revoked"  # encerrada antes do prazo (cliente ou time)

# Validade que o cliente pode escolher, em dias, contada da aprovação.
VALIDITY_DAYS = (7, 30, 90)


def latest(session: Session, staging_target_id: str) -> StagingAuthorization | None:
    return session.scalars(
        select(StagingAuthorization)
        .where(StagingAuthorization.staging_target_id == staging_target_id)
        .order_by(StagingAuthorization.created_at.desc(), StagingAuthorization.auth_id.desc())
        .limit(1)
    ).first()


def is_active(row: StagingAuthorization, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    return row.status == APPROVED and row.valid_until is not None and now < _aware(row.valid_until)


def is_expired(row: StagingAuthorization, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    return row.status == APPROVED and row.valid_until is not None and now >= _aware(row.valid_until)


def staging_cleared(
    session: Session, target_id: str, hosts: list[str], now: datetime | None = None
) -> bool:
    """O escopo é exatamente a cópia liberada, e a liberação está vigente?

    Compara com o host gravado na assinatura: se o endereço do site mudasse depois, a liberação
    não acompanharia.
    """
    row = latest(session, target_id)
    return (
        row is not None
        and is_active(row, now)
        and bool(hosts)
        and {h.lower() for h in hosts} == {row.staging_host}
    )


def _aware(value: datetime) -> datetime:
    """SQLite (testes) devolve datas sem fuso; o Postgres, com. Tudo é gravado em UTC."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)
