"""Orquestra a etapa 5: dedup → validação → severidade → persistência → publicação."""

from __future__ import annotations

import logging

import httpx
import redis
from sqlalchemy import select as sql_select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from scanner.common.authz import check_authorized
from scanner.common.config import Settings
from scanner.common.db import FindingRow, ScanStatus, StageProgress, set_scan_status
from scanner.common.evidence import strip_nul
from scanner.common.models import Finding, Outcome, StageMessage, Status
from scanner.common.queue import STREAM_VALIDATED, make_message, publish
from scanner.common.scope import OutOfScopeError, ScopeGuard
from scanner.validation import dedup, severity
from scanner.validation import proactive as proactive_checks
from scanner.validation.http import ProbeClient, UnsafeRequestError
from scanner.validation.validators import select
from scanner.validation.validators.base import result

log = logging.getLogger(__name__)

OUTCOME_TO_STATUS = {
    Outcome.CONFIRMED: Status.CONFIRMED,
    Outcome.LIKELY: Status.LIKELY,
    Outcome.UNCONFIRMED: Status.UNCONFIRMED,
    Outcome.FALSE_POSITIVE: Status.FALSE_POSITIVE,
}


def validate_one(f: Finding, client: ProbeClient) -> Finding:
    v = select(f)
    if v is None:
        validation = result(
            "none", Outcome.UNCONFIRMED, "ainda não temos teste automático para este tipo de falha"
        )
    else:
        try:
            validation = v.fn(f, client)
        except (OutOfScopeError, UnsafeRequestError) as exc:
            validation = result(v.name, Outcome.UNCONFIRMED, f"prova não executada: {exc}")
        except httpx.TransportError as exc:
            # Alvo fora do ar ou lento na hora da prova: dizer isso, não "erro" genérico.
            log.warning(
                "alvo não respondeu à prova", extra={"validator": v.name, "error": str(exc)}
            )
            validation = result(
                v.name, Outcome.UNCONFIRMED, "o site não respondeu quando repetimos o teste"
            )
        except Exception as exc:
            log.warning("validador falhou", extra={"validator": v.name, "error": str(exc)})
            validation = result(v.name, Outcome.UNCONFIRMED, "erro ao executar a prova")
    validated = f.model_copy(
        update={"validation": validation, "status": OUTCOME_TO_STATUS[validation.outcome]}
    )
    return validated.model_copy(update={"severity": severity.classify(validated)})


def _upsert(session: Session, f: Finding) -> None:
    values = {
        "finding_id": f.finding_id,
        "scan_id": f.scan_id,
        "status": f.status.value,
        "severity": f.severity.value,
        "cwe": f.cwe,
        # O Postgres não aceita \u0000 em JSONB (evidências antigas podem trazê-lo).
        "data": strip_nul(f.model_dump(mode="json")),
    }
    stmt = insert(FindingRow).values(**values)
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=[FindingRow.finding_id],
            set_={k: stmt.excluded[k] for k in ("status", "severity", "cwe", "data")},
        )
    )


def handle(
    session: Session,
    msg: StageMessage,
    settings: Settings,
    r: redis.Redis,
    sessions: sessionmaker,  # type: ignore[type-arg]
) -> None:
    scope = check_authorized(session, msg)
    tool = msg.payload["tool"]
    candidates = [Finding.model_validate(d) for d in msg.payload.get("findings", [])]
    candidates = [c for c in candidates if c.scan_id == msg.scan_id]
    set_scan_status(sessions, msg.scan_id, ScanStatus.VALIDATING, "validate")

    existing = [
        Finding.model_validate(row.data)
        for row in session.scalars(sql_select(FindingRow).where(FindingRow.scan_id == msg.scan_id))
    ]
    new, updated = dedup.deduplicate(candidates, existing)

    # Achados próprios já confirmados pela etapa 4 (A07/A08): entram por upsert direto, sem passar
    # pela re-validação (que rebaixaria um achado sem validador correspondente).
    forwarded = [
        Finding.model_validate(d)
        for d in msg.payload.get("proactive", [])
        if d.get("scan_id") == msg.scan_id
    ]

    client = ProbeClient(ScopeGuard(scope), max_rps=settings.scan_max_requests_per_second)
    try:
        validated = [validate_one(f, client) for f in new]
        # Checagens próprias (fonte "scanner") que o ZAP/nuclei não fazem: rodam uma vez por scan,
        # na mensagem da etapa 4 (toda a cadeia passa por aqui). Idempotentes (finding_id estável).
        proactive = (
            proactive_checks.run_exposed_files(scope, client, msg.scan_id, msg.target_id)
            if tool == "zap"
            else []
        )
    finally:
        client.close()

    for f in [*validated, *proactive, *forwarded, *updated]:
        _upsert(session, f)
    session.execute(
        insert(StageProgress).values(scan_id=msg.scan_id, tool=tool).on_conflict_do_nothing()
    )
    tools_done = sorted(
        session.scalars(sql_select(StageProgress.tool).where(StageProgress.scan_id == msg.scan_id))
    )
    log.info(
        "validação concluída",
        extra={
            "tool": tool,
            "new": len(validated),
            "proactive": len(proactive) + len(forwarded),
            "merged": len(updated),
            "tools_done": tools_done,
        },
    )
    publish(r, STREAM_VALIDATED, make_message(msg, "validated", {"tools_done": tools_done}))
