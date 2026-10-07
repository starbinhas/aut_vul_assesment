"""Cliente de Redis Streams com consumer groups e processamento idempotente."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

import redis
from pydantic import ValidationError
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from scanner.common.authz import UnauthorizedScanError
from scanner.common.db import ProcessedMessage
from scanner.common.logging import scan_id_var
from scanner.common.masking import mask_obj, mask_text
from scanner.common.models import Stage, StageMessage

log = logging.getLogger(__name__)

STREAM_RECON_REQUESTED = "scan.recon.requested"
STREAM_CVE_REQUESTED = "scan.cve.requested"
STREAM_WEB_REQUESTED = "scan.web.requested"
STREAM_CANDIDATES = "scan.candidates"
STREAM_VALIDATED = "scan.validated"
STREAM_REPORT_READY = "scan.report.ready"
DEAD_LETTER_SUFFIX = ".dead"

Handler = Callable[[Session, StageMessage], None]

BLOCK_MS = 5000
RECONNECT_SECONDS = 2
MAX_DELIVERIES = 3


def connect(url: str) -> redis.Redis:
    """Cliente Redis com timeout de leitura maior que a espera bloqueante da fila.

    O redis-py 8 usa socket_timeout=5s por padrão: igual ao BLOCK_MS, o XREADGROUP estouraria.
    """
    return redis.Redis.from_url(
        url, socket_timeout=BLOCK_MS / 1000 + 25, socket_connect_timeout=5, health_check_interval=30
    )


def publish(r: redis.Redis, stream: str, msg: StageMessage) -> None:
    r.xadd(stream, {"data": msg.model_dump_json()})


def _claim(session: Session, stream: str, message_id: str) -> bool:
    """Marca a mensagem como processada; False se já tinha sido (reentrega)."""
    stmt = (
        insert(ProcessedMessage)
        .values(stream=stream, message_id=message_id)
        .on_conflict_do_nothing()
        .returning(ProcessedMessage.message_id)
    )
    return session.execute(stmt).first() is not None


def consume(
    r: redis.Redis,
    sessions: sessionmaker,  # type: ignore[type-arg]
    stream: str,
    group: str,
    consumer: str,
    handler: Handler,
    block_ms: int = BLOCK_MS,
    retry_after_ms: int = 60_000,
) -> None:
    """Loop de consumo. O handler roda na mesma transação que registra a idempotência.

    Mensagem que falhou (sem ack) volta depois de `retry_after_ms`; após MAX_DELIVERIES
    tentativas vai para a dead-letter. `retry_after_ms` precisa ser maior que o tempo máximo de
    processamento, senão outro worker "rouba" uma mensagem que ainda está sendo processada.
    """
    try:
        r.xgroup_create(stream, group, id="0", mkstream=True)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise

    log.info("aguardando mensagens", extra={"stream": stream, "group": group})
    while True:
        try:
            _retry_pending(r, sessions, stream, group, consumer, handler, retry_after_ms)
            resp: Any = r.xreadgroup(group, consumer, {stream: ">"}, count=1, block=block_ms)
        except (redis.TimeoutError, redis.ConnectionError) as exc:
            log.warning("Redis indisponível, tentando de novo", extra={"error": str(exc)})
            time.sleep(RECONNECT_SECONDS)
            continue
        for _stream, entries in resp or []:
            for entry_id, fields in entries:
                _handle_entry(r, sessions, stream, group, entry_id, fields, handler)


def _retry_pending(
    r: redis.Redis,
    sessions: sessionmaker,  # type: ignore[type-arg]
    stream: str,
    group: str,
    consumer: str,
    handler: Handler,
    retry_after_ms: int,
) -> None:
    pending: Any = r.xpending_range(stream, group, min="-", max="+", count=10, idle=retry_after_ms)
    for p in pending:
        entry_id = p["message_id"]
        if p["times_delivered"] >= MAX_DELIVERIES:
            entries: Any = r.xrange(stream, entry_id, entry_id)
            raw = entries[0][1].get(b"data", b"") if entries else b""
            log.error(
                "mensagem falhou várias vezes; dead-letter", extra={"entry_id": str(entry_id)}
            )
            _dead_letter(r, stream, raw, f"falhou {p['times_delivered']} vezes")
            r.xack(stream, group, entry_id)
            continue
        claimed: Any = r.xclaim(stream, group, consumer, retry_after_ms, [entry_id])
        for claimed_id, fields in claimed:
            log.warning("reprocessando mensagem", extra={"attempt": p["times_delivered"] + 1})
            _handle_entry(r, sessions, stream, group, claimed_id, fields, handler)


def _handle_entry(
    r: redis.Redis,
    sessions: sessionmaker,  # type: ignore[type-arg]
    stream: str,
    group: str,
    entry_id: Any,
    fields: dict[Any, Any],
    handler: Handler,
) -> None:
    raw = fields.get(b"data") or fields.get("data") or b""
    try:
        msg = StageMessage.model_validate_json(raw)
    except ValidationError as exc:
        log.error("mensagem inválida, enviada para dead-letter", extra={"error": str(exc)})
        _dead_letter(r, stream, raw, str(exc))
        r.xack(stream, group, entry_id)
        return

    token = scan_id_var.set(msg.scan_id)
    try:
        with sessions.begin() as session:
            if not _claim(session, stream, msg.message_id):
                log.info("mensagem já processada, ignorando", extra={"message_id": msg.message_id})
            else:
                handler(session, msg)
        r.xack(stream, group, entry_id)
    except Exception as exc:
        # Sem ack: fica pendente para nova tentativa. Erros de autorização vão para dead-letter.
        if isinstance(exc, UnauthorizedScanError):
            log.error("scan recusado: não autorizado", extra={"error": str(exc)})
            _dead_letter(r, stream, raw, str(exc))
            r.xack(stream, group, entry_id)
        else:
            log.exception("falha ao processar mensagem")
    finally:
        scan_id_var.reset(token)


def _dead_letter(r: redis.Redis, stream: str, raw: Any, error: str) -> None:
    """Guarda a mensagem rejeitada com segredos mascarados (credenciais nunca em texto puro)."""
    try:
        data = json.dumps(mask_obj(json.loads(raw)))
    except (TypeError, ValueError):
        data = mask_text(raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)) or ""
    r.xadd(stream + DEAD_LETTER_SUFFIX, {"data": data, "error": mask_text(error) or ""})


def make_message(
    prev: StageMessage, stage: Stage, payload: dict[str, Any], suffix: str = ""
) -> StageMessage:
    """Mensagem da próxima etapa, com message_id derivado (idempotente em reentregas)."""
    return StageMessage(
        message_id=f"{prev.message_id}:{stage}{suffix}",
        scan_id=prev.scan_id,
        target_id=prev.target_id,
        stage=stage,
        scope=prev.scope,
        payload=json.loads(json.dumps(payload, default=str)),
    )
