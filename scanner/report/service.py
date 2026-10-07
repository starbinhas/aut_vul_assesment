"""Orquestra a etapa 6: achados validados → remediação → JSON → HTML → PDF → publicação."""

from __future__ import annotations

import logging

import anthropic
import redis
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from scanner.common.authz import check_authorized
from scanner.common.config import Settings
from scanner.common.db import FindingRow, ScanStatus, set_scan_status
from scanner.common.db import Report as ReportRow
from scanner.common.models import Finding, StageMessage
from scanner.common.queue import STREAM_REPORT_READY, make_message, publish
from scanner.report.builder import build_report
from scanner.report.llm import RemediationWriter
from scanner.report.remediation import get_remediation
from scanner.report.render import render_html, render_pdf
from scanner.report.stack import detect_stack

log = logging.getLogger(__name__)


def make_writer(settings: Settings) -> RemediationWriter | None:
    key = settings.anthropic_api_key.get_secret_value()
    if not key:
        log.warning("ANTHROPIC_API_KEY ausente; remediações virão só do catálogo")
        return None
    return RemediationWriter(
        anthropic.Anthropic(api_key=key), settings.llm_model, settings.llm_effort
    )


def handle(
    session: Session,
    msg: StageMessage,
    settings: Settings,
    r: redis.Redis,
    writer: RemediationWriter | None,
    sessions: sessionmaker,  # type: ignore[type-arg]
) -> None:
    check_authorized(session, msg)
    tools_done = set(msg.payload.get("tools_done", []))
    missing = set(settings.report_required_tools) - tools_done
    if missing:
        log.info("aguardando outras fontes", extra={"missing": sorted(missing)})
        set_scan_status(
            sessions,
            msg.scan_id,
            ScanStatus.VALIDATING,
            "aguardando: " + ", ".join(sorted(missing)),
        )
        return
    # `regenerate` vem da interface depois de uma revisão humana.
    existing = session.get(ReportRow, msg.scan_id)
    if existing is not None and not msg.payload.get("regenerate"):
        log.info("relatório já gerado para este scan")
        return
    set_scan_status(sessions, msg.scan_id, ScanStatus.REPORTING, None)

    findings = [
        Finding.model_validate(row.data)
        for row in session.scalars(select(FindingRow).where(FindingRow.scan_id == msg.scan_id))
    ]
    stack = detect_stack(findings)
    language = msg.payload.get("language", "pt-BR")
    report = build_report(
        msg.scan_id,
        msg.target_id,
        findings,
        lambda f: get_remediation(session, writer, f, stack, language),
        language=language,
    )
    html = render_html(report)
    pdf = render_pdf(html)
    values = {
        "report_json": report.model_dump(mode="json"),
        "html": html,
        "pdf": pdf,
        "created_at": func.now(),  # a interface compara revisões humanas com esta data
    }
    stmt = insert(ReportRow).values(scan_id=msg.scan_id, **values)
    session.execute(stmt.on_conflict_do_update(index_elements=[ReportRow.scan_id], set_=values))
    log.info("relatório gerado", extra={"items": len(report.items), "stack": stack})
    set_scan_status(sessions, msg.scan_id, ScanStatus.DONE, None)
    publish(
        r,
        STREAM_REPORT_READY,
        make_message(msg, "report.ready", {"summary": report.summary.model_dump()}),
    )
