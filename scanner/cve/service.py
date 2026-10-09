"""Execução do nuclei (etapa 3) e geração dos candidatos."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess

import redis
from sqlalchemy.orm import Session, sessionmaker

from scanner.common.config import Settings
from scanner.common.models import Finding, StageMessage
from scanner.cve.nuclei import build_nuclei_command, parse_nuclei_jsonl

log = logging.getLogger(__name__)


def run_nuclei(target_url: str, timeout_s: int = 600) -> str:
    """Roda o nuclei contra `target_url` e devolve o stdout (JSONL).

    Recusa com erro claro se o binário `nuclei` não estiver instalado (import continua seguro).
    """
    if shutil.which("nuclei") is None:
        raise RuntimeError(
            "nuclei não encontrado no PATH; instale o binário do ProjectDiscovery para a etapa 3."
        )
    result = subprocess.run(  # noqa: S603 — argv fixo, sem shell
        build_nuclei_command(target_url, os.environ.get("NUCLEI_TEMPLATES_DIR")),
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    return result.stdout


def scan_cves(target_url: str, scan_id: str, target_id: str) -> list[Finding]:
    """Executa o nuclei e converte a saída em candidatos (`Finding`)."""
    output = run_nuclei(target_url)
    return parse_nuclei_jsonl(output, scan_id, target_id)


def scan_targets(targets: list[str], scan_id: str, target_id: str) -> list[Finding]:
    """Roda o nuclei em cada alvo e agrega os candidatos, deduplicados por `finding_id`.

    Antes, a etapa 3 só varria um alvo. Agora varre todos os `cve_targets` do recon (base_urls +
    serviços web em portas descobertas). Se o binário não existir, erra claro no 1º alvo.
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    for target_url in targets:
        for f in scan_cves(target_url, scan_id, target_id):
            if f.finding_id not in seen:
                seen.add(f.finding_id)
                findings.append(f)
    return findings


def handle(
    session: Session,
    msg: StageMessage,
    settings: Settings,
    r: redis.Redis,
    sessions: sessionmaker,  # type: ignore[type-arg]
) -> None:
    """Etapa 3: autoriza, roda o nuclei e publica os candidatos (tool 'nuclei')."""
    from scanner.common.authz import check_authorized
    from scanner.common.db import ScanStatus, set_scan_status
    from scanner.common.queue import STREAM_CANDIDATES, make_message, publish

    with sessions() as authz:
        scope = check_authorized(authz, msg)
    set_scan_status(sessions, msg.scan_id, ScanStatus.CVE_SCANNING, "cve")
    targets = list(msg.payload.get("cve_targets") or scope.base_urls)
    try:
        findings = scan_targets(targets, msg.scan_id, msg.target_id)
    except RuntimeError as exc:
        log.error("nuclei indisponível", extra={"error": str(exc)})
        findings = []
    log.info("cve: candidatos", extra={"findings": len(findings)})
    out = make_message(
        msg,
        "candidates",
        {"tool": "nuclei", "findings": [f.model_dump(mode="json") for f in findings]},
    )
    publish(r, STREAM_CANDIDATES, out)
