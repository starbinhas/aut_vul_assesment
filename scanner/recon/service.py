"""Execução do naabu por subprocess e descoberta por escopo (etapa 2)."""

from __future__ import annotations

import logging
import shutil
import subprocess

import redis
from sqlalchemy.orm import Session, sessionmaker

from scanner.common.config import Settings
from scanner.common.models import Scope, StageMessage
from scanner.recon.naabu import DiscoveredPort, build_naabu_command, parse_naabu_jsonl

log = logging.getLogger(__name__)


def run_naabu(host: str, timeout_s: int = 300) -> list[DiscoveredPort]:
    """Roda o naabu contra um host e devolve as portas abertas.

    Levanta `RuntimeError` claro se o binário não estiver instalado. Não é chamada em tempo de
    import; o `shutil.which` é resolvido só aqui.
    """
    binary = shutil.which("naabu")
    if binary is None:
        raise RuntimeError("naabu não está instalado (binário 'naabu' não encontrado no PATH)")
    cmd = build_naabu_command(host)
    cmd[0] = binary
    log.info("recon iniciado", extra={"host": host, "top_ports": "100"})
    proc = subprocess.run(  # noqa: S603  -- cmd é montado a partir do escopo, sem shell
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    ports = parse_naabu_jsonl(proc.stdout)
    log.info("recon concluído", extra={"host": host, "ports": len(ports)})
    return ports


def discover(scope: Scope, timeout_s: int = 300) -> list[DiscoveredPort]:
    """Varre cada host autorizado do escopo e devolve as portas, deduplicadas.

    Puro de fila/banco: só roda o naabu e agrega. A autorização/escopo já vem travada da etapa 1.
    """
    seen: dict[tuple[str, str, int], DiscoveredPort] = {}
    for host in scope.allowed_hosts:
        for p in run_naabu(host, timeout_s=timeout_s):
            seen.setdefault((p.host, p.ip, p.port), p)
    return list(seen.values())


def handle(
    session: Session,
    msg: StageMessage,
    settings: Settings,
    r: redis.Redis,
    sessions: sessionmaker,  # type: ignore[type-arg]
) -> None:
    """Etapa 2: autoriza, descobre portas e dispara as etapas 3 (CVEs) e 4 (web) em paralelo."""
    from scanner.common.authz import check_authorized
    from scanner.common.db import ScanStatus, set_scan_status
    from scanner.common.queue import (
        STREAM_CVE_REQUESTED,
        STREAM_WEB_REQUESTED,
        make_message,
        publish,
    )

    with sessions() as authz:
        scope = check_authorized(authz, msg)
    set_scan_status(sessions, msg.scan_id, ScanStatus.RECON, "reconhecimento (naabu)")
    try:
        ports = discover(scope)
    except RuntimeError as exc:
        # naabu ausente ou falhou: não trava o pipeline, segue para as próximas etapas.
        log.error("recon indisponível, seguindo", extra={"error": str(exc)})
        ports = []
    set_scan_status(
        sessions, msg.scan_id, ScanStatus.RECON, f"{len(ports)} portas; disparando CVEs e web"
    )
    # Fan-out: etapa 3 (nuclei) e etapa 4 (ZAP) usam o mesmo escopo e correm em paralelo.
    publish(r, STREAM_CVE_REQUESTED, make_message(msg, "cve.requested", dict(msg.payload)))
    publish(r, STREAM_WEB_REQUESTED, make_message(msg, "web.requested", dict(msg.payload)))
