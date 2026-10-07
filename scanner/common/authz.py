"""Regra 1: nenhum scan sem autorização.

A mensagem da fila não é suficiente: o scan precisa existir no banco, com alvo verificado na
etapa 1, escopo travado e o mesmo escopo que veio na mensagem. Não existe modo que pule isso.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from scanner.common.db import Scan
from scanner.common.models import Scope, StageMessage


class UnauthorizedScanError(Exception):
    pass


def check_authorized(session: Session, msg: StageMessage) -> Scope:
    """Retorna o escopo autorizado (do banco) ou levanta UnauthorizedScanError."""
    if not (msg.scope.verified and msg.scope.locked):
        raise UnauthorizedScanError(
            f"scan {msg.scan_id}: escopo da mensagem não verificado/travado"
        )

    scan = session.get(Scan, msg.scan_id)
    if scan is None:
        raise UnauthorizedScanError(f"scan {msg.scan_id}: inexistente no banco")
    if scan.target_id != msg.target_id:
        raise UnauthorizedScanError(f"scan {msg.scan_id}: target_id diverge do banco")
    if not (scan.verified and scan.scope_locked):
        raise UnauthorizedScanError(
            f"scan {msg.scan_id}: alvo não verificado ou escopo não travado"
        )

    db_scope = Scope.model_validate(scan.scope)
    if db_scope != msg.scope:
        raise UnauthorizedScanError(f"scan {msg.scan_id}: escopo da mensagem difere do travado")
    return db_scope
