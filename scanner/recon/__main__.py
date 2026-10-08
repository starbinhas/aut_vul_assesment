"""Worker da etapa 2: consome `scan.recon.requested`, descobre portas e dispara etapas 3 e 4."""

from scanner.common.config import get_settings
from scanner.common.db import ScanStatus, make_session_factory, set_scan_status
from scanner.common.logging import setup_logging
from scanner.common.queue import STREAM_RECON_REQUESTED, connect, consume
from scanner.recon.service import handle


def main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    r = connect(settings.redis_url)
    sessions = make_session_factory(settings.database_url)
    consume(
        r,
        sessions,
        STREAM_RECON_REQUESTED,
        group="recon",
        consumer=settings.consumer_name,
        handler=lambda session, msg: handle(session, msg, settings, r, sessions),
        retry_after_ms=15 * 60_000,
        on_give_up=lambda m: set_scan_status(
            sessions, m.scan_id, ScanStatus.FAILED, "falhou após várias tentativas"
        ),
    )


if __name__ == "__main__":
    main()
