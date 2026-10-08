"""Worker da etapa 6: consome `scan.validated` e publica em `scan.report.ready`."""

from scanner.common.config import get_settings
from scanner.common.db import ScanStatus, make_session_factory, set_scan_status
from scanner.common.logging import setup_logging
from scanner.common.queue import STREAM_VALIDATED, connect, consume
from scanner.report.service import handle, make_writer


def main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    r = connect(settings.redis_url)
    writer = make_writer(settings)
    sessions = make_session_factory(settings.database_url)
    consume(
        r,
        sessions,
        STREAM_VALIDATED,
        group="report",
        consumer=settings.consumer_name,
        handler=lambda session, msg: handle(session, msg, settings, r, writer, sessions),
        on_give_up=lambda m: set_scan_status(
            sessions, m.scan_id, ScanStatus.FAILED, "falhou após várias tentativas"
        ),
    )


if __name__ == "__main__":
    main()
