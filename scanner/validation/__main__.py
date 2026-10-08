"""Worker da etapa 5: consome `scan.candidates` e publica em `scan.validated`."""

from scanner.common.config import get_settings
from scanner.common.db import ScanStatus, make_session_factory, set_scan_status
from scanner.common.logging import setup_logging
from scanner.common.queue import STREAM_CANDIDATES, connect, consume
from scanner.validation.service import handle


def main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    r = connect(settings.redis_url)
    sessions = make_session_factory(settings.database_url)
    consume(
        r,
        sessions,
        STREAM_CANDIDATES,
        group="validation",
        consumer=settings.consumer_name,
        handler=lambda session, msg: handle(session, msg, settings, r, sessions),
        on_give_up=lambda m: set_scan_status(
            sessions, m.scan_id, ScanStatus.FAILED, "falhou após várias tentativas"
        ),
    )


if __name__ == "__main__":
    main()
