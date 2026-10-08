"""Worker da etapa 4: consome `scan.web.requested` e publica em `scan.candidates`."""

from scanner.common.config import get_settings
from scanner.common.db import ScanStatus, make_session_factory, set_scan_status
from scanner.common.logging import setup_logging
from scanner.common.queue import STREAM_WEB_REQUESTED, connect, consume
from scanner.web_scan.service import handle


def main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    r = connect(settings.redis_url)
    sessions = make_session_factory(settings.database_url)
    consume(
        r,
        sessions,
        STREAM_WEB_REQUESTED,
        group="web_scan",
        consumer=settings.consumer_name,
        # Um scan por vez por par ZAP/worker (count=1 no consume).
        handler=lambda session, msg: handle(session, msg, settings, r, sessions),
        # Um scan pode levar o tempo máximo inteiro: só retentar depois disso (+10 min).
        retry_after_ms=(settings.scan_max_duration_minutes + 10) * 60_000,
        on_give_up=lambda m: set_scan_status(
            sessions, m.scan_id, ScanStatus.FAILED, "falhou após várias tentativas"
        ),
    )


if __name__ == "__main__":
    main()
