"""Worker da etapa 3: consome `scan.cve.requested` e publica candidatos em `scan.candidates`."""

from scanner.common.config import get_settings
from scanner.common.db import make_session_factory
from scanner.common.logging import setup_logging
from scanner.common.queue import STREAM_CVE_REQUESTED, connect, consume
from scanner.cve.service import handle


def main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    r = connect(settings.redis_url)
    sessions = make_session_factory(settings.database_url)
    consume(
        r,
        sessions,
        STREAM_CVE_REQUESTED,
        group="cve",
        consumer=settings.consumer_name,
        handler=lambda session, msg: handle(session, msg, settings, r, sessions),
        retry_after_ms=(settings.scan_max_duration_minutes + 10) * 60_000,
    )


if __name__ == "__main__":
    main()
