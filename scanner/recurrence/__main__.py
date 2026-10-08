"""Worker da etapa 7: agendador que repete scans vencidos (semanal/mensal)."""

import time

from scanner.common.config import get_settings
from scanner.common.db import make_session_factory
from scanner.common.logging import setup_logging
from scanner.common.queue import connect, publish
from scanner.recurrence.service import run_once


def main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    r = connect(settings.redis_url)
    sessions = make_session_factory(settings.database_url)

    def publisher(stream: str, msg: object) -> None:
        publish(r, stream, msg)  # type: ignore[arg-type]

    interval_s = settings.recurrence_check_minutes * 60
    while True:
        try:
            run_once(sessions, publisher)
        except Exception:
            import logging

            logging.getLogger(__name__).exception("falha na checagem de recorrência")
        time.sleep(interval_s)


if __name__ == "__main__":
    main()
