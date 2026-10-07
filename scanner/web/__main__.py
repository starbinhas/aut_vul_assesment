"""Servidor da interface: `python -m scanner.web`."""

import uvicorn

from scanner.common.config import get_settings
from scanner.common.db import make_session_factory
from scanner.common.logging import setup_logging
from scanner.common.queue import connect
from scanner.web.app import create_app


def main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    app = create_app(
        settings, make_session_factory(settings.database_url), connect(settings.redis_url)
    )
    # Atrás de um proxy reverso com TLS em produção; o proxy define X-Forwarded-*.
    uvicorn.run(app, host="0.0.0.0", port=8000, proxy_headers=True, server_header=False)  # noqa: S104


if __name__ == "__main__":
    main()
