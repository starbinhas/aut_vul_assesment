"""Logs estruturados em JSON, sempre com scan_id e sempre mascarados."""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from scanner.common.masking import mask_obj, mask_text

scan_id_var: ContextVar[str | None] = ContextVar("scan_id", default=None)

_RESERVED = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": mask_text(record.getMessage()),
            "scan_id": scan_id_var.get(),
        }
        extra = {k: v for k, v in vars(record).items() if k not in _RESERVED}
        data.update(mask_obj(extra))
        if record.exc_info:
            data["exc"] = mask_text(self.formatException(record.exc_info))
        return json.dumps(data, default=str, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # Uma linha por requisição de prova polui o log (e as URLs podem carregar dados do cliente).
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
