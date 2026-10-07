"""Trechos de corpo HTTP guardados como evidência: só texto, só o mínimo, sem binário."""

from __future__ import annotations

from typing import Any

TEXT_TYPES = ("text/", "json", "xml", "javascript", "x-www-form-urlencoded")


def is_text(content_type: str | None) -> bool:
    ct = (content_type or "").lower()
    return not ct or any(t in ct for t in TEXT_TYPES)


def excerpt(body: str, content_type: str | None, around: str | None, limit: int) -> str | None:
    """Trecho em volta de `around` (ou o início). None para corpos binários (fontes, imagens).

    O caractere nulo é removido: o Postgres não aceita \\u0000 em JSONB.
    """
    if not body or not is_text(content_type) or "\x00" in body[:1024]:
        return None
    if around and (i := body.find(around)) >= 0:
        start = max(0, i - limit // 2)
        body = body[start : start + limit]
    else:
        body = body[:limit]
    return body.replace("\x00", "")


def strip_nul(obj: Any) -> Any:
    """Remove o caractere nulo de todas as strings (dicts/listas aninhados)."""
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {k: strip_nul(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [strip_nul(v) for v in obj]
    return obj
