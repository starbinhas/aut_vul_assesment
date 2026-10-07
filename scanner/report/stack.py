"""Detecção simples da stack a partir das evidências (para remediação específica e cache)."""

from __future__ import annotations

from collections.abc import Iterable

from scanner.common.models import Finding

_SIGNATURES: list[tuple[str, str]] = [
    ("nginx", "nginx"),
    ("apache", "apache"),
    ("microsoft-iis", "iis"),
    ("php", "php"),
    ("express", "express"),
    ("asp.net", "aspnet"),
    ("next.js", "nextjs"),
    ("django", "django"),
    ("phpsessid", "php"),
    ("jsessionid", "java"),
    ("connect.sid", "express"),
    ("asp.net_sessionid", "aspnet"),
    ("csrftoken", "django"),
    ("laravel_session", "laravel"),
]

_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "set-cookie", "cookie")


def detect_stack(findings: Iterable[Finding]) -> str:
    seen: set[str] = set()
    for f in findings:
        for ev in f.evidence:
            headers = dict(ev.request.headers)
            if ev.response:
                headers.update(ev.response.headers)
            blob = " ".join(v for k, v in headers.items() if k.lower() in _HEADERS).lower()
            blob += " " + " ".join(k.lower() for k in headers)
            seen.update(tag for sig, tag in _SIGNATURES if sig in blob)
    return "+".join(sorted(seen)) or "generic"
