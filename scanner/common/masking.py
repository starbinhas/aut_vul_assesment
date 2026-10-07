"""Mascaramento de segredos e dados pessoais.

Aplicar antes de logar, antes de enviar ao LLM e antes de gravar evidência no relatório.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "***"

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-zap-api-key",
    }
)

SENSITIVE_KEYS = re.compile(
    r"pass(word|wd)?|secret|token|api[_-]?key|session|sessid|auth|credential|jwt|csrf",
    re.IGNORECASE,
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # JWT
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), MASK),
    # Bearer / Basic
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), rf"\1 {MASK}"),
    # chave=valor em query string, corpo form ou JSON
    (
        re.compile(
            r"(?i)(\"?(?:[\w-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|sessid|session|jwt|csrf)[\w-]*)\"?\s*[=:]\s*\"?)([^\"&\s,;}]+)"
        ),
        rf"\1{MASK}",
    ),
    # e-mail
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<email>"),
    # CPF
    (re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"), "<cpf>"),
    # cartão de crédito (13-19 dígitos, com espaço/hífen opcional)
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "<cartao>"),
]


def mask_text(text: str | None) -> str | None:
    if text is None:
        return None
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def mask_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        k: (
            MASK
            if k.lower() in SENSITIVE_HEADERS or SENSITIVE_KEYS.search(k)
            else mask_text(v) or ""
        )
        for k, v in headers.items()
    }


def mask_obj(obj: Any) -> Any:
    """Mascara recursivamente dicts/listas/strings (para logs e payloads ao LLM)."""
    if isinstance(obj, dict):
        return {
            k: (
                MASK
                if isinstance(k, str)
                and (k.lower() in SENSITIVE_HEADERS or SENSITIVE_KEYS.search(k))
                else mask_obj(v)
            )
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [mask_obj(v) for v in obj]
    if isinstance(obj, str):
        return mask_text(obj)
    return obj
