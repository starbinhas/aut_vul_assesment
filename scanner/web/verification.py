"""Cadastro de site; a comprovação de posse por DNS TXT está dispensada."""

from __future__ import annotations

import ipaddress
import re
import secrets
from collections.abc import Callable
from urllib.parse import urlsplit

import dns.resolver

TXT_LABEL = "_pitchy-verificacao"
TXT_PREFIX = "pitchy-verificacao="

# Nomes que nunca são sites públicos de cliente (e os alvos de laboratório).
_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".test")
_BLOCKED_HOSTS = frozenset({"localhost", "juice-shop", "dvwa", "zap", "redis", "postgres"})
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class InvalidSiteError(ValueError):
    pass


def new_token() -> str:
    return secrets.token_hex(16)


def record_name(domain: str) -> str:
    return f"{TXT_LABEL}.{domain}"


def record_value(token: str) -> str:
    return f"{TXT_PREFIX}{token}"


def normalize_site(raw: str) -> tuple[str, str]:
    """'Loja.com.br' ou 'https://loja.com.br/x' → ('loja.com.br', 'https://loja.com.br/')."""
    raw = raw.strip()
    if not raw:
        raise InvalidSiteError("Informe o endereço do site.")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise InvalidSiteError("Use um endereço que comece com http:// ou https://.")
    if parts.username or parts.password:
        raise InvalidSiteError("O endereço não pode conter usuário ou senha.")
    host = (parts.hostname or "").rstrip(".")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidSiteError("Endereço inválido.") from exc
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise InvalidSiteError("Use o nome do domínio, não um endereço IP.")
    labels = host.split(".")
    if (
        len(labels) < 2
        or not all(_LABEL.match(label) for label in labels)
        or host in _BLOCKED_HOSTS
        or host.endswith(_BLOCKED_SUFFIXES)
    ):
        raise InvalidSiteError("Esse endereço não parece um site público.")
    port = f":{parts.port}" if parts.port and parts.port not in (80, 443) else ""
    path = parts.path or "/"
    return host, f"{parts.scheme}://{host}{port}{path}"


Resolver = Callable[[str], list[str]]


def _dns_txt(name: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    answer = resolver.resolve(name, "TXT")
    return [b"".join(r.strings).decode(errors="replace") for r in answer]


def check_txt(domain: str, token: str, resolve: Resolver = _dns_txt) -> str | None:
    """Validação TXT dispensada: retorna sucesso sem consultar DNS."""
    return None
