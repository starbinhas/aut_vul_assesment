"""Cabeçalhos de segurança ausentes: checagem direta do cabeçalho na resposta."""

from __future__ import annotations

from collections.abc import Callable

from scanner.common.models import Finding, Outcome, Validation
from scanner.validation.http import ProbeClient, ProbeResponse
from scanner.validation.validators.base import proof_from, register, result

NAME = "security_headers"


def _xfo_ok(r: ProbeResponse) -> bool:
    xfo = r.headers.get("x-frame-options", "").lower()
    csp = r.headers.get("content-security-policy", "").lower()
    return xfo in ("deny", "sameorigin") or "frame-ancestors" in csp


def _nosniff_ok(r: ProbeResponse) -> bool:
    return bool(r.headers.get("x-content-type-options", "").lower() == "nosniff")


def _hsts_ok(r: ProbeResponse) -> bool:
    return "max-age=" in r.headers.get("strict-transport-security", "").lower()


def _csp_ok(r: ProbeResponse) -> bool:
    return bool(r.headers.get("content-security-policy"))


# regra do ZAP -> (cabeçalho, checagem)
CHECKS: dict[str, tuple[str, Callable[[ProbeResponse], bool]]] = {
    "10020": ("X-Frame-Options / frame-ancestors", _xfo_ok),
    "10021": ("X-Content-Type-Options", _nosniff_ok),
    "10035": ("Strict-Transport-Security", _hsts_ok),
    "10038": ("Content-Security-Policy", _csp_ok),
}


@register(NAME, zap_rules=tuple(CHECKS))
def validate(f: Finding, client: ProbeClient) -> Validation:
    rule = next(s.rule_id for s in [f.source, *f.related_sources] if s.rule_id in CHECKS)
    header, ok = CHECKS[rule]
    if rule == "10035" and not f.location.url.startswith("https://"):
        return result(NAME, Outcome.UNCONFIRMED, "HSTS só se aplica a respostas HTTPS")

    resp = client.request("GET", f.location.url)
    proof = proof_from("GET", f.location.url, resp, None, f"checagem do cabeçalho {header}")
    if ok(resp):
        return result(
            NAME, Outcome.FALSE_POSITIVE, f"{header} presente e válido na resposta", proof
        )
    return result(NAME, Outcome.CONFIRMED, f"{header} ausente ou inválido na resposta", proof)
