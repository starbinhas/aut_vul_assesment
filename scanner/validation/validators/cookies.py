"""Flags de cookie (Secure, HttpOnly, SameSite): checagem direta do Set-Cookie."""

from __future__ import annotations

from scanner.common.models import Finding, Outcome, Validation
from scanner.validation.http import ProbeClient
from scanner.validation.validators.base import proof_from, register, result

NAME = "cookie_flags"

# regra do ZAP -> atributo exigido
FLAGS = {"10010": "httponly", "10011": "secure", "10054": "samesite"}


def _cookie_name(set_cookie: str) -> str:
    return set_cookie.split("=", 1)[0].strip()


def _attrs(set_cookie: str) -> set[str]:
    return {a.split("=", 1)[0].strip().lower() for a in set_cookie.split(";")[1:]}


@register(NAME, zap_rules=tuple(FLAGS))
def validate(f: Finding, client: ProbeClient) -> Validation:
    rule = next(s.rule_id for s in [f.source, *f.related_sources] if s.rule_id in FLAGS)
    flag = FLAGS[rule]
    cookie = f.location.parameter  # o ZAP põe o nome do cookie em `param`

    resp = client.request("GET", f.location.url)
    cookies = [c for c in resp.set_cookies if not cookie or _cookie_name(c) == cookie]
    proof = proof_from("GET", f.location.url, resp, None, f"checagem do atributo {flag}")
    if not cookies:
        return result(NAME, Outcome.UNCONFIRMED, "cookie não foi definido nesta resposta", proof)
    missing = [_cookie_name(c) for c in cookies if flag not in _attrs(c)]
    if missing:
        return result(
            NAME, Outcome.CONFIRMED, f"cookie(s) {', '.join(missing)} sem o atributo {flag}", proof
        )
    return result(NAME, Outcome.FALSE_POSITIVE, f"todos os cookies têm o atributo {flag}", proof)
