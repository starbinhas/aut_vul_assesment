"""Infra comum dos validadores.

Validador = função `(Finding, ProbeClient) -> Validation`. Sem estado, sem efeitos além das
requisições de prova feitas pelo `ProbeClient` (que já garante escopo e métodos seguros).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from scanner.common.evidence import excerpt
from scanner.common.masking import mask_headers, mask_text
from scanner.common.models import Evidence, Finding, HttpRequest, HttpResponse, Outcome, Validation
from scanner.validation.http import ProbeClient, ProbeResponse

ValidatorFn = Callable[[Finding, ProbeClient], Validation]

PROOF_EXCERPT = 360  # trecho em volta da prova, não a página inteira


@dataclass(frozen=True)
class Validator:
    name: str
    fn: ValidatorFn
    zap_rules: frozenset[str] = frozenset()
    nuclei_templates: frozenset[str] = frozenset()
    cwes: frozenset[int] = frozenset()


registry: list[Validator] = []


def register(
    name: str,
    *,
    zap_rules: tuple[str, ...] = (),
    nuclei_templates: tuple[str, ...] = (),
    cwes: tuple[int, ...] = (),
) -> Callable[[ValidatorFn], ValidatorFn]:
    def deco(fn: ValidatorFn) -> ValidatorFn:
        registry.append(
            Validator(name, fn, frozenset(zap_rules), frozenset(nuclei_templates), frozenset(cwes))
        )
        return fn

    return deco


def select(f: Finding) -> Validator | None:
    """Regra específica (ZAP/nuclei) tem prioridade sobre CWE."""
    for v in registry:
        for s in [f.source, *f.related_sources]:
            if (s.tool == "zap" and s.rule_id in v.zap_rules) or (
                s.tool == "nuclei" and s.rule_id in v.nuclei_templates
            ):
                return v
    for v in registry:
        if f.cwe is not None and f.cwe in v.cwes:
            return v
    return None


def result(name: str, outcome: Outcome, reason: str, proof: Evidence | None = None) -> Validation:
    return Validation(
        validator=name, outcome=outcome, reason=reason, proof=proof, validated_at=datetime.now(UTC)
    )


def proof_from(
    method: str, url: str, resp: ProbeResponse, around: str | None, note: str
) -> Evidence:
    body = excerpt(resp.text, resp.headers.get("content-type"), around, PROOF_EXCERPT)
    return Evidence(
        request=HttpRequest(method=method, url=url),
        response=HttpResponse(
            status=resp.status,
            headers=mask_headers(dict(resp.headers)),
            body_excerpt=mask_text(body),
        ),
        note=note,
    )


def with_param(url: str, param: str, value: str) -> str:
    """Troca (ou adiciona) o valor de um parâmetro de query string."""
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    query.append((param, value))
    return urlunsplit(parts._replace(query=urlencode(query)))


def is_query_param(url: str, param: str | None) -> bool:
    return bool(param) and any(
        k == param for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
    )
