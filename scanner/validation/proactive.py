"""Checagens próprias (fonte "scanner") viram achados do pipeline.

As checagens que o ZAP/nuclei não fazem (acesso entre usuários, arquivos expostos, login sem
bloqueio, token sem assinatura) produzem um `Finding` com `source.tool = "scanner"` — por isso o
contrato subiu para 1.1. Assim elas contam no relatório, não só numa ferramenta à parte.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from scanner.common.models import (
    Finding,
    Location,
    Outcome,
    Scope,
    Severity,
    Source,
    Status,
    Validation,
    make_finding_id,
)
from scanner.common.owasp import owasp_for_cwe
from scanner.common.scope import OutOfScopeError
from scanner.validation.exposed_files import SENSITIVE_PATHS, classify_exposure
from scanner.validation.http import ProbeClient

OUTCOME_TO_STATUS = {
    Outcome.CONFIRMED: Status.CONFIRMED,
    Outcome.LIKELY: Status.LIKELY,
    Outcome.UNCONFIRMED: Status.UNCONFIRMED,
    Outcome.FALSE_POSITIVE: Status.FALSE_POSITIVE,
}


@dataclass(frozen=True)
class ProactiveCheck:
    rule_id: str  # id estável da nossa checagem
    title: str
    owasp: str
    cwe: int | None
    severity: Severity


# Metadados por validador próprio (o nome bate com o `validator` da Validation).
CHECKS: dict[str, ProactiveCheck] = {
    "broken_access_control": ProactiveCheck(
        "PITCHY-AC-01", "Acesso indevido a dados de outro usuário", "A01:2025", 639, Severity.HIGH
    ),
    "exposed_sensitive_file": ProactiveCheck(
        "PITCHY-EF-01", "Arquivo sensível exposto sem autenticação", "A04:2025", 538, Severity.HIGH
    ),
    "weak_authentication": ProactiveCheck(
        "PITCHY-AUTH-01",
        "Login sem bloqueio (permite força bruta)",
        "A07:2025",
        307,
        Severity.MEDIUM,
    ),
    "jwt_integrity": ProactiveCheck(
        "PITCHY-JWT-01", "Token sem assinatura aceito (alg:none)", "A08:2025", 345, Severity.HIGH
    ),
    "logging_monitoring": ProactiveCheck(
        "PITCHY-LOG-01",
        "Ataques não registrados (monitoramento cego)",
        "A09:2025",
        778,
        Severity.MEDIUM,
    ),
}


def build_finding(scan_id: str, target_id: str, url: str, validation: Validation) -> Finding:
    """Monta um Finding (fonte 'scanner') a partir do veredito de uma checagem própria."""
    check = CHECKS[validation.validator]
    source = Source(tool="scanner", rule_id=check.rule_id, rule_name=check.title)
    return Finding(
        finding_id=make_finding_id(scan_id, source, "GET", url, None),
        scan_id=scan_id,
        target_id=target_id,
        source=source,
        title=check.title,
        cwe=check.cwe,
        owasp=check.owasp or owasp_for_cwe(check.cwe),
        severity=check.severity,
        status=OUTCOME_TO_STATUS[validation.outcome],
        location=Location(url=url, method="GET"),
        evidence=[validation.proof] if validation.proof else [],
        validation=validation,
    )


def run_exposed_files(
    scope: Scope, client: ProbeClient, scan_id: str, target_id: str
) -> list[Finding]:
    """Checagem A04 (arquivos sensíveis expostos) contra o escopo — automática, sem credencial.

    Não destrutiva (só GET). Emite achado só quando CONFIRMED/LIKELY; caminho protegido
    (401/403/404) vira FALSE_POSITIVE e não gera achado. finding_id determinístico -> idempotente.
    """
    findings: list[Finding] = []
    for base in scope.base_urls:
        for path in SENSITIVE_PATHS:
            url = urljoin(base, path)
            if not client.guard.allows(url):
                continue
            try:
                resp = client.request("GET", url)
            except (httpx.HTTPError, OutOfScopeError):
                continue
            validation = classify_exposure(path, url, resp)
            if validation.outcome in (Outcome.CONFIRMED, Outcome.LIKELY):
                findings.append(build_finding(scan_id, target_id, url, validation))
    return findings
