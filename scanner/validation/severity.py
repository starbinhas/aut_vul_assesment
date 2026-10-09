"""Classificação de severidade (crítico a baixo)."""

from __future__ import annotations

from scanner.common.models import Finding, Severity, Status

# Severidade base por CWE quando confirmada. Sem entrada aqui, vale a severidade da ferramenta.
BASE_SEVERITY: dict[int, Severity] = {
    78: Severity.CRITICAL,  # injeção de comando no SO
    89: Severity.HIGH,  # SQL injection
    94: Severity.CRITICAL,  # injeção de código
    1336: Severity.CRITICAL,  # SSTI (injeção de template no servidor; costuma levar a RCE)
    611: Severity.HIGH,  # XXE
    22: Severity.HIGH,  # path traversal
    79: Severity.MEDIUM,  # XSS refletido
    601: Severity.MEDIUM,  # open redirect
    1021: Severity.LOW,  # clickjacking
    693: Severity.LOW,  # cabeçalho de proteção ausente
    614: Severity.LOW,  # cookie sem Secure
    1004: Severity.LOW,  # cookie sem HttpOnly
    319: Severity.MEDIUM,  # tráfego sem TLS
}


def classify(f: Finding) -> Severity:
    """Confirmados usam a base do CWE; os demais mantêm a severidade reportada.

    Nunca rebaixamos um achado não confirmado: a falta de prova não é prova de inocuidade.
    """
    if f.status is Status.CONFIRMED and f.cwe in BASE_SEVERITY:
        return BASE_SEVERITY[f.cwe]
    return f.severity
