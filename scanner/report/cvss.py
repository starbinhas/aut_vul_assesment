"""Nota CVSS v3.1 representativa por achado (paridade com DAST do mercado).

Importante: é a nota-base **representativa da classe da falha** (CWE/regra), não um cálculo por
instância — não modelamos as condições exatas de exploração de cada caso. É o mesmo que os
scanners comerciais fazem ao atribuir um CVSS padrão por regra. Serve para priorizar e para exportar
(SARIF, relatório), não como laudo pericial.

A nota é sempre coerente com a severidade que a etapa 5 já atribuiu: o vetor por CWE abaixo foi
escolhido dentro da faixa da severidade do achado.
"""

from __future__ import annotations

from scanner.common.models import Finding, Severity

# CWE -> (nota-base CVSS v3.1, vetor). Vetores representativos da classe da falha.
_BY_CWE: dict[int, tuple[float, str]] = {
    78: (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # injeção de comando no SO
    94: (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # injeção de código
    1336: (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # SSTI (costuma levar a RCE)
    89: (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # SQL injection
    345: (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),  # JWT alg:none aceito
    611: (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L"),  # XXE
    22: (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),  # path traversal
    538: (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),  # arquivo sensível exposto
    639: (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),  # IDOR (acesso entre usuários)
    79: (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),  # XSS refletido
    601: (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),  # open redirect
    319: (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),  # tráfego sem TLS
    307: (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),  # login sem bloqueio
    200: (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),  # exposição de informação
    548: (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),  # listagem de diretório
    1021: (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),  # clickjacking
    693: (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),  # cabeçalho de proteção ausente
    614: (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),  # cookie sem Secure
    1004: (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),  # cookie sem HttpOnly
    778: (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),  # falta de registro (logging)
}

# Fallback por severidade quando o CWE não está no mapa (vetor genérico da faixa).
_BY_SEVERITY: dict[Severity, tuple[float, str]] = {
    Severity.CRITICAL: (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    Severity.HIGH: (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    Severity.MEDIUM: (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    Severity.LOW: (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    Severity.INFO: (0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
}


def cvss_for(f: Finding) -> tuple[float, str]:
    """Nota-base e vetor CVSS v3.1 representativos do achado (por CWE, senão por severidade)."""
    if f.cwe is not None and f.cwe in _BY_CWE:
        return _BY_CWE[f.cwe]
    return _BY_SEVERITY[f.severity]
