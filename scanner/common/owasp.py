"""Mapeamento CWE → OWASP Top 10:2025 (versão vigente)."""

from __future__ import annotations

OWASP_VERSION = "2025"

CATEGORIES: dict[str, str] = {
    "A01:2025": "Quebra de Controle de Acesso",
    "A02:2025": "Configuração de Segurança Incorreta",
    "A03:2025": "Falhas na Cadeia de Suprimentos de Software",
    "A04:2025": "Falhas Criptográficas",
    "A05:2025": "Injeção",
    "A06:2025": "Design Inseguro",
    "A07:2025": "Falhas de Autenticação",
    "A08:2025": "Falhas de Integridade de Software ou Dados",
    "A09:2025": "Falhas de Registro e Alerta de Segurança",
    "A10:2025": "Tratamento Inadequado de Condições Excepcionais",
}

_CWE_TO_OWASP: dict[int, str] = {
    # A01 — controle de acesso
    22: "A01:2025",
    23: "A01:2025",
    35: "A01:2025",
    200: "A01:2025",
    201: "A01:2025",
    352: "A01:2025",
    359: "A01:2025",
    538: "A01:2025",
    548: "A01:2025",
    601: "A01:2025",
    639: "A01:2025",
    918: "A01:2025",
    # A02 — configuração
    16: "A02:2025",
    525: "A02:2025",
    611: "A02:2025",
    614: "A02:2025",
    693: "A02:2025",
    942: "A02:2025",
    1004: "A02:2025",
    1021: "A02:2025",
    1275: "A02:2025",
    # A03 — cadeia de suprimentos / componentes vulneráveis
    937: "A03:2025",
    1035: "A03:2025",
    1104: "A03:2025",
    # A04 — criptografia
    295: "A04:2025",
    311: "A04:2025",
    319: "A04:2025",
    326: "A04:2025",
    327: "A04:2025",
    328: "A04:2025",
    # A05 — injeção
    74: "A05:2025",
    77: "A05:2025",
    78: "A05:2025",
    79: "A05:2025",
    89: "A05:2025",
    90: "A05:2025",
    91: "A05:2025",
    94: "A05:2025",
    97: "A05:2025",
    113: "A05:2025",
    643: "A05:2025",
    917: "A05:2025",
    # A07 — autenticação
    287: "A07:2025",
    384: "A07:2025",
    521: "A07:2025",
    613: "A07:2025",
    798: "A07:2025",
    # A08 — integridade
    345: "A08:2025",
    502: "A08:2025",
    829: "A08:2025",
    # A09 — registro e alerta
    778: "A09:2025",
    # A10 — condições excepcionais
    209: "A10:2025",
    248: "A10:2025",
    755: "A10:2025",
}


def owasp_for_cwe(cwe: int | None) -> str | None:
    return _CWE_TO_OWASP.get(cwe) if cwe else None
