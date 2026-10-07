"""Perfis de scan ativo do ZAP (níveis de intensidade).

Três níveis. Quanto mais alto, mais cobertura e mais risco para o alvo:

- `safe`      — allowlist curada de regras não destrutivas. Padrão. Pode rodar em site de cliente.
- `balanced`  — safe + detecções mais pesadas, porém ainda só de leitura (injeção baseada em
                tempo, XSS DOM), força de ataque alta. Pode rodar em site de cliente.
- `aggressive`— TODAS as regras instaladas do ZAP, incluindo as que gravam dados no alvo, fazem o
                alvo sair para a internet (SSRF/RFI) ou pesam como DoS. **Só alvo de laboratório.**

A trava do `aggressive` (destructive=True) é aplicada em `web_scan/service.py` contra a allowlist
de hosts de laboratório: nunca atinge um site real, mesmo que alguém peça. As demais salvaguardas
(autorização, escopo travado, limite de requisições/s e tempo máximo) valem em todos os perfis.
"""

from __future__ import annotations

from dataclasses import dataclass

POLICY_NAME = "scanner-policy"

# Regras não destrutivas: detectam sem gravar dados, sem fazer o alvo sair, sem pesar como DoS.
SAFE_ACTIVE_RULES: dict[int, str] = {
    0: "Directory Browsing",
    6: "Path Traversal",
    10045: "Source Code Disclosure - /WEB-INF",
    10048: "Remote Code Execution - Shell Shock",
    10058: "GET for POST",
    10095: "Backup File Disclosure",
    20019: "External Redirect",
    40003: "CRLF Injection",
    40008: "Parameter Tampering",
    40009: "Server Side Include",
    40012: "Cross Site Scripting (Reflected)",
    40018: "SQL Injection",
    40028: "ELMAH Information Leak",
    40029: "Trace.axd Information Leak",
    40032: ".htaccess Information Leak",
    40034: ".env Information Leak",
    40035: "Hidden File Finder",
    40042: "Spring Actuator Information Leak",
    90017: "XSLT Injection",
    90019: "Server Side Code Injection",
    90020: "Remote OS Command Injection",
    90021: "XPath Injection",
    90023: "XML External Entity Attack",
    90025: "Expression Language Injection",
    90026: "SOAP Action Spoofing",
    90029: "SOAP XML Injection",
}

# Mais cobertura, ainda só de leitura: variantes de injeção baseadas em tempo (mais lentas) e o
# XSS baseado em DOM (principal lacuna apontada no Juice Shop). Nenhuma grava dados no alvo.
BALANCED_EXTRA_RULES: dict[int, str] = {
    40019: "SQL Injection - MySQL (baseada em tempo)",
    40020: "SQL Injection - Hypersonic (baseada em tempo)",
    40021: "SQL Injection - Oracle (baseada em tempo)",
    40022: "SQL Injection - PostgreSQL (baseada em tempo)",
    40024: "SQL Injection - SQLite (baseada em tempo)",
    40026: "Cross Site Scripting (DOM Based)",
}


@dataclass(frozen=True)
class ScanProfile:
    name: str
    label: str  # nome em pt-BR para a interface
    summary: str  # uma linha explicando o trade-off
    attack_strength: str  # LOW | MEDIUM | HIGH | INSANE
    alert_threshold: str  # LOW | MEDIUM | HIGH
    destructive: bool  # True = pode alterar dados / pesar no alvo → só laboratório
    # Conjunto de regras a ligar; None liga TODAS as regras instaladas do ZAP.
    rules: frozenset[int] | None


PROFILES: dict[str, ScanProfile] = {
    "safe": ScanProfile(
        name="safe",
        label="Seguro",
        summary="Não causa dano. Deixa de fora testes pesados e os que alteram dados; "
        "pode faltar falha.",
        attack_strength="MEDIUM",
        alert_threshold="MEDIUM",
        destructive=False,
        rules=frozenset(SAFE_ACTIVE_RULES),
    ),
    "balanced": ScanProfile(
        name="balanced",
        label="Completo seguro",
        summary="Mais cobertura e mais lento, ainda sem alterar dados do alvo.",
        attack_strength="HIGH",
        alert_threshold="LOW",
        destructive=False,
        rules=frozenset(SAFE_ACTIVE_RULES) | frozenset(BALANCED_EXTRA_RULES),
    ),
    "aggressive": ScanProfile(
        name="aggressive",
        label="Completo agressivo (laboratório)",
        summary="Todos os testes, inclusive os que gravam dados, fazem o alvo sair e pesam "
        "como DoS. Só em alvo de laboratório.",
        attack_strength="HIGH",
        alert_threshold="LOW",
        destructive=True,
        rules=None,
    ),
}

DEFAULT_PROFILE = "safe"


def resolve(name: str | None) -> ScanProfile:
    """Nome → perfil. Nome desconhecido ou vazio cai no perfil seguro."""
    return PROFILES.get(name or "", PROFILES[DEFAULT_PROFILE])


def is_lab_scope(hosts: list[str], lab_hosts: list[str]) -> bool:
    """True só se TODO host do escopo é de laboratório (um host real misturado já reprova)."""
    allowed = {h.lower() for h in lab_hosts}
    return bool(hosts) and {h.lower() for h in hosts} <= allowed
