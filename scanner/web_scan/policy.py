"""Perfis de scan ativo do ZAP (níveis de intensidade).

Quatro níveis. Quanto mais alto, mais cobertura e mais risco para o alvo:

- `safe`      — allowlist curada de regras não destrutivas. Padrão. Pode rodar em site de cliente.
- `balanced`  — safe + detecções mais pesadas, porém ainda só de leitura (injeção baseada em
                tempo, XSS DOM, SSTI, NoSQL, vazamento de Git/SVN, CORS...). Pode rodar em cliente.
- `intrusive` — todas as regras instaladas MENOS as de sobrecarga (`LAB_ONLY_RULES`): grava dados
                e faz o alvo sair para a internet (SSRF/RFI/OAST). **Só em cópia de teste do
                cliente, com autorização assinada e aprovada pelo time** (`common/staging.py`).
- `aggressive`— TODAS as regras instaladas do ZAP, inclusive as que pesam como DoS. **Só alvo de
                laboratório OU uma cópia de teste descartável liberada para teste de resiliência**
                (`common/staging.py`, `stress_cleared`): o cliente aceita por escrito que a cópia
                pode ficar fora do ar. Nunca no site oficial.

A trava (`clearance` + `is_cleared`) é aplicada em `web_scan/service.py` (`resolve_profile`):
laboratório pela allowlist `settings.lab_hosts`; cópia de teste pela autorização vigente no banco
(nível `intrusive` libera o intrusivo; nível `stress` libera também o agressivo).
Nunca atinge produção, mesmo que alguém peça. As demais salvaguardas (autorização, escopo travado,
limite de requisições/s e tempo máximo) valem em todos os perfis.
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

# Mais cobertura, ainda só de leitura: variantes de injeção baseadas em tempo (mais lentas), o
# XSS baseado em DOM (principal lacuna apontada no Juice Shop) e as regras beta/alpha que só leem.
# Conferidas no help do ZAP (ascanrules 84, beta 67, alpha 58). Nenhuma grava dados no alvo, faz o
# alvo sair para a internet (OAST) ou pesa como DoS.
BALANCED_EXTRA_RULES: dict[int, str] = {
    40019: "SQL Injection - MySQL (baseada em tempo)",
    40020: "SQL Injection - Hypersonic (baseada em tempo)",
    40021: "SQL Injection - Oracle (baseada em tempo)",
    40022: "SQL Injection - PostgreSQL (baseada em tempo)",
    40024: "SQL Injection - SQLite (baseada em tempo)",
    40026: "Cross Site Scripting (DOM Based)",
    40027: "SQL Injection - MsSQL (baseada em tempo)",
    40033: "NoSQL Injection - MongoDB",
    90039: "NoSQL Injection - MongoDB (baseada em tempo)",
    40015: "LDAP Injection",
    90035: "Server Side Template Injection",
    90037: "Remote OS Command Injection (baseada em tempo)",
    20017: "Source Code Disclosure - CVE-2012-1823",
    20018: "Remote Code Execution - CVE-2012-1823",  # mesmo tipo de prova do 90020 (eco)
    40045: "Spring4Shell",  # valor inválido de propósito: o servidor recusa, nada muda
    40048: "Remote Code Execution (React2Shell)",  # força um erro, sem executar nada
    41: "Source Code Disclosure - Git",
    42: "Source Code Disclosure - SVN",
    43: "Source Code Disclosure - File Inclusion",
    10047: "HTTPS Content Available via HTTP",
    10051: "Relative Path Confusion",
    10106: "HTTP Only Site",
    20012: "Anti-CSRF Tokens Check",
    20014: "HTTP Parameter Pollution",
    20016: "Cross-Domain Misconfiguration",
    40013: "Session Fixation",
    40025: "Proxy Disclosure",
    40038: "Bypassing 403",
    40040: "CORS Header",
    90024: "Generic Padding Oracle",
}

# Fora do `balanced` de propósito (ficam para o agressivo/intrusivo), mesmo sendo "só leitura":
# - 90036 SSTI cego, 40043 Log4Shell, 40047 Text4shell, 40046 SSRF, 7 RFI, 40031 OOB XSS,
#   10107 Httpoxy: fazem o alvo abrir conexão para fora (OAST/callback).
# - 20015 Heartbleed: explora a falha e lê memória do servidor (dado real).
# - 90034 Cloud Metadata: faz o proxy do cliente buscar o metadata da nuvem (dado real).
# - 90028 Insecure HTTP Method: pode explorar PUT/PATCH. 40023 Username Enumeration: tentativas
#   de login podem bloquear contas reais. 40039 Web Cache Deception: mexe no cache de usuários.
# - 10104 User Agent Fuzzer e 90027 Cookie Slack: muitas requisições para achado só informativo.


# Onde cada perfil pode rodar (`ScanProfile.clearance`).
ANYWHERE = "any"  # qualquer site verificado, inclusive produção
STAGING = "staging"  # cópia de teste com autorização assinada e aprovada (ou laboratório)
STRESS_STAGING = "stress_staging"  # cópia de teste liberada para resiliência/DoS (ou laboratório)
LAB = "lab"  # só hosts de laboratório (`settings.lab_hosts`)

# Pesam como DoS (podem derrubar o servidor) ou executam scripts arbitrários. Ficam de fora do
# intrusivo: só rodam em laboratório ou numa cópia de teste descartável liberada para resiliência
# (`clearance = STRESS_STAGING`), onde o cliente aceitou por escrito que a cópia pode cair. Nunca
# no site oficial, nem numa cópia liberada só para o intrusivo.
LAB_ONLY_RULES: dict[int, str] = {
    30001: "Buffer Overflow",
    30002: "Format String Error",
    30003: "Integer Overflow Error",
    40044: "Exponential Entity Expansion (Billion Laughs)",
    50000: "Script Active Scan Rules",
}


@dataclass(frozen=True)
class ScanProfile:
    name: str
    label: str  # nome em pt-BR para a interface
    summary: str  # uma linha explicando o trade-off
    attack_strength: str  # LOW | MEDIUM | HIGH | INSANE
    alert_threshold: str  # LOW | MEDIUM | HIGH
    destructive: bool  # True = pode alterar dados no alvo → nunca em produção
    # Conjunto de regras a ligar; None liga TODAS as regras instaladas do ZAP (menos `excluded`).
    rules: frozenset[int] | None
    clearance: str = ANYWHERE
    excluded: frozenset[int] = frozenset()


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
    "intrusive": ScanProfile(
        name="intrusive",
        label="Intrusivo (cópia de teste)",
        summary="Tudo do completo seguro, mais os testes que gravam dados e fazem o site acessar "
        "endereços externos. Sem testes de sobrecarga. Só em cópia de teste autorizada.",
        attack_strength="HIGH",
        alert_threshold="LOW",
        destructive=True,
        rules=None,
        clearance=STAGING,
        excluded=frozenset(LAB_ONLY_RULES),
    ),
    "aggressive": ScanProfile(
        name="aggressive",
        label="Resiliência (cópia descartável)",
        summary="Tudo do intrusivo mais os testes de sobrecarga, que podem derrubar o alvo. Só em "
        "laboratório ou numa cópia de teste liberada para resiliência (o cliente aceita que ela "
        "pode ficar fora do ar).",
        attack_strength="HIGH",
        alert_threshold="LOW",
        destructive=True,
        rules=None,
        clearance=STRESS_STAGING,
    ),
}

DEFAULT_PROFILE = "safe"


def resolve(name: str | None) -> ScanProfile:
    """Nome → perfil. Nome desconhecido ou vazio cai no perfil seguro."""
    return PROFILES.get(name or "", PROFILES[DEFAULT_PROFILE])


def is_cleared(profile: ScanProfile, *, lab: bool, staging: bool, stress: bool = False) -> bool:
    """O perfil pode rodar aqui?

    `lab`: todo o escopo é de laboratório. `staging`: cópia liberada para o intrusivo. `stress`:
    cópia liberada para resiliência/DoS (que também cobre o intrusivo). O laboratório libera tudo.
    """
    if profile.clearance == LAB:
        return lab
    if profile.clearance == STRESS_STAGING:
        return lab or stress
    if profile.clearance == STAGING:
        return lab or staging or stress
    return True


def is_lab_scope(hosts: list[str], lab_hosts: list[str]) -> bool:
    """True só se TODO host do escopo é de laboratório (um host real misturado já reprova)."""
    allowed = {h.lower() for h in lab_hosts}
    return bool(hosts) and {h.lower() for h in hosts} <= allowed
