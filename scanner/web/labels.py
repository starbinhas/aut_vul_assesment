"""Textos da interface em pt-BR (rótulos de severidade, status e andamento)."""

from __future__ import annotations

from scanner.report import names

SEVERITY = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Informativa",
}
STATUS = {
    "confirmed": "Confirmada",
    "likely": "Provável",
    "unconfirmed": "Não confirmada",
    "false_positive": "Falso positivo",
    "candidate": "Candidata",
}
SCAN_STATUS = {
    "requested": "Na fila",
    "recon": "Procurando o que existe no site",
    "cve_scanning": "Procurando falhas conhecidas",
    "web_scanning": "Testando o site",
    "validating": "Validando",
    "reporting": "Gerando relatório",
    "done": "Concluído",
    "failed": "Falhou",
    "pending": "Na fila",
}
PHASE = {
    "starting": "Preparando o teste",
    "recon": "Procurando o que existe no site",
    "cve": "Procurando falhas conhecidas",
    "validate": "Confirmando os achados",
    "spider": "Mapeando as páginas",
    "ajax_spider": "Mapeando páginas dinâmicas",
    "passive": "Analisando as respostas",
    "active": "Testes ativos",
    "retrying": "Houve um erro; tentando de novo",
}
STEPS = [
    ("requested", "Na fila"),
    ("web_scanning", "Teste da aplicação"),
    ("validating", "Validação"),
    ("reporting", "Relatório"),
    ("done", "Pronto"),
]


AUDIT = {
    "auth.login": "Entrou",
    "auth.login_failed": "Tentativa de login recusada",
    "auth.password_changed": "Trocou a própria senha",
    "site.create": "Cadastrou site",
    "site.verified": "Comprovou domínio",
    "site.recurrence": "Mudou a recorrência",
    "scan.start": "Iniciou scan",
    "finding.review": "Revisou achado",
    "report.regenerate": "Pediu novo relatório",
    "org.create": "Criou cliente",
    "user.create": "Criou acesso",
    "user.active": "Reativou acesso",
    "user.inactive": "Desativou acesso",
    "user.password_reset": "Gerou nova senha",
}


def audit_action(value: object) -> str:
    return AUDIT.get(str(value), str(value))


def severity(value: object) -> str:
    return SEVERITY.get(str(value), str(value))


def status(value: object) -> str:
    return STATUS.get(str(value), str(value))


def scan_status(value: object) -> str:
    return SCAN_STATUS.get(str(value), str(value))


def phase(value: object) -> str:
    return PHASE.get(str(value), str(value)) if value else ""


def public_phase(value: object) -> str:
    """Só fases conhecidas: `status_detail` também guarda notas livres da operação (motivo de
    cancelamento), que o cliente não deve ver."""
    return PHASE.get(str(value), "") if value else ""


def is_command(value: object) -> bool:
    return names.is_command(value)


def reason(value: object) -> str:
    return sentence(names.client_reason(str(value or "")))


def sentence(value: object) -> str:
    """Só a primeira letra maiúscula (o `capitalize` do Jinja rebaixa o resto: "SQL" → "sql")."""
    text = str(value or "")
    return text[:1].upper() + text[1:]


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"
