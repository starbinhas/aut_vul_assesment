"""Textos da interface em pt-BR (rótulos de severidade, status e andamento)."""

from __future__ import annotations

from typing import Any

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
    "target-unstable": "Esperando o site voltar",
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
    "scan.stop_partial": "Parou a espera e pediu o relatório parcial",
    "scan.manual_review": "Marcou um item de revisão manual",
    "login.set": "Configurou o login de teste do site",
    "login.clear": "Removeu o login de teste do site",
    "finding.review": "Revisou achado",
    "report.regenerate": "Pediu novo relatório",
    "org.create": "Criou cliente",
    "user.create": "Criou acesso",
    "user.active": "Reativou acesso",
    "user.inactive": "Desativou acesso",
    "user.password_reset": "Gerou nova senha",
    "staging.register": "Cadastrou cópia de teste",
    "staging.sign": "Assinou a autorização da cópia de teste",
    "staging.approve": "Aprovou cópia de teste",
    "staging.reject": "Recusou cópia de teste",
    "staging.revoke": "Encerrou a autorização da cópia de teste",
    "staging.renew": "Pediu nova autorização da cópia de teste",
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


PARTIAL_REASON = {
    "aggressive-dos": (
        "O teste agressivo sobrecarregou o site e ele saiu do ar — isso é esperado nesse nível "
        "(ele pesa como um ataque de negação de serviço). Para um teste completo sem derrubar o "
        "site, use o perfil “Completo seguro”."
    ),
    "target-unstable": (
        "O site saiu do ar sozinho durante o teste (instabilidade do próprio alvo), e o scan "
        "esperou sem ele voltar a tempo."
    ),
    "operator-stopped": (
        "Você parou a espera e pediu o relatório parcial antes de o teste ativo terminar."
    ),
}


def partial_reason(value: object) -> str:
    return PARTIAL_REASON.get(str(value or ""), "O teste ativo não foi concluído.")


def reason(value: object) -> str:
    return sentence(names.client_reason(str(value or "")))


def sentence(value: object) -> str:
    """Só a primeira letra maiúscula (o `capitalize` do Jinja rebaixa o resto: "SQL" → "sql")."""
    text = str(value or "")
    return text[:1].upper() + text[1:]


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


# O que cada perfil de scan faz, para o cliente decidir. Fatos de `web_scan/policy.py` (regras) e
# `web_scan/zap.py` (limites); manter em sincronia ao mudar um perfil.
PROFILE_INFO: dict[str, dict[str, Any]] = {
    "safe": {
        "level": 1,
        "pitch": "Para rodar em produção, a qualquer hora.",
        "tag": "Recomendado",
        "tests": "Injeção de SQL e de comandos, XSS refletido, arquivos expostos (.env, backup, "
        "pastas ocultas), XXE e leitura de arquivos fora da pasta do site.",
        "never": "Não grava nem apaga dados, não faz testes por tempo de resposta e não "
        "sobrecarrega o site.",
        "watch": [
            "Formulários recebem valores de teste: um formulário de contato pode disparar e-mails.",
        ],
        "button": "Iniciar scan seguro",
    },
    "balanced": {
        "level": 2,
        "pitch": "Mais fundo, ainda sem mexer em dados.",
        "tag": None,
        "tests": "Tudo do seguro, mais injeção medida pelo tempo de resposta (SQL, NoSQL, "
        "comandos), XSS que acontece no navegador (DOM), injeção em templates (SSTI), código "
        "exposto em .git e .svn, CORS mal configurado e fixação de sessão.",
        "never": "Não grava nem apaga dados.",
        "watch": [
            "Os testes por tempo fazem o banco esperar alguns segundos a cada tentativa: o site "
            "pode ficar mais lento durante o scan. Prefira um horário de pouco movimento.",
            "Formulários recebem valores de teste: um formulário de contato pode disparar e-mails.",
        ],
        "button": "Iniciar scan completo",
    },
    "intrusive": {
        "level": 3,
        "pitch": "Para uma cópia de teste do site, com a sua autorização.",
        "tag": "Cópia de teste",
        "tests": "Tudo do completo, mais XSS que fica gravado no site, SSRF e inclusão remota "
        "(o site tenta acessar endereços externos), Log4Shell, SSTI cego e métodos HTTP que "
        "alteram arquivos.",
        "never": "Não faz testes de sobrecarga e não toca no site oficial.",
        "watch": [
            "Grava cadastros, comentários e textos estranhos na cópia. Depois do teste, apague ou "
            "refaça a cópia.",
            "Só aparece numa cópia de teste aprovada pelo time, dentro da validade.",
        ],
        "button": "Iniciar scan intrusivo",
    },
    "aggressive": {
        "level": 4,
        "pitch": "Testa se dá para derrubar o site. Só numa cópia de teste descartável.",
        "tag": "Cópia de resiliência",
        "tests": "Tudo do intrusivo, mais os testes de sobrecarga que tentam derrubar o servidor "
        "(Buffer Overflow, Billion Laughs e afins).",
        "never": "Nunca roda no site oficial, nem numa cópia liberada só para o intrusivo.",
        "watch": [
            "É esperado que a cópia fique instável ou fora do ar durante o teste.",
            "Só aparece numa cópia liberada para resiliência, com termo de indisponibilidade "
            "assinado e aprovado pelo time.",
        ],
        "button": "Iniciar teste de resiliência",
    },
}
