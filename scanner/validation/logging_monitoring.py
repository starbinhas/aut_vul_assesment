"""Registro e monitoramento (A09): o site anota os ataques? E alguém é avisado?

Não é visível num scan de caixa-preta. Duas abordagens:
  1. CHECKLIST — revisão humana (não depende de nada do cliente).
  2. classify_logging — teste de correlação: marcamos nossos ataques e, com acesso aos logs do
     cliente, conferimos se as marcas aparecem. O que não aparece não foi registrado (monitoramento
     cego). Determinístico; "false_positive" (está tudo registrado) só vem desta checagem.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from scanner.common.models import Outcome, Validation
from scanner.validation.validators.base import result

NAME = "logging_monitoring"


@dataclass(frozen=True)
class ChecklistItem:
    id: str
    question: str
    why: str


# Revisão humana do A09: o que perguntar/conferir com o cliente.
CHECKLIST: tuple[ChecklistItem, ...] = (
    ChecklistItem(
        "auth_failures",
        "Tentativas de login malsucedidas são registradas (com origem e horário)?",
        "Sem isso, um ataque de força bruta passa despercebido.",
    ),
    ChecklistItem(
        "access_denied",
        "Acessos negados (controle de acesso) são registrados?",
        "Tentativas de ver dados de outro usuário precisam deixar rastro.",
    ),
    ChecklistItem(
        "input_validation",
        "Falhas de validação de entrada (injeção, payloads estranhos) são registradas?",
        "São sinais de ataque em andamento.",
    ),
    ChecklistItem(
        "central",
        "Os logs ficam num local central, fora do servidor atacado?",
        "Quem invade o servidor apaga os logs locais.",
    ),
    ChecklistItem(
        "tamper_resistant",
        "Os logs são protegidos contra adulteração/remoção?",
        "Log que o atacante pode editar não serve de prova.",
    ),
    ChecklistItem(
        "alerting",
        "Há alerta automático para atividade suspeita (ex.: muitas falhas de login)?",
        "Registrar sem avisar ninguém não impede o ataque a tempo.",
    ),
    ChecklistItem(
        "retention",
        "Há retenção adequada dos logs (tempo suficiente para investigar)?",
        "Incidentes costumam ser descobertos semanas depois.",
    ),
    ChecklistItem(
        "no_secrets",
        "Os logs evitam gravar dados sensíveis (senhas, tokens, dados pessoais)?",
        "O próprio log não pode virar uma fonte de vazamento.",
    ),
)


def classify_logging(markers: Sequence[str], log_text: str, name: str = NAME) -> Validation:
    """Quantas das nossas marcas de ataque aparecem nos logs do cliente."""
    if not markers:
        return result(name, Outcome.UNCONFIRMED, "nenhuma marca de ataque foi enviada")
    found = [m for m in markers if m in log_text]
    if not found:
        return result(
            name,
            Outcome.CONFIRMED,
            f"nenhuma das {len(markers)} tentativas de ataque foi registrada: monitoramento cego",
        )
    if len(found) < len(markers):
        return result(
            name,
            Outcome.LIKELY,
            f"só {len(found)} de {len(markers)} tentativas foram registradas: registro incompleto",
        )
    return result(
        name,
        Outcome.FALSE_POSITIVE,
        f"todas as {len(markers)} tentativas foram registradas: o logging funciona",
    )


def _print_checklist() -> None:
    print("\nRevisão de registro e monitoramento (A09) — conferir com o cliente:\n")
    for i, item in enumerate(CHECKLIST, 1):
        print(f"{i}. {item.question}")
        print(f"   Por quê: {item.why}\n")


if __name__ == "__main__":
    _print_checklist()
