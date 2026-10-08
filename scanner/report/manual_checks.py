"""Catálogo de revisão manual (A06 Design Inseguro, A09 Registro e Alerta).

Estas categorias não são automatizáveis de forma geral (lógica de negócio; acesso aos logs do
cliente). Em vez de deixá-las invisíveis, o relatório traz um checklist guiado: cada item diz o
que verificar, por que importa e como. O estado (a fazer / ok / falha / não se aplica) é marcado
por uma pessoa na interface e guardado por scan.
"""

from __future__ import annotations

from dataclasses import dataclass

# Estados possíveis de um item (o "pending" é o padrão, antes de alguém revisar).
STATES = ("pending", "ok", "fail", "na")


@dataclass(frozen=True)
class ManualCheck:
    check_id: str  # id estável (não muda entre versões)
    owasp: str
    title: str  # o que verificar, em uma linha
    why: str  # por que importa
    how: str  # como verificar, passo concreto


CHECKS: tuple[ManualCheck, ...] = (
    # --- A06: Design Inseguro (lógica de negócio) ---------------------------------------
    ManualCheck(
        "A06-valores",
        "A06:2025",
        "O fluxo de compra aceita valores inválidos?",
        "Se o servidor confia no que o navegador manda, dá para pagar menos, ganhar crédito ou "
        "estourar estoque — fraude sem precisar invadir nada.",
        "No carrinho, tente quantidade negativa ou zero, preço alterado e cupom aplicado várias "
        "vezes. O servidor deve recusar; o navegador não basta.",
    ),
    ManualCheck(
        "A06-etapas",
        "A06:2025",
        "É possível pular etapas obrigatórias?",
        "Pular o pagamento ou a verificação quebra a regra de negócio e deixa concluir algo sem "
        "cumprir o pré-requisito.",
        "Tente ir direto à confirmação do pedido sem pagar (repetindo a requisição da etapa "
        "seguinte). Deve ser barrado no servidor.",
    ),
    ManualCheck(
        "A06-limites",
        "A06:2025",
        "Os limites de negócio são impostos no servidor?",
        "Limites só no navegador (quantas vezes resgatar, quanto sacar, quantos pedidos) são "
        "contornáveis e permitem abuso em escala.",
        "Repita a ação além do limite anunciado (ex.: resgatar o mesmo benefício duas vezes). O "
        "servidor deve impor o teto.",
    ),
    # --- A09: Registro e Alerta ----------------------------------------------------------
    ManualCheck(
        "A09-login",
        "A09:2025",
        "Tentativas de login falhas são registradas?",
        "Sem registro de falhas de login, um ataque de senha passa despercebido — ninguém vê a "
        "força bruta acontecendo.",
        "Faça algumas tentativas de login erradas e confira nos registros do servidor se "
        "aparecem (com horário e origem).",
    ),
    ManualCheck(
        "A09-sensiveis",
        "A09:2025",
        "Ações sensíveis geram registro?",
        "Troca de senha, acesso de admin e exclusão de dados precisam deixar rastro para "
        "investigar um incidente depois.",
        "Faça uma troca de senha e um acesso a área administrativa; confirme que cada ação gerou "
        "um registro identificável.",
    ),
    ManualCheck(
        "A09-alerta",
        "A09:2025",
        "Há alerta para picos de erro ou ataque?",
        "Registrar não basta se ninguém olha. Sem alerta, o ataque só é descoberto quando o dano "
        "já aconteceu.",
        "Verifique se existe monitoramento que avisa a equipe em picos de erro 4xx/5xx ou de "
        "tentativas de login — e para quem o alerta vai.",
    ),
)

BY_OWASP: dict[str, list[ManualCheck]] = {}
for _c in CHECKS:
    BY_OWASP.setdefault(_c.owasp, []).append(_c)

CHECK_IDS = frozenset(c.check_id for c in CHECKS)


def check(check_id: str) -> ManualCheck | None:
    return next((c for c in CHECKS if c.check_id == check_id), None)
