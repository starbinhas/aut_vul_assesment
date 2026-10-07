"""Mapa de cobertura por categoria do OWASP Top 10: o que cobrimos e o que falta.

Torna o plano rastreável: cada categoria tem um estado honesto. "Cobrir todas as debilidades" não é
100% automático — parte depende de revisão humana ou de outras etapas do time. Este mapa separa o
que é nosso e automatizável do que não é, e o boletim de cobertura o usa para explicar cada linha.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# coberto  — já detectamos (validador no ar).
# parcial  — detecção pronta, falta integrar no pipeline automático.
# planejado— automatizável e não destrutivo; ainda não construído.
# manual   — exige revisão humana (lógica de negócio); não automatizável de forma geral.
# externo  — responsabilidade de outra etapa do time (reconhecimento / falhas conhecidas).
Status = Literal["coberto", "parcial", "planejado", "manual", "externo"]


@dataclass(frozen=True)
class CategoryPlan:
    owasp: str
    status: Status
    detector: str  # o que cobre (ou cobriria) a categoria
    note: str


PLAN: dict[str, CategoryPlan] = {
    "A01:2025": CategoryPlan(
        "A01:2025",
        "parcial",
        "teste de acesso entre usuários (access_probe)",
        "detecção pronta e provada; falta integrar no pipeline automático (precisa de 2 usuários).",
    ),
    "A02:2025": CategoryPlan(
        "A02:2025",
        "coberto",
        "validadores de cabeçalhos e cookies",
        "cabeçalhos de segurança e flags de cookie já são confirmados.",
    ),
    "A03:2025": CategoryPlan(
        "A03:2025",
        "externo",
        "análise de dependências / etapa 3 (nuclei)",
        "Retire.js não enxerga bibliotecas empacotadas (bundle); cobertura real é por SCA/CVEs.",
    ),
    "A04:2025": CategoryPlan(
        "A04:2025",
        "parcial",
        "sonda de arquivos/dados sensíveis expostos",
        "detecção de arquivos expostos pronta (no boletim); cripto fraca continua manual.",
    ),
    "A05:2025": CategoryPlan(
        "A05:2025",
        "coberto",
        "validadores de XSS refletido e SQLi por erro",
        "injeção refletida e por erro já são confirmadas; outras variantes são planejadas.",
    ),
    "A06:2025": CategoryPlan(
        "A06:2025",
        "manual",
        "revisão humana de lógica de negócio",
        "design inseguro (pular etapa, cupom negativo) não é automatizável de forma geral.",
    ),
    "A07:2025": CategoryPlan(
        "A07:2025",
        "planejado",
        "sondas de autenticação (bloqueio de login, sessão)",
        "falta de bloqueio e falhas de sessão são testáveis; senha fraca em parte é manual.",
    ),
    "A08:2025": CategoryPlan(
        "A08:2025",
        "planejado",
        "checagem de desserialização / integridade",
        "exige sondas específicas e não destrutivas; ainda não construído.",
    ),
    "A09:2025": CategoryPlan(
        "A09:2025",
        "manual",
        "revisão de registro e alerta",
        "falhas de log não são observáveis de fora do alvo.",
    ),
    "A10:2025": CategoryPlan(
        "A10:2025",
        "parcial",
        "mensagens de erro reveladoras",
        "SQLi por erro já expõe parte; outras condições excepcionais são caso a caso.",
    ),
}


def plan_for(owasp: str) -> CategoryPlan | None:
    return PLAN.get(owasp)


def missing() -> list[CategoryPlan]:
    """Categorias que ainda dependem de trabalho nosso (automatizável, não feito)."""
    return [p for p in PLAN.values() if p.status in ("parcial", "planejado")]
