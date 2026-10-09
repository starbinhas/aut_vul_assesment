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
        "coberto",
        "teste de acesso entre usuários (run_access_control na etapa 4, via ZAP)",
        "IDOR integrado ao pipeline: roda com 2º usuário e recursos privados configurados; "
        "prova determinística (só GET, não destrutivo).",
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
        "scan de componentes (SCA: python -m scanner.sca)",
        "SCA pronto: confere o manifesto que o cliente fornece contra o OSV. Sobrepõe a etapa 3 "
        "(nuclei) do time — alinhar a fronteira antes de produção.",
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
        "parcial",
        "sonda de bloqueio de login (força bruta)",
        "ausência de bloqueio no login detectada (no boletim); senha fraca/sessão ainda faltam.",
    ),
    "A08:2025": CategoryPlan(
        "A08:2025",
        "parcial",
        "checagem de token sem assinatura (alg:none)",
        "aceitação de token não assinado detectada (no boletim); desserialização ainda falta.",
    ),
    "A09:2025": CategoryPlan(
        "A09:2025",
        "manual",
        "checklist de revisão + teste de correlação de logs",
        "checklist humano pronto; correlação (marcar ataques e conferir nos logs) automatiza com "
        "acesso aos registros do cliente. De fora, invisível.",
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
