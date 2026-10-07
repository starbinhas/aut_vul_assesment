"""A lógica de contagem da cobertura (sem rede nem banco)."""

from __future__ import annotations

from scanner.common.owasp import CATEGORIES
from tests.lab_coverage import JUICE_CATEGORY_TO_OWASP, CategoryCoverage, _print


def test_every_juice_category_maps_to_a_known_owasp_or_none() -> None:
    for owasp in JUICE_CATEGORY_TO_OWASP.values():
        assert owasp is None or owasp in CATEGORIES


def test_print_counts_touched_categories(capsys) -> None:
    rows = [
        CategoryCoverage("A01:2025", "Controle de Acesso", target_weaknesses=5, our_findings=0),
        CategoryCoverage(
            "A05:2025", "Injeção", target_weaknesses=8, our_findings=12, our_confirmed=7
        ),
        CategoryCoverage("A09:2025", "Registro", target_weaknesses=0, our_findings=0),
    ]
    _print(rows, "lab-juice-shop-x")
    out = capsys.readouterr().out
    # 2 categorias do alvo (A01, A05); só A05 teve achado nosso.
    assert "1/2" in out
    assert "A09:2025" in out  # categoria sem desafio no alvo ainda aparece na tabela


# --- mapa de cobertura (plano por categoria) ---------------------------------------------

from scanner.validation.coverage_map import PLAN, missing, plan_for  # noqa: E402


def test_every_owasp_category_has_a_plan() -> None:
    from scanner.common.owasp import CATEGORIES

    assert set(PLAN) == set(CATEGORIES)  # nenhuma categoria sem plano explícito


def test_plan_status_values_are_valid() -> None:
    allowed = {"coberto", "parcial", "planejado", "manual", "externo"}
    assert all(p.status in allowed for p in PLAN.values())


def test_missing_lists_only_our_pending_work() -> None:
    # "parcial"/"planejado" = nosso e ainda não pronto; manual/externo/coberto ficam de fora.
    assert all(p.status in ("parcial", "planejado") for p in missing())
    assert plan_for("A01:2025").status == "parcial"
    assert plan_for("A05:2025").status == "coberto"
