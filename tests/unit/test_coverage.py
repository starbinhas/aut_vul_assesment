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
