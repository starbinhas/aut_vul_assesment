"""Eval de qualidade da remediação: a correção do catálogo é concreta, não genérica.

Prova determinística do nosso valor central ("correção executável, não genérica"). Vale para o
catálogo estático, que é o texto que SEMPRE aparece quando o LLM falha/está desligado.
"""

from __future__ import annotations

from scanner.report.catalog import static_remediation
from scanner.report.eval import score_remediation
from scanner.report.models import FixStep, Remediation
from tests.conftest import make_finding

# CWEs com entrada de catálogo que deve trazer trecho concreto (comando/config/código).
CONCRETE_CWES = (79, 89, 1021, 614, 319, 538, 548, 200)


def test_catalog_is_concrete_for_known_families() -> None:
    for cwe in CONCRETE_CWES:
        rule = "40018" if cwe == 89 else "40012" if cwe == 79 else "99999"
        rem = static_remediation(make_finding(rule_id=rule, cwe=cwe))
        score = score_remediation(rem)
        assert score.is_concrete, f"remediação do CWE {cwe} não é concreta: {score}"


def test_injection_remediations_pass_full_rubric() -> None:
    for cwe, rule in ((79, "40012"), (89, "40018")):
        rem = static_remediation(make_finding(rule_id=rule, cwe=cwe))
        assert score_remediation(rem).passed == 6


def test_rubric_rejects_generic_text() -> None:
    vague = Remediation(
        what_it_is="Há um problema de segurança.",
        why_it_matters="Pode ser explorado.",
        how_to_fix=[FixStep(title="Corrija", detail="Melhore a segurança.")],
        how_to_verify="Verifique.",
        references=[],
    )
    score = score_remediation(vague)
    assert not score.is_concrete
    assert not score.has_snippet
