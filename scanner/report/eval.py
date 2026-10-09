"""Avaliação da qualidade da remediação — o nosso valor central é "correção executável".

A CLAUDE.md exige escolher o modelo "medido contra o conjunto de avaliação". Este módulo define a
rubrica objetiva de "a correção é concreta?" e serve para dois usos:

- teste determinístico do catálogo estático (o texto que SEMPRE aparece quando o LLM falha);
- comparar modelos (gpt-oss do MVP vs. Claude) antes de trocar — o runner em
  `tests/eval_remediation.py` pontua lado a lado.

A rubrica não julga se a correção está "certa" (isso é humano); julga se é **concreta e
executável**: tem passos, pelo menos um trecho (comando/config/código), diz como verificar e cita
referência.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.report.models import Remediation

MIN_DETAIL_CHARS = 40


@dataclass(frozen=True)
class RemediationScore:
    has_steps: bool  # tem passo a passo
    has_snippet: bool  # pelo menos um passo com trecho concreto (comando/config/código)
    has_verify: bool  # diz como confirmar que corrigiu
    has_refs: bool  # cita referência (OWASP/CWE)
    explains: bool  # explica o que é e por que importa
    steps_detailed: bool  # os passos têm explicação de verdade, não uma linha vazia

    @property
    def passed(self) -> int:
        return sum(
            (
                self.has_steps,
                self.has_snippet,
                self.has_verify,
                self.has_refs,
                self.explains,
                self.steps_detailed,
            )
        )

    @property
    def total(self) -> int:
        return 6

    @property
    def is_concrete(self) -> bool:
        """O mínimo para não ser genérico: passos + trecho concreto + como verificar."""
        return self.has_steps and self.has_snippet and self.has_verify and self.steps_detailed


def score_remediation(r: Remediation) -> RemediationScore:
    """Pontua uma remediação contra a rubrica de concretude. Função pura."""
    has_snippet = any(bool(step.snippet and step.snippet.strip()) for step in r.how_to_fix)
    steps_detailed = bool(r.how_to_fix) and all(
        len(step.detail.strip()) >= MIN_DETAIL_CHARS for step in r.how_to_fix
    )
    return RemediationScore(
        has_steps=bool(r.how_to_fix),
        has_snippet=has_snippet,
        has_verify=len(r.how_to_verify.strip()) >= MIN_DETAIL_CHARS,
        has_refs=bool(r.references),
        explains=bool(r.what_it_is.strip()) and bool(r.why_it_matters.strip()),
        steps_detailed=steps_detailed,
    )
