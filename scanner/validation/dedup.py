"""Deduplicação: mesma URL + método + parâmetro + CWE vira um achado só."""

from __future__ import annotations

from collections.abc import Iterable

from scanner.common.models import Finding


def merge(primary: Finding, other: Finding) -> Finding:
    """Funde `other` em `primary` (mantém id/validação do primário, soma fontes e evidências)."""
    sources = [primary.source, *primary.related_sources]
    for s in [other.source, *other.related_sources]:
        if s not in sources:
            sources.append(s)
    severity = max(primary.severity, other.severity, key=lambda s: s.rank)
    return primary.model_copy(
        update={
            "related_sources": sources[1:],
            "evidence": primary.evidence + [e for e in other.evidence if e not in primary.evidence],
            "severity": severity,
            "description": primary.description or other.description,
            "owasp": primary.owasp or other.owasp,
        }
    )


def deduplicate(
    candidates: Iterable[Finding], existing: Iterable[Finding] = ()
) -> tuple[list[Finding], list[Finding]]:
    """Retorna (novos achados a validar, achados existentes atualizados com novas fontes).

    Candidatos sem CWE só se juntam com outros da mesma ferramenta e regra.
    """
    by_key: dict[tuple[object, ...], Finding] = {}
    existing_keys: set[tuple[object, ...]] = set()

    def key(f: Finding) -> tuple[object, ...]:
        k = f.dedup_key()
        return k if f.cwe is not None else (*k, f.source.tool, f.source.rule_id)

    for f in existing:
        by_key[key(f)] = f
        existing_keys.add(key(f))

    touched: set[tuple[object, ...]] = set()
    for f in candidates:
        k = key(f)
        if k in by_key:
            if by_key[k].finding_id == f.finding_id:
                continue  # reentrega do mesmo candidato
            by_key[k] = merge(by_key[k], f)
        else:
            by_key[k] = f
        touched.add(k)

    new = [by_key[k] for k in touched if k not in existing_keys]
    updated = [by_key[k] for k in touched if k in existing_keys]
    return new, updated
