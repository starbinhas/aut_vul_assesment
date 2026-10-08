"""Agrupa achados da mesma falha (mesmo tipo + mesmo título) espalhados por várias páginas.

Para o cliente, "cabeçalho X ausente" em 120 páginas é uma correção só, não 120.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from scanner.common.models import Finding, Severity, Status

# Do mais forte para o mais fraco: o grupo assume o melhor status entre suas páginas.
STATUS_STRENGTH = {
    Status.CONFIRMED: 0,
    Status.LIKELY: 1,
    Status.UNCONFIRMED: 2,
    Status.CANDIDATE: 3,
    Status.FALSE_POSITIVE: 4,
}


# Variante no fim do título que não muda a correção: "Insecure HTTP Method - PUT", "- COPY"...
_METHOD_SUFFIX = re.compile(
    r"\s+-\s+(get|head|post|put|patch|delete|options|trace|connect|copy|lock|unlock|mkcol|move"
    r"|propfind|proppatch)$",
    re.IGNORECASE,
)


def title_family(title: str) -> str:
    """Título sem a variante: a mesma falha com vários métodos HTTP vira um item só."""
    return _METHOD_SUFFIX.sub("", title.strip()).lower()


def group_key(f: Finding) -> str:
    kind = f"cwe:{f.cwe}" if f.cwe else f"{f.source.tool}:{f.source.rule_id}"
    return f"{kind}|{title_family(f.title)}"


def normalize_key(key: str) -> str:
    """Chave de relatórios antigos (antes de `title_family`) no formato atual, para comparar."""
    kind, _, title = key.partition("|")
    return f"{kind}|{title_family(title)}"


@dataclass
class FindingGroup:
    key: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def representative(self) -> Finding:
        """O achado com prova mais forte (e mais grave) representa o grupo."""
        return min(self.findings, key=lambda f: (STATUS_STRENGTH[f.status], -f.severity.rank))

    @property
    def status(self) -> Status:
        return self.representative.status

    @property
    def severity(self) -> Severity:
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def title(self) -> str:
        return self.representative.title


def group_findings(findings: Iterable[Finding]) -> list[FindingGroup]:
    groups: dict[str, FindingGroup] = {}
    for f in findings:
        groups.setdefault(group_key(f), FindingGroup(group_key(f))).findings.append(f)
    return sorted(
        groups.values(),
        key=lambda g: (STATUS_STRENGTH[g.status], -g.severity.rank, g.title),
    )
