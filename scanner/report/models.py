"""Modelos do relatório. O JSON do relatório é a fonte da verdade; HTML/PDF derivam dele."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from scanner.common.models import Finding, Severity, Status


class FixStep(BaseModel):
    title: str = Field(description="Ação curta no imperativo, ex.: 'Escape a saída no template'.")
    detail: str = Field(description="Explicação do passo para alguém não especialista.")
    snippet: str | None = Field(
        default=None, description="Comando, configuração ou trecho de código concreto."
    )
    snippet_language: str | None = Field(
        default=None, description="Linguagem do trecho (nginx, apache, python, js, php, bash...)."
    )


class Remediation(BaseModel):
    what_it_is: str = Field(description="O que é a falha, em 2-4 frases simples.")
    why_it_matters: str = Field(description="O que um atacante consegue fazer e o impacto.")
    how_to_fix: list[FixStep] = Field(description="Passo a passo concreto e executável.")
    how_to_verify: str = Field(description="Como o cliente confirma que a correção funcionou.")
    references: list[str] = Field(default_factory=list, description="Links OWASP/CWE/documentação.")


RemediationSource = Literal["llm", "cache", "catalog"]


class AffectedLocation(BaseModel):
    finding_id: str
    method: str
    url: str
    parameter: str | None
    status: Status


class ReportItem(BaseModel):
    """Uma falha (grupo): o achado representativo + todas as páginas afetadas."""

    group_key: str
    finding: Finding
    severity: Severity
    status: Status
    locations: list[AffectedLocation]
    owasp_name: str | None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    remediation: Remediation
    remediation_source: RemediationSource


class DiscardedItem(BaseModel):
    group_key: str
    title: str
    urls: list[str]
    reason: str
    finding_ids: list[str] = []


class Summary(BaseModel):
    """Contagens por falha (grupo), não por página."""

    by_severity: dict[str, int]
    by_status: dict[str, int]
    total_reported: int
    affected_pages: int


class Report(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    target_id: str
    generated_at: datetime
    language: str
    owasp_version: str
    summary: Summary
    items: list[ReportItem]
    discarded: list[DiscardedItem]
