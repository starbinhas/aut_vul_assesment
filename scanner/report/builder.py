"""Monta o relatório JSON (fonte da verdade) a partir dos achados validados."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime

from scanner.common.grouping import STATUS_STRENGTH, group_findings
from scanner.common.masking import mask_obj, mask_text
from scanner.common.models import Finding, Severity, Status
from scanner.common.owasp import CATEGORIES, OWASP_VERSION
from scanner.report.cvss import cvss_for
from scanner.report.models import (
    AffectedLocation,
    DiscardedItem,
    Remediation,
    RemediationSource,
    Report,
    ReportItem,
    Summary,
)

RemediationFn = Callable[[Finding], tuple[Remediation, RemediationSource]]


def _masked(f: Finding) -> Finding:
    """Defesa em profundidade: evidência já chega mascarada, mascaramos de novo."""
    return Finding.model_validate(
        mask_obj(f.model_dump(mode="json"))
        | {
            "finding_id": f.finding_id,
            "scan_id": f.scan_id,
            "target_id": f.target_id,
            "location": f.location.model_dump(mode="json"),
        }
    )


def build_report(
    scan_id: str,
    target_id: str,
    findings: list[Finding],
    remediate: RemediationFn,
    language: str = "pt-BR",
) -> Report:
    reported = [f for f in findings if f.status is not Status.FALSE_POSITIVE]
    discarded = [f for f in findings if f.status is Status.FALSE_POSITIVE]

    items = []
    for group in group_findings(reported):
        rep = group.representative
        remediation, source = remediate(rep)
        # CVSS representativo da classe, coerente com a severidade do grupo (não da ferramenta).
        cvss_score, cvss_vector = cvss_for(rep.model_copy(update={"severity": group.severity}))
        items.append(
            ReportItem(
                group_key=group.key,
                finding=_masked(rep),
                severity=group.severity,
                status=group.status,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                locations=[
                    AffectedLocation(
                        finding_id=f.finding_id,
                        method=f.location.method,
                        url=mask_text(f.location.url) or "",
                        parameter=f.location.parameter,
                        status=f.status,
                    )
                    for f in sorted(
                        group.findings, key=lambda f: (STATUS_STRENGTH[f.status], f.location.url)
                    )
                ],
                owasp_name=CATEGORIES.get(rep.owasp or ""),
                remediation=remediation,
                remediation_source=source,
            )
        )

    # Ordena o que importa primeiro: severidade (crítica → informativa) e, dentro dela, o mais
    # provado antes. Assim o ruído informativo afunda e não disputa o topo com as falhas reais.
    items.sort(key=lambda i: (-i.severity.rank, -STATUS_STRENGTH[i.status], i.group_key))

    by_sev = Counter(i.severity.value for i in items)
    by_status = Counter(i.status.value for i in items)
    discarded_groups = group_findings(discarded)
    return Report(
        scan_id=scan_id,
        target_id=target_id,
        generated_at=datetime.now(UTC),
        language=language,
        owasp_version=OWASP_VERSION,
        summary=Summary(
            by_severity={s.value: by_sev.get(s.value, 0) for s in Severity},
            by_status={
                s.value: (
                    len(discarded_groups)
                    if s is Status.FALSE_POSITIVE
                    else by_status.get(s.value, 0)
                )
                for s in Status
                if s is not Status.CANDIDATE
            },
            total_reported=len(items),
            affected_pages=len({f.location.url for f in reported}),
        ),
        items=items,
        discarded=[
            DiscardedItem(
                group_key=g.key,
                title=g.title,
                urls=sorted({mask_text(f.location.url) or "" for f in g.findings}),
                finding_ids=[f.finding_id for f in g.findings],
                reason=(
                    g.representative.validation.reason
                    if g.representative.validation
                    else "revisão humana"
                ),
            )
            for g in discarded_groups
        ],
    )
