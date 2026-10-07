"""Monta o relatório JSON (fonte da verdade) a partir dos achados validados."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime

from scanner.common.grouping import STATUS_STRENGTH, group_findings
from scanner.common.masking import mask_obj, mask_text
from scanner.common.models import Finding, Severity, Status
from scanner.common.owasp import CATEGORIES, OWASP_VERSION
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
        items.append(
            ReportItem(
                group_key=group.key,
                finding=_masked(rep),
                severity=group.severity,
                status=group.status,
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
