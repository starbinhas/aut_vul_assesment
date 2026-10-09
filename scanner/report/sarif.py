"""Exportação do relatório em SARIF 2.1.0 (Static Analysis Results Interchange Format).

SARIF é o formato que GitHub code scanning, Invicti, Rapid7 e afins ingerem. Exportar nele é
paridade de mercado e destrava "quebrar o build no CI" a partir do nosso scan. Derivamos do
`Report` (fonte da verdade); não é uma fonte nova de dados.
"""

from __future__ import annotations

from typing import Any

from scanner.common.models import Severity, Status
from scanner.report.models import Report, ReportItem

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "Pitchy Scanner"

# Severidade → nível SARIF. SARIF só tem error/warning/note/none.
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _rule_id(item: ReportItem) -> str:
    """Id estável da regra: o rule_id da ferramenta, senão o CWE, senão a chave do grupo."""
    rid = item.finding.source.rule_id
    if rid:
        return rid
    if item.finding.cwe is not None:
        return f"CWE-{item.finding.cwe}"
    return item.group_key


def _result(item: ReportItem) -> dict[str, Any]:
    locations = [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": loc.url},
            },
            "logicalLocations": (
                [{"name": loc.parameter, "kind": "parameter"}] if loc.parameter else []
            ),
        }
        for loc in item.locations
    ]
    properties: dict[str, Any] = {
        "status": item.status.value,
        "owasp": item.finding.owasp,
    }
    if item.finding.cwe is not None:
        properties["cwe"] = f"CWE-{item.finding.cwe}"
    if item.cvss_score is not None:
        properties["cvss_score"] = item.cvss_score
        properties["cvss_vector"] = item.cvss_vector
        # GitHub code scanning lê daqui a severidade numérica.
        properties["security-severity"] = str(item.cvss_score)
    return {
        "ruleId": _rule_id(item),
        "level": _LEVEL[item.severity],
        "message": {"text": item.finding.title},
        "locations": locations,
        "properties": properties,
    }


def _rules(items: list[ReportItem]) -> list[dict[str, Any]]:
    """Uma regra por rule_id distinto (SARIF exige a definição da regra no driver)."""
    seen: dict[str, dict[str, Any]] = {}
    for item in items:
        rid = _rule_id(item)
        if rid in seen:
            continue
        rule: dict[str, Any] = {
            "id": rid,
            "name": item.finding.source.rule_name or item.finding.title,
            "shortDescription": {"text": item.finding.title},
            "properties": {
                "tags": [t for t in [item.finding.owasp] if t],
            },
        }
        if item.finding.cwe is not None:
            rule["properties"]["cwe"] = f"CWE-{item.finding.cwe}"
        seen[rid] = rule
    return list(seen.values())


def to_sarif(report: Report) -> dict[str, Any]:
    """Converte o relatório em SARIF 2.1.0. Só os achados reportados (não os descartados)."""
    reported = [i for i in report.items if i.status is not Status.FALSE_POSITIVE]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": "https://pitchy.me",
                        "rules": _rules(reported),
                    }
                },
                "automationDetails": {"id": f"scan/{report.scan_id}"},
                "results": [_result(i) for i in reported],
            }
        ],
    }
