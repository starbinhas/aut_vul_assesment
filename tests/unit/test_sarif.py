"""Exportação SARIF 2.1.0 a partir do relatório."""

from __future__ import annotations

from datetime import UTC, datetime

from scanner.common.models import Outcome, Severity, Status, Validation
from scanner.report.builder import build_report
from scanner.report.catalog import static_remediation
from scanner.report.sarif import SARIF_VERSION, to_sarif
from tests.conftest import make_finding


def _report():
    confirmed = make_finding(
        rule_id="40018", cwe=89, severity=Severity.HIGH, status=Status.CONFIRMED
    )
    fp = make_finding(rule_id="10020", cwe=1021, param=None, status=Status.FALSE_POSITIVE)
    fp = fp.model_copy(
        update={
            "validation": Validation(
                validator="h",
                outcome=Outcome.FALSE_POSITIVE,
                reason="cabeçalho presente",
                validated_at=datetime.now(UTC),
            )
        }
    )
    return build_report(
        "scan-1", "target-1", [confirmed, fp], lambda f: (static_remediation(f), "catalog")
    )


def test_sarif_shape_and_excludes_false_positives() -> None:
    doc = to_sarif(_report())
    assert doc["version"] == SARIF_VERSION
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    [run] = doc["runs"]
    assert run["tool"]["driver"]["name"] == "Pitchy Scanner"
    # só o confirmado entra; o falso positivo é descartado
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["level"] == "error"  # SQLi = high → error
    assert result["ruleId"]
    assert result["properties"]["security-severity"] == "9.8"
    # a regra do resultado está declarada no driver
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert result["ruleId"] in rule_ids


def test_sarif_automation_id_carries_scan() -> None:
    doc = to_sarif(_report())
    assert doc["runs"][0]["automationDetails"]["id"] == "scan/scan-1"
