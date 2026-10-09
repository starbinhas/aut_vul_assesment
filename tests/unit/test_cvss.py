"""Nota CVSS representativa por achado e no relatório."""

from __future__ import annotations

from scanner.common.models import Severity, Status
from scanner.report.builder import build_report
from scanner.report.catalog import static_remediation
from scanner.report.cvss import cvss_for
from tests.conftest import make_finding


def test_cvss_by_cwe() -> None:
    sqli = make_finding(rule_id="40018", cwe=89, severity=Severity.HIGH)
    score, vector = cvss_for(sqli)
    assert score == 9.8 and vector.startswith("CVSS:3.1/")

    xss = make_finding(cwe=79, severity=Severity.MEDIUM)
    score, _ = cvss_for(xss)
    assert score == 6.1


def test_cvss_falls_back_to_severity_when_cwe_unknown() -> None:
    f = make_finding(rule_id="99999", cwe=None, severity=Severity.HIGH)
    score, vector = cvss_for(f)
    assert score == 7.5 and vector.startswith("CVSS:3.1/")


def test_report_items_carry_cvss() -> None:
    f = make_finding(rule_id="40018", cwe=89, status=Status.CONFIRMED)
    report = build_report("scan-1", "target-1", [f], lambda f: (static_remediation(f), "catalog"))
    item = report.items[0]
    assert item.cvss_score is not None and item.cvss_vector is not None
    assert 0.0 <= item.cvss_score <= 10.0
